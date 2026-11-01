# @craftainer/bff

> [!NOTE]
> This repository is vibe coded with [Claude](https://claude.com/product/claude-code).

`@craftainer/bff` is the Backend-for-Frontend library for craftainer
single-page apps, following RFC 10017 section 6.1. Built on Fastify and
`openid-client`, it acts as the confidential OIDC client on the SPA's behalf,
keeps sessions server-side in Valkey so no tokens reach the browser, and
proxies API calls to an allowlist of upstream routes. It also serves the
SPA's static files, the well-known endpoints (`security.txt` and friends), and
an optional, consent-aware analytics intake.

It is ESM-only TypeScript, created from
[`template-npm-package`](https://github.com/craftainer/template-npm-package)
(see [`docs/TEMPLATE.md`](docs/TEMPLATE.md) for the conventions shared by
every instance). The design is recorded in
[ADR 0002](docs/adrs/0002-bff-design.md) (sessions and OIDC),
[ADR 0003](docs/adrs/0003-well-known-endpoints.md) (well-known endpoints) and
[ADR 0004](docs/adrs/0004-analytics-endpoint.md) (analytics); the security
requirements are in [NFR-0001](docs/nfrs/NFR-0001-session-security.md) and
[NFR-0002](docs/nfrs/NFR-0002-analytics-privacy.md).

## Install

```sh
pnpm add @craftainer/bff
```

Requires Node.js 24.22 or newer and a Valkey (or Redis-compatible) server for
the session store. The package is ESM-only. Fastify is a regular dependency,
not a peer; the package re-exports the Fastify types an app needs.

`@opentelemetry/api-logs` is an **optional peer dependency** (`^0.223.0`),
needed only for `ANALYTICS_BACKEND=otel`. Install it yourself in that case and
register a `LoggerProvider` in your app. Without the package, or without a
registered provider, the `otel` backend warns once and discards events, like
`none`.

## Usage

```ts
import { createBff, loadConfig } from "@craftainer/bff";

const config = loadConfig(process.env); // throws ConfigError listing every problem
const app = await createBff(config);

// Your own routes go here, before listen().
app.get("/bff/ping", async () => ({ ok: true }));

await app.listen({ port: config.port, host: config.host });
```

`loadConfig(env)` validates the environment (see below) and returns a typed
`BffConfig`. Empty variables count as unset. Its `ConfigError` lists every
problem and never prints a secret value.

`createBff(config, opts?)` returns the Fastify instance **unstarted** and
never calls `ready()`, so the app adds its own routes first. Options:

- `sessionStore`: replaces the Valkey store (tests, single-process use; the
  caller closes it). `createMemorySessionStore()` is exported for that.
- `logger`: Fastify's `logger` option. Option objects get the library's
  request serializer (no query strings, which carry authorization codes) and
  redaction of `Authorization`, `Cookie` and `Set-Cookie`. Default: JSON logs
  at `info`.

Discovery and the Valkey connection are lazy (first login, first
authenticated request or `/health/ready`), so `/health/live` passes with
neither present.

Own routes: outside `/bff/*`, `/api/*`, `/health/*` and `/.well-known/*` they
are yours entirely. Anything under `/bff/` gets the CSRF rule (non-GET needs
`X-CSRF: 1`; see Endpoints) and `Cache-Control: no-store` by default. `request.bffSession`
(`null` when not signed in, otherwise `{ id, data, accessTokenFor(upstream) }`)
is available to your handlers on `/bff/*` and `/api/*` paths only.

### Plugin order

`createBff` registers these plugins, in this order (each is also exported
individually, so an app can compose its own set, keeping the order):

1. `headers`: security headers on every response (CSP, COOP, CORP,
   `Referrer-Policy`, `Permissions-Policy`, `nosniff`, HSTS in production
   over https). `Cache-Control: no-store` on `/api/*` and `/bff/*`.
2. `csrf`: `X-CSRF: 1` plus Origin / `Sec-Fetch-Site` checks.
3. `session`: session store, cookie, `request.bffSession`, token refresh.
4. `health`: `/health/live` and `/health/ready`.
5. `@fastify/formbody` (16 KB), for the back-channel logout form post.
6. `auth`: login, callback, logout, user, config, back-channel logout.
7. `wellKnown`: `/.well-known/*`.
8. `analytics`: `/bff/analytics` and `/bff/consent`.
9. `proxy`: `/api/<name>/*`.
10. `static`: the built SPA, SPA fallback and the JSON 404.

## Configuration

All configuration is read by `loadConfig(env)`; there is no `SESSION_SECRET`
(nothing the browser holds is encrypted or signed). Booleans accept `true`,
`false`, `1` and `0`. Integers must be positive.

### Server and proxy

| Variable          | Default   | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ----------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NODE_ENV`        | unset     | `production` turns on HSTS and the production-only rules below.                                                                                                                                                                                                                                                                                                                                                                        |
| `BFF_PORT`        | `8080`    | 1 to 65535.                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `BFF_HOST`        | `0.0.0.0` | Bind address (used by your `listen()` call).                                                                                                                                                                                                                                                                                                                                                                                           |
| `BFF_STATIC_DIR`  | unset     | Directory of the built SPA. Unset: no static files, only the JSON 404.                                                                                                                                                                                                                                                                                                                                                                 |
| `PUBLIC_ORIGIN`   | required  | The browser-facing origin: `https://host[:port]`, no path, query or credentials. `http` only for `localhost` outside production. It derives `redirect_uri`, the Origin check and HSTS; the `Host` header is never used.                                                                                                                                                                                                                |
| `BFF_TRUST_PROXY` | `false`   | Fastify `trustProxy`, which sets `request.ip` and so the rate-limit buckets and logs. `true` (trust every hop; a client can then forge `X-Forwarded-For`, so avoid), `false`, a hop count (e.g. `1`), or a comma-separated list of IPs / CIDRs / `loopback`, `linklocal`, `uniquelocal`. Behind a reverse proxy prefer a hop count or the proxy's address range. With `false`, all clients behind a proxy share one rate-limit bucket. |

### OIDC

| Variable               | Default                                          | Notes                                                                                                                                                                                                                                                            |
| ---------------------- | ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OIDC_ISSUER`          | required                                         | The expected `iss` of ID, access and logout tokens. https (or `OIDC_ALLOW_INSECURE`).                                                                                                                                                                            |
| `OIDC_DISCOVERY_URL`   | `<OIDC_ISSUER>/.well-known/openid-configuration` | The full discovery URL; other shapes are rejected. Set it when the BFF reaches the IdP at an internal host while `iss` stays public. The discovery document's `issuer` must equal `OIDC_ISSUER`.                                                                 |
| `OIDC_CLIENT_ID`       | `bff`                                            | The confidential client.                                                                                                                                                                                                                                         |
| `OIDC_CLIENT_SECRET`   | required                                         |                                                                                                                                                                                                                                                                  |
| `OIDC_SCOPES`          | `openid profile email`                           | Must include `openid`.                                                                                                                                                                                                                                           |
| `OIDC_ALLOW_INSECURE`  | `false`                                          | Allows plain-http IdP URLs (and an http `CHANGE_PASSWORD_URL`). Development only; refused when `NODE_ENV=production`.                                                                                                                                            |
| `OIDC_TIMEOUT_SECONDS` | `10`                                             | Timeout of every IdP HTTP request (discovery, token, JWKS). Whole seconds, and `loadConfig` rejects 30 or more (it must be **below the 30 s refresh-lock TTL**, so a refresh ends while its lock is held), so 1 to 29. (Revocation has its own fixed 2 s limit.) |
| `BFF_UPSTREAMS`        | unset                                            | JSON, see [Proxy](#api-proxy).                                                                                                                                                                                                                                   |

### Sessions and rate limits

| Variable                        | Default               | Notes                                                                                                                                                                                                                                     |
| ------------------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SESSION_STORE_URL`             | required              | `redis://`, `rediss://`, `valkey://` or `valkeys://`. **Plaintext `redis://` / `valkey://` to any non-loopback host is refused** (loopback: `localhost`, `127.0.0.0/8`, `::1`), whatever `NODE_ENV` says, because the store holds tokens. |
| `SESSION_STORE_ALLOW_PLAINTEXT` | `false`               | Set `true` to accept plaintext to a non-loopback host, e.g. a sidecar on a private network. `rediss://` and `valkeys://` are always accepted.                                                                                             |
| `SESSION_IDLE_SECONDS`          | `1800`                | Sliding idle timeout. Must not exceed the absolute timeout.                                                                                                                                                                               |
| `SESSION_ABSOLUTE_SECONDS`      | `28800`               | Absolute lifetime. Never later than the refresh token's lifetime when the IdP reports `refresh_expires_in`.                                                                                                                               |
| `SESSION_COOKIE_NAME`           | `__Host-Http-session` | Must start with `__Host-` (ASVS 3.3.3) and differ from the login cookie `__Host-Http-login`. The cookie is `Secure; HttpOnly; SameSite=Strict; Path=/`, with no `Domain`.                                                                 |
| `RATE_LIMIT_MAX`                | `20`                  | Requests per window per client IP on `/bff/login`, `/bff/callback`, `/bff/analytics` and `/bff/consent`. In memory, so per replica. Max 100000.                                                                                           |
| `RATE_LIMIT_WINDOW_SECONDS`     | `60`                  | The window. Max 86400.                                                                                                                                                                                                                    |

### Well-known endpoints

| Variable                           | Notes                                                                                                               |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `SECURITY_TXT_CONTACT`             | Comma-separated; each entry an `https:`, `mailto:` or `tel:` URI. `security.txt` is served only when this is set.   |
| `SECURITY_TXT_EXPIRES`             | ISO 8601 date-time. **Required in production** when a contact is set. Otherwise it defaults to startup + 364 days.  |
| `SECURITY_TXT_POLICY`              | URI of the disclosure policy.                                                                                       |
| `SECURITY_TXT_PREFERRED_LANGUAGES` | e.g. `en, de`.                                                                                                      |
| `SECURITY_TXT_CANONICAL`           | Default `<PUBLIC_ORIGIN>/.well-known/security.txt`.                                                                 |
| `CHANGE_PASSWORD_URL`              | https URL (http only with `OIDC_ALLOW_INSECURE`). `/.well-known/change-password` answers `302` to it only when set. |

Every `SECURITY_TXT_*` value is rejected by `loadConfig` if it contains a CR
or LF (a line break would start a new `security.txt` field).

### Analytics

| Variable                | Default   | Notes                                                                                                                           |
| ----------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `ANALYTICS_ENABLED`     | `true`    | `false` drops everything (the endpoints still answer `202`).                                                                    |
| `ANALYTICS_BACKEND`     | `none`    | `none`, `log` (one structured log line per event), `umami` or `otel`.                                                           |
| `ANALYTICS_ENDPOINT`    | unset     | Umami base URL; `/api/batch` is appended. Required for `umami`. Redirects are not followed, so it must be the final URL.        |
| `ANALYTICS_SITE_ID`     | unset     | Umami website ID. Required for `umami`.                                                                                         |
| `ANALYTICS_HOSTNAME`    | unset     | Sent as `payload.hostname`.                                                                                                     |
| `ANALYTICS_CONSENT`     | `implied` | `implied` records unless the visitor declined; `opt-in` records only after the visitor granted consent.                         |
| `ANALYTICS_RESPECT_GPC` | `true`    | Drop events when the request carries `Sec-GPC: 1` or `DNT: 1`; also serves `/.well-known/gpc.json`.                             |
| `ANALYTICS_GEO`         | `none`    | `none` or `coarse`. `coarse` is currently a **no-op**: the BFF forwards no IP to the backend, so there is nothing to geolocate. |
| `ANALYTICS_PROP_KEYS`   | empty     | Comma-separated allowlist of event property keys.                                                                               |

## Endpoints

Every non-GET request to `/bff/*` and every request to `/api/*` (any
method) must send `X-CSRF: 1`; GET to the other `/bff/*` routes needs no header.
Unsafe methods are also rejected (`403`) when `Origin` is not `PUBLIC_ORIGIN`
or `Sec-Fetch-Site` is not `same-origin` / `none`. The BFF sends no CORS
headers. `GET /bff/login` and `GET /bff/callback` are top-level navigations
and carry no header; `POST /bff/backchannel-logout` is exempt from both checks
because the IdP calls it and the signed logout token authenticates it. A `401`
from the SPA's point of view means: navigate to `/bff/login`.

| Endpoint                         | Behaviour                                                                                                                                                                                                                                                                                                         |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /bff/login?returnTo=<path>` | Starts authorization code + PKCE (`S256`). `returnTo` must be a same-origin path. Rate limited. `503 idp_unavailable` when discovery fails.                                                                                                                                                                       |
| `GET /bff/callback`              | Completes the login, sets the session cookie, redirects to `returnTo`. `400 login_failed` for a bad or expired transaction. Rate limited.                                                                                                                                                                         |
| `POST /bff/logout`               | Ends the session, best-effort revokes the refresh token at the IdP (RFC 7009, 2 s), clears the cookie, answers `200 {logoutUrl}` (the IdP's end-session URL). `401` without a session.                                                                                                                            |
| `GET /bff/user`                  | `200 {sub, name, email?, roles, expiresAt}` or `401`. Roles are a UI hint; authorize in the upstreams.                                                                                                                                                                                                            |
| `POST /bff/backchannel-logout`   | OIDC Back-Channel Logout 1.0, form-encoded `logout_token`. The token is verified and its `jti` single-use. `400` for a bad token (permanent); `503` when the IdP's discovery or keys cannot be used, or the check fails for a reason that is not the token's fault (the IdP retries). No rate limit, 16 KB limit. |
| `GET /bff/config`                | Unauthenticated public runtime config: `{analytics: {enabled, consent, respectGpc}, upstreams: [names]}`.                                                                                                                                                                                                         |
| `GET /health/live`               | Always `200`; touches neither Valkey nor the IdP.                                                                                                                                                                                                                                                                 |
| `GET /health/ready`              | `200` only when the session store answers PING and IdP discovery succeeds, else `503`; body `{status, checks: {store, idp}}`.                                                                                                                                                                                     |
| `POST /bff/analytics`            | See below.                                                                                                                                                                                                                                                                                                        |
| `GET` / `POST /bff/consent`      | See below.                                                                                                                                                                                                                                                                                                        |
| `/.well-known/*`                 | See below.                                                                                                                                                                                                                                                                                                        |
| `/api/<name>/*`                  | See [API proxy](#api-proxy).                                                                                                                                                                                                                                                                                      |

Error bodies carry the library's own codes (`{error: "..."}`), or
`rate_limited` / `request_failed`; Fastify's `FST_*` codes are never exposed.

### Well-known endpoints

GET and HEAD work on all of them. A route whose setting is absent answers `404`.

- `/.well-known/security.txt` (RFC 9116): only when `SECURITY_TXT_CONTACT`
  is set. `Expires` defaults to startup + 364 days (a stable value), and
  `Canonical` to `<PUBLIC_ORIGIN>/.well-known/security.txt`.
- `/.well-known/change-password`: `302` to `CHANGE_PASSWORD_URL`, only when set.
- `/.well-known/gpc.json`: `{"gpc": true, "lastUpdate": ...}`, served while
  `ANALYTICS_RESPECT_GPC` is true.
- `/.well-known/api-catalog` (RFC 9727): an `application/linkset+json`
  linkset with one entry per configured upstream (an empty linkset with
  none), and a `Link: rel="api-catalog"` header.

### Analytics intake

`POST /bff/analytics` takes one event or an array of 1 to 50:
`{name, props?, url?}`. `name` matches `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`
(at most 50 characters); `props` are scalars whose keys are on
`ANALYTICS_PROP_KEYS` (string values at most 200 characters); `url` is a path
(at most 500 characters, query and fragment stripped, default `/`). Unknown
fields and keys off the allowlist are rejected. The SPA sends it with
`fetch(..., {method: "POST", keepalive: true, headers: {"X-CSRF": "1"}})`.

- `202` (empty body) for an accepted event **and** for a dropped one, so the
  SPA learns nothing about the policy. The drop check runs before validation.
- `400 invalid_event` for a malformed body of an event that would be recorded.
- `413` above the 16 KB body limit. Rate limited like login.
- Events are dropped when analytics is disabled or the backend is `none`;
  when GPC / DNT applies (and `ANALYTICS_RESPECT_GPC`); when the consent cookie
  is `0`; and, under `opt-in`, unless the consent cookie is `1`.
- The Umami backend queues up to 1000 events, flushes every 5 s in batches of
  50 with a 2 s timeout, and drops on overflow. It never blocks a request.
  `payload.ip` is an opaque daily pseudonymous token (an HMAC of IP and
  User-Agent under an in-memory salt rotated at 00:00 UTC), never a raw IP.

`POST /bff/consent` with `{"analytics": true | false}` stores the choice in
the cookie `__Host-Http-consent` (`1` / `0`, `HttpOnly; Secure;
SameSite=Strict; Path=/`, 180 days) and answers `{analytics}`;
`GET /bff/consent` returns the current `{analytics}`. A stored `0` stops
recording in **every** mode, including `implied`.

### API proxy

`BFF_UPSTREAMS` is an explicit allowlist, JSON of the form

```json
{
  "crud": {
    "url": "http://crud:8000",
    "audience": "api",
    "methods": ["GET", "POST", "PUT", "DELETE"],
    "stream": false,
    "tokenExchange": false
  }
}
```

Names match `[a-z][a-z0-9-]*`; `url` is http(s) with no credentials, query or
fragment; `methods` is a non-empty subset of `GET HEAD POST PUT PATCH DELETE
OPTIONS`. `stream: true` disables the body timeout for server-sent events.
`tokenExchange: true` (RFC 8693) is accepted by the schema but not
implemented: it fails at use.

Each upstream is mounted at `/api/<name>/*` with the prefix stripped:

- No session: `401 unauthorized`, checked **before** the method (`405` with
  an `Allow` header, for a method not in `methods`).
- The request is forwarded with `Authorization: Bearer <access token>`,
  refreshed first when it is about to expire. A refresh the IdP rejects
  ends the session (`401 session_expired`); an IdP outage keeps it (`503`).
- The raw (still percent-encoded) path goes upstream untouched; `.`/`..`
  segments (also encoded) and backslashes are rejected with `400
invalid_path`. The body is streamed byte for byte, any content type.
- Request headers are an allowlist: `Accept`, `Accept-Language`,
  `Accept-Encoding`, `Content-Type`, `Content-Length`, the conditional headers
  (`If-*`), `Range`, `traceparent`, `tracestate`, `X-Request-Id`, `Sec-GPC`
  and `DNT`. Inbound `Authorization`, `Cookie`, `X-CSRF` and `X-Forwarded-*`
  never pass.
- `Analytics-Consent`: any inbound value is dropped; the BFF sends
  `Analytics-Consent: 1` upstream only when the visitor's consent cookie is
  `1`. This is the contract the craftainer backends' analytics read.
- Upstream `Set-Cookie`, `Strict-Transport-Security` and `Access-Control-*`
  response headers are removed. Responses carry `Cache-Control: no-store`
  whatever the upstream said, and the BFF's security headers.
- An unreachable upstream answers `502 bad_gateway`.

## Security events

Security-relevant events are logged as structured JSON,
`{"security": true, "event": ..., ...}`, never with tokens, cookies, session
IDs or authorization codes. Level `info`: `login_started`, `login_success`,
`logout`, `backchannel_logout`. Level `warn`: `login_failed`, `refresh_failed`,
`csrf_rejected`, `origin_rejected`, `backchannel_logout_rejected`,
`rate_limited` and `token_revocation_failed` (the best-effort refresh-token
revocation at logout, or of an orphaned token after a lost refresh race, failed
or timed out; the logout itself is never blocked).

## Known limitations

- **Visitor-token counts inflate** across replicas and restarts: the daily
  salt of the pseudonymous Umami visitor token is held in memory per process,
  so one visitor counts again on every replica and after every restart.
  Accepted over keeping a shared secret (ADR 0004).
- **Refresh tokens are revoked only on explicit logout** (plus the orphan case
  of a lost refresh race). Sessions that end by back-channel logout, idle or
  absolute expiry, re-login or a failed refresh are not revoked at the IdP
  (ADR 0002).
- Rate limits are in memory, per replica, so the effective limit grows with the
  replica count.
- `/bff/config` and `/health/ready` details are unauthenticated.
- `__Host-` cookies need `Secure`, which works on `http://localhost` in
  Chromium and Firefox but not in Safari; develop and test with those browsers.
- Sessions are lost if Valkey loses its data, and authenticated requests need
  Valkey to be available.

## Publishing to npm

`make publish-packages` is a no-op (with a `::warning::` in the log) until you opt
in by setting the repository variable `NPM_PUBLISH` (any non-empty value). npm has no pending publishers,
so the first release is bootstrapped with a token and every later one uses
[trusted publishing](https://docs.npmjs.com/trusted-publishers) (GitHub
OIDC, with provenance), with no token stored:

1. Create the `NPM_TOKEN` secret: a granular token for the `@craftainer`
   scope with "Read and write (stage only)". Set `NPM_PUBLISH`.
2. Run the first release. `make publish-packages` runs `npm stage publish`, which
   stages the tarball without 2FA. Approve it with 2FA: `npm stage list`,
   then `npm stage approve <stage-id>` (or on npmjs.com). Until then the
   version is not installable, and `make verify-published` (the release
   workflow's last job, after the GitHub release exists) fails saying so;
   re-run that job after approving.
3. On npmjs.com, add the package's trusted publisher (this repository,
   workflow `release.yml`), then delete the `NPM_TOKEN` secret. Later
   releases publish directly through OIDC; npm expires a trusted-publisher
   configuration that has not published within 48 hours, so do this just
   before the next release.

The version lives only in the git tag `release.yml` computes;
`package.json` stays at `0.0.0` and `make build` stamps `RELEASE_VERSION`
into the build without committing it. Details: `docs/TEMPLATE.md`, "Package
template notes".

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
