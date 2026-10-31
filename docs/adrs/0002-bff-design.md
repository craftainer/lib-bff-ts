# 0002. Terminate OIDC in a library BFF with server-side sessions

## Status

Accepted

## Context

craftainer single-page apps need to sign users in and call APIs. Keeping
OAuth tokens in the browser (`oidc-client-ts` with `sessionStorage`, as
`template-react` did) exposes them to any script that runs in the page.
[RFC 10017](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/)
(BCP 212, OAuth 2.0 for Browser-Based Applications) ranks that pattern
least secure and recommends a Backend-for-Frontend (section 6.1): a
confidential OIDC client on the app's own origin that keeps the tokens and
gives the browser only a cookie. [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)
(BCP 240) adds the current security baseline for the flows involved.

Several apps will need the same BFF, and its code is security-relevant, so
it should be fixed once and reach the apps as a version bump rather than as
a copy in each app (which is why it is a library, `@craftainer/bff`, instead
of code in `template-react`). One BFF serves one frontend.

## Decision

We will implement the BFF as this library: a Fastify 5 plugin set with
`openid-client` 6 as the OIDC client, `jose` for logout tokens and `zod` 4
for configuration. `createBff(config)` composes the plugins and returns the
unstarted instance. These choices are settled:

- **Flow.** Confidential client, authorization code with PKCE `S256`,
  discovery from the IdP's metadata, and the `iss` authorization-response
  parameter checked (RFC 9207, RFC 10017 6.1.3.1, RFC 9700 2.1). No
  implicit grant and no password grant (RFC 9700 2.1.2, 2.4). The
  discovery document's `issuer` must equal `OIDC_ISSUER`, and the discovery
  URL is configured separately, so containers can reach the IdP at an
  internal host while `iss` stays the public one.
- **Login transaction.** State, nonce and the PKCE verifier live in Valkey
  for five minutes and are single-use. The `SameSite=Lax` cookie
  `__Host-Http-login` (Lax, because the callback is a cross-site top-level
  redirect) carries only a random ID that equals `state`. There is no
  `SESSION_SECRET` and no encrypted cookie. This replaces the original idea
  of an encrypted transaction cookie: nothing the browser holds can be
  decrypted, replayed or re-signed.
- **Session.** An opaque 256-bit random ID (CSPRNG) in the cookie
  `__Host-Http-session` (`Secure; HttpOnly; SameSite=Strict; Path=/`, no
  `Domain`; the name is configurable, RFC 10017 6.1.3.2). The session lives
  in Valkey and holds the tokens, which never reach the browser (6.1.2.3).
  The ID is rotated at every login and the previous session is destroyed.
  There is an idle timeout (sliding) and an absolute timeout, and the
  absolute timeout never exceeds the refresh token's lifetime when the IdP
  reports `refresh_expires_in` (6.1.2.2).
- **Own session store.** The library keeps its own store (not
  `@fastify/session`): `sess:<id>` plus `sid:` and `sub:` index sets for
  back-channel logout, a `SET NX PX` lock per session for refresh, and
  `tx:` login transactions. It sits behind a minimal key-value interface
  (`KvClient`) with `iovalkey` and in-memory implementations, so the same
  store logic is tested without a server and tests can inject a store.
  Discovery and the Valkey connection are lazy: `/health/live` needs
  neither.
- **Proxy trust.** `BFF_TRUST_PROXY` mirrors Fastify's `trustProxy`: `false`
  (default), `true` (every hop, so a client can forge `X-Forwarded-For`
  and dodge per-IP rate limits and logs), a hop count, or a comma-separated
  list of IPs/CIDRs. Behind a reverse proxy prefer a specific hop count or
  the proxy's address range over `true`; with `false` all clients share the
  proxy's address and one rate-limit bucket.
- **Request targets.** One canonical `pathOf` (percent-decoded the way the
  router decodes, no query or fragment) serves the CSRF guard, session
  loading and logging. A target that does not start with exactly one `/`
  (`//bff/x`, absolute-form) or has malformed escapes is guarded like
  `/api` (fail closed).
- **Session cookie hygiene.** A cookie that is not a 43-character base64url
  ID never reaches a store key, and the cookie is cleared when its session
  is unknown or expired. Error bodies carry the library's own codes, or
  `rate_limited` / `request_failed`; Fastify's `FST_*` codes are not exposed.
- **Upstream names.** `BFF_UPSTREAMS` becomes a prototype-less object and
  lookups use `Object.hasOwn`, so `constructor` is not an upstream.
- **Roles keys.** Roles are built without a prototype; a client named
  `realm` (the realm-roles key) or `__proto__` is ignored with a warning.
- **Public origin.** `PUBLIC_ORIGIN`, never the `Host` header, derives
  `redirect_uri`, the Origin check and HSTS.
- **CSRF.** `X-CSRF: 1` is required on every `/api/*` request and every
  non-GET `/bff/*` request (RFC 10017 6.1.3.3.2), plus a rejection of
  unsafe methods whose `Origin` is not `PUBLIC_ORIGIN` or whose
  `Sec-Fetch-Site` is not `same-origin` or `none` (OWASP CSRF Prevention
  Cheat Sheet). The BFF sends no CORS headers. Exactly three requests are
  exempt: `GET /bff/login` and `GET /bff/callback` (top-level
  navigations, protected by the login transaction) and
  `POST /bff/backchannel-logout` (authenticated by its signed token).
- **Atomic store writes.** `KvClient.multi` applies a list of operations in
  one Valkey `MULTI`/`EXEC` (in memory, one synchronous tick): no other
  command runs in between. It is not a rollback, since Valkey does not undo
  commands that fail at run time, so `put` (the session and its `sub:` and
  `sid:` index entries in one `multi`) deletes the session key again when the
  `multi` rejects, and a session never stays live without its index entries.
  Index sets expire by their own TTL (the absolute session lifetime, renewed
  on each add); a logout never deletes a whole set, so a session that logged
  in meanwhile keeps its entry. `take` (used by `destroy`) is an atomic
  `GETDEL` that returns exactly what was removed; the index cleanup follows in
  a `multi`, and a failure there leaves a stale member that is harmless and is
  dropped by the next back-channel logout.
- **Fencing.** Every session record carries a `version` (0 at login).
  `SessionStore.replace(id, data, ttlMs, expectedVersion)` is a
  compare-and-set (a Lua script in Valkey, one synchronous step in memory):
  it writes, with the version bumped, only when the stored version still
  equals `expectedVersion`. A lost compare-and-set (another refresh won, or a
  logout removed the session) makes the refresh treat the tokens it was just
  issued as orphans: it revokes the new refresh token best effort (only when
  the IdP rotated it) and re-reads the session; a newer session is used, a
  missing one answers 401. So a refresh can neither undo a logout nor
  overwrite a newer refresh, whatever the timing.
- **Plaintext store URLs.** The store holds access, refresh and ID tokens.
  `loadConfig` rejects `redis://` and `valkey://` to any host other than
  `localhost`, 127.0.0.0/8 and `::1`, whatever `NODE_ENV` says (it may be
  unset), unless `SESSION_STORE_ALLOW_PLAINTEXT=true` (a sidecar on a private
  network). `rediss://` and `valkeys://` are always accepted.
- **Session cookie name.** `SESSION_COOKIE_NAME` must start with `__Host-`
  (the default is `__Host-Http-session`), so the prefix guarantee of
  ASVS 3.3.3 is enforced, not only the default.
- **Refresh.** The BFF refreshes access tokens itself, under a per-session
  lock (30 s) so concurrent requests mostly refresh once, which suits
  refresh-token rotation. Correctness does not depend on the lock: if it
  lapses and two requests refresh, fencing (above) keeps one result and
  revokes the other's orphaned token; a request whose refresh token was
  already rotated by the winner (`invalid_grant`) uses the winner's session
  instead of ending it. Only an OAuth `invalid_grant` that no newer session
  explains destroys the session and answers 401 (the SPA navigates to
  `/bff/login`). Every other failure (another OAuth error such as
  `invalid_client`, a 5xx, `server_error`, `temporarily_unavailable`, a
  network or discovery failure, a timeout) keeps the session and answers 503
  `idp_unavailable`, so an IdP blip does not log users out. The refresh
  re-checks `absoluteExpiresAt` first (an expired session answers 401) and
  honours a `refresh_expires_in` in the response, which can only shorten the
  absolute limit. Every IdP request has a timeout (`OIDC_TIMEOUT_SECONDS`,
  default 10 s); `loadConfig` caps it below the lock TTL as a sanity limit
  that keeps the lock useful, not as a correctness invariant. A failing lock
  release is logged and never masks the outcome.
- **Logout.** `POST /bff/logout` takes the session out of the store
  atomically (`take`), revokes the refresh token of that stored record, not
  of the request's snapshot, at the IdP (RFC 7009) when discovery advertises
  `revocation_endpoint`, and returns `{logoutUrl}` (`end_session_endpoint`
  with `id_token_hint` and `post_logout_redirect_uri`). Revocation is best
  effort: awaited for at most 2 s, a failure is logged as the
  `token_revocation_failed` security event, and the logout is never blocked.
  Revocation is deliberately limited to explicit logout and to the orphaned
  tokens above: back-channel logout (the IdP ended its session), re-login,
  and expiry or refresh failure (the IdP rejected or aged the token) do not
  revoke. `POST /bff/backchannel-logout` implements OIDC Back-Channel Logout
  1.0: it verifies the logout token with `jose` (`typ`, signature, `iss`,
  `aud`, `iat`/`exp`/`jti`, the event, `sid` or `sub`, no `nonce`), rejects a
  replayed `jti`, and ends the sessions of the `sid` (or of the `sub` when
  there is no `sid`). The `jti` is claimed first and released again when
  ending the sessions throws, so the IdP's retry gets through; a process
  crash between the claim and the end of the sessions keeps the token
  consumed for 10 minutes. That window is accepted: claiming after the
  destroy would let a replayed token log out a session created later. When
  the IdP's discovery or key set is unreachable the answer is 503 (the IdP
  retries), not 400. The route has a 16 KB body limit and deliberately no
  rate limit: the IdP is the caller, throttling would drop real logouts, and
  the signed token authenticates the request.
- **Upstreams.** `BFF_UPSTREAMS` is an explicit allowlist validated with
  `zod` (RFC 10017 6.1.3.6). The session API for the proxy is
  `request.bffSession?.accessTokenFor(upstream)`. Per-upstream token
  exchange (RFC 8693) is a defined option that is not implemented yet and
  fails loudly when set.
- **Roles are a UI hint.** `/bff/user` returns roles (Keycloak's
  `realm_access` and `resource_access`, from the ID token and the decoded
  access token); authorization stays in the upstreams.
- **Abuse and logging.** In-memory rate limits (per replica) on
  `/bff/login` and `/bff/callback`. Login, logout, refresh failure,
  CSRF/Origin rejections and rate limiting are logged as structured JSON
  security events. Tokens, cookies, session IDs and authorization codes are
  never logged: the request serializer drops query strings and the
  `Authorization` and `Cookie` headers are redacted.
- **Standard.** OWASP ASVS 5.0 level 2, chapters V3, V7 and V10;
  [NFR-0001](../nfrs/NFR-0001-session-security.md) maps requirements to
  tests.

## Consequences

- Tokens never reach the browser, so XSS cannot exfiltrate them; it can
  still make requests as the user while the page is open, which the BFF
  cannot prevent (RFC 10017 6.1.4).
- Apps depend on Valkey being available for login and for every
  authenticated request, and sessions are lost if Valkey loses data.
- Rate limits are per replica until a shared store is shown to work, so
  the effective limit grows with the replica count.
- `__Host-` cookies need `Secure`, which works on `http://localhost` in
  Chromium and Firefox but not in Safari, so development and end-to-end
  runs use those browsers. Safari does not enforce the prefix.
- `X-CSRF: 1` is a static value that relies on the browser's refusal to
  send custom headers cross-origin without a preflight; the Origin and
  Fetch Metadata check backs it up, not replaces it.
- Back-channel logout works only when the IdP can reach the BFF, and a
  replayed logout token is only detected within the 10-minute claim
  window, which is longer than the five-minute token age the BFF accepts.
- Fixes to this code reach apps as `@craftainer/bff` upgrades, so each
  app's composition stays thin and owned by the app.
