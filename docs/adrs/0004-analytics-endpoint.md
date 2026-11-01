# 0004. Take SPA analytics events at `/bff/analytics`, cookieless by default

## Status

Accepted

## Context

craftainer apps want product analytics (page views, a few domain events)
without a tracking cookie, a third-party script or a raw IP leaving the
server. The SPA cannot be trusted to send only what we want, and the
Python and Rust backends already record server-side events through the
shared contract "I3" (`track(name, props, url)`, in `lib-observability-py`
and `-rs`). The BFF is the one component that sees the visitor's IP and
User-Agent and is on the app's own origin, so it is where browser events
belong. The privacy reference is CNIL's audience-measurement consent
exemption ([sheet no. 16](https://www.cnil.fr/en/sheet-ndeg16-use-analytics-your-websites-and-applications),
[the French rules page](https://www.cnil.fr/fr/cookies-et-autres-traceurs/regles/cookies-solutions-pour-les-outils-de-mesure-daudience));
NFR-0002 maps its conditions to tests. CNIL is the reference, not a legal
opinion.

## Decision

**Endpoint.** `POST /bff/analytics` takes one event or an array of 1 to 50
(`{name, props?, url?}`), sent by the SPA with `X-CSRF: 1` (the CSRF guard
already covers non-GET `/bff`), at most 16 KB, rate limited with
`RATE_LIMIT_*`. Validation uses zod 4 and follows I3: `name` matches
`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$` and is at most 50 characters; `props`
holds string (at most 200 characters), number or boolean values whose keys
are on `ANALYTICS_PROP_KEYS` (default: none); `url` is a path only, with the
query and fragment stripped (default `/`). An unknown field, an unlisted
key or any other violation answers `400 {"error":"invalid_event"}`.

**Always 202 when it is a policy matter.** An event is dropped, with the same
empty `202` as an accepted one, when analytics is disabled, the backend is
`none`, `Sec-GPC: 1` or `DNT: 1` arrives while `ANALYTICS_RESPECT_GPC` is
true, or `ANALYTICS_CONSENT=opt-in` and consent was not granted. The drop
check runs before validation, so the SPA cannot probe the policy.

**Consent state.** `POST /bff/consent {analytics: boolean}` sets the
cookie `__Host-Http-consent` to `1` (granted) or `0` (declined; an explicit
decline also stops recording under `implied` consent) (`HttpOnly; Secure; SameSite=Strict;
Path=/`, no `Domain`, `Max-Age` 180 days, about the six months CNIL
recommends before asking again). `GET /bff/consent` answers
`{analytics: boolean}`. An `onRequest` hook sets
`request.bffAnalyticsConsent = true` only when the cookie says `1` (interface
I6): the API proxy reads it and sends `Analytics-Consent: 1` upstream,
after stripping any inbound copy. The cookie holds no identifier and is the
only cookie analytics ever sets.

**Visitor token.** The only identifier is
`base64url(HMAC-SHA256(dailySalt, ip + "\n" + userAgent))` cut to 22
characters, sent to Umami as `payload.ip` (an undocumented field of its
schema, so Umami never sees a raw IP and skips geolocation). The salt is 32
random bytes held in memory and replaced when the UTC date changes. No raw
IP or User-Agent leaves the BFF, and no token is logged. `request.ip` is the
IP; `BFF_TRUST_PROXY` decides what that is.

**Adapters** (`ANALYTICS_BACKEND`):

- `none`: discards.
- `log`: one structured log line per event with props flattened to
  `analytics_prop_<key>` (OpenTelemetry attributes must be primitives),
  plus `analytics_event` and `analytics_url`.
- `otel`: one OpenTelemetry log record per event with the same flat
  attributes, through `logs.getLogger("@craftainer/bff")` from
  `@opentelemetry/api-logs`. That package is an optional peer dependency
  (OpenTelemetry JS wants one global API copy per app) loaded with a dynamic
  `import()`. When it is missing, or no LoggerProvider is registered, the
  adapter warns once and discards events, like `none`.
- `umami`: `POST {ANALYTICS_ENDPOINT}/api/batch`, at most 50 items per
  request, `User-Agent: Mozilla/5.0 (compatible; craftainer-bff)` (Umami
  silently drops bot-like agents), items
  `{type:"event", payload:{website, url, name, ip, timestamp, hostname?, data?}}`
  with no `id` and no title, a 2 s timeout, and no redirects followed (a
  3xx is logged and the batch dropped; the endpoint must be the final URL).
  The `errors` count in the 200 reply is checked and logged.

`ANALYTICS_GEO=coarse` has no effect in the BFF: it never forwards a raw IP,
so Umami has nothing to locate.

**Delivery.** `umami` events go through a queue of 1000 with a flush every 5
s; an event that arrives when it is full is dropped, and the count is logged
once per flush window. `log` and `otel` run inline. Nothing is raised into a
request, and `onClose` flushes the queue.

## Consequences

- No analytics cookie, no browser ID and no raw IP leave the BFF, so the
  default fits the CNIL exemption. The consent cookie is set only when the
  visitor answers `POST /bff/consent` and holds a flag, not an identifier.
- **Limitation, accepted:** each replica keeps its own salt, so one visitor
  served by several replicas, or across a restart within a day, gets
  several tokens and unique-visitor counts inflate. A shared salt would need
  a secret or the session store, which would bring back the secret
  (`SESSION_SECRET`) the design avoids. Page views and event counts are
  unaffected.
- `payload.ip` is undocumented in Umami's API. A contract test (a stub
  asserting the exact JSON) guards the shape; a check against the pinned
  Umami image belongs in the e2e suite (BF5). The fallback if Umami removes
  the field is `payload.id`.
- Unlisted props are rejected rather than dropped, so a mistyped key shows up
  in development as a 400, at the cost of a stricter SPA contract.
- The `otel` adapter needs the optional peer and an app that registers a
  LoggerProvider; otherwise it silently does nothing after one warning.
- A queue loses at most 5 s of events on a hard crash. That is the price of
  never blocking a request.
