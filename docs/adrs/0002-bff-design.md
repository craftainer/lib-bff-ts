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
- **Refresh.** The BFF refreshes access tokens itself, under the
  per-session lock so concurrent requests refresh once, which suits
  refresh-token rotation. When the IdP rejects a refresh, the session is
  destroyed and the answer is 401 (the SPA navigates to `/bff/login`). A
  network failure keeps the session and answers 503.
- **Logout.** `POST /bff/logout` destroys the session and returns
  `{logoutUrl}` (`end_session_endpoint` with `id_token_hint` and
  `post_logout_redirect_uri`). `POST /bff/backchannel-logout` implements
  OIDC Back-Channel Logout 1.0: it verifies the logout token with `jose`
  (`typ`, signature, `iss`, `aud`, `iat`/`exp`/`jti`, the event, `sid` or
  `sub`, no `nonce`), rejects a replayed `jti`, and ends the sessions of the
  `sid` (or of the `sub` when there is no `sid`).
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
