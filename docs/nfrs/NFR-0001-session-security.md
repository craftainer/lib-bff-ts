# NFR-0001. Session security meets OWASP ASVS 5.0 level 2 (V3, V7, V10)

## Status

Implemented

## Attribute

Security.

## Description

The BFF's browser-facing session and OAuth/OIDC client behaviour satisfies
the requirements of OWASP ASVS 5.0.0 level 2 in the chapters V3 (web
frontend security, the parts this library owns), V7 (session management)
and V10 (OAuth and OIDC, client side). Each requirement below is
covered by a named test; a requirement with no test is listed as not
applicable or deferred with the reason.

Targets that are measurable:

- Session IDs carry at least 128 bits of entropy (the library uses 256).
- The session ID changes at every login.
- The login transaction expires after 5 minutes and is single-use.
- Idle timeout 30 minutes and absolute timeout 8 hours by default,
  configurable, with the absolute timeout never later than the refresh
  token's lifetime when the IdP reports it.
- Tokens, cookies, session IDs and authorization codes appear in no log
  line.

| ASVS 5.0            | Requirement (short)                                                                 | Where                                                      | Test                                                                                                                |
| ------------------- | ----------------------------------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| 3.3.1, 3.3.3, 3.3.4 | `Secure`, `__Host-`, `HttpOnly` cookies                                             | `setSessionCookie`, login cookie                           | `auth-flow.test.ts` "completes the flow: session cookie attributes", "starts the code flow"                         |
| 3.3.2               | `SameSite` fits the purpose (Strict session, Lax login transaction)                 | same                                                       | same                                                                                                                |
| 3.4.2               | No CORS headers                                                                     | no CORS plugin is registered                               | `csrf.test.ts` (cross-origin requests are refused; no `Access-Control-*` header exists in any response)             |
| 3.5.1, 3.5.3        | Anti-CSRF with a non-safelisted header, `Sec-Fetch-*` validation for unsafe methods | `src/csrf.ts`                                              | `csrf.test.ts` (all)                                                                                                |
| 7.1.1               | Idle and absolute timeouts documented                                               | ADR 0002, this NFR                                         | n/a (documentation)                                                                                                 |
| 7.2.1               | Session verification in a trusted backend service                                   | `session` plugin                                           | `auth-flow.test.ts` "answers 401 without a session or with an unknown session ID"                                   |
| 7.2.2, 7.2.3        | Reference tokens, unique, CSPRNG, at least 128 bits                                 | `randomId`                                                 | `session-store.test.ts` "randomId"                                                                                  |
| 7.2.4               | New session token at login, old one terminated                                      | `/bff/callback`                                            | `auth-flow.test.ts` "rotates the session ID at login"                                                               |
| 7.3.1               | Inactivity timeout                                                                  | sliding TTL in the store                                   | `auth-flow.test.ts` "expires an idle session and slides the idle timeout"                                           |
| 7.3.2               | Absolute lifetime                                                                   | `absoluteExpiresAt`                                        | `auth-flow.test.ts` "ends a session at its absolute expiry"; `session.test.ts`                                      |
| 7.4.1               | No use after termination                                                            | `destroy`                                                  | `auth-flow.test.ts` "destroys the session and returns the RP-initiated logout URL"                                  |
| 7.4.4               | Logout available                                                                    | `POST /bff/logout`                                         | same                                                                                                                |
| 7.6.1               | RP-IdP lifetimes coordinated                                                        | back-channel logout and refresh failure                    | `auth-backchannel.test.ts`, `auth-refresh.test.ts` "destroys the session ... when the refresh is rejected"          |
| 10.1.1              | Tokens only in the backend                                                          | session store                                              | `auth-flow.test.ts` "user profile without tokens"                                                                   |
| 10.1.2              | Responses only for flows started in the same user agent session                     | login cookie equals `state`, single-use transaction        | `auth-flow.test.ts` "rejects a callback whose state does not match", "makes the login transaction single use"       |
| 10.2.1              | PKCE or `state` against CSRF on the code flow                                       | both are used                                              | `auth-flow.test.ts` "starts the code flow", "rejects a code that does not match the PKCE verifier"                  |
| 10.2.2              | Mix-up defence (`iss`)                                                              | `openid-client` with the checked issuer                    | `auth-flow.test.ts` "rejects a wrong or missing iss parameter", "refuses a discovery document whose issuer differs" |
| 10.2.3              | Only the needed scopes                                                              | `OIDC_SCOPES`, default `openid profile email`              | `config.test.ts`                                                                                                    |
| 10.4.10             | Confidential client authentication                                                  | `client_secret_post`                                       | `auth-flow.test.ts` (the test IdP requires the secret)                                                              |
| 10.4.8              | Refresh tokens have an absolute expiry                                              | session `absoluteExpiresAt` capped by `refresh_expires_in` | `session.test.ts` "absoluteExpiry"                                                                                  |
| 10.5.1              | Nonce checked                                                                       | transaction nonce                                          | `auth-flow.test.ts` "rejects an ID token with the wrong nonce"                                                      |
| 10.5.2              | Identify users by `sub`                                                             | `sub` is the session subject                               | `auth-flow.test.ts` "completes the flow"                                                                            |
| 10.5.3              | Reject metadata whose issuer differs                                                | `createOidcClient`                                         | `auth-flow.test.ts` "refuses a discovery document whose issuer differs"                                             |
| 10.5.4              | ID token `aud` is the client ID                                                     | `openid-client`                                            | `auth-flow.test.ts` (the library validates `aud`; the test IdP issues for `bff`)                                    |
| 10.5.5              | Logout token type, event, no `nonce`, short expiry                                  | `verifyLogoutToken`                                        | `auth-backchannel.test.ts` "rejects invalid logout tokens"                                                          |

Out of this library's scope, covered elsewhere: 3.4.1, 3.4.3 to 3.4.8
(security headers, the `headers` plugin); 10.3 (resource servers, the
backends); 10.4.1 to 10.4.7 and 10.4.9 (the IdP).

Not claimed: 7.1.2 to 7.1.3 and 7.4.2, 7.4.3, 7.4.5, 7.5, 7.6.2 (user and
administrator session management belongs to the IdP), 10.4.5 (refresh-token
rotation is the IdP's, the BFF is a confidential client and serialises its
refreshes).

The ASVS IDs and summaries were read from the `v5.0.0` tag of the
[OWASP ASVS repository](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en)
on 2026-10-31.

## Source

The settled decisions in the BFF plan (2026-10-29 to 2026-10-31), in
particular "Verification standard for BFF work: ASVS 5.0 L2, chapters V3,
V7, V10", and [ADR 0002](../adrs/0002-bff-design.md). RFC 10017 section
6.1 and RFC 9700 are the underlying sources.

## Verification

The test suite in this repository runs against an in-process
`oidc-provider` on every change (`make test` and the `prek` hooks, with a
100% coverage gate). The OWASP scan (`owasp-scan` skill with `asvs=V3,V7,V10`)
and the end-to-end suite in `template-react` (real Keycloak, Valkey and
browser) re-check the behaviour before each release.
