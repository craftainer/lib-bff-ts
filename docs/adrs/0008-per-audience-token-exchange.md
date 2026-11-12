# 0008. Per-audience token exchange (RFC 8693) for upstreams

## Status

Accepted

Amends [0002](0002-bff-design.md): replaces its "Upstreams" statement that
per-upstream token exchange is defined but not implemented. 0002's other
decisions are unchanged, and its Status stays `Accepted`.

## Context

0002 forwarded the session's one access token to every upstream, and
`UpstreamConfig.audience` was validated but never used. The OWASP review of the
BFF found the consequence: an upstream (or anything that sees its inbound
`Authorization`) holds a token that every other upstream accepts, with the
user's full scopes. RFC 9700 section 2.3 asks for audience-restricted access
tokens so that a resource server cannot replay a token at another one, and
RFC 8693 is the standard way to obtain one from the IdP for a user who is
already signed in. Keycloak 26.2 and later implements it as "standard token
exchange" (v2, enabled by default).

## Decision

An upstream with `tokenExchange: true` gets an audience-restricted token
instead of the session's own:

- **Request.** `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
  `subject_token` the session's access token, `subject_token_type` and
  `requested_token_type` both `urn:ietf:params:oauth:token-type:access_token`,
  and `audience` the upstream's `audience`. The BFF authenticates as its
  confidential client, as for the refresh grant. It sends no `scope`, so the
  IdP applies the client's default scopes.
- **Cache.** The exchanged token is stored in the session
  (`SessionData.exchanged`, by audience, with its expiry) and reused until
  `expires_in` minus `accessTokenSkewSeconds` (30 s) has passed, then
  exchanged again. A response without `expires_in`, or with one no longer than
  the skew, is used for that request and not cached. Upstreams that share an
  audience share the entry. The subject token is refreshed first when it is
  stale, by the existing refresh path; the cache survives that refresh.
- **Concurrency.** Requests of one process for the same session and audience
  share one in-flight exchange. Across replicas, the exchange runs under the
  session's refresh lock, and a request that finds the lock held waits for the
  cached result, exactly like a refresh. The cache write is fenced by the
  session version like a refresh write.
- **Fail closed.** If the exchange does not yield a valid token, the request
  gets an error and nothing goes upstream; the session's own token is never
  the fallback. The IdP answering with an error (`invalid_target`,
  `access_denied`, ...) gives `502 token_exchange_failed`. An IdP that cannot
  be reached gives `503 idp_unavailable`, as for a refresh. Neither ends the
  session: a denied exchange is a configuration or policy problem, not a dead
  login. A response is also refused (502) when its `token_type` is not
  `Bearer`, its `issued_token_type` is not an access token, or its token is the
  subject token itself (the IdP restricted nothing). Failures are logged as the
  warn-level security event `token_exchange_failed` with `sub`, `audience` and a
  reason code, never a token.
- **Opt-in, per upstream.** `tokenExchange` already existed in the schema
  with default `false`. It stays off by default, so no existing config changes
  behaviour and the release is a minor one.

## Consequences

- With exchange on, an upstream only ever sees a token for its own audience.
  Without it, nothing changes, and the shared-token exposure remains for
  those upstreams. Operators should turn it on for every upstream when the IdP
  supports it; making it the default is a breaking change left for a major
  release.
- The IdP needs setup (client flag, audiences); a missing setup shows up as
  `502 token_exchange_failed` on exactly the affected upstream. Keycloak's
  standard exchange does not support sessions from offline tokens, so the BFF
  client should not request `offline_access` when exchange is on.
- The first request per audience costs one extra IdP round trip, then one per
  access-token lifetime. Sessions grow by one small entry per audience.
- Keycloak's `audience` parameter only narrows the audiences the client's
  default scopes already put in the token, so the BFF's own login token still
  carries all of them; it never leaves the BFF.
- Exchanged tokens are not revoked at logout (Keycloak does not revoke access
  tokens through exchange); they expire on their own, within the IdP's access
  token lifetime.
- A cached exchanged token is not revalidated for revoked consent or a changed
  role until it expires, like any short-lived bearer token.
- Not done: a per-upstream `scope` to request optional client scopes, a check
  that a JWT exchanged token's `aud` contains the audience (the upstream
  rejects it anyway), and exchange for non-access-token types.
