# 0006. Always mark upstream `Cache-Control` as `private` on `/api/*`

## Status

Accepted

Amends [0005](0005-csp-nonce-and-api-cache-control.md): replaces how its
`API_CACHE_CONTROL=upstream` mode treats an upstream-sent `Cache-Control`.
0005's other decisions (the CSP nonce, the placeholder, the `no-store`
default) are unchanged. 0005's Status stays `Accepted`, as its CSP decisions
still stand.

## Context

0005 let `API_CACHE_CONTROL=upstream` pass an upstream's `Cache-Control`
through, rewriting only `public` to `private`. The OWASP review of the BFF
found that a response sent with just `max-age=60` or `s-maxage=60` kept
those directives and no `private`. `/api/*` responses are per-user and are
authenticated by a session cookie that a cache key ignores, so a CDN or
shared proxy in front of the BFF could store one user's response and serve
it to the next user requesting the same URL. RFC 9111 section 5.2.2.7 says
`private` is what stops a shared cache from storing a response.

## Decision

In `upstream` mode the BFF keeps the upstream's `Cache-Control` and always
makes it `private`: `public` is rewritten to `private`, and `private, ` is
put in front unless `private` or `no-store` is already present. A response
without a `Cache-Control` still gets `no-store`. The default `no-store` mode
is unchanged.

Alternatives considered: stripping `s-maxage` (leaves `max-age` cacheable by
shared caches that ignore it), and adding `Vary: Cookie` (a cache that keys
on the cookie would store one copy per user, and many do not honour it).

## Consequences

- A shared cache never stores an `/api/*` response, whatever the upstream
  sent. Only the browser's own cache can keep it, for as long as the
  upstream's `max-age` says.
- An app that wanted a CDN to cache public reference data through the BFF
  can no longer do so in `upstream` mode; serve such data outside `/api/*`.
- The upstream still decides `max-age` and `no-store` for the browser cache.
