# 0005. Nonce the SPA's styles per request; let apps opt in to upstream Cache-Control on `/api/*`

## Status

Accepted

## Context

The BFF's fixed Content-Security-Policy had `style-src 'self'`. MUI's
Emotion injects `<style>` tags at runtime, so behind the BFF the SPA
rendered unstyled (found by template-react's real-stack end-to-end run).
MUI's CSP guide and Vite's `html.cspNonce` both answer this with a
per-request nonce. MUI also sets inline `style` attributes, which a nonce
cannot cover.

Separately, the BFF forced `Cache-Control: no-store` on every `/api/*`
response, whatever the upstream said. That is the safe choice for per-user
data (ASVS 5.0 14.3.2 asks for anti-caching headers on responses with
sensitive data), but it stops an app from caching responses it knows are
safe to cache, such as public reference data behind an upstream.

## Decision

- **CSP nonce.** The static plugin serves `index.html` (at `/`,
  `/index.html` and as the SPA fallback) from a per-request read, replaces
  every `__CSP_NONCE__` with a fresh `crypto.randomBytes(16)` base64 nonce
  and sends `Cache-Control: no-store`, so a nonce is never cached. The
  `headers` plugin then sends, for that response only,
  `style-src-elem 'self' 'nonce-<n>'` and `style-src-attr 'unsafe-inline'`
  (`style-src 'self'` stays as the fallback for browsers without the CSP 3
  split). `script-src` stays `'self'`: Vite's module scripts are external
  files, so they need no nonce. All other directives are unchanged, and
  every other response keeps the fixed policy.
- **Placeholder.** The fixed string `__CSP_NONCE__` (exported as
  `CSP_NONCE_PLACEHOLDER`). An app sets Vite's `html.cspNonce` to it. Vite
  accepts any string and writes it into `nonce` attributes and the
  `<meta property="csp-nonce">` tag. A fixed value needs no config knob; a
  knob would only add a way to disagree with the build.
- **`API_CACHE_CONTROL`.** `no-store` (default) keeps the forced header.
  `upstream` passes an upstream-sent `Cache-Control` through unchanged and
  sets `no-store` only on responses without one. `loadConfig` rejects any
  other value.

## Consequences

- `style-src-attr 'unsafe-inline'` is a weaker style policy: injected
  markup can restyle the page (CSS-based UI redress, limited exfiltration
  through attribute selectors). Scripts are unaffected. MUI needs it, and
  the alternative, an unstyled app, was not an option.
- Each page load costs a small file read and a 16-byte random draw; the
  HTML is never cached by browsers or proxies.
- Apps must set `html.cspNonce` to the placeholder. Without it the HTML has
  no nonce attributes and the page's `<style>` tags are blocked, as before.
- `upstream` mode trades ASVS 14.3.2 for cacheability: a shared cache or the
  browser may keep an `/api/*` response, including per-user data, if the
  upstream says so. The upstream becomes responsible for sending `private`
  or `no-store` on such responses. Use it only for upstreams that do.
  Responses without a Cache-Control header still get `no-store`.
