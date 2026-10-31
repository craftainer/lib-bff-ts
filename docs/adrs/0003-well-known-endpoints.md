# 0003. Serve a small, role-based set of well-known endpoints from the BFF

## Status

Accepted

## Context

A craftainer app's origin is the BFF ([ADR 0002](0002-bff-design.md)): it
is the only server a browser, a crawler or a security researcher talks to.
The [IANA well-known URI registry](https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml)
lists many URIs, and serving one is a commitment to keep it correct. The
library cannot know an app's repository, its IdP's account page or whether
its backends publish API descriptions, so each endpoint must follow from
configuration the app already supplies.

## Decision

We will serve these from the `wellKnown` plugin, which `createBff`
registers after `auth`. An endpoint whose configuration is absent is not
registered at all and answers 404. GET and HEAD work on all of them, and
they carry the library's security headers like every other response.

| URI               | Spec                                                                  | Served when                                   | Behaviour                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ----------------- | --------------------------------------------------------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `security.txt`    | [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116.html)               | `SECURITY_TXT_CONTACT` is non-empty           | `text/plain; charset=utf-8` with `Contact` (one line each, in the configured order), `Expires`, `Policy`, `Preferred-Languages` and `Canonical`. Fields whose value contains a line break are dropped (no field injection).                                                                                                                                                                                                                                                                                                                                                                                               |
| `change-password` | [W3C Change Password URL](https://www.w3.org/TR/change-password-url/) | `CHANGE_PASSWORD_URL` is set                  | 302 to that URL (the IdP's account page).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `gpc.json`        | [W3C GPC](https://www.w3.org/TR/gpc/)                                 | `ANALYTICS_RESPECT_GPC` is true (the default) | `application/json`: `{"gpc":true,"lastUpdate":"2026-10-31"}`. `lastUpdate` is a constant, the date the library began honouring `Sec-GPC`, because the spec defines it as the time the statement of support was made.                                                                                                                                                                                                                                                                                                                                                                                                      |
| `api-catalog`     | [RFC 9727](https://www.rfc-editor.org/rfc/rfc9727.html)               | always                                        | `application/linkset+json; profile="https://www.rfc-editor.org/info/rfc9727"` ([RFC 9264](https://www.rfc-editor.org/rfc/rfc9264.html) linkset, RFC 9727 section 4.2). One context object anchored at the catalog; per upstream an `item` link to `<origin>/api/<name>/` (section 3.1) and an `api-catalog` link to `<origin>/api/<name>/.well-known/api-catalog` (section 4.3), which the proxy forwards to the upstream. With no upstreams the linkset is empty (the RFC has no rule for that). Responses carry `Link: <origin/.well-known/api-catalog>; rel="api-catalog"`, which RFC 9727 section 2 requires on HEAD. |

`security.txt` details:

- `Expires` is required by RFC 9116 section 2.5.5, which recommends less than
  a year ahead. `loadConfig` requires `SECURITY_TXT_EXPIRES` in production.
  Elsewhere, and when none is set, the plugin computes startup + 364 days once
  (so the value is stable between requests and stays inside "less than a
  year").
- `Canonical` defaults to `<PUBLIC_ORIGIN>/.well-known/security.txt`, never a
  Host-derived value.
- The legacy `/security.txt` is not served or redirected: RFC 9116 section 3
  only says such a file or redirect "might" exist, and the `/.well-known/`
  copy must win anyway.
- The P-D3 default contact, `https://github.com/craftainer/<repo>/security/advisories/new`
  (private vulnerability reporting), lives in the app's environment (for
  example `template-react`'s `bff/`), not in the library, which cannot know
  the repository. Without a contact the library serves no `security.txt`
  rather than a file with a wrong or missing `Contact`.

We will deliberately not serve these, because each belongs to someone else or
to a feature the apps do not have:

- `openid-configuration`, `oauth-authorization-server` and JWKS: the IdP's
  metadata. Re-serving it from the app's origin would claim an issuer the app
  is not and could drift from the real one.
- `webfinger` and `host-meta`: there is no federation.
- `assetlinks.json` and `apple-app-site-association`: there are no native apps.
- Health stays at `/health/*`; no well-known URI is registered for it.

## Consequences

- The set is small and every member is justified by configuration, so there is
  little to keep current. Adding one later is a new plugin branch plus a row
  here.
- Apps get a valid `security.txt` only by setting a contact, so forgetting it
  silently means no file; the app templates carry the default so that does not
  happen in practice.
- A linkset entry for an upstream only advertises where the catalog
  would be; whether the upstream really serves `/.well-known/api-catalog`
  (fastapi and axum do) is not checked at runtime.
- `gpc.json` is tied to `ANALYTICS_RESPECT_GPC`: turning that off removes the
  claim instead of publishing `gpc: false`, so the endpoint never contradicts
  the analytics behaviour.
