# NFR-0002. Analytics collects no more than CNIL's audience-measurement exemption allows

## Status

Implemented

## Attribute

Security and privacy.

## Description

The analytics endpoint ([ADR 0004](../adrs/0004-analytics-endpoint.md))
stays inside the conditions of CNIL's consent exemption for audience
measurement, read in the stricter way wherever CNIL's pages differ. **CNIL
is the reference here, not a legal opinion**; an app that needs more than
audience measurement, or runs in another jurisdiction, assesses that itself.
Sources: [sheet no. 16](https://www.cnil.fr/en/sheet-ndeg16-use-analytics-your-websites-and-applications),
[the French rules page](https://www.cnil.fr/fr/cookies-et-autres-traceurs/regles/cookies-solutions-pour-les-outils-de-mesure-daudience).

| CNIL condition                                     | How the BFF meets it                                                                                                                                                                             | Test                                                                                                                                           |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Audience measurement only                          | The endpoint takes named events with allowlisted scalar props and a path; no title, no referrer, no free text beyond 200 characters per allowlisted prop                                         | `analytics-units.test.ts` "validation schema"; `analytics-endpoint.test.ts` "answers 400 invalid_event"                                        |
| No cross-checking with other data                  | The token is a keyed hash of IP and User-Agent with a salt that is discarded daily; no user ID, `sub` or session ID is ever sent                                                                 | `analytics-units.test.ts` "visitor token"; `analytics-umami.test.ts` "posts the exact documented body" (no raw IP, UA, `id`)                   |
| One publisher, one site                            | The BFF sends to the app's own backend, with its own site ID                                                                                                                                     | `analytics-umami.test.ts` "posts the exact documented body"                                                                                    |
| No raw IP (stricter than truncating the last byte) | Only the 22-character HMAC leaves the BFF, as `payload.ip`; `ANALYTICS_GEO=coarse` is inert                                                                                                      | `analytics-umami.test.ts` "posts the exact documented body"; `analytics-endpoint.test.ts` "accepts one event" (no token or IP in the log line) |
| Tracer lifetime at most 13 months                  | No browser identifier exists. The token lives one UTC day. The only cookie, `__Host-Http-consent`, lasts 180 days and only in `opt-in` mode                                                      | `analytics-units.test.ts` "changes when the UTC date changes"; `analytics-consent.test.ts` "grants consent"                                    |
| Right to object, easily                            | `Sec-GPC: 1` and `DNT: 1` drop events (`ANALYTICS_RESPECT_GPC`, default true); `POST /bff/consent {analytics:false}` withdraws consent; `ANALYTICS_CONSENT=opt-in` records nothing until granted | `analytics-endpoint.test.ts` "drop rules"; `analytics-consent.test.ts`                                                                         |
| Information                                        | Not a code matter: the app's privacy notice must say that cookieless audience measurement runs, what it records and how to object                                                                | none (app documentation)                                                                                                                       |
| Data retention                                     | The backend owns it. CNIL's French page allows at most 25 months for measurement data, and this NFR adopts that as the ceiling; the app's Umami stack documents its purge (stack item AN0)       | none (deployment)                                                                                                                              |

Further requirements:

- An invalid or dropped event never changes the response: policy drops answer
  the same `202` (test: "drops before validating").
- Analytics never fails or slows a request: a down backend, a redirect, a
  timeout or a full queue is logged only (tests: `analytics-umami.test.ts`
  "never fails the request when Umami is down", "drops events beyond the
  1000-event queue"; `analytics-units.test.ts` "times out").
- Visitor tokens are per replica and per day, so unique-visitor counts
  inflate across replicas (accepted; ADR 0004).
- Analytics adds no cookie that identifies a visitor, and the consent
  cookie is `HttpOnly`, `Secure`, `SameSite=Strict` and host-bound.

## Source

The project owner's decision (2026-10-31) to ship cookieless analytics that
honours GPC by default, and the CNIL guidance above. See
[ADR 0004](../adrs/0004-analytics-endpoint.md).

## Verification

The tests named above run in `pnpm test` with 100% coverage. Before each
release, re-read the two CNIL pages for changes to the conditions. The
Umami contract is checked against the pinned image in the e2e suite (BF5).
