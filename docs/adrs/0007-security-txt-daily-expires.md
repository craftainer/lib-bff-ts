# 0007. Compute the default `security.txt` `Expires` per UTC day

## Status

Accepted

Amends [0003](0003-well-known-endpoints.md): replaces how the default
`Expires` of `security.txt` is computed. 0003's other decisions are
unchanged, and its Status stays `Accepted`.

## Context

0003 computed the default `Expires` (startup + 364 days) once when the plugin
registered, so it was stable between requests. The OWASP review of the BFF
found the flaw: a process that runs for more than 364 days serves a file whose
`Expires` has passed, and RFC 9116 section 2.5.5 treats an expired file as
stale. Computing it on every request instead would give a value that changes
each millisecond, which defeats caching and makes tests depend on timing.

## Decision

The default `Expires` is the start of the current UTC day plus 364 days. The
plugin works it out on each request and rebuilds the body only when the day
has changed, so the value is identical for every request within a UTC day and
never lags the clock by more than a day. A configured `SECURITY_TXT_EXPIRES`
is unchanged: served verbatim, with the boot warning and the 404 once it has
passed.

## Consequences

- A long-running process keeps a valid `Expires` between 363 and 364 days
  ahead, so it stays inside "less than a year".
- The value moves once a day, at UTC midnight, so a cache that holds the file
  for less than a day never serves a stale one; tests fix it with fake time.
- The per-request cost is one date calculation and a string compare.
