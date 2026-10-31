# @craftainer/bff

> [!NOTE]
> This repository is vibe coded with [Claude](https://claude.com/product/claude-code).

`@craftainer/bff` is the Backend-for-Frontend library for craftainer
single-page apps, following RFC 10017 section 6.1. Built on Fastify and
`openid-client`, it acts as the confidential OIDC client on the SPA's behalf,
keeps sessions server-side in Valkey so no tokens reach the browser, and
proxies API calls to an allowlist of upstream routes.

It is ESM-only TypeScript, created from
[`template-npm-package`](https://github.com/craftainer/template-npm-package)
(see [`docs/TEMPLATE.md`](docs/TEMPLATE.md) for the conventions shared by
every instance). Usage documentation is still to come.

## Publishing to npm

`make publish-packages` is a no-op (with a `::warning::` in the log) until you opt
in by setting the repository variable `NPM_PUBLISH` (any non-empty value). npm has no pending publishers,
so the first release is bootstrapped with a token and every later one uses
[trusted publishing](https://docs.npmjs.com/trusted-publishers) (GitHub
OIDC, with provenance), with no token stored:

1. Create the `NPM_TOKEN` secret: a granular token for the `@craftainer`
   scope with "Read and write (stage only)". Set `NPM_PUBLISH`.
2. Run the first release. `make publish-packages` runs `npm stage publish`, which
   stages the tarball without 2FA. Approve it with 2FA: `npm stage list`,
   then `npm stage approve <stage-id>` (or on npmjs.com). Until then the
   version is not installable, and `make verify-published` (the release
   workflow's last job, after the GitHub release exists) fails saying so;
   re-run that job after approving.
3. On npmjs.com, add the package's trusted publisher (this repository,
   workflow `release.yml`), then delete the `NPM_TOKEN` secret. Later
   releases publish directly through OIDC; npm expires a trusted-publisher
   configuration that has not published within 48 hours, so do this just
   before the next release.

The version lives only in the git tag `release.yml` computes;
`package.json` stays at `0.0.0` and `make build` stamps `RELEASE_VERSION`
into the build without committing it. Details: `docs/TEMPLATE.md`, "Package
template notes".

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
