# template-npm-package

> [!NOTE]
> This repository is vibe coded with [Claude](https://claude.com/product/claude-code).

A template for a typed, tested and publishable ESM TypeScript npm package:
pnpm (via Corepack), a `tsdown` build with generated declarations, strict
`tsc`, `vitest` with a 100% coverage gate, `oxlint`, `prettier`, `publint`
and `arethetypeswrong`, and a release that publishes to npm through trusted
publishing with provenance. It is itself an instance of
[`template-base`](https://github.com/craftainer/template-base) (so it gets
the devcontainer, CI, release workflow and template sync from there) and is
itself a template: a package created from it receives fixes through template
sync. See [`docs/TEMPLATE.md`](docs/TEMPLATE.md) for the conventions shared
by every instance, and
[`docs/adrs/0001-npm-package-template.md`](docs/adrs/0001-npm-package-template.md)
for why it exists.

## Creating a package from this template

1. On GitHub, use "Use this template" on this repository (or
   `gh repo create <org>/<name> --template craftainer/template-npm-package`).
2. Rename the package: `package.json`'s `name` to `@craftainer/<name>`, its
   description, and this file's title and description. Edit `src/`,
   `tests/`, and the `exports` map together with `tsdown.config.ts`'s
   `entry`. Point `repository.url` (`git+https://github.com/<owner>/<repo>.git`),
   `homepage` and `bugs.url` at the new repository: `package.json` is
   instance-owned, and `make publish-packages` refuses a mismatch (npm rejects
   provenance otherwise). Then run `pnpm install` to refresh `pnpm-lock.yaml`.
3. Point template sync at this template. `.github/template-sync-state.json`
   here records the `template-base` tag this template itself last synced
   from; the copy in a new package must instead name this repository and
   the tag it was created at (the latest release of
   `craftainer/template-npm-package`):

   ```json
   {
     "template_repo": "craftainer/template-npm-package",
     "synced_tag": "vX.Y.Z"
   }
   ```

   Add a `TEMPLATE_SYNC_TOKEN` secret too (see `.github/workflows/README.md`,
   "Template sync"). Files the package owns beyond the manifest's `ignore`
   tier go in `.github/template-sync-manifest.local.yml` under `ignore:`.

4. Open the repository in the devcontainer, then run
   `prek run --all-files --hook-stage manual`; everything should pass before
   you write any code.
5. Keep `LICENSE` (GPL-3.0) or replace it with the license you choose.

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
