# scripts/

- `develop.sh` — `../.devcontainer/Dockerfile`'s `develop`-stage setup: installs `prek`,
  the Claude Code CLI, `snip` and the GitHub CLI (`gh`), the only tooling this template requires
  regardless of instance language. An instance adds its own language
  runtime/tooling install on top, either by extending this script or
  copying its shape into a second script. Prefer the hook below over
  either. Every download goes through its `fetch` helper (bounded curl
  retries with backoff; GitHub URLs authenticated when the optional
  `github_token` BuildKit secret is present) and the installers
  that download for themselves run through `retry` (the installer script
  itself is fetched once, by `fetch`, so the two layers of retries do not
  multiply; a failed download names the installer and URL before the script
  aborts, an empty one is rejected, and `fetch` itself retries DNS and
  connect failures (curl exit 6/7) and truncated transfers (18/52/55/56) up
  to 4 times; timeouts are left to curl's own `--retry`), so CI's shared-IP
  HTTP 429s don't fail the image build. Local builds need no token.
- `post-create.sh` — the devcontainer's `postCreateCommand`: git
  `safe.directory`, `prek install`, then every `post-create.d/*.sh`.
- `release-*.sh` — the release logic behind the `Makefile` targets (see
  `docs/TEMPLATE.md`, "Package template notes"). `release-lib.sh` (sourced)
  pins the npm and Syft versions; `release-run.sh` runs a script on the
  host, or in the pinned Node image when the host has no pnpm;
  `release-build.sh` stamps the version, builds and packs into `dist/`;
  `release-sbom.sh` (+ `release-sbom-install.sh`, `release-field.sh`) writes the SPDX SBOM;
  `release-publish.sh` (`make publish-packages`; `make publish` is a no-op) skips (with a `::warning::`), first checks
  `repository.url` against `GITHUB_REPOSITORY` (`check_repository` in
  `release-lib.sh`), stages with the bootstrap token
  (`npm stage publish`) or publishes through OIDC, under a dist-tag from
  `dist_tag` (prerelease id or `next`; `v<major>-latest` for a backport); `release-check.sh`
  installs the `dist/` tarball into a scratch project and imports every
  `exports` entry (it gates the GitHub release and publishing, so it checks
  only the local artifact); `release-verify-published.sh`
  (`make verify-published`, after `publish-packages`, only when a `*_PUBLISH`
  variable is set) does the same from the registry if `NPM_PUBLISH` is set,
  with no secrets (retries about 6 minutes for registry propagation; a version
  that never appears, e.g. staged and unapproved, fails with an error; re-run
  the job after approving). `publish-packages` cannot detect a staged,
  unapproved version (`npm stage list` does not work with OIDC), so do not
  re-run it before approving or rejecting the stage.
- `develop.d/`, `post-create.d/` — instance hook directories. This template
  ships `develop.d/10-corepack.sh` (enables pnpm, installing a pinned
  Corepack when Node lacks one) and
  `post-create.d/10-pnpm-install.sh` (installs dependencies); a package adds
  its own scripts after them.

## Do

- Pass a token to the build as a BuildKit secret (`github_token`), never
  a `--build-arg`/`ARG`: an ARG is baked into the image history.
- Keep this script's own tools pinned to an exact version (a `# renovate:`
  ARG in `../.devcontainer/Dockerfile`) and checksum-verified where the upstream project
  publishes checksums, matching the pattern each install step here already
  follows.
- Keep `NPM_VERSION` in `release-lib.sh` at 11.15.0 or later (staged
  publishing) and pin it exactly, with its `# renovate:` marker.

## Don't

- Set or export `NODE_AUTH_TOKEN` in a release script, even empty: npm's
  OIDC trusted publishing breaks if it is present.
- Add a language runtime or stack-specific tool here — that belongs in the
  instance's own layer (`develop.d/`), not the base template's.
