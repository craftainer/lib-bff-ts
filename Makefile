# template-npm-package's implementation of template-base's release contract
# (docs/TEMPLATE.md, "Release: a Makefile contract"). release.yml sets
# RELEASE_VERSION / RELEASE_TAG / RELEASE_ARCH -- see there. One pure-JS
# tarball is built once, on one arch; the version lives only in the git tag
# and `build` stamps it. The logic is in scripts/release-*.sh; release-run.sh
# runs it on the host, or in the pinned Node image when the host has no pnpm
# (release.yml's bare runner). NPM_PUBLISH (a repository variable; any
# non-empty value) turns publishing on -- see scripts/README.md. Publishing
# is `publish-packages` (template-base >= 1.9.0: runs once, after every arch
# leg, in its own job); the per-arch `publish` is image-only, so a no-op here.

.PHONY: release-arches build sbom release-assets publish publish-packages verify-published release-check finalize

release-arches:
	@echo '["amd64"]'

# Leaves only the packed tarball in dist/: dist/ is what release.yml attaches
# to the GitHub release.
build:
	scripts/release-run.sh scripts/release-build.sh

sbom:
	scripts/release-sbom.sh

release-assets:
	@set -e; for pat in 'dist/*.tgz' 'dist/*.spdx.json'; do \
		ls $$pat >/dev/null 2>&1 || { echo "missing release asset: $$pat" >&2; exit 1; }; \
	done; ls dist

# Per arch, image registries only: this template ships no image.
publish:
	@echo "npm package -- no image to publish (see publish-packages)."

# Once, in release.yml's `publish-packages` job, which exists only when
# NPM_PUBLISH is set and has `id-token: write` plus NPM_TOKEN. That job is a
# bare runner: a checkout plus dist/ (the build leg's tarball), no pnpm, so
# release-run.sh runs the script in the pinned Node image. It uploads the
# tarball already in dist/; nothing is rebuilt.
publish-packages:
	scripts/release-run.sh scripts/release-publish.sh

# Once, in release.yml's `verify-published` job, after `publish-packages`
# succeeded and only when a *_PUBLISH variable is set: installs the published
# version from the registry. A bare runner with no secrets, so like
# `publish-packages` it goes through release-run.sh. See
# scripts/release-verify-published.sh.
verify-published:
	scripts/release-run.sh scripts/release-verify-published.sh

# Runs once after the arch leg, inside the devcontainer, and gates the GitHub
# release and publishing; dist/ holds the downloaded tarball. Checks the local
# tarball only. See scripts/release-check.sh.
release-check:
	scripts/release-check.sh

# Nothing to combine: a single tarball is built once.
finalize:
	@echo "Single pure-JS tarball -- nothing to finalize."
