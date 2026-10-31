#!/usr/bin/env bash
# `make sbom`: an SPDX JSON SBOM of the packed tarball and its production
# dependency tree, next to the tarball in dist/.
#
# Syft finds npm packages from node_modules or a lock file, not from a bare
# package.json, so the tarball is installed into a scratch project first
# (release-sbom-install.sh) and that is scanned. Source name and version are
# set so the document does not carry the scratch path. Runs on the host: it
# needs docker for Syft.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/release-lib.sh
source scripts/release-lib.sh

tarball=$(find_tarball)
rel=dist/$(basename "$tarball")
name=$(scripts/release-run.sh scripts/release-field.sh "$rel" name)
version=$(scripts/release-run.sh scripts/release-field.sh "$rel" version)
scratch=$(mktemp -d "$PWD/dist/.sbom.XXXXXX")
on_exit "rm -rf '$scratch'"

scripts/release-run.sh scripts/release-sbom-install.sh "$rel" "dist/$(basename "$scratch")"

out=${tarball%.tgz}.spdx.json
docker run --rm -u "$(id -u):$(id -g)" --tmpfs /tmp:rw,mode=1777 -e XDG_CACHE_HOME=/tmp -v "$PWD/dist:/dist" "anchore/syft:$SYFT_VERSION" \
    "dir:/dist/$(basename "$scratch")" --source-name "$name" --source-version "$version" \
    -o "spdx-json=/dist/$(basename "$out")"
ls dist
