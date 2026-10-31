#!/usr/bin/env bash
# `make build`: build the package and pack it into dist/.
#
# Reads: RELEASE_VERSION (stamped into package.json only while building, then
# restored, so the checkout stays clean; unset keeps package.json's version).
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/release-lib.sh
source scripts/release-lib.sh

tmp=$(mktemp -d)
bak=$tmp/package.json
cp package.json "$bak"
on_exit 'cp "$bak" package.json; rm -rf "$tmp"'
use_npm

pnpm install --frozen-lockfile
if [[ -n ${RELEASE_VERSION:-} ]]; then
    npm pkg set "version=$RELEASE_VERSION"
fi
pnpm build
# --ignore-scripts: the tarball is exactly the built `files`, nothing a
# lifecycle script adds. Packed outside dist/, which build output fills.
npm pack --ignore-scripts --pack-destination "$tmp" >/dev/null
# tsdown's output must not stay: dist/ is what release.yml attaches.
rm -rf dist
mkdir dist
mv "$tmp"/*.tgz dist/
ls dist
