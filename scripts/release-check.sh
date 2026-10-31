#!/usr/bin/env bash
# `make release-check`: install the built tarball into a scratch project and
# import every `exports` entry. It gates the GitHub release and publishing,
# so it checks only the local artifact; the check of the published release is
# scripts/release-verify-published.sh (`make verify-published`), which runs
# after `publish-packages`.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/release-lib.sh
source scripts/release-lib.sh
use_npm

tmp=$(mktemp -d)
on_exit "rm -rf '$tmp'"

tarball=$(find_tarball)
name=$(tarball_field "$tarball" name)
version=$(tarball_field "$tarball" version)

echo "== local tarball: $(basename "$tarball")"
mkdir "$tmp/local"
install_into "$tmp/local" "$tarball"
check_import "$tmp/local" "$name" "$version"
