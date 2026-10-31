#!/usr/bin/env bash
# Helper of release-sbom.sh: print one package.json field of the tarball. A
# separate script because Node is only guaranteed where release-run.sh runs.
#
# Usage: release-field.sh <tarball> <field>, the tarball relative to the repo
# root (the path differs inside the Node image).
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/release-lib.sh
source scripts/release-lib.sh

tarball_field "$1" "$2"
