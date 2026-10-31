#!/usr/bin/env bash
# Helper of release-sbom.sh: install the tarball (production only, no scripts)
# into an empty scratch project, which Syft then scans. A separate script
# because it needs Node and npm, which release-run.sh provides, while the Syft
# step needs docker, which the Node image lacks.
#
# Usage: release-sbom-install.sh <tarball> <scratch dir>, both relative to the
# repo root (the path differs inside the Node image).
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/release-lib.sh
source scripts/release-lib.sh
use_npm

tarball=$PWD/$1
echo '{"private":true}' >"$2/package.json"
(cd "$2" && npm install --omit=dev --ignore-scripts --no-audit --no-fund --silent "$tarball")
