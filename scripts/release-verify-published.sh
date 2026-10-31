#!/usr/bin/env bash
# `make verify-published`: install the release that `publish-packages` just
# uploaded from the registry into a scratch project and import every
# `exports` entry.
#
# Runs after the GitHub release exists and the upload succeeded, only when a
# *_PUBLISH variable is set (release.yml), with no secrets or OIDC token; with
# NPM_PUBLISH unset (another registry is publishing) it does nothing. Needs
# `dist/` (the tarball `build` produced names the expected package and
# version).
#
# Reads: NPM_PUBLISH, and RELEASE_CHECK_ATTEMPTS / RELEASE_CHECK_DELAY /
# RELEASE_CHECK_MAX_DELAY (retry tuning for registry propagation, defaults
# 10 attempts, 5 seconds doubling up to 60: about 6 minutes in all, since npm
# can take minutes to show a version that publish just uploaded).
#
# A version that never shows up on the registry fails the script: a release
# whose package did not appear must not pass verification. That includes a
# first release that was staged (`npm stage publish`) and is still awaiting
# approval; the message says so, and re-running this job after
# `npm stage approve` verifies it.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/release-lib.sh
source scripts/release-lib.sh

if [[ -z ${NPM_PUBLISH:-} ]]; then
    echo "NPM_PUBLISH not set -- nothing to verify."
    exit 0
fi

use_npm

tmp=$(mktemp -d)
on_exit "rm -rf '$tmp'"

tarball=$(find_tarball)
name=$(tarball_field "$tarball" name)
version=$(tarball_field "$tarball" version)

echo "== registry: $name@$version"
attempts=${RELEASE_CHECK_ATTEMPTS:-10}
delay=${RELEASE_CHECK_DELAY:-5}
max_delay=${RELEASE_CHECK_MAX_DELAY:-60}
for ((i = 1; i <= attempts; i++)); do
    # Empty = not found: the package exists but that version does not (still
    # propagating, or staged and unapproved), or the package is unknown
    # (E404). Anything else (network, auth) is a real failure.
    found=$(npm_view_field "$name@$version" version) || exit 1
    if [[ -n $found ]]; then
        mkdir "$tmp/published"
        install_into "$tmp/published" "$name@$version"
        check_import "$tmp/published" "$name" "$version"
        exit 0
    fi
    if ((i < attempts)); then
        echo "attempt $i/$attempts: not found; retrying in ${delay}s (registry propagation)"
        sleep "$delay"
        delay=$((delay * 2 > max_delay ? max_delay : delay * 2))
    fi
done
echo "ERROR: $name@$version is not on the registry after $attempts attempts." >&2
echo "ERROR: if this release was staged (first release, NPM_TOKEN bootstrap), approve it with 'npm stage list && npm stage approve <stage-id>' and re-run this job." >&2
echo "ERROR: otherwise the publish did not take effect; check the publish-packages job." >&2
exit 1
