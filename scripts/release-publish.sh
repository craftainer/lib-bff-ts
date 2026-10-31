#!/usr/bin/env bash
# `make publish-packages`: publish the tarball in dist/ to npm -- the exact
# file that was SBOM'd, never rebuilt -- by one of two paths. release.yml runs
# it once, in a job with a checkout and the downloaded dist/ only.
#
# Reads: NPM_PUBLISH (empty = skip, with a ::warning::), NPM_TOKEN (empty =
# absent), GITHUB_REPOSITORY (package.json's repository.url must match it).
#   - NPM_TOKEN set (bootstrap: the first release, before the package has a
#     trusted publisher): `npm stage publish`. The token is stage-only, so
#     this uploads the tarball to a staging area; nothing is public until a
#     maintainer approves the printed stage id with 2FA.
#   - NPM_TOKEN empty: `npm publish --provenance` through OIDC trusted
#     publishing (the job's `id-token: write`), no stored credential.
# The dist-tag is `latest` unless the version is a prerelease (its first
# non-numeric identifier, else `next`) or older than the current `latest`
# (`v<major>-latest`). `npm_config_dry_run=true` makes either path a dry run.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/release-lib.sh
source scripts/release-lib.sh
use_npm

# npm's OIDC trusted publishing breaks if this is set, even empty.
unset NODE_AUTH_TOKEN

if [[ -z ${NPM_PUBLISH:-} ]]; then
    echo "::warning title=npm publish skipped::NPM_PUBLISH is not set, so this package was NOT published to npm. To enable it, set the NPM_PUBLISH repository variable (any non-empty value; Settings > Secrets and variables > Actions > Variables) and re-run the release."
    exit 0
fi

tarball=$(find_tarball)
# Before any stage or publish: a mismatch would only fail later, at npm.
check_repository "$tarball"
name=$(tarball_field "$tarball" name)
version=$(tarball_field "$tarball" version)
# npm refuses a prerelease without an explicit tag, and a backport must not
# move `latest` backwards: see dist_tag.
tag=$(dist_tag "$name" "$version")
echo "Publishing $name@$version under dist-tag '$tag'."

# Re-runnable (docs/TEMPLATE.md, release flow): a re-run of the failed jobs
# after an earlier attempt already published must not publish again, which
# npm rejects. `npm view name@version version` prints nothing for a version
# that is not published (or is only staged), and E404 means the package is
# unknown; any other lookup failure (network, auth) stops here rather than
# guessing (see npm_view_field). A staged tarball cannot be seen here, and
# cannot be detected at all under the auth modes used: `npm stage list`
# cannot use OIDC tokens (it needs interactive authentication), and a
# stage-only token is documented to stage, deprecate and move dist-tags only.
# Re-running after a staged, still-unapproved version would stage it again:
# approve or reject the existing stage with `npm stage` first.
published=$(npm_view_field "$name@$version" version) || exit 1
if [[ -n $published ]]; then
    echo "$name@$version is already on the registry -- nothing to publish."
    exit 0
fi

if [[ -n ${NPM_TOKEN:-} ]]; then
    echo "NPM_TOKEN set -- staging $(basename "$tarball") with the bootstrap token."
    npmrc=$(mktemp)
    on_exit "rm -f '$npmrc'"
    chmod 600 "$npmrc"
    printf '//registry.npmjs.org/:_authToken=%s\n' "$NPM_TOKEN" >"$npmrc"
    # --userconfig replaces the user npmrc, so the token reaches npm through a
    # file, never the command line or the environment.
    args=(--userconfig "$npmrc" --access public --tag "$tag")
    if [[ -n ${ACTIONS_ID_TOKEN_REQUEST_URL:-} ]]; then
        args+=(--provenance)
    fi
    npm stage publish "$tarball" "${args[@]}"
    echo "Staged, NOT yet public. A maintainer must approve it with 2FA:"
    echo "  npm stage list && npm stage approve <stage-id>   (or on npmjs.com)"
    echo "Do NOT re-run publish-packages for this version before then: a re-run cannot see the stage and would stage a duplicate."
    echo "Re-run only verify-published after approving."
else
    echo "NPM_TOKEN empty -- publishing $(basename "$tarball") with OIDC trusted publishing."
    npm publish "$tarball" --provenance --access public --tag "$tag"
fi
