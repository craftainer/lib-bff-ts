#!/usr/bin/env bash
# Runs the given command on the host if it has pnpm, else in the pinned Node
# image (release.yml's bare runners -- the build leg and the publish-packages and
# verify-published jobs -- have docker but no pnpm).
#
# The container sees the working tree at /src and an allowlist of variables
# (see below), not the runner's environment.
set -euo pipefail

cd "$(dirname "$0")/.."

if command -v pnpm >/dev/null 2>&1; then
    exec "$@"
fi

# The pinned image (tag and digest) lives in release-lib.sh; Renovate bumps it
# together with the devcontainer Dockerfile's NODE_VERSION, which must name the
# same Node release (the devcontainer and the release build use one Node).
node_image=$(sed -n 's/^NODE_IMAGE=//p' scripts/release-lib.sh)
node_version=$(sed -n 's/^ARG NODE_VERSION=//p' .devcontainer/Dockerfile)
if [[ -z $node_image || ${node_image%%@*} != "node:${node_version}-trixie-slim" ]]; then
    echo "scripts/release-lib.sh's NODE_IMAGE (${node_image:-unset}) must be node:${node_version}-trixie-slim@sha256:<digest>, matching .devcontainer/Dockerfile's NODE_VERSION. Update them together." >&2
    exit 1
fi
corepack_version=$(sed -n 's/^COREPACK_VERSION=//p' scripts/develop.d/10-corepack.sh)

# The container gets an explicit allowlist of variables, never a prefix match:
# `pnpm install` and the build run dependency code (tsdown and its tree), which
# must not see GITHUB_TOKEN (contents/packages: write), ACTIONS_RUNTIME_TOKEN,
# ACTIONS_ID_TOKEN_REQUEST_* or the other runner variables. Only the publish
# step gets the job environment (minus GITHUB_TOKEN, ACTIONS_RUNTIME_TOKEN,
# ACTIONS_RESULTS_URL and ACTIONS_CACHE_URL) and NPM_TOKEN, for OIDC trusted
# publishing and provenance; it runs no dependency code (a tarball upload with
# a pinned npm).
# NODE_AUTH_TOKEN is deliberately never forwarded: its presence, even empty,
# breaks OIDC publishing.
names=(RELEASE_VERSION RELEASE_TAG RELEASE_ARCH NPM_PUBLISH
    RELEASE_CHECK_ATTEMPTS RELEASE_CHECK_DELAY RELEASE_CHECK_MAX_DELAY)
case ${1:-} in
scripts/release-publish.sh)
    # A deny-list, not an allowlist: npm reads an undocumented set of GITHUB_*
    # and RUNNER_* names for provenance, and this step runs no dependency code.
    names+=(NPM_TOKEN)
    while IFS= read -r name; do
        case $name in
        GITHUB_TOKEN | ACTIONS_RUNTIME_TOKEN | ACTIONS_RESULTS_URL | ACTIONS_CACHE_URL) ;;
        GITHUB_* | RUNNER_* | ACTIONS_*) names+=("$name") ;;
        esac
    done < <(compgen -e)
    ;;
esac
env_args=()
for name in "${names[@]}"; do
    env_args+=(-e "$name")
done

# The registry installs of Corepack below run without the publish credentials
# (`env -u`) and without lifecycle scripts.
exec docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/src" -w /src \
    -e HOME=/tmp/home -e COREPACK_HOME=/tmp/corepack \
    -e COREPACK_ENABLE_DOWNLOAD_PROMPT=0 -e "COREPACK_VERSION=$corepack_version" "${env_args[@]}" \
    "$node_image" bash -c \
    'mkdir -p /tmp/bin /tmp/home /tmp/cp && PATH=/tmp/bin:$PATH
     # Node 25+ images have no Corepack; install the pinned one from npm.
     command -v corepack >/dev/null || { env -u NPM_TOKEN -u ACTIONS_ID_TOKEN_REQUEST_URL -u ACTIONS_ID_TOKEN_REQUEST_TOKEN npm install --prefix /tmp/cp --ignore-scripts --no-audit --no-fund --silent "corepack@$COREPACK_VERSION" && PATH=/tmp/cp/node_modules/.bin:$PATH; }
     corepack enable --install-directory /tmp/bin && exec "$@"' -- "$@"
