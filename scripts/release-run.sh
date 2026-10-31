#!/usr/bin/env bash
# Runs the given command on the host if it has pnpm, else in the pinned Node
# image (release.yml's bare runners -- the build leg and the publish-packages and
# verify-published jobs -- have docker but no pnpm).
#
# The container sees the working tree at /src and the CI variables npm needs
# for OIDC trusted publishing and provenance. NODE_AUTH_TOKEN is deliberately
# never forwarded: its presence, even empty, breaks OIDC publishing.
set -euo pipefail

cd "$(dirname "$0")/.."

if command -v pnpm >/dev/null 2>&1; then
    exec "$@"
fi

# Same Node as the devcontainer; its Dockerfile is the single source.
node_version=$(sed -n 's/^ARG NODE_VERSION=//p' .devcontainer/Dockerfile)
corepack_version=$(sed -n 's/^COREPACK_VERSION=//p' scripts/develop.d/10-corepack.sh)
env_args=()
for name in RELEASE_VERSION RELEASE_TAG RELEASE_ARCH NPM_PUBLISH NPM_TOKEN \
    RELEASE_CHECK_ATTEMPTS RELEASE_CHECK_DELAY \
    $(env | grep -E '^(GITHUB_|RUNNER_|ACTIONS_)' | cut -d= -f1); do
    env_args+=(-e "$name")
done

exec docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/src" -w /src \
    -e HOME=/tmp/home -e COREPACK_HOME=/tmp/corepack \
    -e COREPACK_ENABLE_DOWNLOAD_PROMPT=0 -e "COREPACK_VERSION=$corepack_version" "${env_args[@]}" \
    "node:${node_version}-trixie-slim" bash -c \
    'mkdir -p /tmp/bin /tmp/home /tmp/cp && PATH=/tmp/bin:$PATH
     # Node 25+ images have no Corepack; install the pinned one from npm.
     command -v corepack >/dev/null || { npm install --prefix /tmp/cp --no-audit --no-fund --silent "corepack@$COREPACK_VERSION" && PATH=/tmp/cp/node_modules/.bin:$PATH; }
     corepack enable --install-directory /tmp/bin && exec "$@"' -- "$@"
