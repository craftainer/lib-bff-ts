#!/usr/bin/env bash
# Installs the package's dependencies into node_modules, which the prek hooks
# (oxlint/prettier/tsc/vitest/tsdown/publint/attw) all run from.
set -euo pipefail

cd /workspace
# No one to answer Corepack's download prompt here.
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
pnpm install --frozen-lockfile
