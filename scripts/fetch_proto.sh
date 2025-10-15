#!/usr/bin/env bash
set -euo pipefail

# Allow overriding proto version; default pinned
PROTO_VERSION="${PROTO_VERSION:-v1.0.4}"

# Fetch protosol at specified tag/branch
if [ ! -d protosol ]; then
    git clone --depth=1 --branch "$PROTO_VERSION" https://github.com/firedancer-io/protosol.git
else
    cd protosol
    git fetch --tags
    git checkout "$PROTO_VERSION"
    cd ..
fi
