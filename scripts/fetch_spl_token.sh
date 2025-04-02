#!/bin/bash

: "${SPL_PROGRAMS_DIR:=spl_programs}"
SPL_TOKEN_DIR="$SPL_PROGRAMS_DIR/token"
SPL_PROGRAMS_OUT_DIR="$SPL_PROGRAMS_DIR/lib"
BRANCH_NAME="febo/new-instructions-feature"

mkdir -p $SPL_PROGRAMS_DIR
mkdir -p $SPL_PROGRAMS_OUT_DIR

if [ -d "$SPL_TOKEN_DIR" ]; then
    echo "Updating spl-token program repository...";
    git -C $SPL_TOKEN_DIR fetch origin $BRANCH_NAME;
else
    echo "Cloning spl-token program repository...";
    git clone https://github.com/solana-program/token $SPL_TOKEN_DIR;
    git -C $SPL_TOKEN_DIR checkout $BRANCH_NAME;
fi

# First build SPL-Token
cargo build-sbf --manifest-path=$SPL_TOKEN_DIR/program/Cargo.toml \
    --sbf-out-dir $SPL_PROGRAMS_OUT_DIR

# Now build P-Token
cargo build-sbf --manifest-path=$SPL_TOKEN_DIR/p-token/Cargo.toml \
    --sbf-out-dir $SPL_PROGRAMS_OUT_DIR