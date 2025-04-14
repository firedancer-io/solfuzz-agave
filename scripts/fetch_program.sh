#!/bin/bash

if [ -z "$1" ]; then
    echo "Error: Program name argument is missing."
    exit 1
fi

: "${BPF_PROGRAMS_DIR:=bpf_programs}"
BPF_PROGRAMS_OUT_DIR="$BPF_PROGRAMS_DIR/lib"

# Optionally, set the branch name to the 2nd argument.
if [ -n "$2" ]; then
    BRANCH_NAME="$2"
else
    BRANCH_NAME="main"
fi

mkdir -p $BPF_PROGRAMS_DIR
mkdir -p $BPF_PROGRAMS_OUT_DIR

if [ -d "$BPF_PROGRAMS_DIR/$1" ]; then
    echo "Updating program $1...";
    git -C $BPF_PROGRAMS_DIR/$1 fetch --all;
    git -C $BPF_PROGRAMS_DIR/$1 checkout $BRANCH_NAME;
    git -C $BPF_PROGRAMS_DIR/$1 pull origin $BRANCH_NAME;
else
    echo "Cloning program $1...";
    git clone https://github.com/solana-program/$1 $BPF_PROGRAMS_DIR/$1;
    git -C $BPF_PROGRAMS_DIR/$1 checkout $BRANCH_NAME;
fi

# If the argument is "token", don't include any features. Otherwise, build with
# "bpf-entrypoint" feature.
FEATURES_OPTION="--features bpf-entrypoint"
if [ "$1" == "token" ]; then
    FEATURES_OPTION=""
fi

cargo build-sbf --manifest-path=$BPF_PROGRAMS_DIR/$1/program/Cargo.toml \
    $FEATURES_OPTION --sbf-out-dir $BPF_PROGRAMS_OUT_DIR

# If the argument is "token", build P-Token as well.
if [ "$1" == "token" ]; then
    cargo build-sbf --manifest-path=$BPF_PROGRAMS_DIR/$1/p-token/Cargo.toml \
        --sbf-out-dir $BPF_PROGRAMS_OUT_DIR
fi