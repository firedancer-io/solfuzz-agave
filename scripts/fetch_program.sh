#!/bin/bash

if [ -z "$1" ]; then
    echo "Error: Program name argument is missing."
    exit 1
fi

: "${BPF_PROGRAMS_DIR:=bpf_programs}"
BPF_PROGRAMS_OUT_DIR="$BPF_PROGRAMS_DIR/lib"

mkdir -p $BPF_PROGRAMS_DIR
mkdir -p $BPF_PROGRAMS_OUT_DIR

if [ -d "$BPF_PROGRAMS_DIR/$1" ]; then
    echo "Updating program $1...";
    (cd $BPF_PROGRAMS_DIR/$1 && git fetch && git pull);
else
    echo "Cloning program $1...";
    git clone https://github.com/solana-program/$1 $BPF_PROGRAMS_DIR/$1;
fi

cargo build-sbf --manifest-path=$BPF_PROGRAMS_DIR/$1/program/Cargo.toml \
    --features bpf-entrypoint \
    --sbf-out-dir $BPF_PROGRAMS_OUT_DIR
