#!/bin/bash

: "${SPL_PROGRAMS_DIR:=spl_programs}"
: "${RUSTFLAGS:=}"
: "${CARGO:=cargo}"

if [ -z "$1" ]; then
    echo "Error: Program name argument is missing."
    exit 1
fi

BPF_PROGRAM_ID="TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

set_bpf_vars() {
    case "$1" in
        pinocchio)
            BPF_TARGET="$SPL_PROGRAMS_DIR/lib/pinocchio_token_program.so"
            ;;
        spl)
            BPF_TARGET="$SPL_PROGRAMS_DIR/lib/spl_token.so"
            ;;
        *)
            echo "Invalid argument. Use 'pinocchio' or 'spl'."
            exit 1
            ;;
    esac
}

set_bpf_vars "$1"

BPF_PROGRAM_ID=$BPF_PROGRAM_ID BPF_TARGET=$BPF_TARGET FORCE_RECOMPILE=true $CARGO build \
    --target x86_64-unknown-linux-gnu \
    --features bpf-program-conformance \
    --lib \
    --release

BPF_PROGRAM_ID=$BPF_PROGRAM_ID BPF_TARGET=$BPF_TARGET FORCE_RECOMPILE=true $CARGO build \
    --target x86_64-unknown-linux-gnu \
    --features bpf-program-conformance,stub-agave \
    --lib \
    --release \
    --target-dir target/stub-agave