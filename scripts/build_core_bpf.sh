#!/bin/bash

: "${BPF_PROGRAMS_DIR:=bpf_programs}"
: "${CARGO:=cargo}"

if [ -z "$1" ]; then
    echo "Error: Program name argument is missing."
    exit 1
fi

set_core_bpf_vars() {
    case "$1" in
        address-lookup-table)
            CORE_BPF_PROGRAM_ID="AddressLookupTab1e1111111111111111111111111"
            CORE_BPF_TARGET="$BPF_PROGRAMS_DIR/lib/solana_address_lookup_table_program.so"
            ;;
        config)
            CORE_BPF_PROGRAM_ID="Config1111111111111111111111111111111111111"
            CORE_BPF_TARGET="$BPF_PROGRAMS_DIR/lib/solana_config_program.so"
            ;;
        stake)
            CORE_BPF_PROGRAM_ID="Stake11111111111111111111111111111111111111"
            CORE_BPF_TARGET="$BPF_PROGRAMS_DIR/lib/solana_stake_program.so"
            ;;
        *)
            echo "Invalid argument. Use 'address-lookup-table', 'config', or 'stake'."
            exit 1
            ;;
    esac
}

set_core_bpf_vars "$1"

CORE_BPF_PROGRAM_ID=$CORE_BPF_PROGRAM_ID CORE_BPF_TARGET=$CORE_BPF_TARGET FORCE_RECOMPILE=true $CARGO build \
    --target x86_64-unknown-linux-gnu \
    --features core-bpf \
    --lib \
    --release
