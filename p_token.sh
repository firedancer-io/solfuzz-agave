#!/bin/bash

./scripts/fetch_program.sh token febo/new-instructions-feature

PROGRAM_ID="TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
LOADER_KEY="BPFLoaderUpgradeab1e11111111111111111111111"
SPL_TARGET="bpf_programs/lib/spl_token.so"
P_TARGET="bpf_programs/lib/pinocchio_token_program.so"

# SPL sancov
BPF_PROGRAM_ID=$PROGRAM_ID \
  BPF_TARGET=$SPL_TARGET \
  BPF_LOADER_KEY=$LOADER_KEY \
  OUTPUT_TARGET_NAME="ground_spl_token.so" \
  make shared_obj_bpf_conformance

# P sancov
BPF_PROGRAM_ID=$PROGRAM_ID \
  BPF_TARGET=$P_TARGET \
  BPF_LOADER_KEY=$LOADER_KEY \
  OUTPUT_TARGET_NAME="target_p_token.so" \
  make shared_obj_bpf_conformance

# SPL debug
BPF_PROGRAM_ID=$PROGRAM_ID \
  BPF_TARGET=$SPL_TARGET \
  BPF_LOADER_KEY=$LOADER_KEY \
  OUTPUT_TARGET_NAME="ground_spl_token_debug.so" \
  make shared_obj_bpf_conformance_debug

# P debug
BPF_PROGRAM_ID=$PROGRAM_ID \
  BPF_TARGET=$P_TARGET \
  BPF_LOADER_KEY=$LOADER_KEY \
  OUTPUT_TARGET_NAME="target_p_token_debug.so" \
  make shared_obj_bpf_conformance_debug
