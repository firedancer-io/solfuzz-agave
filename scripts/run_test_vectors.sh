#!/bin/bash

set -ex

if [ "$LOG_PATH" == "" ]; then
  LOG_PATH="`mktemp -d`"
else
  rm    -rf $LOG_PATH
  mkdir -pv $LOG_PATH
fi


mkdir -p dump

if [ ! -d dump/test-vectors ]; then
  cd dump
  git clone --depth=1 -q https://github.com/firedancer-io/test-vectors.git
  cd ..
else
  cd dump/test-vectors
  git pull -q
  cd ../..
fi

find dump/test-vectors/instr/fixtures -type f -name '*.fix' -exec ./target/release/test_exec_instr {} + > $LOG_PATH/test_exec_instr.log 2>&1
# secp256r1 currently not working, agave has bugs
# find dump/test-vectors/txn/fixtures/precompile -type f -name '*.fix' -exec ./target/release/test_exec_txn {} + > $LOG_PATH/test_exec_precompile.log 2>&1
find dump/test-vectors/txn/fixtures/precompile/ed25519 -type f -name '*.fix' -exec ./target/release/test_exec_txn {} + > $LOG_PATH/test_exec_precompile.log 2>&1
find dump/test-vectors/txn/fixtures/precompile/secp256k1 -type f -name '*.fix' -exec ./target/release/test_exec_txn {} + > $LOG_PATH/test_exec_precompile.log 2>&1
find dump/test-vectors/txn/fixtures/programs -type f -name '*.fix' -exec ./target/release/test_exec_txn {} + > $LOG_PATH/test_exec_txn.log 2>&1
find dump/test-vectors/cpi/fixtures -type f -name '*.fix' -exec ./target/release/test_exec_cpi {} + > $LOG_PATH/test_exec_cpi.log 2>&1
find dump/test-vectors/syscall/fixtures -type f -name '*.fix' -exec ./target/release/test_exec_vm_syscall {} + > $LOG_PATH/test_exec_vm_syscall.log 2>&1
find dump/test-vectors/vm_interp/fixtures -type f -name '*.fix' -exec ./target/release/test_exec_vm_interp {} + > $LOG_PATH/test_exec_vm_interp.log 2>&1
find dump/test-vectors/elf_loader/fixtures -type f -name '*.fix' -exec ./target/release/test_exec_elf_loader {} + > $LOG_PATH/test_exec_elf_loader.log 2>&1
find dump/test-vectors/vm_validate/fixtures -type f -name '*.fix' -exec ./target/release/test_exec_vm_validate {} + > $LOG_PATH/test_exec_vm_validate.log 2>&1

failed=`grep -wR FAIL $LOG_PATH | wc -l`
passed=`grep -wR OK $LOG_PATH | wc -l`

echo Test vectors success
