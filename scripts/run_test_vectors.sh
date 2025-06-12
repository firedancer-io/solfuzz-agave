#!/bin/bash

set -ex

NUM_PROCESSES=${NUM_PROCESSES:-$(nproc)}

if [ "$LOG_PATH" == "" ]; then
  LOG_PATH="`mktemp -d`"
else
  rm    -rf $LOG_PATH
  mkdir -pv $LOG_PATH
fi

echo "LOG_PATH: $LOG_PATH"


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

find dump/test-vectors/instr/fixtures -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./target/release/test_exec_instr                > $LOG_PATH/test_exec_instr.log 2>&1
find dump/test-vectors/txn/fixtures/precompile -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./target/release/test_exec_txn         > $LOG_PATH/test_exec_precompile.log 2>&1
find dump/test-vectors/txn/fixtures/programs -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./target/release/test_exec_txn           > $LOG_PATH/test_exec_txn.log 2>&1
find dump/test-vectors/block/fixtures -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./target/release/test_exec_block                > $LOG_PATH/test_exec_block.log 2>&1
find dump/test-vectors/syscall/fixtures -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./target/release/test_exec_vm_syscall         > $LOG_PATH/test_exec_vm_syscall.log 2>&1
find dump/test-vectors/vm_interp/fixtures/latest -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./target/release/test_exec_vm_interp > $LOG_PATH/test_exec_vm_interp.log 2>&1
find dump/test-vectors/vm_interp/fixtures/v0 -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./target/release/test_exec_vm_interp     > $LOG_PATH/test_exec_vm_interp.log 2>&1
find dump/test-vectors/vm_interp/fixtures/v1 -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./target/release/test_exec_vm_interp     > $LOG_PATH/test_exec_vm_interp.log 2>&1
find dump/test-vectors/vm_interp/fixtures/v2 -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./target/release/test_exec_vm_interp     > $LOG_PATH/test_exec_vm_interp.log 2>&1
find dump/test-vectors/vm_interp/fixtures/v3 -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./target/release/test_exec_vm_interp     > $LOG_PATH/test_exec_vm_interp.log 2>&1
find dump/test-vectors/elf_loader/fixtures -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./target/release/test_exec_elf_loader      > $LOG_PATH/test_exec_elf_loader.log 2>&1

failed=`grep -wR FAIL $LOG_PATH | wc -l`
passed=`grep -wR OK $LOG_PATH | wc -l`

echo Test vectors success
