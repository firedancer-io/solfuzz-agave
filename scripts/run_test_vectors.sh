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

run_test() {
  local log_file="$1"
  local cmd="$2"
  
  if ! eval "$cmd > $log_file 2>&1"; then
    cat "$log_file"
    exit 1
  fi
}

run_test "$LOG_PATH/test_exec_instr.log" "find dump/test-vectors/instr/fixtures -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./target/release/test_exec_instr"
run_test "$LOG_PATH/test_exec_precompile.log" "find dump/test-vectors/txn/fixtures/precompile -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./target/release/test_exec_txn"
run_test "$LOG_PATH/test_exec_txn.log" "find dump/test-vectors/txn/fixtures/programs -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./target/release/test_exec_txn"
run_test "$LOG_PATH/test_exec_block.log" "find dump/test-vectors/block/fixtures -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./target/release/test_exec_block"
run_test "$LOG_PATH/test_exec_vm_syscall.log" "find dump/test-vectors/syscall/fixtures -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./target/release/test_exec_vm_syscall"
run_test "$LOG_PATH/test_exec_vm_interp.log" "find dump/test-vectors/vm_interp/fixtures -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./target/release/test_exec_vm_interp"
run_test "$LOG_PATH/test_exec_elf_loader.log" "find dump/test-vectors/elf_loader/fixtures -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./target/release/test_exec_elf_loader"

failed=`grep -wR FAIL $LOG_PATH | wc -l`
passed=`grep -wR OK $LOG_PATH | wc -l`

echo Test vectors success
