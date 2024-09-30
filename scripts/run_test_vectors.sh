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
find dump/test-vectors/txn/fixtures/ -type f -name '*.fix' -exec ./target/release/test_exec_txn {} + > $LOG_PATH/test_exec_txn.log 2>&1

failed=`grep -wR FAIL $LOG_PATH | wc -l`
passed=`grep -wR OK $LOG_PATH | wc -l`

echo Test vectors success
