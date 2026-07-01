#!/usr/bin/env bash
set -euo pipefail

NUM_PROCESSES="${NUM_PROCESSES:-$(nproc)}"
EXPECT_REGEX="${EXPECT_REGEX:-[Ee]xpected}"
ACTUAL_REGEX="${ACTUAL_REGEX:-[Aa]ctual}"
FAIL_CONTEXT_LINES="${FAIL_CONTEXT_LINES:-200}"

# Prepare LOG_PATH
if [ -z "${LOG_PATH:-}" ]; then
  LOG_PATH="$(mktemp -d)"
else
  rm -rf "$LOG_PATH"
  mkdir -pv "$LOG_PATH"
fi
echo "LOG_PATH: $LOG_PATH"

# Show the commit hashes being used
repo_commit=$(git rev-parse HEAD)
echo "Using repo commit: $repo_commit"

# If WORK_DIR is provided, use it directly and skip the whole
# git clone/checkout/cache of test-vectors. The provided directory is
# expected to already contain the fixtures laid out as
# <WORK_DIR>/{instr,txn,block,syscall,elf_loader,shred}/fixtures
if [ -n "${WORK_DIR:-}" ]; then
  echo "Using provided WORK_DIR: $WORK_DIR"
else
  mkdir -p dump

  # Get commit SHA from file or env
  GIT_REF=${GIT_REF:-$(cat ./scripts/test-vectors-commit-sha.txt)}
  echo "Using test-vectors commit: $GIT_REF"

  # Fetch/update test-vectors repo
  if [ ! -d dump/test-vectors ]; then
    echo "Cloning test-vectors repository..."
    (cd dump && git clone --depth=1 -q --no-tags https://github.com/firedancer-io/test-vectors.git)
  fi

  # Checkout specific commit non-destructively
  (
    cd dump/test-vectors
    if ! git checkout -q $GIT_REF; then
      git remote update
      git checkout -q $GIT_REF
    fi
  )

  # Show the commit hashes being used
  test_vectors_commit=$(cd dump/test-vectors && git rev-parse HEAD)
  echo "Using test-vectors commit: $test_vectors_commit"

  WORK_DIR="dump/test-vectors"
fi

# Run one fixture per process, capture per-fixture output, and collect failures/successes.
run_fixtures_per_file() {
  local name="$1"
  local bin="$2"
  local fixture_dir="$3"
  local job_log="$4"
  local procs="${5:-$NUM_PROCESSES}"

  local fail_log="${job_log%.log}.failures"
  local ok_log="${job_log%.log}.passed"
  local pf_dir="$LOG_PATH/per_fixture/$name"

  mkdir -p "$pf_dir"

  # Validate inputs
  if [[ ! -x "$bin" ]]; then
    echo "ERROR: Binary not executable: $bin" | tee -a "$job_log"
    echo "BIN_NOT_EXEC:$bin" >> "$fail_log"
    return 1
  fi
  if [[ ! -d "$fixture_dir" ]]; then
    echo "ERROR: Fixture dir not found: $fixture_dir" | tee -a "$job_log"
    return 1
  fi

  # Calculate optimal chunk size: min(128, file_count / procs)
  local file_count
  file_count=$(find "$fixture_dir" -type f -name '*.fix' | wc -l)
  local chunk_size
  if [[ $file_count -eq 0 ]]; then
    chunk_size=128
  else
    chunk_size=$(( (file_count + procs - 1) / procs ))  # Ceiling division
    if [[ $chunk_size -gt 128 ]]; then
      chunk_size=128
    fi
    if [[ $chunk_size -lt 1 ]]; then
      chunk_size=1
    fi
  fi

  export name bin job_log fail_log ok_log pf_dir EXPECT_REGEX ACTUAL_REGEX FAIL_CONTEXT_LINES
  find "$fixture_dir" -type f -name '*.fix' -print0 \
    | xargs -0 -r -P "$procs" -n "$chunk_size" bash -c '
        set -euo pipefail

        # $@ contains all the files in this chunk
        # Use first file for naming the per-chunk log
        first_file="$1"
        first_basename="$(basename "$first_file" .fix)"

        # Create a per-chunk log file
        pf="$(mktemp -p "$pf_dir" "${name}_${first_basename}_XXXXXX.log")"

        # Run binary with all fixtures in this chunk; capture output to per-chunk log
        "$bin" -- "$@" >> "$pf" 2>&1 || true

        # Parse the log to find which files actually failed/passed
        grep -o "FAIL: .*" "$pf" | sed "s/FAIL: //" | sed "s/\"//g" >> "$fail_log" || true
        grep -o "OK: .*" "$pf" | sed "s/OK: //" | sed "s/\"//g" >> "$ok_log" || true

        # Append per-chunk output to the job log
        cat "$pf" >> "$job_log" 2>&1
      ' _
}

# Define jobs: name -> fixtures dir(s)
declare -A JOBS=(
  [test_exec_instr]="$WORK_DIR/instr/fixtures"
  [test_exec_txn]="$WORK_DIR/txn/fixtures/"
  [test_exec_block]="$WORK_DIR/block/fixtures"
  [test_exec_vm_syscall]="$WORK_DIR/syscall/fixtures"
  [test_exec_elf_loader]="$WORK_DIR/elf_loader/fixtures"
  [test_exec_shred]="$WORK_DIR/shred/fixtures"
  [test_exec_gossip]="$WORK_DIR/gossip/fixtures"
  [test_exec_cost]="$WORK_DIR/cost/fixtures"
  [test_exec_vm_serialization]="$WORK_DIR/vm_serialization/fixtures"
)

any_job_failed=0

# Get total number of jobs
total_jobs=${#JOBS[@]}
current_job=0

# Execute each job
for name in "${!JOBS[@]}"; do
  current_job=$((current_job + 1))
  echo "=== Job $current_job/$total_jobs: $name ==="
  bin="./target/release/$name"
  fixtures="${JOBS[$name]}"
  job_log="$LOG_PATH/${name}.log"

  # Initialize log files once per job (before processing multiple fixture directories)
  fail_log="${job_log%.log}.failures"
  ok_log="${job_log%.log}.passed"
  : > "$job_log"
  : > "$fail_log"
  : > "$ok_log"

  # Handle multiple fixture directories
  for fixture_dir in $fixtures; do
    run_fixtures_per_file "$name" "$bin" "$fixture_dir" "$job_log" "$NUM_PROCESSES"
  done

  # Mark job failure if any fixtures failed
  if [ -s "$fail_log" ]; then
    any_job_failed=1
    echo "Job $current_job/$total_jobs: $name : FAILED"
  else
    echo "Job $current_job/$total_jobs: $name : PASSED"
  fi
done

# Aggregate summary
all_failures="$LOG_PATH/all.failures"
all_passed="$LOG_PATH/all.passed"
: > "$all_failures"
: > "$all_passed"

cat "$LOG_PATH"/*.failures 2>/dev/null >> "$all_failures" || true
cat "$LOG_PATH"/*.passed   2>/dev/null >> "$all_passed"   || true

# Dedupe
sort -u -o "$all_failures" "$all_failures" 2>/dev/null || true
sort -u -o "$all_passed"   "$all_passed"   2>/dev/null || true

failed_count=$(wc -l < "$all_failures" 2>/dev/null || echo 0)
passed_count=$(wc -l < "$all_passed"   2>/dev/null || echo 0)

echo "Test vectors complete. Passed: $passed_count, Failed: $failed_count"

# Echo detailed summaries for failing fixtures in CI
if [ "$failed_count" -gt 0 ]; then
  echo
  echo "==== Failing fixture details ===="
  # Print per-fixture summaries
  find "$LOG_PATH/per_fixture" -type f -name "*.fail.txt" -print0 \
    | sort -z \
    | xargs -0 -r cat
  echo "Failing fixtures written to: $all_failures"
fi

# Final exit code: fail if any job had failures
if [ "$any_job_failed" -eq 1 ] || [ "$failed_count" -gt 0 ]; then
  echo "=== FINAL RESULT: FAIL ==="
  exit 1
else
  echo "=== FINAL RESULT: PASS ==="
  exit 0
fi
