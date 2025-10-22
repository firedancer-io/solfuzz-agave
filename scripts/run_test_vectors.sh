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

mkdir -p dump

# Show the commit hashes being used
repo_commit=$(git rev-parse HEAD)
echo "Using repo commit: $repo_commit"

# Get commit SHA from file or env
GIT_REF=${GIT_REF:-$(cat ./scripts/test-vectors-commit-sha.txt)}
echo "Using test-vectors commit: $GIT_REF"

# Fetch/update test-vectors repo
if [ ! -d dump/test-vectors ]; then
  echo "Cloning test-vectors repository..."
  (cd dump && git clone --depth=1 -q https://github.com/firedancer-io/test-vectors.git)
else
  echo "Updating test-vectors repository..."
  (cd dump/test-vectors && git fetch -q origin "$GIT_REF" || true)
fi

# Checkout specific commit non-destructively
(
  cd dump/test-vectors
  if ! git cat-file -e "$GIT_REF"^{commit} 2>/dev/null; then
    echo "Fetching test vectors commit $GIT_REF..."
    git fetch -q origin "$GIT_REF"
  fi
  git checkout -q --detach "$GIT_REF"
)

# Show the commit hashes being used
test_vectors_commit=$(cd dump/test-vectors && git rev-parse HEAD)
echo "Using test-vectors commit: $test_vectors_commit"

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
  : > "$job_log"
  : > "$fail_log"
  : > "$ok_log"

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

  export name bin job_log fail_log ok_log pf_dir EXPECT_REGEX ACTUAL_REGEX FAIL_CONTEXT_LINES
  find "$fixture_dir" -type f -name '*.fix' -print0 \
    | xargs -0 -r -P "$procs" -n 1 bash -c '
        set -euo pipefail
        file="$1"

        # Create a per-fixture log file
        pf="$(mktemp -p "$pf_dir" "${name}_XXXXXX.log")"

        # Run fixture; capture output to per-fixture log
        if "$bin" -- "$file" >> "$pf" 2>&1; then
          # Fallback: some binaries may still print FAIL but exit 0.
          if grep -w -q FAIL "$pf"; then
            echo "$file" >> "$fail_log"
            sf="${pf}.fail.txt"
            {
              echo "==== FAIL: $file ===="
              echo "Per-fixture log: $pf"
              echo "--- Expected/Actual (pattern: $EXPECT_REGEX / $ACTUAL_REGEX) ---"
              grep -E -i "$EXPECT_REGEX" "$pf" || true
              grep -E -i "$ACTUAL_REGEX" "$pf" || true
              echo "--- Tail of output (last $FAIL_CONTEXT_LINES lines) ---"
              tail -n "$FAIL_CONTEXT_LINES" "$pf" || true
              echo
            } > "$sf"
          else
            echo "$file" >> "$ok_log"
          fi
        else
          # Non-zero exit => failure
          echo "$file" >> "$fail_log"
          sf="${pf}.fail.txt"
          {
            echo "==== FAIL: $file ===="
            echo "Per-fixture log: $pf"
            echo "--- Expected/Actual (pattern: $EXPECT_REGEX / $ACTUAL_REGEX) ---"
            grep -E -i "$EXPECT_REGEX" "$pf" || true
            grep -E -i "$ACTUAL_REGEX" "$pf" || true
            echo "--- Tail of output (last $FAIL_CONTEXT_LINES lines) ---"
            tail -n "$FAIL_CONTEXT_LINES" "$pf" || true
            echo
          } > "$sf"
        fi

        # Append per-fixture output to the job log
        cat "$pf" >> "$job_log" 2>&1
      ' _
}

# Define jobs: name -> fixtures dir(s)
declare -A JOBS=(
  [test_exec_instr]="dump/test-vectors/instr/fixtures"
  [test_exec_txn]="dump/test-vectors/txn/fixtures/programs dump/test-vectors/txn/fixtures/precompile"
  [test_exec_block]="dump/test-vectors/block/fixtures"
  [test_exec_vm_syscall]="dump/test-vectors/syscall/fixtures"
  [test_exec_vm_interp]="dump/test-vectors/vm_interp/fixtures"
  [test_exec_elf_loader]="dump/test-vectors/elf_loader/fixtures"
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

  # Handle multiple fixture directories
  for fixture_dir in $fixtures; do
    run_fixtures_per_file "$name" "$bin" "$fixture_dir" "$job_log" "$NUM_PROCESSES"
  done

  fail_log="${job_log%.log}.failures"

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
