#!/bin/bash

set -euo pipefail

DURATION="60m"
JOBS_PER_TEST=6
TARGET_CLASS="net.lingala.zip4j.FuzzTests"
COVERAGE_DIR="target/coverage-reports"

FUZZ_TESTS=(
    "fuzzRoundTrip"
    "fuzzFileOperations"
    "fuzzInputStream"
    "fuzzDecompressionBomb"
    "fuzzRawParsingAndValidation"
    "fuzzSplitOperations"
    "fuzzCrossLibraryCompatibility"
)

mvn clean
mkdir -p ${COVERAGE_DIR}

echo "=== Running fuzzing for ${DURATION} ==="

for fuzz_test in "${FUZZ_TESTS[@]}"; do
  echo "Fuzzing: ${fuzz_test}"

  pids=()

  for ((i=1; i <= JOBS_PER_TEST; i++)); do
    (
      JAZZER_FUZZ=1 mvn \
        -Djazzer.max_duration=${DURATION} \
        -Dtest="${TARGET_CLASS}#${fuzz_test}" \
        -Dmaven.test.failure.ignore=true \
        test
    ) &
    pids+=($!)
  done

  # Wait for all fuzzing jobs to finish
  for pid in "${pids[@]}"; do
    wait "$pid"
  done
done

echo "=== Replaying corpus for coverage ==="

for fuzz_test in "${FUZZ_TESTS[@]}"; do
  echo "Replaying: ${fuzz_test}"

  mvn \
    jacoco:prepare-agent \
    -Dtest="${TARGET_CLASS}#${fuzz_test}" \
    -Dmaven.test.failure.ignore=true \
    test

  if [ -f "target/jacoco.exec" ]; then
    mv target/jacoco.exec "${COVERAGE_DIR}/jacoco-${fuzz_test}.exec"
  else
    echo "No coverage data found"
  fi
done

echo "=== Merging data and creating report ==="

mvn jacoco:merge@merge-results jacoco:report

