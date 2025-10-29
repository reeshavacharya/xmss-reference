#!/bin/bash

# Run speed benchmarks for several XMSS/XMSSMT variants and save results to a log
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

LOG="$SCRIPT_DIR/benchmark_results.log"
echo "=== XMSS reference benchmark run ===" > "$LOG"
echo "Started: $(date -u)" >> "$LOG"
echo >> "$LOG"

# Allow passing number of iterations as first argument, default to 100
ITERATIONS=${1:-100}
echo "Iterations: $ITERATIONS" >> "$LOG"

# Compiler and flags (mirror Makefile)
CC=/usr/bin/gcc
CFLAGS="-w -g -O3"
LDLIBS="-lcrypto"

# Sources (SOURCES_FAST as used by Makefile for speed)
SOURCES_FAST="params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss.c xmss_core_fast.c xmss_commons.c utils.c"

# Variants to test: pair of (is_mt, variant_string)
VARIANTS=(
  "0:XMSS-SHA2_10_256"
)

# Number of signature iterations for the speed test (override default)
SIGS=10000

for entry in "${VARIANTS[@]}"; do
  ismt="${entry%%:*}"
  variant="${entry#*:}"

  echo "========================================" >> "$LOG"
  echo "Testing variant: $variant (XMSSMT=$ismt)" >> "$LOG"
  echo "Build start: $(date -u)" >> "$LOG"

  # Build command
  CMD="$CC"
  if [ "$ismt" = "1" ]; then
    # Ensure the variant macro is passed as a C string literal
    CMD="$CMD -DXMSSMT -DXMSS_VARIANT=\\\"$variant\\\""
  else
    CMD="$CMD -DXMSS_VARIANT=\\\"$variant\\\""
  fi
  # Pass the number of iterations to the test via -DNTESTS
  CMD="$CMD -DNTESTS=$ITERATIONS $CFLAGS -o test/xmss_timing $SOURCES_FAST test/xmss_timing.c $LDLIBS"

  echo "Running: $CMD" >> "$LOG"
  # Execute build and capture output
  eval $CMD >> "$LOG" 2>&1
  if [ $? -ne 0 ]; then
    echo "Build failed for $variant (see $LOG)" >> "$LOG"
    continue
  fi

  echo "Running: ./test/xmss_timing" >> "$LOG"
  ./test/xmss_timing >> "$LOG" 2>&1

  echo "Cleaning binary" >> "$LOG"
  rm -f test/xmss_timing
  echo "Build end: $(date -u)" >> "$LOG"
  echo >> "$LOG"
done

echo "Finished: $(date -u)" >> "$LOG"
echo "Results saved to $LOG"
