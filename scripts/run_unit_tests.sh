#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_DIR="$ROOT_DIR/tests/unit"
OUT_DIR="$ROOT_DIR/build/tests"

mkdir -p "$OUT_DIR"

fail=0
for test_file in "$TEST_DIR"/*.c; do
  test_name=$(basename "$test_file" .c)
  out_bin="$OUT_DIR/$test_name"

  echo "Compiling $test_name..."
  if cc -std=c11 -D_DEFAULT_SOURCE -I"$ROOT_DIR/include" "$test_file" -o "$out_bin" -lcrypto; then
    echo "OK: $test_name"
    if "$out_bin"; then
      echo "RUN: $test_name OK"
    else
      echo "RUN: $test_name FAIL"
      fail=1
    fi
  else
    echo "FAIL: $test_name"
    fail=1
  fi
  echo
 done

if [ "$fail" -ne 0 ]; then
  echo "Unit tests: FAIL"
  exit 1
fi

echo "Unit tests: PASS"
