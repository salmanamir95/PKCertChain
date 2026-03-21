#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SEC_DIR="$ROOT_DIR/tests/security"
REPORT_DIR="$SEC_DIR/reports"
TS=$(date +%Y-%m-%d_%H-%M-%S)
LOG="$REPORT_DIR/security-$TS.log"
BUILD_DIR="$ROOT_DIR/build-security"

mkdir -p "$REPORT_DIR"

note() {
  printf "%s\n" "$*" | tee -a "$LOG"
}

section() {
  printf "\n== %s ==\n" "$*" | tee -a "$LOG"
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

note "Automated Security Audit (Local)"
note "Timestamp: $TS"
note "Repo: $ROOT_DIR"

section "Environment"
note "OS: $(uname -a)"
if has_cmd cc; then note "Compiler: $(cc --version | head -n 1)"; fi

section "Build (compile_commands.json)"
if has_cmd cmake; then
  note "Generating compile_commands.json in $BUILD_DIR"
  cmake -S "$ROOT_DIR" -B "$BUILD_DIR" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON 2>&1 | tee -a "$LOG"
else
  note "cmake not found; skipping compile_commands.json"
fi

section "cppcheck"
if has_cmd cppcheck; then
  cppcheck --enable=all --inconclusive --std=c11 -I "$ROOT_DIR/include" "$ROOT_DIR/src" \
    --inline-suppr --error-exitcode=2 2>&1 | tee -a "$LOG" || CPP_RC=$?
  : ${CPP_RC:=0}
  note "cppcheck exit: $CPP_RC"
else
  note "cppcheck not found; skipped"
  CPP_RC=0
fi

section "clang-tidy"
if has_cmd clang-tidy; then
  if [ -f "$BUILD_DIR/compile_commands.json" ]; then
    find "$ROOT_DIR/src" -name '*.c' -print0 \
      | xargs -0 clang-tidy -p "$BUILD_DIR" --quiet 2>&1 | tee -a "$LOG" || TIDY_RC=$?
    : ${TIDY_RC:=0}
    note "clang-tidy exit: $TIDY_RC"
  else
    note "compile_commands.json not found; skipped clang-tidy"
    TIDY_RC=0
  fi
else
  note "clang-tidy not found; skipped"
  TIDY_RC=0
fi

section "clang-format (dry-run)"
if has_cmd clang-format; then
  if [ -f "$ROOT_DIR/.clang-format" ]; then
    find "$ROOT_DIR/src" "$ROOT_DIR/include" -name '*.c' -o -name '*.h' -print0 \
      | xargs -0 clang-format --dry-run --Werror 2>&1 | tee -a "$LOG" || FMT_RC=$?
    : ${FMT_RC:=0}
    note "clang-format exit: $FMT_RC"
  else
    note ".clang-format not found; skipped"
    FMT_RC=0
  fi
else
  note "clang-format not found; skipped"
  FMT_RC=0
fi

section "Dangerous Function Scan"
if has_cmd rg; then
  rg -n "\b(strcpy|strcat|sprintf|gets|scanf)\b" "$ROOT_DIR/src" "$ROOT_DIR/include" 2>&1 \
    | tee -a "$LOG" || true
else
  note "rg not found; skipped"
fi

section "Summary"
TOTAL_RC=$((CPP_RC + TIDY_RC + FMT_RC))
if [ "$TOTAL_RC" -eq 0 ]; then
  note "Result: PASS (no tool errors)"
else
  note "Result: FAIL (one or more tools reported issues)"
fi

note "Log saved: $LOG"

exit "$TOTAL_RC"
