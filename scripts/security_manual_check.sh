#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SEC_DIR="$ROOT_DIR/tests/security"
TS=$(date +%Y-%m-%d_%H-%M-%S)
LOG="$SEC_DIR/reports/security-$TS.log"

mkdir -p "$SEC_DIR/reports"

{
  echo "Manual Security Check"
  echo "Timestamp: $TS"
  echo "Repo: $ROOT_DIR"
  echo
  echo "Checklist: $SEC_DIR/checklists/owasp_top10_c_adapted.md"
  echo "Tools (optional):"
  echo "  cppcheck --enable=all --inconclusive --std=c11 -I include src"
  echo "  clang-tidy (if configured)"
  echo "  clang-format (if configured)"
  echo
  echo "Notes:"
  echo "- Fill in findings below"
  echo
} > "$LOG"

echo "Created log: $LOG"

echo "Open the checklist and fill the log manually."
