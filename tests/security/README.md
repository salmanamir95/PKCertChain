# Security (Manual)

This folder is **manual-only**. Nothing runs automatically.

## Structure
- `bugs/` Confirmed security bugs.
- `vulnerabilities/` Tracked vulnerabilities and risk notes.
- `checklists/` Manual checklists and results.
- `checklists/passed/` Passed checklists with evidence.
- `reports/` Security reviews and summaries.
- `notes/` Ad-hoc notes and follow-ups.

## Log naming
Every manual entry should use:
- `security-YYYY-MM-DD_HH-MM-SS.log`

Example:
- `security-2026-03-22_18-45-10.log`

## Workflow
1. Pick a checklist in `checklists/`.
2. Run your manual review or tooling.
3. Record results in `reports/`.
4. If a checklist is clean, copy the log into `checklists/passed/`.
5. Track confirmed issues in `bugs/` or `vulnerabilities/`.

## Automated local audit
Run the local audit script (manual, on demand):
- `./scripts/security_audit.sh`

It writes a timestamped log to `tests/security/reports/` and never runs automatically.
