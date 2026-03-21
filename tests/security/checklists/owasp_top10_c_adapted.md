# OWASP Top 10 (Adapted for C Project)

Use this as a manual checklist. Check items that apply to this codebase.

## A01: Broken Access Control
- [ ] Identify any authorization logic (if any).
- [ ] Ensure no privileged operations are exposed without checks.
- [ ] Validate file or path access restrictions (if used).

## A02: Cryptographic Failures
- [ ] Confirm all crypto uses OpenSSL correctly (no custom crypto).
- [ ] Ensure secure random sources are used where needed.
- [ ] Check for weak hash usage or truncation.

## A03: Injection
- [ ] Review all string handling for format-string vulnerabilities.
- [ ] Ensure no unchecked user input reaches system calls or parsers.

## A04: Insecure Design
- [ ] Review critical flows for missing bounds checks or unsafe defaults.
- [ ] Confirm assumptions are documented for safety-critical code paths.

## A05: Security Misconfiguration
- [ ] Check compiler flags (warnings, stack protection, PIE, RELRO if applicable).
- [ ] Ensure build does not ship with debug/test hooks.

## A06: Vulnerable and Outdated Components
- [ ] Verify OpenSSL version requirements.
- [ ] Document and track external dependencies.

## A07: Identification and Authentication Failures
- [ ] Not applicable unless authentication is implemented.
- [ ] If present, confirm no plaintext secrets in code.

## A08: Software and Data Integrity Failures
- [ ] Confirm build pipeline integrity assumptions.
- [ ] Review any update or plug-in mechanism for integrity checks.

## A09: Security Logging and Monitoring Failures
- [ ] Note absence of logging (if intended, document why).
- [ ] If logging exists, ensure no sensitive data leaks.

## A10: Server-Side Request Forgery (SSRF)
- [ ] Not applicable unless network requests are made.
- [ ] If present, validate destination allowlists and URL parsing.
