# Manual Security Tooling (Optional)

These are *manual* checks you can run when you want. Nothing runs automatically.

## Static analysis
- `cppcheck --enable=all --inconclusive --std=c11 -I include src`
- `clang-tidy` (configure via `.clang-tidy` if desired)

## Formatting
- `clang-format` (add a `.clang-format` if you want consistent style)

## Build hardening (manual review)
- Review CMake flags for: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fPIE`, `-Wl,-z,relro,-z,now` (platform-dependent)

## Fuzzing (manual setup)
- Consider libFuzzer or AFL for critical parsing/serialization code.
