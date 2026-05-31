# Contributing to ZOTE

## Scope

Contributions are accepted in the following areas:

- Detection rule additions or corrections
- MITRE ATT&CK coverage expansions (techniques, actors, software, services)
- Bug fixes with accompanying test cases
- Performance improvements with benchmark evidence
- Documentation corrections
- New unit tests for uncovered code paths

Contributions that introduce external dependencies will not be accepted. ZOTE
is a zero-dependency library; this is a design constraint, not a preference.

## Development Requirements

- GCC 13+ or Clang 16+ with C++23 support
- CMake 3.20+
- Catch2 v3 (for tests)

## Standards

All code must conform to the following:

- ISO C++23. No compiler extensions. No platform-specific headers outside
  the standard library.
- Zero warnings under `-Wall -Wextra` with GCC 13+ and Clang 16+.
- No undefined behaviour. AddressSanitizer and UBSanitizer must pass
  cleanly on the CI sanitizer job.
- Every new public API function must have at least one test case.
- Every bug fix must include a regression test.
- `noexcept` is applied only where genuinely guaranteed — functions that
  allocate or perform I/O are not marked `noexcept`.

## Submitting Changes

1. Fork the repository and create a branch from `main`.
2. Make changes. Run the full test suite locally before submitting.
3. Open a pull request against `main`. Describe the change, its rationale,
   and any limitations.
4. CI must pass. All existing tests must continue to pass.

## Rule Contributions

Detection rules submitted as pull requests must include:

- Rule type, name, and pattern or conditions
- MITRE technique ID where applicable
- Severity classification with justification
- At least one test signal that triggers the rule
- At least one test signal that does not trigger the rule (false positive test)

## Reporting Issues

Security vulnerabilities: see `docs/security/SECURITY.md`.  
All other issues: open a GitHub issue with a minimal reproduction case.
