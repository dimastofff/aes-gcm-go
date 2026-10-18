# Changelog

## Unreleased
- Correct the memory-use description and document the v1 ciphertext format, key-use limits, and application responsibilities.
- Add security reporting and contribution guidance, plus an executable usage example.
- Update CI for supported Go releases and retain a separate Go 1.13 compatibility check; add race, coverage, fuzz, and scheduled vulnerability checks.
- Add known-answer, interoperability, concurrent-use, and error-contract tests; expand allocation-reporting benchmarks.
- Remove the redundant raw-key field and constructor copy; encrypt in a single operation-local buffer.
- Add output-ownership regression tests and a constructor benchmark.
- Preserve the public API, Go 1.13 source compatibility, and existing ciphertext format.

## v1.1.0 (2025-07-14)
- Fix import path in code snippet example in `README.md` [#2]
- Downgrade minimal Go version to `1.13` [#3]
- Add GitHub Workflow CI with running tests and benchmarks [#3]

## v1.0.0 (2025-07-13)
- Implemented AES-256-GCM encryption/decryption [#1]
