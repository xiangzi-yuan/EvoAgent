---
name: test-quality
description: Review test changes for missing coverage of changed behavior, ineffective assertions, brittle fixtures, and untested failure paths. Use when a diff adds or changes production behavior, tests, CI configuration, or test helpers.
allowed-tools:
  - search_diff
  - search_repository
  - read_file
  - changed_line
  - symbol
  - locate_tests
  - run_repository_checks
---

# Test quality review

Map each behavior-changing production edit to the test that proves the new contract or failure handling.

- Check that assertions observe the changed effect rather than merely executing code.
- Look for tests that mock away the behavior under review or accept exceptions without validating them.
- Prioritize authorization, validation, error handling, persistence, concurrency, and compatibility paths when the diff touches them.
- Do not demand tests for comments, formatting-only edits, or behavior already covered by an unchanged focused test.

