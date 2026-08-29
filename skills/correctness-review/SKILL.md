---
name: correctness-review
description: Review code changes for incorrect state transitions, boundary conditions, error handling, data loss, and broken invariants. Use when behavior, business logic, parsing, validation, or persistence changes.
allowed-tools:
  - search_diff
  - search_repository
  - read_file
  - changed_line
  - symbol
  - ast_analyze
  - locate_tests
  - run_repository_checks
---

# Correctness review

Model the changed behavior's inputs, state transitions, outputs, and failure paths before reporting an issue.

- Check empty, null, duplicate, maximum, minimum, ordering, retry, and partial-failure boundaries relevant to the diff.
- Verify exceptions cannot leave state, caches, or persisted records inconsistent.
- Compare callers and existing tests when an API contract or validation rule changed.
- Report only a reproducible incorrect outcome introduced by the change, with the missing precondition or counterexample.

