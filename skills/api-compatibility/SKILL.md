---
name: api-compatibility
description: Review public API, CLI, configuration, event, and schema changes for backward-compatibility breaks. Use when a change modifies request or response fields, defaults, endpoints, command options, serialized data, or integration contracts.
allowed-tools:
  - search_diff
  - search_repository
  - read_file
  - changed_line
  - symbol
  - locate_tests
  - read_project_controls
---

# API compatibility review

Identify the contract consumers observe, then compare old and new accepted inputs, defaults, outputs, errors, and serialized representations.

- Look for renamed or removed fields, changed nullability or types, narrowed validation, changed defaults, and error-code changes.
- Inspect callers, fixtures, documentation, and compatibility adapters before claiming a break.
- Treat internal-only refactors as out of scope unless they alter an externally consumed contract.
- State the affected consumer and a compatible migration or fallback in every finding.

