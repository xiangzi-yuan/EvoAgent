---
name: security-review
description: Review code changes for authorization failures, injection, secret exposure, unsafe deserialization, and dangerous data flows. Use when a change handles untrusted input, credentials, permissions, network boundaries, or code execution.
allowed-tools:
  - search_diff
  - search_repository
  - read_file
  - changed_line
  - symbol
  - ast_analyze
  - git_context
  - run_scanners
---

# Security review

Trace data from an untrusted source to a sensitive sink. Inspect authorization decisions separately from authentication, and verify that checks occur before the protected action.

- Prioritize injection, path traversal, unsafe deserialization, SSRF, command execution, insecure secrets, and privilege-boundary changes.
- Use repository evidence to establish a concrete source-to-sink path or missing authorization condition.
- Treat a suspicious API alone as a lead, not a finding; report only an exploitable defect introduced by the change.
- For high-severity findings, cite changed-line evidence plus a call chain or tool evidence.

