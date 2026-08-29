---
name: observability-review
description: Review code changes for missing actionable logs, metrics, traces, and error context in important operational paths. Use when a change adds external I/O, background work, retries, failures, queues, authentication, or state transitions.
allowed-tools:
  - search_diff
  - search_repository
  - read_file
  - changed_line
  - symbol
  - locate_tests
---

# Observability review

Check whether operators can detect, diagnose, and safely correlate failures introduced by the changed path.

- Preserve error causes and relevant safe identifiers at failure boundaries without logging secrets or sensitive payloads.
- Look for missing outcome metrics or trace boundaries on new externally visible asynchronous or remote work.
- Do not request logs or metrics for trivial local computations with no operational decision value.
- Report missing observability only when it prevents diagnosing a meaningful changed failure or correctness outcome.

