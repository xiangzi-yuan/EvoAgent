---
name: reliability-review
description: Review code changes for timeout, retry, concurrency, resource-lifetime, idempotency, and operational failure risks. Use when a change adds asynchronous work, I/O, queues, caches, background jobs, or error recovery.
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

# Reliability review

Follow each changed operation through success, timeout, cancellation, retry, and concurrent execution.

- Check resource acquisition and release on every exit path.
- Verify retries are bounded, idempotent where required, and do not duplicate externally visible work.
- Check that concurrent updates have a clear ownership, lock, atomic primitive, or conflict policy.
- Distinguish an operational improvement from a defect: report only a failure mode the diff introduces or makes reachable.

