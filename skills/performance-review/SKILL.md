---
name: performance-review
description: Review code changes for avoidable latency, unbounded work, excessive memory use, blocking I/O, and inefficient repeated operations. Use when a change adds loops, collection processing, queries, network calls, serialization, caching, or hot request paths.
allowed-tools:
  - search_diff
  - search_repository
  - read_file
  - changed_line
  - symbol
  - ast_analyze
  - run_repository_checks
---

# Performance review

Estimate the work added on the hot path and identify the input size, call frequency, and expensive operation that make it material.

- Check nested iteration, repeated remote calls, N+1 queries, unbounded buffering, repeated serialization, and synchronous blocking in async paths.
- Use existing limits, pagination, batching, and cache semantics as evidence; do not invent workload assumptions.
- Report only a regression with a plausible growth path or request amplification mechanism.
- Recommend the smallest bounded, batched, cached, or streaming alternative consistent with current semantics.

