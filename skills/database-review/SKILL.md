---
name: database-review
description: Review database queries, transactions, migrations, and persistence changes for data integrity, locking, performance, and rollback safety. Use when code changes schemas, SQL, ORM queries, transaction boundaries, or durable records.
allowed-tools:
  - search_diff
  - search_repository
  - read_file
  - changed_line
  - symbol
  - locate_tests
  - read_project_controls
---

# Database review

Inspect the changed persistence operation together with its transaction scope, constraints, callers, and migration order.

- Check lost updates, partial writes, isolation assumptions, and missing uniqueness or foreign-key enforcement.
- Identify unbounded reads, N+1 query paths, missing predicates, and index-sensitive new queries only when they affect the changed path.
- For migrations, verify backward-compatible rollout, data backfill safety, and a feasible rollback or forward fix.
- Report a concrete integrity, availability, or performance failure rather than a generic ORM preference.

