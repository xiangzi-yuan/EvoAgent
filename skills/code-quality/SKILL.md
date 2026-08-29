---
name: code-quality
description: Review added production code for TODO or FIXME markers that may represent unfinished behavior. Use during code review and merge-readiness checks; ignore markers added under tests/.
allowed-tools:
  - search_diff
  - changed_line
---

# Review unfinished production behavior

Inspect added lines for `TODO` or `FIXME` markers.

- Ignore files under `tests/` and markers that only document completed behavior.
- Report a finding only when the marker represents unfinished production behavior.
- Cite the exact added line and explain the concrete behavior that remains incomplete.
- Recommend completing the behavior or linking a tracked owner and deadline.
- Require a regression test for the unfinished path.
