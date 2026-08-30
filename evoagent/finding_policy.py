"""Canonical rule identities and conservative publication policy helpers."""
import json
import re
from typing import List

from .models import Finding


CANONICAL_RULE_IDS = frozenset({
    "SEC-EVAL",
    "SEC-SUBPROCESS-SHELL",
    "SEC-HARDCODED-SECRET",
    "SEC-SQL-CONCAT",
    "REL-EMPTY-EXCEPT",
    "REL-DEBUG-PRINT",
    "SEC-PATH-TRAVERSAL",
    "SEC-YAML-LOAD",
    "SEC-WEAK-HASH",
    "SEC-INSECURE-TEMPFILE",
    "SEC-WEAK-RANDOM",
    "REL-UNBOUNDED-RETRY",
    "SEC-ASSERT-AUTH",
    "SEC-INSECURE-COOKIE",
    "SEC-PICKLE-LOAD",
    "REL-FLOAT-MONEY",
    "REL-NAIVE-DATETIME",
    "REL-BLOCKING-ASYNC",
    "REL-NONATOMIC-WRITE",
    "SEC-OPEN-REDIRECT",
    "SEC-LOG-FORGING",
})

RULE_ID_ALIASES = {
    "INJECTION-PICKLE-UNTRUSTED": "SEC-PICKLE-LOAD",
    "UNSAFE-PICKLE-DESERIALIZATION": "SEC-PICKLE-LOAD",
    "UNSAFE-DESERIALIZATION-PICKLE": "SEC-PICKLE-LOAD",
    "DYNAMIC-CODE-EXECUTION": "SEC-EVAL",
    "COMMAND-INJECTION-SHELL-TRUE": "SEC-SUBPROCESS-SHELL",
    "HARDCODED-SECRET": "SEC-HARDCODED-SECRET",
    "SQL-INJECTION-CONCAT": "SEC-SQL-CONCAT",
}

GENERIC_MODEL_RULE = re.compile(
    r"^(?:CORRECTNESS|RELIABILITY|SECURITY|SEC|REL|CR|BUG|ISSUE)(?:-|_)?\d+$"
)
VALID_RULE_ID = re.compile(r"^[A-Z][A-Z0-9_-]{1,79}$")

DETERMINISTIC_SOURCE_PREFIXES = (
    "local-rule-scanner",
    "declarative-scanner:",
)

REPOSITORY_EVIDENCE_TOOLS = frozenset({
    "search_repository",
    "read_file",
    "symbol",
    "locate_tests",
    "read_project_controls",
    "ast_analyze",
    "git_context",
    "run_scanners",
    "run_repository_checks",
    "semgrep",
    "bandit",
    "eslint",
    "typecheck",
    "test",
})


def normalize_rule_id(value: str) -> str:
    """Normalize known aliases without destroying valid dynamic Skill rule ids."""
    rendered = re.sub(r"[^A-Za-z0-9]+", "-", str(value or "").strip()).strip("-")
    rendered = rendered.upper()[:80]
    if not rendered:
        return "LLM-OTHER"
    rendered = RULE_ID_ALIASES.get(rendered, rendered)
    if rendered in CANONICAL_RULE_IDS:
        return rendered
    if GENERIC_MODEL_RULE.fullmatch(rendered) or not VALID_RULE_ID.fullmatch(rendered):
        return "LLM-OTHER"
    return rendered


def is_deterministic_finding(finding: Finding) -> bool:
    source = str(finding.source or "")
    return source.startswith(DETERMINISTIC_SOURCE_PREFIXES)


def is_validated_agent_skill_finding(finding: Finding) -> bool:
    return str(finding.source or "").startswith("agent-skill:")


def repository_evidence_refs(finding: Finding) -> List[dict]:
    return [
        item for item in finding.evidence_refs
        if isinstance(item, dict)
        and item.get("evidence_id")
        and str(item.get("tool")) in REPOSITORY_EVIDENCE_TOOLS
        and _repository_evidence_has_facts(item)
    ]


def _repository_evidence_has_facts(item: dict) -> bool:
    """Reject empty/unavailable tool calls masquerading as supporting evidence."""
    payload = item.get("output")
    if payload is None:
        payload = item.get("output_preview")
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = payload.strip()
    tool = str(item.get("tool"))
    if payload in (None, "", [], {}):
        return False
    if tool in {"search_repository", "locate_tests", "read_project_controls"}:
        return isinstance(payload, list) and bool(payload)
    if tool == "read_file":
        return isinstance(payload, dict) and bool(str(payload.get("content", "")).strip())
    if tool == "symbol":
        return isinstance(payload, dict) and any(
            payload.get(key) for key in ("definitions", "callers", "callees")
        )
    if tool == "ast_analyze":
        return isinstance(payload, dict) and payload.get("valid") is True
    if tool == "git_context":
        return (
            isinstance(payload, dict)
            and payload.get("available") is True
            and any(str(value.get("output", "")).strip() for value in payload.get("results") or [])
        )
    if tool in {"run_scanners", "semgrep", "bandit", "eslint", "typecheck"}:
        return (
            isinstance(payload, dict)
            and payload.get("available") is not False
            and any(
                run.get("available") is True and bool(str(run.get("output", "")).strip())
                for run in payload.get("runs") or []
                if isinstance(run, dict)
            )
        )
    if tool in {"run_repository_checks", "test"}:
        return (
            isinstance(payload, dict)
            and payload.get("available") is True
            and ("passed" in payload or "returncode" in payload)
        )
    return True


def finding_identity(finding: Finding) -> tuple:
    return finding.path, int(finding.line), finding.rule_id
