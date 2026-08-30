"""Replay repository evidence and publication gates without new model calls."""
import argparse
from copy import deepcopy
import hashlib
import json
import os
import re
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from evoagent.agentic_core import ModeRouterReviewer  # noqa: E402
from evoagent.diff_parser import parse_unified_diff  # noqa: E402
from evoagent.evaluation_harness import load_jsonl  # noqa: E402
from evoagent.evaluation_v2 import ProductionEvaluationHarness  # noqa: E402
from evoagent.finding_policy import (  # noqa: E402
    REPOSITORY_EVIDENCE_TOOLS,
    repository_evidence_refs,
)
from evoagent.gates import FindingGate  # noqa: E402
from evoagent.repository_tools import RepositoryToolSuite  # noqa: E402
from evoagent.telemetry import ExecutionLedger  # noqa: E402


def _read(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset")
    parser.add_argument("report")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    cases = {str(case["id"]): case for case in load_jsonl(args.dataset)}
    report_raw = _read(args.report)
    report = json.loads(report_raw.decode("utf-8"))
    harness = ProductionEvaluationHarness()
    rescored = []
    totals = harness._empty_totals()
    split_totals = {}
    promoted_count = 0
    replayed_tools = 0
    replay_attempts = []

    for original in report.get("case_results") or []:
        result = deepcopy(original)
        case = cases.get(str(result.get("id", "")))
        if case is None:
            parser.error("dataset is missing report case %s" % result.get("id"))
        parsed = parse_unified_diff(case["diff"])
        root = str(case.get("repository_root") or "")
        if not root or not os.path.isdir(root):
            parser.error("case %s has no repository checkout" % case["id"])
        ledger = ExecutionLedger("gate-replay")
        suite = RepositoryToolSuite(root, case["diff"], parsed, ledger)
        registry = suite.registry("gate-replay", set(REPOSITORY_EVIDENCE_TOOLS))
        evidence_by_id = {}
        summary = result.get("agentic_summary") or {}
        for call in summary.get("tool_call_log") or []:
            tool = str(call.get("tool", ""))
            if not call.get("ok") or tool not in registry.names():
                continue
            try:
                value = registry.invoke(tool, dict(call.get("arguments") or {}))
            except Exception:
                continue
            if isinstance(value, dict) and value.get("evidence_id"):
                evidence_by_id[str(value["evidence_id"])] = value
                old_id = re.search(
                    r"['\"]evidence_id['\"]\s*:\s*['\"]([^'\"]+)",
                    str(call.get("result_preview", "")),
                )
                if old_id:
                    evidence_by_id[old_id.group(1)] = value
                replayed_tools += 1

        formal = harness._restore_findings(result.get("predicted_findings") or [])
        suggestions = harness._restore_findings(result.get("suggested_findings") or [])
        formal_keys = {
            (item.rule_id, item.source, item.path, item.line) for item in formal
        }
        remaining = []
        decisions = summary.get("publication_decisions") or []
        critic = {
            int(item["finding_index"]): item
            for item in summary.get("critic_decisions") or []
            if str(item.get("finding_index", "")).isdigit()
        }
        accepted_indices = {
            int(value) for value in (summary.get("lead_final") or {}).get(
                "accepted_finding_indices", []
            )
        }
        replay_candidates = list(suggestions)
        for decision in decisions:
            if decision.get("disposition") != "confirmed":
                continue
            matching = []
            for worker in summary.get("worker_results") or []:
                for value in worker.get("findings") or []:
                    if (
                        str(value.get("rule_id")) == str(decision.get("rule_id"))
                        and str(value.get("source")) == str(decision.get("source"))
                    ):
                        matching.append(value)
            if len(matching) != 1:
                continue
            recovered = harness._restore_findings(matching)[0]
            key = (recovered.rule_id, recovered.source, recovered.path, recovered.line)
            if key not in formal_keys and all(
                key != (item.rule_id, item.source, item.path, item.line)
                for item in replay_candidates
            ):
                replay_candidates.append(recovered)

        for finding in replay_candidates:
            for ref in finding.evidence_refs:
                replayed = evidence_by_id.get(str(ref.get("evidence_id", "")))
                if replayed:
                    ref["tool"] = replayed.get("tool", ref.get("tool", ""))
                    ref["output"] = replayed.get("output")
            decision = next((
                item for item in decisions
                if str(item.get("rule_id")) == finding.rule_id
                and str(item.get("source")) == finding.source
            ), None)
            index = int(decision.get("finding_index", -1)) if decision else -1
            objections = set(decision.get("reasons") or []) if decision else set()
            critic_ready = bool((critic.get(index) or {}).get("publication_ready"))
            evidence_only_block = bool(decision) and objections == {
                "no repository-backed tool evidence"
            }
            confirmed_before_global_gate = bool(decision) and (
                decision.get("disposition") == "confirmed"
            )
            attempt = {
                "case_id": case["id"], "rule_id": finding.rule_id,
                "finding_index": index,
                "lead_selected": index in accepted_indices,
                "critic_ready": critic_ready,
                "evidence_only_block": evidence_only_block,
                "confirmed_before_global_gate": confirmed_before_global_gate,
                "repository_evidence_count": len(repository_evidence_refs(finding)),
                "promoted": False,
            }
            if (
                index in accepted_indices
                and critic_ready
                and (evidence_only_block or confirmed_before_global_gate)
            ):
                published, _suggestions, _decisions = (
                    ModeRouterReviewer._partition_publication(
                        [], [finding], [finding],
                        [{"finding_index": 0, "publication_ready": True}],
                        repository_available=True,
                    )
                )
                gated = FindingGate().apply(published, parsed)
                if gated.accepted:
                    promoted = gated.accepted[0]
                    promoted.disposition = "confirmed"
                    formal.append(promoted)
                    promoted_count += 1
                    attempt["promoted"] = True
                    replay_attempts.append(attempt)
                    continue
                attempt["gate_rejections"] = list(gated.rejected)
            replay_attempts.append(attempt)
            remaining.append(finding)

        result["predicted_findings"] = [item.to_dict() for item in formal]
        result["suggested_findings"] = [item.to_dict() for item in remaining]
        summary["suggested_findings"] = [item.to_dict() for item in remaining]
        summary["suggestion_count"] = len(remaining)
        summary["accepted_findings"] = len(formal)
        result["agentic_summary"] = summary
        harness.rescore_cached_result(result, case)
        rescored.append(result)
        harness._accumulate(totals, result)
        bucket = split_totals.setdefault(case["split"], harness._empty_totals())
        harness._accumulate(bucket, result)

    report["case_results"] = rescored
    report["metrics"] = harness._metrics(totals)
    report["by_split"] = {
        split: harness._metrics(values)
        for split, values in sorted(split_totals.items())
    }
    report["status"] = "complete"
    report["gate_replay"] = {
        "model_calls": 0,
        "promoted_findings": promoted_count,
        "replayed_repository_tools": replayed_tools,
        "attempts": replay_attempts,
        "source_report": os.path.normpath(args.report).replace("\\", "/"),
        "source_report_sha256": hashlib.sha256(report_raw).hexdigest(),
    }
    output = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    temporary = output + ".tmp"
    with open(temporary, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, output)
    print(json.dumps({
        "gate_replay": report["gate_replay"], "metrics": report["metrics"],
    }, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
