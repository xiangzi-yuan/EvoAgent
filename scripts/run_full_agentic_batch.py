"""Run a resumable, progress-visible batch through the full Agentic reviewer."""
import argparse
from collections import Counter
import json
import os
import sys
import time


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from evoagent.config import Settings  # noqa: E402
from evoagent.evaluation_harness import (  # noqa: E402
    dataset_fingerprint,
    load_jsonl,
)
from evoagent.evaluation_v2 import (  # noqa: E402
    ProductArmReviewer,
    ProductionEvaluationHarness,
    validate_real_dataset,
)
from evoagent.llm import JsonChatClient  # noqa: E402


def select_cases(cases: list, limit: int) -> list:
    """Round-robin across split and positive/clean buckets."""
    keys = [
        (split, risk)
        for split in ("validation", "holdout", "train")
        for risk in (True, False)
    ]
    buckets = {
        key: [
            case for case in cases
            if case["split"] == key[0]
            and bool(case["expected_findings"]) is key[1]
        ]
        for key in keys
    }
    selected = []
    while len(selected) < limit and any(buckets.values()):
        for key in keys:
            if buckets[key] and len(selected) < limit:
                selected.append(buckets[key].pop(0))
    return selected


def load_results(path: str, allowed_ids: set) -> dict:
    if not path or not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as handle:
        report = json.load(handle)
    return {
        item["id"]: item
        for item in report.get("case_results", [])
        if item.get("id") in allowed_ids
    }


def build_report(
    harness, selected: list, completed: dict, config: dict,
    token_budget: int, time_budget: int, timeout: int,
    started: float, status: str,
) -> dict:
    ordered = [completed[case["id"]] for case in selected if case["id"] in completed]
    totals = harness._empty_totals()
    for result in ordered:
        harness._accumulate(totals, result)
    by_split = {}
    for split in ("validation", "holdout"):
        split_totals = harness._empty_totals()
        for result in ordered:
            if result["split"] == split:
                harness._accumulate(split_totals, result)
        by_split[split] = harness._metrics(split_totals)
    role_calls = Counter()
    for result in ordered:
        role_calls.update(result.get("model_roles") or {})
    return {
        "schema_version": 1,
        "name": "full-agentic-batch",
        "status": status,
        "progress": {"completed": len(ordered), "total": len(selected)},
        "model": {
            "provider": config["provider"],
            "name": config["model"],
            "base_url": config["base_url"],
        },
        "configuration": {
            "roles": ["lead", "security", "correctness-reliability", "critic"],
            "token_budget_per_pr": token_budget,
            "time_budget_seconds_per_pr": time_budget,
            "model_request_timeout_seconds": timeout,
        },
        "dataset": {
            "cases": len(selected),
            "repositories": len({case["repository"] for case in selected}),
            "risk_cases": sum(bool(case["expected_findings"]) for case in selected),
            "clean_cases": sum(not case["expected_findings"] for case in selected),
            "sha256": dataset_fingerprint(selected),
            "readiness": validate_real_dataset(selected),
        },
        "metrics": harness._metrics(totals),
        "by_split": by_split,
        "execution": {"model_role_calls": dict(sorted(role_calls.items()))},
        "duration_seconds": round(time.monotonic() - started, 4),
        "case_results": ordered,
    }


def save_report(path: str, report: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset")
    parser.add_argument("--max-cases", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--token-budget", type=int, default=16000)
    parser.add_argument("--time-budget", type=int, default=120)
    parser.add_argument("--seed-report", default="")
    parser.add_argument(
        "--output",
        default=os.path.join(
            ROOT, "output", "agentic-evaluation", "full-agentic-batch.json"
        ),
    )
    args = parser.parse_args()
    if args.max_cases < 1:
        parser.error("--max-cases must be positive")

    settings = Settings.from_env()
    config = settings.resolved_llm()
    if not config:
        parser.error("a model provider must be configured")
    cases = load_jsonl(args.dataset)
    for case in cases:
        for finding in case["expected_findings"]:
            finding.setdefault("should_comment", True)
    selected = select_cases(cases, args.max_cases)
    allowed_ids = {case["id"] for case in selected}
    output = os.path.abspath(args.output)
    completed = load_results(output, allowed_ids)
    completed.update(load_results(os.path.abspath(args.seed_report), allowed_ids))

    client = JsonChatClient(
        str(config["base_url"]), str(config["api_key"]), str(config["model"]),
        provider=str(config["provider"]), timeout=args.timeout,
    )
    reviewer = ProductArmReviewer(
        "full-agentic", client, args.token_budget, args.time_budget
    )
    harness = ProductionEvaluationHarness()
    started = time.monotonic()
    save_report(output, build_report(
        harness, selected, completed, config, args.token_budget,
        args.time_budget, args.timeout, started, "running",
    ))
    for index, case in enumerate(selected, 1):
        if case["id"] in completed:
            print(
                "SKIP %d/%d case=%s checkpoint=complete"
                % (index, len(selected), case["id"]),
                flush=True,
            )
            continue
        print(
            "START %d/%d case=%s split=%s risk=%s"
            % (
                index, len(selected), case["id"], case["split"],
                bool(case["expected_findings"]),
            ),
            flush=True,
        )
        case_started = time.monotonic()
        result = harness.run(reviewer, [case], "full-agentic")["case_results"][0]
        completed[case["id"]] = result
        save_report(output, build_report(
            harness, selected, completed, config, args.token_budget,
            args.time_budget, args.timeout, started, "running",
        ))
        print(
            "DONE %d/%d case=%s success=%s predicted=%d tp=%d fp=%d fn=%d "
            "tokens=%d elapsed=%.1fs"
            % (
                index, len(selected), case["id"], result["execution_success"],
                result["predicted"], result["tp"], result["fp"], result["fn"],
                result["total_tokens"], time.monotonic() - case_started,
            ),
            flush=True,
        )
        if result.get("error"):
            print("ERROR case=%s %s" % (case["id"], result["error"]), flush=True)
    save_report(output, build_report(
        harness, selected, completed, config, args.token_budget,
        args.time_budget, args.timeout, started, "complete",
    ))
    print("COMPLETE %s" % output, flush=True)


if __name__ == "__main__":
    main()
