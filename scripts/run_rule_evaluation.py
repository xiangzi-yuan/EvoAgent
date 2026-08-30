"""Evaluate the deterministic 6-rule or 14-rule baseline without model calls."""
import argparse
import json
import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from evoagent.evaluation_benchmark import ContextRuleReviewer  # noqa: E402
from evoagent.evaluation_harness import (  # noqa: E402
    EndToEndEvaluationHarness,
    dataset_fingerprint,
    load_jsonl,
)
from evoagent.reviewer import CompositeReviewer, LocalRuleReviewer  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset")
    parser.add_argument("--rules", type=int, choices=(6, 14), default=14)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    cases = load_jsonl(args.dataset)
    reviewers = [LocalRuleReviewer()]
    if args.rules == 14:
        reviewers.append(ContextRuleReviewer())
    reviewer = CompositeReviewer(reviewers)
    report = EndToEndEvaluationHarness().run(
        reviewer, cases, "deterministic-%d-rule" % args.rules
    )
    report["configuration"] = {
        "dataset": os.path.abspath(args.dataset),
        "dataset_sha256": dataset_fingerprint(cases),
        "deterministic_rules": args.rules,
        "model_calls": 0,
    }
    output = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    temporary = output + ".tmp"
    with open(temporary, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, output)
    print(json.dumps(report["metrics"], ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
