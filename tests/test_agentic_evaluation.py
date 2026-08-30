import json
import unittest

from evoagent.diff_parser import parse_unified_diff
from evoagent.evaluation_benchmark import ContextRuleReviewer
from evoagent.evaluation_v2 import (
    FairAblationSuite,
    ProductArmReviewer,
    ProductionEvaluationHarness,
    product_reviewer_factories,
)
from evoagent.models import Finding, Severity
from evoagent.reviewer import LocalRuleReviewer


DIFF = (
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -0,0 +1 @@\n"
    "+value = open(base / user_path)\n"
)


class FakeClient:
    provider = "fake"
    model = "fake-model"

    def complete_json(self, role, _system, user, ledger=None, max_tokens=None):
        if ledger:
            ledger.record_model(
                role, self.provider, self.model,
                {"prompt_tokens": 10, "completion_tokens": 5}, 1,
            )
        if role == "lead":
            managed = json.loads(user)
            task = json.loads(managed["task"])
            if task["phase"] == "delegate":
                return {
                    "action": "final",
                    "delegations": [
                        {
                            "assignment_id": "security-1", "worker": "security",
                            "objective": "Review security",
                        },
                        {
                            "assignment_id": "reliability-1",
                            "worker": "correctness-reliability",
                            "objective": "Review correctness",
                        },
                    ],
                }
            if task["phase"] == "assess-workers":
                return {
                    "action": "final", "revision_requests": [],
                    "critic_objective": "Blindly verify every candidate.",
                }
            if task["phase"] == "finalize":
                return {
                    "action": "final",
                    "accepted_finding_indices": list(
                        range(len(task["candidate_findings"]))
                    ),
                    "confidence_adjustments": [],
                }
            raise AssertionError(task["phase"])
        if role in {"security", "correctness-reliability"}:
            return {"action": "final", "findings": []}
        if role == "critic":
            managed = json.loads(user)
            task = json.loads(managed["task"])
            return {
                "action": "final",
                "decisions": [
                    {
                        "finding_index": index,
                        "accepted": True,
                        "objections": [],
                        "confidence_adjustment": 0.0,
                    }
                    for index, _item in enumerate(task["candidates"])
                ],
            }
        raise AssertionError(role)


class AgenticEvaluationTests(unittest.TestCase):
    def test_suggestion_metrics_measure_recovery_without_publishing_the_claim(self):
        suggestion = Finding(
            rule_id="CWE-502", severity=Severity.HIGH,
            title="Unsafe deserialization", explanation="Untrusted bytes are loaded.",
            path="app.py", line=1, evidence="pickle.loads(value)",
            fix="Use a safe format.", test="Reject a crafted payload.",
            source="security", disposition="suggestion",
        )

        class SuggestionOnlyReviewer:
            name = "suggestion-only"

            def review_case(self, _case, _parsed):
                return []

            def evaluation_execution(self):
                return {}

            def evaluation_summary(self):
                return {
                    "suggestion_count": 1,
                    "suggested_findings": [suggestion.to_dict()],
                }

        case = {
            "id": "suggestion-recovery", "repository": "repo", "pull_request": 1,
            "split": "validation", "source": {"kind": "synthetic-controlled"},
            "diff": (
                "--- a/app.py\n+++ b/app.py\n@@ -0,0 +1 @@\n"
                "+pickle.loads(value)\n"
            ),
            "expected_findings": [{
                "path": "app.py", "start_line": 1, "end_line": 1,
                "rule_id": "SEC-PICKLE-LOAD", "cwe": "CWE-502",
                "severity": "high", "should_comment": True,
            }],
        }

        report = ProductionEvaluationHarness().run(
            SuggestionOnlyReviewer(), [case], "suggestion-recovery"
        )
        metrics = report["metrics"]
        self.assertEqual(0, metrics["tp"])
        self.assertEqual(1, metrics["incremental_suggestion_tp"])
        self.assertEqual(1.0, metrics["missed_finding_recovery_rate"])
        self.assertEqual(1.0, metrics["combined_recall_after_verification"])

    def test_agentic_arms_share_exactly_fourteen_rules_and_real_role_topologies(self):
        self.assertEqual(14, len(LocalRuleReviewer.RULES) + len(ContextRuleReviewer.RULES))
        expected_calls = {
            "multi-llm-no-critic": {
                "lead": 3, "security": 1, "correctness-reliability": 1,
            },
            "full-agentic": {
                "lead": 3, "security": 1,
                "correctness-reliability": 1, "critic": 1,
            },
        }
        parsed = parse_unified_diff(DIFF)
        for arm, calls in expected_calls.items():
            reviewer = ProductArmReviewer(arm, FakeClient(), 4096, 40)
            findings = reviewer.review(DIFF, parsed)
            self.assertEqual(["SEC-PATH-TRAVERSAL"], [item.rule_id for item in findings])
            actual = {}
            for item in reviewer.evaluation_execution()["model_call_log"]:
                actual[item["role"]] = actual.get(item["role"], 0) + 1
            self.assertEqual(calls, actual)
            self.assertEqual(14, reviewer.evaluation_config()["deterministic_rules"])

    def test_weak_hash_rule_ignores_fixed_fixture_but_keeps_dynamic_input(self):
        diff = (
            "--- a/app.py\n+++ b/app.py\n@@ -0,0 +1,2 @@\n"
            "+fixture = hashlib.md5(b'fixture-id').hexdigest()\n"
            "+digest = hashlib.md5(value).hexdigest()\n"
        )
        findings = ContextRuleReviewer().review(diff, parse_unified_diff(diff))

        self.assertEqual(1, len(findings))
        self.assertEqual("digest = hashlib.md5(value).hexdigest()", findings[0].evidence)

    def test_non_production_data_can_debug_but_cannot_prove_claims(self):
        cases = []
        for index, split in enumerate(("train", "validation", "holdout"), 1):
            cases.append({
                "id": "case-%d" % index,
                "repository": "repo-%d" % index,
                "pull_request": index,
                "split": split,
                "source": {"kind": "synthetic-controlled"},
                "diff": DIFF,
                "expected_findings": [{
                    "path": "app.py", "start_line": 1, "end_line": 1,
                    "rule_id": "SEC-PATH-TRAVERSAL", "cwe": "CWE-22",
                    "severity": "high", "should_comment": True,
                }],
            })
        suite = FairAblationSuite(
            product_reviewer_factories(FakeClient(), 40),
            "fake-model", 4096, require_production_ready=False,
            bootstrap_iterations=200,
        )
        report = suite.run(cases)
        self.assertFalse(report["dataset"]["ready"])
        self.assertFalse(report["critic_gate"]["passed"])
        self.assertEqual(
            {"lead": 9, "security": 3, "correctness-reliability": 3, "critic": 3},
            report["arms"]["full-agentic"]["execution"]["model_role_calls"],
        )


if __name__ == "__main__":
    unittest.main()
