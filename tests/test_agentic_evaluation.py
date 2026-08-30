import json
import unittest

from evoagent.diff_parser import parse_unified_diff
from evoagent.agentic_core import BoundedRole, ModeRouterReviewer
from evoagent.evaluation_benchmark import ContextRuleReviewer
from evoagent.evaluation_harness import one_to_one_match
from evoagent.evaluation_v2 import (
    FairAblationSuite,
    ProductArmReviewer,
    ProductionEvaluationHarness,
    product_reviewer_factories,
)
from evoagent.models import Finding, Severity
from evoagent.reviewer import LocalRuleReviewer
from evoagent.repository_tools import RepositoryToolSuite
from evoagent.runtime import AgentTool, ToolRegistry
from evoagent.telemetry import ExecutionLedger


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
    def test_repository_preflight_prioritizes_semantic_source_over_config(self):
        class RecordingTools:
            def __init__(self):
                self.calls = []

            def names(self):
                return [
                    "read_file", "search_repository", "semantic_probe", "ast_analyze",
                ]

            def invoke(self, name, arguments):
                self.calls.append((name, dict(arguments)))
                return {
                    "evidence_id": "%s:%d" % (name, len(self.calls)),
                    "tool": name, "output": dict(arguments),
                }

        parsed = parse_unified_diff(
            "--- a/.github/workflow.yml\n+++ b/.github/workflow.yml\n"
            "@@ -0,0 +1 @@\n+name: build\n"
            "--- a/src/app.py\n+++ b/src/app.py\n"
            "@@ -99,0 +100 @@\n+message = str(err).replace(inv_location, safe_url)\n"
        )
        tools = RecordingTools()

        observations = ModeRouterReviewer._repository_preflight(
            {"files": parsed.files}, parsed, tools,
        )

        self.assertTrue(observations)
        self.assertEqual("read_file", tools.calls[0][0])
        self.assertEqual("src/app.py", tools.calls[0][1]["path"])
        queries = [
            arguments["query"] for name, arguments in tools.calls
            if name == "search_repository"
        ]
        self.assertIn("inv_location", queries)
        self.assertIn(
            ("semantic_probe", {"kind": "url-normalization-redaction"}), tools.calls
        )

    def test_url_normalization_probe_demonstrates_exact_replacement_gap(self):
        evidence = RepositoryToolSuite.semantic_probe("url-normalization-redaction")
        output = evidence["output"]

        self.assertFalse(output["exact_original_still_matches"])
        self.assertTrue(output["credentials_remaining"])
        self.assertFalse(output["network_used"])
        self.assertFalse(output["arbitrary_code_executed"])

    def test_expected_finding_can_declare_review_taxonomy_aliases(self):
        finding = Finding(
            rule_id="CWE-200", severity=Severity.HIGH,
            title="Leak", explanation="Credentials remain visible.",
            path="app.py", line=5, evidence="replace(raw, safe)",
            fix="Redact normalized values.", test="Use an encoded password.",
        )
        expected = [{
            "cwe": "CWE-532", "acceptable_cwes": ["CWE-200", "CWE-522"],
            "path": "app.py", "start_line": 5, "end_line": 5,
            "severity": "high",
        }]

        self.assertEqual(1, len(one_to_one_match(expected, [finding])))

    def test_same_semantic_probe_and_location_are_deduplicated_across_roles(self):
        values = [
            Finding(
                rule_id=rule_id, severity=Severity.HIGH,
                title="Credential leak", explanation="Normalized URL leaks a password.",
                path="app.py", line=5, evidence="replace(raw, safe)",
                evidence_refs=[{
                    "evidence_id": "semantic_probe:test", "tool": "semantic_probe",
                    "output": {"kind": "url-normalization-redaction",
                               "arbitrary_code_executed": False},
                }],
                fix="Redact normalized values.", test="Use an encoded password.",
                source=source,
            )
            for rule_id, source in (
                ("CWE-200", "security"),
                ("CWE-522", "correctness-reliability"),
            )
        ]

        self.assertEqual(1, len(ModeRouterReviewer._merge(values)))

    def test_delegation_coverage_gate_assigns_every_production_source(self):
        delegations = ModeRouterReviewer._normalize_delegations(
            [{
                "assignment_id": "correctness-1",
                "worker": "correctness-reliability",
                "files": ["uv.lock"],
            }],
            {"correctness-reliability"},
            ["uv.lock", ".github/workflow.yml", "sqlmodel/main.py", "tests/test_main.py"],
        )

        self.assertIn("sqlmodel/main.py", delegations[0]["files"])
        self.assertNotIn("tests/test_main.py", delegations[0]["files"])

    def test_repository_role_cannot_finish_before_a_factual_tool_call(self):
        class SequencedClient:
            def __init__(self):
                self.actions = [
                    {"action": "final", "findings": []},
                    {"action": "tool", "tool": "read_file", "arguments": {}},
                    {"action": "final", "findings": []},
                ]

            def complete_json(self, *_args, **_kwargs):
                return self.actions.pop(0)

        registry = ToolRegistry([AgentTool(
            "read_file", "Read evidence.",
            {"type": "object", "properties": {}, "additionalProperties": False},
            lambda: {"evidence_id": "read_file:test", "output": "value"},
        )])
        result = BoundedRole(
            "correctness-reliability", "Review.", SequencedClient(),
            token_budget=4000, time_budget=30, minimum_tool_calls=1,
        ).run("{}", registry, ExecutionLedger("agentic"))

        self.assertEqual(3, result["_steps"])
        self.assertEqual("protocol-requirement", result["_observations"][0]["tool"])
        self.assertTrue(result["_observations"][1]["ok"])

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
        self.assertEqual(1.0, metrics["suggestion_utility_rate"])

    def test_targeted_review_labels_do_not_call_unmatched_findings_invalid(self):
        finding = Finding(
            rule_id="CWE-754", severity=Severity.MEDIUM,
            title="Unexpected issue", explanation="A separate review candidate.",
            path="app.py", line=2, evidence="other()",
            fix="Fix it.", test="Test it.",
        )

        class FormalReviewer:
            name = "formal"

            def review_case(self, _case, _parsed):
                return [finding]

        case = {
            "id": "targeted", "repository": "repo", "pull_request": 1,
            "split": "validation",
            "source": {
                "kind": "public-github-pr",
                "label_completeness": "targeted-review-comments",
            },
            "diff": (
                "--- a/app.py\n+++ b/app.py\n@@ -0,0 +1,2 @@\n"
                "+expected()\n+other()\n"
            ),
            "expected_findings": [{
                "path": "app.py", "start_line": 1, "end_line": 1,
                "cwe": "CWE-476", "severity": "high", "should_comment": True,
            }],
        }

        metrics = ProductionEvaluationHarness().run(
            FormalReviewer(), [case], "targeted"
        )["metrics"]
        self.assertEqual(0, metrics["formal_invalid_findings"])
        self.assertEqual(1, metrics["formal_unjudged_findings"])
        self.assertEqual(0.0, metrics["invalid_comments_per_pr"])
        self.assertEqual(
            "not-estimable-until-unexpected-findings-are-adjudicated",
            metrics["precision_interpretation"],
        )

    def test_suggestion_utility_uses_only_adjudicated_optional_and_invalid_labels(self):
        suggestions = [
            Finding(
                rule_id=rule_id, severity=Severity.MEDIUM,
                title=verdict, explanation="Adjudication fixture.",
                path="app.py", line=line, evidence="value_%d" % line,
                fix="Apply a focused fix.", test="Add a focused test.",
                source="security", disposition="suggestion",
            )
            for line, rule_id, verdict in (
                (1, "CWE-561", "optional"),
                (2, "CWE-20", "invalid"),
                (3, "CWE-248", "duplicate"),
                (4, "CWE-999", "unjudged"),
            )
        ]

        class SuggestionReviewer:
            name = "adjudicated-suggestions"

            def review_case(self, _case, _parsed):
                return []

            def evaluation_execution(self):
                return {}

            def evaluation_summary(self):
                return {
                    "suggestion_count": len(suggestions),
                    "suggested_findings": [item.to_dict() for item in suggestions],
                }

        case = {
            "id": "adjudicated-suggestions", "repository": "repo", "pull_request": 1,
            "split": "validation", "source": {"kind": "synthetic-controlled"},
            "diff": (
                "--- a/app.py\n+++ b/app.py\n@@ -0,0 +1,4 @@\n"
                "+value_1\n+value_2\n+value_3\n+value_4\n"
            ),
            "expected_findings": [],
            "suggestion_judgments": [
                {"path": "app.py", "line": 1, "rule_id": "CWE-561", "verdict": "optional"},
                {"path": "app.py", "line": 2, "rule_id": "CWE-20", "verdict": "invalid"},
                {"path": "app.py", "line": 3, "rule_id": "CWE-248", "verdict": "duplicate"},
            ],
        }

        metrics = ProductionEvaluationHarness().run(
            SuggestionReviewer(), [case], "adjudicated-suggestions"
        )["metrics"]
        self.assertEqual(1, metrics["suggestion_optional"])
        self.assertEqual(1, metrics["suggestion_invalid"])
        self.assertEqual(1, metrics["suggestion_duplicate"])
        self.assertEqual(1, metrics["suggestion_unjudged"])
        self.assertEqual(0.3333, metrics["suggestion_utility_rate"])
        self.assertEqual(0.75, metrics["suggestion_adjudication_coverage"])
        self.assertEqual(0.6667, metrics["suggestion_nuisance_rate"])

    def test_cached_result_rescore_updates_formal_truth_after_label_revision(self):
        formal = Finding(
            rule_id="CWE-95", severity=Severity.CRITICAL,
            title="eval", explanation="Dynamic execution.", path="app.py", line=1,
            evidence="eval(value)", fix="Remove eval.", test="Add an injection test.",
        )
        suggestion = Finding(
            rule_id="CWE-476", severity=Severity.HIGH,
            title="none", explanation="None dereference.", path="app.py", line=2,
            evidence="value.name", fix="Guard value.", test="Add a None test.",
            disposition="suggestion",
        )
        case = {
            "expected_findings": [
                {
                    "path": "app.py", "start_line": 1, "end_line": 1,
                    "cwe": "CWE-95", "severity": "critical", "should_comment": True,
                },
                {
                    "path": "app.py", "start_line": 2, "end_line": 2,
                    "cwe": "CWE-476", "severity": "high", "should_comment": True,
                },
            ],
        }
        cached = {
            "predicted_findings": [formal.to_dict()],
            "suggested_findings": [suggestion.to_dict()],
            "matches": [],
        }

        rescored = ProductionEvaluationHarness().rescore_cached_result(cached, case)

        self.assertEqual((1, 0, 1), (rescored["tp"], rescored["fp"], rescored["fn"]))
        self.assertEqual(1, rescored["incremental_suggestion_tp"])
        self.assertEqual(2, rescored["combined_tp_after_verification"])
        self.assertEqual(2, len(rescored["expected_findings"]))

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
