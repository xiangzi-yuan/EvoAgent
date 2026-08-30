import unittest

from evoagent.agentic_core import ModeRouterReviewer
from evoagent.diff_parser import parse_unified_diff
from evoagent.finding_policy import normalize_rule_id
from evoagent.gates import FindingGate
from evoagent.models import Finding, Severity


DIFF = "--- a/app.py\n+++ b/app.py\n@@ -0,0 +1 @@\n+dangerous(value)\n"


def finding(rule_id="MODEL-CLAIM", source="security", severity=Severity.MEDIUM):
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title="Potential issue",
        explanation="The added call may violate an unstated invariant.",
        path="app.py",
        line=1,
        evidence="dangerous(value)",
        fix="Validate the invariant before invoking the call.",
        test="Add a regression test for the invalid value.",
        confidence=0.9,
        source=source,
    )


class FindingPolicyTests(unittest.TestCase):
    def test_known_aliases_are_canonicalized_and_generic_ids_are_bucketed(self):
        self.assertEqual(
            "SEC-PICKLE-LOAD",
            normalize_rule_id("injection-pickle-untrusted"),
        )
        self.assertEqual("LLM-OTHER", normalize_rule_id("correctness-1"))
        self.assertEqual("LLM-OTHER", normalize_rule_id("SEC-001"))
        self.assertEqual("QUALITY-UNFINISHED", normalize_rule_id("quality_unfinished"))

    def test_deterministic_baseline_survives_lead_and_critic_rejection(self):
        baseline = finding("SEC-EVAL", "local-rule-scanner", Severity.CRITICAL)
        candidate = finding()

        published, suggestions, decisions = ModeRouterReviewer._partition_publication(
            [baseline],
            [baseline, candidate],
            [],
            [
                {"finding_index": 0, "publication_ready": False},
                {"finding_index": 1, "publication_ready": False},
            ],
            repository_available=False,
        )

        self.assertEqual(["SEC-EVAL"], [item.rule_id for item in published])
        self.assertEqual([], suggestions)
        self.assertEqual("confirmed", decisions[0]["disposition"])
        self.assertEqual("rejected", decisions[1]["disposition"])

    def test_lead_selected_model_claim_without_repository_proof_is_a_suggestion(self):
        candidate = finding()

        published, suggestions, decisions = ModeRouterReviewer._partition_publication(
            [],
            [candidate],
            [candidate],
            [{"finding_index": 0, "publication_ready": True}],
            repository_available=False,
        )

        self.assertEqual([], published)
        self.assertEqual(["MODEL-CLAIM"], [item.rule_id for item in suggestions])
        self.assertEqual("suggestion", decisions[0]["disposition"])
        self.assertIn("repository context is unavailable", decisions[0]["reasons"])

    def test_repository_backed_lead_and_critic_approved_claim_is_publishable(self):
        candidate = finding()
        candidate.evidence_refs = [{
            "evidence_id": "read_file:1234",
            "tool": "read_file",
            "output": {"path": "app.py", "content": "dangerous(value)"},
        }]

        published, suggestions, decisions = ModeRouterReviewer._partition_publication(
            [],
            [candidate],
            [candidate],
            [{"finding_index": 0, "publication_ready": True}],
            repository_available=True,
        )

        self.assertEqual(["MODEL-CLAIM"], [item.rule_id for item in published])
        self.assertEqual([], suggestions)
        self.assertEqual("confirmed", decisions[0]["disposition"])

    def test_empty_repository_search_is_not_publication_evidence(self):
        candidate = finding()
        candidate.evidence_refs = [{
            "evidence_id": "search_repository:empty",
            "tool": "search_repository",
            "output_preview": "[]",
        }]

        published, suggestions, decisions = ModeRouterReviewer._partition_publication(
            [], [candidate], [candidate],
            [{"finding_index": 0, "publication_ready": True}],
            repository_available=True,
        )

        self.assertEqual([], published)
        self.assertEqual([candidate], suggestions)
        self.assertIn("no repository-backed tool evidence", decisions[0]["reasons"])

    def test_raw_high_risk_call_chain_does_not_replace_tool_evidence(self):
        candidate = finding(severity=Severity.HIGH)
        candidate.call_chain = [{"from": "input", "to": "dangerous"}]

        result = FindingGate().apply(
            [candidate], parse_unified_diff(DIFF)
        )

        self.assertEqual([], result.accepted)
        self.assertIn(
            "evidence gate: high-risk finding requires verified scanner or tool evidence",
            result.rejected[0]["reasons"],
        )


if __name__ == "__main__":
    unittest.main()
