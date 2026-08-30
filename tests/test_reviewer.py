import unittest

from evoagent.diff_parser import parse_unified_diff
from evoagent.reviewer import LocalRuleReviewer


class LocalReviewerTests(unittest.TestCase):
    def test_detects_security_findings_only_on_added_lines(self):
        diff = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
-eval(old_input)
+password = "super-secret"
+eval(user_input)
 safe = True
"""
        findings = LocalRuleReviewer().review(diff, parse_unified_diff(diff))
        self.assertEqual({"SEC-EVAL", "SEC-HARDCODED-SECRET"}, {item.rule_id for item in findings})
        self.assertTrue(all(item.line in {1, 2} for item in findings))

    def test_ignores_explicit_placeholder_secret_but_keeps_real_literal(self):
        diff = (
            "--- a/app.py\n+++ b/app.py\n@@ -0,0 +1,2 @@\n"
            "+token = 'test-placeholder'\n"
            "+api_key = 'production-secret-value'\n"
        )
        findings = LocalRuleReviewer().review(diff, parse_unified_diff(diff))

        self.assertEqual(1, len(findings))
        self.assertEqual("api_key = 'production-secret-value'", findings[0].evidence)


if __name__ == "__main__":
    unittest.main()
