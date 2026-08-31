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

    def test_debug_print_rule_ignores_github_form_examples(self):
        diff = (
            "--- /dev/null\n+++ b/.github/DISCUSSION_TEMPLATE/questions.yml\n"
            "@@ -0,0 +1,2 @@\n+placeholder: |\n+  print(example)\n"
            "--- /dev/null\n+++ b/app.py\n@@ -0,0 +1 @@\n+print(secret)\n"
        )

        findings = LocalRuleReviewer().review(diff, parse_unified_diff(diff))

        self.assertEqual(1, len(findings))
        self.assertEqual("app.py", findings[0].path)
        self.assertEqual("REL-DEBUG-PRINT", findings[0].rule_id)

    def test_detects_jinja_sandbox_downgrade_but_not_security_fix(self):
        regression = (
            "--- a/environment.py\n+++ b/environment.py\n@@ -1,2 +1,2 @@\n"
            "-from jinja2.sandbox import SandboxedEnvironment\n"
            "+from jinja2 import Environment\n"
            "-env = SandboxedEnvironment()\n+env = Environment()\n"
            "-return SandboxedEnvironment()\n+return Environment()\n"
        )
        security_fix = (
            "--- a/environment.py\n+++ b/environment.py\n@@ -1,2 +1,2 @@\n"
            "-from jinja2 import Environment\n"
            "+from jinja2.sandbox import SandboxedEnvironment\n"
            "-env = Environment()\n+env = SandboxedEnvironment()\n"
        )

        findings = LocalRuleReviewer().review(
            regression, parse_unified_diff(regression),
        )
        fixed_findings = LocalRuleReviewer().review(
            security_fix, parse_unified_diff(security_fix),
        )

        self.assertEqual(["SEC-JINJA-UNSANDBOXED"], [item.rule_id for item in findings])
        self.assertEqual(2, findings[0].line)
        self.assertEqual([], fixed_findings)


if __name__ == "__main__":
    unittest.main()
