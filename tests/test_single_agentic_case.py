import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.run_single_agentic_case import (
    expected_repository_sha,
    validate_repository_checkout,
)


class SingleAgenticCaseTests(unittest.TestCase):
    def test_expected_sha_tracks_the_new_file_state(self):
        reversal = {
            "source": {
                "kind": "public-security-fix-reversal",
                "vulnerable_base_sha": "bad-state",
                "fixed_head_sha": "fixed-state",
            },
        }
        security_fix = {
            "source": {
                "kind": "public-security-fix-slice",
                "base_sha": "bad-state",
                "head_sha": "fixed-state",
            },
        }

        self.assertEqual("bad-state", expected_repository_sha(reversal))
        self.assertEqual("fixed-state", expected_repository_sha(security_fix))

    @patch("scripts.run_single_agentic_case.subprocess.run")
    def test_rejects_checkout_at_the_wrong_sha_before_model_execution(self, run):
        run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="wrong-state\n", stderr="",
        )
        case = {"source": {"kind": "public-github-pr", "head_sha": "right-state"}}

        with self.assertRaisesRegex(ValueError, "HEAD mismatch"):
            validate_repository_checkout(case, "/checkout")

    @patch("scripts.run_single_agentic_case.subprocess.run")
    def test_accepts_checkout_at_the_expected_sha(self, run):
        run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="right-state\n", stderr="",
        )
        case = {"source": {"kind": "public-github-pr", "head_sha": "right-state"}}

        validate_repository_checkout(case, "/checkout")

    @patch("scripts.run_single_agentic_case.subprocess.run")
    def test_reads_detached_head_when_git_binary_is_unavailable(self, run):
        run.side_effect = FileNotFoundError("git")
        case = {"source": {"kind": "public-github-pr", "head_sha": "a" * 40}}
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, ".git"))
            with open(
                os.path.join(root, ".git", "HEAD"), "w", encoding="utf-8",
            ) as handle:
                handle.write("a" * 40 + "\n")

            validate_repository_checkout(case, root)


if __name__ == "__main__":
    unittest.main()
