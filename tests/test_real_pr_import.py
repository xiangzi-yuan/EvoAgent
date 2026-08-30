import os
import tempfile
import unittest
from unittest import mock

from scripts.import_github_pr_dataset import validate_checkout
from scripts.import_github_review_dataset import build_case


class RealPrImportTests(unittest.TestCase):
    @mock.patch("scripts.import_github_pr_dataset.subprocess.run")
    def test_checkout_must_match_pr_head_exactly(self, run):
        run.return_value = mock.Mock(returncode=0, stdout="abc123\n", stderr="")
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(
                os.path.abspath(root), validate_checkout(root, "ABC123")
            )
            with self.assertRaisesRegex(ValueError, "does not match PR head"):
                validate_checkout(root, "def456")

    def test_checkout_directory_must_exist(self):
        with tempfile.TemporaryDirectory() as root:
            missing = os.path.join(root, "missing")
            with self.assertRaisesRegex(ValueError, "not an existing directory"):
                validate_checkout(missing, "abc123")

    @mock.patch("scripts.import_github_review_dataset.fetch_review_comment")
    @mock.patch("scripts.import_github_review_dataset.git_output")
    def test_review_dataset_is_bound_to_trusted_comment_snapshot(self, git, fetch):
        git.side_effect = lambda _root, args: (
            "head123\n" if args[:2] == ["rev-parse", "HEAD"] else
            "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
            "@@ -1 +1 @@\n-old\n+new\n" if args[0] == "diff" else ""
        )
        fetch.return_value = {
            "author_association": "MEMBER",
            "body": "This changes the behavior.",
            "html_url": "https://github.com/org/repo/pull/7#discussion_r11",
            "original_commit_id": "head123",
            "original_line": 1,
            "path": "app.py",
            "pull_request_url": "https://api.github.com/repos/org/repo/pulls/7",
        }
        item = {
            "id": "real-1", "repository": "org/repo", "pull_request": 7,
            "split": "validation", "base_sha": "base123",
            "snapshot_sha": "head123", "checkout": "repo-head123",
            "expected_findings": [{
                "review_comment_id": 11, "rule_id": "LOGIC-1",
                "cwe": "CWE-670", "severity": "medium", "path": "app.py", "start_line": 1,
                "end_line": 1, "should_comment": True,
            }],
        }
        with tempfile.TemporaryDirectory() as root:
            os.mkdir(os.path.join(root, "repo-head123"))
            case = build_case(item, root)
        self.assertEqual("public-github-review-comment", case["source"]["label_kind"])
        self.assertEqual("MEMBER", case["source"]["review_evidence"][0]["author_association"])
        self.assertEqual("head123", case["source"]["head_sha"])

    @mock.patch("scripts.import_github_review_dataset.fetch_review_comment")
    @mock.patch("scripts.import_github_review_dataset.git_output")
    def test_review_dataset_rejects_untrusted_commenter(self, git, fetch):
        git.return_value = "head123\n"
        fetch.return_value = {
            "author_association": "NONE", "original_commit_id": "head123",
            "original_line": 1, "path": "app.py",
            "pull_request_url": "https://api.github.com/repos/org/repo/pulls/7",
        }
        item = {
            "id": "real-1", "repository": "org/repo", "pull_request": 7,
            "split": "validation", "base_sha": "base123",
            "snapshot_sha": "head123", "checkout": "repo-head123",
            "expected_findings": [{
                "review_comment_id": 11, "rule_id": "LOGIC-1",
                "cwe": "CWE-670", "severity": "medium", "path": "app.py", "start_line": 1,
                "end_line": 1,
            }],
        }
        with tempfile.TemporaryDirectory() as root:
            os.mkdir(os.path.join(root, "repo-head123"))
            with self.assertRaisesRegex(ValueError, "untrusted author association"):
                build_case(item, root)


if __name__ == "__main__":
    unittest.main()
