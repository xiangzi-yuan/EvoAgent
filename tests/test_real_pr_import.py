import os
import tempfile
import unittest
from unittest import mock

from scripts.import_github_pr_dataset import validate_checkout


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


if __name__ == "__main__":
    unittest.main()
