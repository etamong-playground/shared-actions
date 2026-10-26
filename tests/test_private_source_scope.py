import os
from pathlib import Path
import subprocess
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / ".github/actions/private-source-token/validate.sh"


class PrivateSourceScope(unittest.TestCase):
    def run_validation(self, changes):
        env = {
            "PATH": os.defpath,
            "SOURCE_OWNER": "example-org",
            "SOURCE_REPOSITORY": "private-library",
            "SOURCE_VAULT_URL": "https://vault.example.com",
            "SOURCE_VAULT_ROLE": "source-reader",
            "SOURCE_VAULT_AUTH_PATH": "kubernetes",
            "SOURCE_TOKEN_PATH": "/projected/runner/token",
            "SOURCE_APP_SECRET_PATH": "secret/data/ci/source-app",
        }
        env.update(changes)
        return subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True)

    def test_explicit_single_repository(self):
        result = self.run_validation({})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_rejects_missing_or_multiple_repository_scope(self):
        for value in ["", " ", "*", "owner/repo", "repo,other", "repo\nother", "repo other", ".", ".."]:
            with self.subTest(value=value):
                result = self.run_validation({"SOURCE_REPOSITORY": value})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertIn("Invalid private source token configuration:", result.stderr)

    def test_rejects_invalid_identity_and_secret_selectors(self):
        cases = {
            "SOURCE_OWNER": ["", "*", "owner/other"],
            "SOURCE_VAULT_URL": ["", "http://vault.example.com", "https://vault.example.com\nother", "https://", "https://user:password@vault.example.com", "https://vault.example.com?token=value"],
            "SOURCE_VAULT_ROLE": ["", "role; other"],
            "SOURCE_VAULT_AUTH_PATH": ["", "../kubernetes", "auth/../other"],
            "SOURCE_APP_SECRET_PATH": ["", "secret/data/a; secret/data/b", "secret/data/a\nsecret/data/b", "secret/../other"],
            "SOURCE_TOKEN_PATH": ["", "relative/token", "/token\nother"],
        }
        for variable, values in cases.items():
            for value in values:
                with self.subTest(variable=variable, value=value):
                    result = self.run_validation({variable: value})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
