from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from secretsweep.cli import main
from secretsweep.gitutils import build_pre_commit_hook_script, install_pre_commit_hook


class SecretsweepCliTests(unittest.TestCase):
    @staticmethod
    def fake_database_url() -> str:
        return "".join(
            [
                "postgres",
                "://",
                "admin",
                ":",
                "password123",
                "@",
                "prod-db.example.com",
                ":5432/app",
            ]
        )

    @staticmethod
    def fake_github_token() -> str:
        return "gh" + "p_" + "1234567890abcdefghijABCDEFGHIJ"

    @staticmethod
    def fake_entropy_secret() -> str:
        return "9fK2mQ7xR4vN8pL1tY6zH3wB0cD5sJ"

    def run_cli(self, *args: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(list(args))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_scan_json_reports_high_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            (root / ".env").write_text(
                f'DATABASE_URL="{self.fake_database_url()}"\n',
                encoding="utf-8",
            )

            code, stdout, _ = self.run_cli("scan", str(root), "--json", "--no-git")

            self.assertEqual(code, 1)
            payload = json.loads(stdout)
            self.assertEqual(payload["scanned_files"], 1)
            self.assertEqual(payload["summary"]["high"], 1)
            self.assertEqual(payload["findings"][0]["rule"], "database-url")

    def test_allowlist_suppresses_matching_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            (root / ".env").write_text(
                f'DATABASE_URL="{self.fake_database_url()}"\n',
                encoding="utf-8",
            )
            (root / "allowlist.toml").write_text(
                '[allowlist]\npatterns = ["prod-db\\\\.example\\\\.com"]\n',
                encoding="utf-8",
            )

            code, stdout, _ = self.run_cli(
                "scan",
                str(root),
                "--json",
                "--no-git",
                "--allowlist",
                str(root / "allowlist.toml"),
            )

            self.assertEqual(code, 0)
            payload = json.loads(stdout)
            self.assertEqual(payload["findings"], [])

    def test_baseline_filters_existing_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            target = root / ".env"
            target.write_text(
                f'DATABASE_URL="{self.fake_database_url()}"\n',
                encoding="utf-8",
            )
            baseline = root / ".secretsweep-baseline.json"
            baseline.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "file": ".env",
                                "line": 1,
                                "rule": "database-url",
                                "match": self.fake_database_url(),
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            code, stdout, _ = self.run_cli(
                "scan",
                str(root),
                "--json",
                "--no-git",
                "--baseline",
                str(baseline),
            )

            self.assertEqual(code, 0)
            payload = json.loads(stdout)
            self.assertEqual(payload["summary"]["high"], 0)
            self.assertEqual(payload["findings"], [])

    def test_write_baseline_generates_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            target = root / ".env"
            target.write_text(
                f'DATABASE_URL="{self.fake_database_url()}"\n',
                encoding="utf-8",
            )
            baseline = root / ".secretsweep-baseline.json"

            code, stdout, _ = self.run_cli(
                "scan",
                str(root),
                "--json",
                "--no-git",
                "--write-baseline",
                str(baseline),
            )

            self.assertEqual(code, 1)
            payload = json.loads(stdout)
            written = json.loads(baseline.read_text(encoding="utf-8"))
            self.assertEqual(written["summary"], payload["summary"])
            self.assertEqual(written["findings"][0]["rule"], "database-url")

    def test_redact_command_replaces_secret_values(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            target = root / ".env"
            target.write_text(
                f'DATABASE_URL="{self.fake_database_url()}"\n',
                encoding="utf-8",
            )

            code, stdout, _ = self.run_cli("redact", str(target))

            self.assertEqual(code, 0)
            self.assertIn("Redacted 1 finding(s)", stdout)
            contents = target.read_text(encoding="utf-8")
            self.assertNotIn(self.fake_database_url(), contents)
            self.assertIn("[REDACTED]", contents)

    def test_scan_redact_modifies_file_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            target = root / ".env"
            target.write_text(f'API_KEY="{self.fake_github_token()}"\n', encoding="utf-8")

            code, _, _ = self.run_cli("scan", str(root), "--no-git", "--redact")

            self.assertEqual(code, 1)
            contents = target.read_text(encoding="utf-8")
            self.assertIn("[REDACTED]", contents)

    def test_init_writes_starter_config(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            previous = Path.cwd()
            try:
                import os

                os.chdir(root)
                code, stdout, _ = self.run_cli("init")
            finally:
                os.chdir(previous)

            self.assertEqual(code, 0)
            self.assertIn("Wrote starter config", stdout)
            self.assertTrue((root / "secretsweep.toml").exists())

    def test_staged_scan_only_reports_staged_file(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            subprocess.run(["git", "init", "-b", "main"], cwd=root, check=True, capture_output=True, text=True)
            subprocess.run(["git", "config", "user.name", "Test User"], cwd=root, check=True, capture_output=True, text=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True, capture_output=True, text=True)

            staged = root / ".env"
            staged.write_text(f'DATABASE_URL="{self.fake_database_url()}"\n', encoding="utf-8")
            unstaged = root / "other.env"
            unstaged.write_text(f'API_KEY="{self.fake_github_token()}"\n', encoding="utf-8")

            subprocess.run(["git", "add", ".env"], cwd=root, check=True, capture_output=True, text=True)

            code, stdout, _ = self.run_cli("scan", str(root), "--staged", "--json")

            self.assertEqual(code, 1)
            payload = json.loads(stdout)
            self.assertEqual(payload["scanned_files"], 1)
            self.assertEqual({finding["file"] for finding in payload["findings"]}, {".env"})

    def test_entropy_detection_produces_medium_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            target = root / ".env"
            target.write_text(f'SECRET_KEY="{self.fake_entropy_secret()}"\n', encoding="utf-8")

            code, stdout, _ = self.run_cli("scan", str(root), "--json", "--no-git", "--entropy", "4.0")

            self.assertEqual(code, 1)
            payload = json.loads(stdout)
            rules = {finding["rule"] for finding in payload["findings"]}
            self.assertIn("high-entropy", rules)

    def test_install_hook_uses_module_fallback_when_binary_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            subprocess.run(["git", "init", "-b", "main"], cwd=root, check=True, capture_output=True, text=True)
            hook_path = install_pre_commit_hook(root)
            contents = hook_path.read_text(encoding="utf-8")

            self.assertIn("PYTHONPATH=src python3 -m secretsweep", contents)
            self.assertIn("command -v secretsweep", contents)
            self.assertIn('REPO_ROOT="$(git rev-parse --show-toplevel)"', contents)

    def test_hook_script_includes_windows_python_fallbacks(self) -> None:
        contents = build_pre_commit_hook_script()

        self.assertIn('command -v py', contents)
        self.assertIn('PYTHONPATH=src py -m secretsweep', contents)
        self.assertIn('command -v python', contents)

    def test_non_sensitive_uppercase_source_constant_is_not_entropy_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            target = root / "tooling.py"
            target.write_text(
                'SCAN_CMD = "PYTHONPATH=src python3 -m secretsweep scan . --staged --json --fail-on high"\n',
                encoding="utf-8",
            )

            code, stdout, _ = self.run_cli("scan", str(root), "--json", "--no-git")

            self.assertEqual(code, 0)
            payload = json.loads(stdout)
            self.assertEqual(payload["findings"], [])


if __name__ == "__main__":
    unittest.main()
