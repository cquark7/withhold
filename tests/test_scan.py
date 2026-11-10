"""Offline inspection uses synthetic inputs and an isolated home."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

NATIVE = os.environ.get("WITHHOLD_TEST_NATIVE")
TOKEN = "AKIA4X7Q2W3K7MNDZBXP"
EMAIL = "scan-fixture@example.com"


@unittest.skipUnless(NATIVE, "native executable required")
class ScanTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="withhold-scan-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("WITHHOLD_", "BETTERLEAKS_", "GITLEAKS_"))
        }
        self.env.update(
            HOME=str(self.home),
            USERPROFILE=str(self.home),
            WITHHOLD_DIR=str(self.home / "state"),
            WITHHOLD_INTEGRATION="invalid-but-irrelevant",
            WITHHOLD_INTERNAL_DEBUG_FINDINGS="1",
            WITHHOLD_INTERNAL_SCAN_SECRETS="0",
            HTTP_PROXY="http://127.0.0.1:1",
            HTTPS_PROXY="http://127.0.0.1:1",
        )

    def scan(self, *args, expected=0, text=""):
        result = subprocess.run(
            [NATIVE, "scan", *args],
            input=text,
            text=True,
            capture_output=True,
            cwd=self.root,
            env=self.env,
            timeout=15,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)
        self.assertNotIn(EMAIL, result.stdout + result.stderr)
        self.assertEqual(list(self.home.iterdir()), [])
        return result

    def test_text_stdin_and_engine_selection_do_not_write_state_or_values(self):
        report = json.loads(
            self.scan(
                "--text", TOKEN + " " + EMAIL, "--pii", "email", "--json", expected=1
            ).stdout
        )
        self.assertEqual(report["schema"], 1)
        self.assertTrue(report["summary"]["complete"])
        self.assertEqual(
            [row["rule_id"] for row in report["findings"]],
            ["aws-access-token", "pii-email"],
        )
        self.assertTrue(all(row["path"] is None for row in report["findings"]))
        report = json.loads(
            self.scan(
                "--secrets=false",
                "--pii=email",
                "--json",
                text=TOKEN + " " + EMAIL,
                expected=1,
            ).stdout
        )
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["source"], "stdin")
        self.assertFalse(report["detectors"]["secrets"])
        self.scan("--text", "ordinary text")
        self.scan("--text", "", "--secrets=false", expected=2)

    def test_recursive_files_locations_exclusions_and_incomplete_exit(self):
        project = self.root / "project"
        project.mkdir()
        (project / ".env").write_text("heading\n  " + TOKEN + "\n", encoding="utf-8")
        (project / ".gitignore").write_text(".env\n", encoding="utf-8")
        (project / "skip.txt").write_text(TOKEN, encoding="utf-8")
        (project / "binary").write_bytes(b"\x00\x01")
        result = self.scan(
            "project", "--exclude", "project/skip.txt", "--json", expected=1
        )
        report = json.loads(result.stdout)
        self.assertEqual(len(report["findings"]), 1)
        row = report["findings"][0]
        self.assertEqual(Path(row["path"]), Path("project/.env"))
        self.assertEqual((row["start_line"], row["start_column"]), (2, 3))
        self.assertEqual(report["summary"]["skipped"], {"binary": 1, "excluded": 1})
        report = json.loads(
            self.scan("project/.env", "missing.txt", "--json", expected=2).stdout
        )
        self.assertFalse(report["summary"]["complete"])
        self.assertEqual(report["summary"]["findings"], 1)
        self.assertEqual(report["errors"][0]["code"], "read-error")
        self.scan("project/.env", "--max-bytes", "4", expected=2)
        self.assertIn("No eligible text inputs", self.scan("home").stdout)

    def test_help_completion_and_configured_pii_remain_read_only(self):
        self.env["WITHHOLD_CONFIG"] = str(self.root / "missing.toml")
        self.scan("--help")
        self.scan("--text", "text", "--debug", expected=2)
        self.env.pop("WITHHOLD_CONFIG")
        config = self.root / "config.toml"
        config.write_text('schema = 1\n[protection]\npii = ["email"]\n')
        self.scan("--config", str(config), "--text", EMAIL, expected=1)
        self.scan("--config", str(config), "--text", EMAIL, "--pii", "off")
        result = subprocess.run(
            [NATIVE, "_complete", "scan", "--secrets=f"],
            env=self.env,
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.stdout.strip(), "--secrets=false")
