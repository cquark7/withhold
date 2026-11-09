"""Public onboarding commands use isolated state and no live providers."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

NATIVE = os.environ.get("WITHHOLD_TEST_NATIVE")


@unittest.skipUnless(NATIVE, "native executable required")
class ReleasePolishTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="withhold-onboarding-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.scratch = self.root / "temporary"
        self.home.mkdir()
        self.scratch.mkdir()
        self.env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("WITHHOLD_", "BETTERLEAKS_", "GITLEAKS_"))
        }
        self.env.update(
            HOME=str(self.home),
            USERPROFILE=str(self.home),
            APPDATA=str(self.home / "appdata"),
            XDG_CONFIG_HOME=str(self.home / "config"),
            TMPDIR=str(self.scratch),
            TMP=str(self.scratch),
            TEMP=str(self.scratch),
            WITHHOLD_DIR=str(self.home / "state"),
            WITHHOLD_CONFIG=str(self.home / "missing.toml"),
            WITHHOLD_INTEGRATION="invalid",
            WITHHOLD_PII="invalid",
            WITHHOLD_EDITOR_SETTINGS_DIR="../invalid",
            WITHHOLD_MAX_BYTES="invalid",
            WITHHOLD_PLACEHOLDER_KEY="private-user-key-not-for-demo",
            WITHHOLD_INTERNAL_DEBUG_FINDINGS="1",
            HTTP_PROXY="http://127.0.0.1:1",
            HTTPS_PROXY="http://127.0.0.1:1",
        )

    def command(self, *args, env=None, expected=0):
        result = subprocess.run(
            [NATIVE, *args],
            env=self.env if env is None else env,
            capture_output=True,
            text=True,
            timeout=45,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def test_demo_is_local_isolated_and_cleans_up_with_broken_current_config(self):
        for args in (("demo",), ("demo", "--json")):
            result = self.command(*args)
            detail = result.stdout
            if "--json" in args:
                report = json.loads(result.stdout)
                detail = report["checks"][0]["detail"]
                self.assertEqual(report["schema"], 1)
                self.assertTrue(report["ok"])
                self.assertEqual(report["scope"], "synthetic-loopback-only")
                self.assertEqual(
                    [row["name"] for row in report["checks"]], ["redact", "block"]
                )
                self.assertTrue(all(row["ok"] for row in report["checks"]))
            else:
                self.assertIn("[PASS] redact", result.stdout)
                self.assertIn("[PASS] block", result.stdout)
                self.assertIn("does not verify application routing", result.stdout)
            self.assertIn("<WITHHELD_", detail)
            self.assertNotIn("AKIA4X7Q2W8K9MNDZZZZ", result.stdout + result.stderr)
            self.assertNotIn("private-user-key", result.stdout + result.stderr)
            self.assertEqual(list(self.home.iterdir()), [])
            self.assertEqual(list(self.scratch.iterdir()), [])

    def test_toml_starter_does_not_read_config_write_state_or_export_overrides(self):
        result = self.command("config", "--example", "--integration", "vscode-copilot")
        self.assertIn("#", result.stdout)
        self.assertIn("[application]", result.stdout)
        self.assertNotIn(str(self.home), result.stdout)
        self.assertNotIn("private-user-key", result.stdout)
        self.assertEqual(list(self.home.iterdir()), [])
        path = self.root / "example.toml"
        path.write_text(result.stdout)
        env = {
            key: value
            for key, value in self.env.items()
            if not key.startswith("WITHHOLD_")
        }
        effective = json.loads(
            self.command("config", "--config", str(path), env=env).stdout
        )
        self.assertEqual(effective["protection"]["chat"], "redact")
        self.assertEqual(effective["protection"]["inline"], "block")
        self.assertFalse(effective["protection"]["observe"])
        self.assertEqual(effective["application"]["binary"], "code")
        self.assertEqual(list(self.home.iterdir()), [])

    def test_onboarding_help_completion_and_option_errors_are_read_only(self):
        for command in ("demo", "config"):
            self.command(command, "--help")
        self.assertIn("--example", self.command("_complete", "config", "--ex").stdout)
        self.assertIn("demo", self.command("_complete", "de").stdout)
        self.command("demo", "--config", "ignored.toml", expected=2)
        self.command("config", "--example", "--max-bytes", "1m", expected=2)
        self.command("config", "--example", "--integration", "unknown", expected=2)
        self.assertEqual(list(self.home.iterdir()), [])
        self.assertEqual(list(self.scratch.iterdir()), [])
