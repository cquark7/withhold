"""Public onboarding commands use isolated state and no live providers."""

import json
import os
import subprocess
import tempfile
import tomllib
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
            self.command("config", "--json", "--config", str(path), env=env).stdout
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
        self.command("config", "--init", "--integration", "unknown", expected=2)
        self.assertEqual(list(self.home.iterdir()), [])
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_install_and_config_init_create_only_new_inheriting_files(self):
        env = {
            key: value
            for key, value in self.env.items()
            if not key.startswith("WITHHOLD_")
        }
        state = self.home / "state"
        env["WITHHOLD_DIR"] = str(state)
        destination = self.home / "bin"
        result = self.command("install", "--bin-dir", str(destination), env=env)
        path = state / "config.toml"
        self.assertIn(str(path), result.stdout)
        self.assertEqual(tomllib.loads(path.read_text()), {"schema": 1})
        self.assertIn("# [application.traffic]", path.read_text())
        if os.name != "nt":
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

        customized = 'schema = 1\n[protection]\nchat = "block"\n'
        path.write_text(customized)
        self.command("install", "--bin-dir", str(destination), env=env)
        self.assertEqual(path.read_text(), customized)
        self.command("config", "--init", env=env, expected=1)
        self.assertEqual(path.read_text(), customized)

        selected = self.home / "elsewhere" / "custom.toml"
        self.command("config", "--init", "--config", str(selected), env=env)
        self.assertEqual(tomllib.loads(selected.read_text()), {"schema": 1})
        self.command("config", "--init", "--config", str(selected), env=env, expected=1)
        self.command("config", "--init", "--json", env=env, expected=2)

    def test_install_respects_explicit_config_and_init_refuses_symlinks(self):
        env = {
            key: value
            for key, value in self.env.items()
            if not key.startswith("WITHHOLD_")
        }
        state = self.home / "state"
        selected = self.home / "selected.toml"
        env.update(WITHHOLD_DIR=str(state), WITHHOLD_CONFIG=str(selected))
        self.command("install", "--bin-dir", str(self.home / "bin"), env=env)
        self.assertFalse((state / "config.toml").exists())
        self.assertFalse(selected.exists())
        self.command("config", "--init", env=env)
        self.assertEqual(tomllib.loads(selected.read_text()), {"schema": 1})

        if os.name != "nt":
            target = self.home / "target.toml"
            target.write_text("original")
            link = self.home / "link.toml"
            link.symlink_to(target)
            self.command("config", "--init", "--config", str(link), env=env, expected=1)
            self.assertEqual(target.read_text(), "original")
            self.assertTrue(link.is_symlink())

    def test_init_saves_selected_adapter_without_snapshotting_ambient_overrides(self):
        path = self.root / "custom.toml"
        self.command(
            "config", "--init", "--integration", "vscode-copilot", "--config", str(path)
        )
        self.assertEqual(
            tomllib.loads(path.read_text()),
            {"schema": 1, "integration": "vscode-copilot"},
        )
        self.assertNotIn("private-user-key", path.read_text())

    def test_setup_guidance_distinguishes_commands(self):
        env = {
            key: value
            for key, value in self.env.items()
            if not key.startswith("WITHHOLD_")
        }
        env["WITHHOLD_DIR"] = str(self.home / "state")
        result = self.command("setup", "--trust", "manual", env=env)
        self.assertIn("'withhold doctor'", result.stdout)
        self.assertIn("'withhold on'", result.stdout)

    def test_effective_toml_and_json_show_overrides_without_writing(self):
        env = {
            key: value
            for key, value in self.env.items()
            if not key.startswith("WITHHOLD_")
        }
        env["WITHHOLD_DIR"] = str(self.home / "state")
        env["WITHHOLD_MAX_BYTES"] = "16m"
        env["WITHHOLD_EDITOR_BIN"] = "env-code"
        result = self.command("config", "--max-bytes", "24m", env=env)
        self.assertIn(str(self.home / "state" / "config.toml"), result.stdout)
        self.assertIn("No file found", result.stdout)
        rendered = tomllib.loads(result.stdout)
        expected = json.loads(
            self.command("config", "--json", "--max-bytes", "24m", env=env).stdout
        )
        self.assertEqual(rendered, expected)
        self.assertEqual(rendered["proxy"]["max_bytes"], "24m")
        self.assertEqual(rendered["proxy"]["suspicion_pattern"], "copilot")
        self.assertEqual(rendered["application"]["binary"], "env-code")
        self.assertIn(
            "/v1/engines/[^/]+/completions",
            rendered["application"]["traffic"]["inline_paths"],
        )
        self.assertEqual(list(self.home.iterdir()), [])
        self.command("config", "--example", "--json", env=env, expected=2)
