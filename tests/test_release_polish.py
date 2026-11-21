"""Public onboarding commands use isolated state and no live providers."""

import json
import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import tomllib
import unittest
from pathlib import Path

from tools.package_native import ROOT

NATIVE = os.environ.get("WITHHOLD_TEST_NATIVE")


class ReleaseNotesTests(unittest.TestCase):
    def test_release_tag_requires_notes_but_manual_build_does_not(self):
        workflow = (ROOT / ".github/workflows/native-artifacts.yml").read_text()
        validate = (
            workflow.split("- name: Validate release version\n", 1)[1]
            .split("          python - <<'PY'\n", 1)[1]
            .split("\n          PY", 1)[0]
        )
        version = "v9.8.7-rc.1"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            notes = root / "docs" / "releases" / f"{version}.md"
            notes.parent.mkdir(parents=True)
            output = root / "output"
            for event, content, success in (
                ("push", None, False),
                ("push", " \n", False),
                ("push", "## What's new\n\nFixed a fixture bug.\n", True),
                ("workflow_dispatch", None, True),
            ):
                with self.subTest(event=event, notes=content):
                    notes.unlink(missing_ok=True)
                    output.unlink(missing_ok=True)
                    if content is not None:
                        notes.write_text(content, encoding="utf-8")
                    result = subprocess.run(
                        [sys.executable, "-c", textwrap.dedent(validate)],
                        cwd=root,
                        env=dict(
                            os.environ,
                            EVENT_NAME=event,
                            GITHUB_REPOSITORY="cquark7/withhold",
                            GITHUB_REF_NAME=version,
                            INPUT_VERSION=version,
                            GITHUB_OUTPUT=str(output),
                            PYTHONPATH=str(ROOT),
                        ),
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(result.returncode == 0, success, result.stderr)
                    if success:
                        self.assertEqual(output.read_text(), f"version={version}\n")
                    else:
                        self.assertIn(f"{version}.md before tagging", result.stderr)
                        self.assertFalse(output.exists())


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
            WITHHOLD_PLACEHOLDER_KEY="private-user-key",
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

    def test_toml_starter_does_not_read_config_write_state_or_export_overrides(self):
        result = self.command("config", "--example", "vscode-copilot")
        self.assertIn("#", result.stdout)
        self.assertIn("[applications.vscode-copilot]", result.stdout)
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
        self.assertEqual(effective["applications"]["vscode-copilot"]["binary"], "code")
        self.assertEqual(list(self.home.iterdir()), [])

    def test_onboarding_help_completion_and_option_errors_are_read_only(self):
        overview = self.command().stdout
        self.assertIn("withhold agents", overview)
        self.assertIn("withhold setup AGENT", overview)
        self.assertIn("All commands: withhold --help", overview)
        self.assertNotIn("withhold demo", overview)
        self.assertNotIn("init-ca", overview)
        self.assertIn("init-ca", self.command("--help").stdout)
        for command in ("agents", "config"):
            self.command(command, "--help")
        self.assertIn("--example", self.command("_complete", "config", "--ex").stdout)
        self.assertEqual("", self.command("_complete", "de").stdout)
        self.command("demo", expected=2)
        self.command("config", "--example", "--max-bytes", "1m", expected=2)
        self.command("config", "--example", "unknown", expected=2)
        self.command("config", "--init", "unknown", expected=2)
        self.assertEqual(list(self.home.iterdir()), [])
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_fresh_status_and_doctor_lead_to_agent_selection(self):
        env = {
            key: value
            for key, value in self.env.items()
            if not key.startswith("WITHHOLD_")
        }
        env["WITHHOLD_DIR"] = str(self.home / "state")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = str(listener.getsockname()[1])
        status = self.command("status", "--port", port, env=env)
        self.assertIn("withhold agents", status.stdout)
        self.assertNotIn("coverage:", status.stdout)
        self.assertNotIn("debug:", status.stdout)
        doctor = self.command("doctor", "--port", port, env=env, expected=1)
        self.assertTrue(doctor.stdout.startswith("[FAIL] agents"), doctor.stdout)
        self.assertIn("CA and trust not checked", doctor.stdout)
        self.assertNotIn("[FAIL] ca-files", doctor.stdout)
        self.assertNotIn("[FAIL] request-cap", doctor.stdout)
        self.assertEqual(list(self.home.iterdir()), [])

    def test_no_implicit_agent_or_legacy_selector(self):
        env = {
            key: value
            for key, value in self.env.items()
            if not key.startswith("WITHHOLD_")
        }
        env["WITHHOLD_DIR"] = str(self.home / "state")
        env["WITHHOLD_INTEGRATION"] = "cursor"  # Removed selectors cannot pick agents.
        result = self.command("on", env=env, expected=2)
        self.assertIn("no agents selected", result.stderr)
        self.assertIn("withhold setup AGENT", result.stderr)
        self.command("integrations", env=env, expected=2)
        self.command("on", "--integration", "cursor", env=env, expected=2)
        self.command("on", "8090", env=env, expected=2)
        typo = self.command("on", "curser", env=env, expected=2)
        self.assertIn('did you mean "cursor"', typo.stderr)
        self.assertEqual(list(self.home.iterdir()), [])

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
        self.assertIn("# agents = []", path.read_text())
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
        self.command("config", "--init", "vscode-copilot", "--config", str(path))
        self.assertEqual(
            tomllib.loads(path.read_text()),
            {"schema": 1, "agents": ["vscode-copilot"]},
        )
        self.assertNotIn("private-user-key", path.read_text())

    def test_setup_guidance_distinguishes_commands(self):
        env = {
            key: value
            for key, value in self.env.items()
            if not key.startswith("WITHHOLD_")
        }
        env["WITHHOLD_DIR"] = str(self.home / "state")
        result = self.command("setup", "cursor", "--trust", "manual", env=env)
        self.assertIn("Saved agents: cursor", result.stdout)
        self.assertIn("'withhold on'", result.stdout)
        self.assertLess(
            result.stdout.index("import "), result.stdout.index("'withhold on'")
        )
        self.assertIn("manual trust cannot be verified", result.stdout)

    def test_effective_toml_and_json_show_overrides_without_writing(self):
        env = {
            key: value
            for key, value in self.env.items()
            if not key.startswith("WITHHOLD_")
        }
        env["WITHHOLD_DIR"] = str(self.home / "state")
        env["WITHHOLD_MAX_BYTES"] = "16m"
        env["WITHHOLD_EDITOR_BIN"] = "env-code"
        result = self.command("config", "vscode-copilot", "--max-bytes", "24m", env=env)
        self.assertIn(str(self.home / "state" / "config.toml"), result.stdout)
        self.assertIn("No file found", result.stdout)
        rendered = tomllib.loads(result.stdout)
        expected = json.loads(
            self.command(
                "config", "vscode-copilot", "--json", "--max-bytes", "24m", env=env
            ).stdout
        )
        self.assertEqual(rendered, expected)
        self.assertEqual(rendered["proxy"]["max_bytes"], "24m")
        self.assertEqual(rendered["proxy"]["port"], 8451)
        self.assertNotIn("suspicion_pattern", rendered["proxy"])
        application = rendered["applications"]["vscode-copilot"]
        self.assertEqual(application["binary"], "env-code")
        self.assertIn(
            "/v1/engines/[^/]+/completions",
            application["traffic"]["inline_paths"],
        )
        self.assertEqual(list(self.home.iterdir()), [])
        self.command("config", "--example", "--json", env=env, expected=2)

    @unittest.skipIf(os.name == "nt", "Windows paths cannot contain line breaks")
    def test_effective_toml_escapes_line_breaks_in_config_path_comment(self):
        env = {
            key: value
            for key, value in self.env.items()
            if not key.startswith("WITHHOLD_")
        }
        directory = self.root / "custom\nstate\r"
        env["WITHHOLD_DIR"] = str(directory)
        path = directory / "config.toml"
        result = self.command("config", env=env)
        display_path = str(path).replace("\r", r"\r").replace("\n", r"\n")
        self.assertEqual(
            result.stdout.splitlines()[0],
            f"# Configuration file: {display_path}",
        )
        self.assertEqual(tomllib.loads(result.stdout)["schema"], 1)
