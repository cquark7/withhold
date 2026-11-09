"""Native desktop checks use temporary homes, manual test trust, and empty PATH."""

import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from tests.test_native_proxy import BODY, FIXTURE, NATIVE, stop


@unittest.skipUnless(NATIVE, "set WITHHOLD_TEST_NATIVE to the native executable")
class NativeDesktopTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="withhold-session-")
        self.addCleanup(self.cleanup_state)
        self.root = Path(self.temp.name)
        empty = self.root / "no-tools"
        empty.mkdir()
        self.env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("WITHHOLD_", "BETTERLEAKS_", "GITLEAKS_"))
        }
        self.env.update(
            HOME=str(self.root),
            USERPROFILE=str(self.root),
            APPDATA=str(self.root / "appdata"),
            LOCALAPPDATA=str(self.root / "localappdata"),
            XDG_CONFIG_HOME=str(self.root / "config"),
            PATH=str(empty),
            WITHHOLD_DIR=str(self.root / "state"),
            WITHHOLD_AUDIT=str(self.root / "audit"),
            WITHHOLD_HINT=str(self.root / "hint"),
            WITHHOLD_PLACEHOLDER_KEY="isolated-native-desktop-test",
        )
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.run_guard("setup", "--trust", "manual")
        self.addCleanup(self.run_guard, "off", expected=None)
        status = json.loads(self.run_guard("status", "--json").stdout)
        self.settings = Path(status["settings"]["path"])
        self.settings.parent.mkdir(parents=True, exist_ok=True)

    def cleanup_state(self):
        # Shutdown closes the listener before the detached process finishes
        # releasing its log handle. Windows cannot unlink an open log file.
        deadline = time.monotonic() + 5
        while True:
            try:
                self.temp.cleanup()
                return
            except PermissionError:
                if os.name != "nt" or time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)

    def run_guard(self, *args, expected=0, env=None, binary=NATIVE):
        # With no recorded session, diagnostics/cleanup still use an isolated port.
        if (
            args[0] in ("status", "doctor", "off")
            and not (self.root / "state" / "session.json").exists()
            and not any(str(arg).startswith("--port") for arg in args)
        ):
            args = (*args, "--port", self.port)
        result = subprocess.run(
            [binary, *map(str, args)],
            env=env or self.env,
            capture_output=True,
            text=True,
            timeout=20,
        )
        if expected is not None:
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def on(self, *args):
        return self.run_guard("on", "--port", self.port, *args)

    def test_on_reuse_restore_and_new_session(self):
        self.settings.write_text('{/* before */ "http.proxy":"http://old", "keep":1,}')
        started = self.on()
        self.assertIn("withhold is running", started.stdout)
        self.assertIn("startup does not prove traffic is inspected", started.stdout)
        status = json.loads(self.run_guard("status", "--json").stdout)
        self.assertEqual(status["schema"], 4)
        self.assertFalse(status["debug"]["enabled"])
        self.assertEqual(status["coverage"]["state"], "awaiting-traffic")
        self.assertEqual(status["traffic"]["received"], 0)
        self.assertTrue(status["proxy"]["authenticated"])
        self.assertEqual(status["port"], self.port)
        self.assertIn("withhold is running", self.run_guard("status").stdout)
        record = self.root / "state" / "session.json"
        if os.name != "nt":
            self.assertEqual(record.stat().st_mode & 0o777, 0o600)
        self.on()
        current = json.loads(self.settings.read_text())
        current["mid-session"] = True
        self.settings.write_text(json.dumps(current))
        self.run_guard("off")
        self.assertIn("withhold is off", self.run_guard("status").stdout)
        restored = json.loads(self.settings.read_text())
        self.assertEqual(restored["http.proxy"], "http://old")
        self.assertTrue(restored["mid-session"])
        self.assertNotIn("http.proxySupport", restored)
        restored["http.proxy"] = "http://new"
        self.settings.write_text(json.dumps(restored))
        self.on()
        self.run_guard("off")
        self.assertEqual(
            json.loads(self.settings.read_text())["http.proxy"], "http://new"
        )

    def test_foreign_listener_is_refused_without_settings_changes(self):
        self.settings.write_text('{"keep": true}')
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", self.port))
            listener.listen()
            self.run_guard("on", "--port", self.port, expected=2)
            self.assertEqual(self.settings.read_text(), '{"keep": true}')
            self.assertFalse((self.root / "state" / "session.json").exists())
            self.run_guard("off", "--port", self.port, expected=1)
            self.assertEqual(listener.getsockname()[1], self.port)

    def test_debug_status_reports_live_traffic_and_log_write_failures(self):
        upstream = subprocess.Popen(
            [FIXTURE, "--root", str(self.root / "upstream.pem")],
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        self.addCleanup(stop, upstream)
        urls = json.loads(upstream.stdout.readline())
        upstream.stdout.close()
        self.run_guard(
            "on",
            "--port",
            self.port,
            "--debug",
            env=dict(self.env, WITHHOLD_TEST_ALLOW_HOSTS="127.0.0.1"),
        )
        path = self.root / "state" / "debug-findings.log"
        first = json.loads(self.run_guard("status", "--json").stdout)
        self.assertTrue(first["debug"]["enabled"])
        self.assertEqual(first["debug"]["path"], str(path))
        self.assertEqual(first["traffic"]["received"], 0)
        self.assertEqual(first["traffic"]["connections"], 0)
        self.assertIn("No HTTP requests", self.run_guard("status").stdout)

        # Only a detection attempts a findings write. No real provider or trust
        # store is contacted; the loopback fixture receives the redacted body.
        def send_finding():
            client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            try:
                client.request(
                    "POST",
                    urls["http"] + "/chat/completions",
                    BODY,
                    {"Content-Type": "application/json"},
                )
                response = client.getresponse()
                self.assertEqual(response.status, 200)
                response.read()
            finally:
                client.close()

        path.unlink()
        path.mkdir()
        send_finding()
        failed_report = json.loads(self.run_guard("status", "--json").stdout)
        failed = failed_report["debug"]
        self.assertEqual(failed_report["traffic"]["received"], 1)
        self.assertFalse(failed["healthy"])
        self.assertGreater(failed["write_failures"], 0)
        path.rmdir()
        send_finding()
        recovered_report = json.loads(self.run_guard("status", "--json").stdout)
        recovered = recovered_report["debug"]
        self.assertTrue(recovered["healthy"])
        self.assertEqual(recovered_report["traffic"]["received"], 2)
        self.assertEqual(recovered["write_failures"], failed["write_failures"])
        self.assertEqual(len(path.read_text().splitlines()), 1)
        self.assertIn("findings log is incomplete", self.run_guard("status").stdout)
        self.assertIn(
            "debug findings write failed",
            (self.root / "state" / "proxy.log").read_text(),
        )
        self.run_guard("off")
        stopped = json.loads(self.run_guard("status", "--json").stdout)
        self.assertFalse(stopped["debug"]["enabled"])
        self.assertIsNone(stopped["traffic"])
        self.assertEqual(stopped["coverage"]["state"], "unavailable")

    def test_startup_failure_rolls_back_managed_settings(self):
        before = {
            "http.proxy": "http://old",
            "http.noProxy": ["*"],
            "http.systemCertificates": False,
            "http.fetchAdditionalSupport": False,
            "http.webSocketAdditionalSupport": False,
            "keep": True,
        }
        self.settings.write_text(json.dumps(before))
        self.run_guard("on", "--port", self.port, "--scan-timeout", "1ns", expected=1)
        self.assertEqual(json.loads(self.settings.read_text()), before)
        self.assertFalse((self.root / "state" / "session.json").exists())

    def test_coverage_counters_work_without_debug_and_do_not_claim_failed_scans(self):
        upstream = subprocess.Popen(
            [FIXTURE, "--root", str(self.root / "upstream.pem")],
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        self.addCleanup(stop, upstream)
        urls = json.loads(upstream.stdout.readline())
        upstream.stdout.close()
        env = dict(self.env, WITHHOLD_TEST_ALLOW_HOSTS="127.0.0.1")
        self.run_guard("on", "--port", self.port, env=env)

        def send(method, body, expected):
            client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            try:
                client.request(
                    method,
                    urls["http"] + "/chat/completions",
                    body,
                    {"Content-Type": "application/json"},
                )
                response = client.getresponse()
                self.assertEqual(response.status, expected)
                response.read()
            finally:
                client.close()
            return json.loads(self.run_guard("status", "--json").stdout)

        passed = send("GET", None, 200)
        self.assertEqual(passed["coverage"]["state"], "traffic-observed")
        self.assertEqual(passed["traffic"]["passthrough"], 1)
        failed = send("POST", "not JSON", 429)
        self.assertEqual(failed["coverage"]["state"], "traffic-observed")
        self.assertEqual(failed["traffic"]["scan_attempts"], 1)
        self.assertEqual(failed["traffic"]["inspected"], 0)
        inspected = send("POST", BODY, 200)
        self.assertEqual(inspected["coverage"]["state"], "inspected")
        self.assertFalse(inspected["coverage"]["observe"])
        self.assertEqual(inspected["traffic"]["inspected"], 1)
        self.assertEqual(inspected["traffic"]["redacted"], 1)
        self.assertFalse(inspected["debug"]["enabled"])
        self.assertFalse((self.root / "state" / "debug-findings.log").exists())
        self.run_guard("off")
        self.run_guard("on", "--port", self.port, "--observe", env=env)
        observed = send("POST", BODY, 200)
        self.assertTrue(observed["coverage"]["observe"])
        self.assertEqual(observed["traffic"]["redacted"], 0)
        self.assertIn("OBSERVE", self.run_guard("status").stderr)

    def test_corrupt_token_never_authorizes_shutdown_but_restores(self):
        self.on()
        record = self.root / "state" / "session.json"
        original = record.read_bytes()
        data = json.loads(original)
        data["identity"]["token"] = "0" * 64
        record.write_text(json.dumps(data))
        try:
            self.run_guard("off", expected=1)
            self.assertFalse(self.settings.exists())
            with socket.create_connection(("127.0.0.1", self.port), timeout=2):
                pass
        finally:
            record.write_bytes(original)

    def test_configuration_change_requires_off_and_doctor_uses_native_schema(self):
        self.on()
        self.run_guard("on", "--port", self.port, "--chat-mode", "block", expected=2)
        doctor = json.loads(self.run_guard("doctor", "--json").stdout)
        self.assertEqual(doctor["schema"], 2)
        self.assertTrue(doctor["ok"])
        self.assertEqual(
            [r["id"] for r in doctor["checks"]][:2], ["native-runtime", "scanner"]
        )

    def test_pii_selection_requires_a_new_session_and_doctor_checks_it(self):
        self.on()
        env = dict(self.env, WITHHOLD_PII="aadhaar")
        result = self.run_guard("on", "--port", self.port, env=env, expected=2)
        self.assertIn("configuration changed", result.stderr)
        self.run_guard("off")
        self.run_guard("on", "--port", self.port, env=env)
        report = json.loads(self.run_guard("doctor", "--json", env=env).stdout)
        detail = next(
            row["detail"] for row in report["checks"] if row["id"] == "scanner"
        )
        self.assertIn("Alcatraz 0.23.0: aadhaar", detail)

    def test_binary_install_and_upgrade(self):
        destination = self.root / "installed"
        self.run_guard("install", "--bin-dir", destination)
        binary = destination / ("withhold.exe" if os.name == "nt" else "withhold")
        self.assertIn(
            "betterleaks 1.10.0", self.run_guard("version", binary=binary).stdout
        )
        self.on()
        self.run_guard("install", "--bin-dir", destination, expected=1)
        self.run_guard("off")
        self.run_guard("install", "--bin-dir", destination)

    def test_public_cli_and_completion_use_withhold_identity(self):
        self.assertTrue(self.run_guard("version").stdout.startswith("withhold "))
        self.assertIn("Usage: withhold COMMAND", self.run_guard("--help").stdout)
        self.assertIn("Usage: withhold on", self.run_guard("help", "on").stdout)
        for shell in ("bash", "zsh", "fish", "powershell"):
            script = self.run_guard("completion", shell).stdout
            self.assertIn("withhold _complete", script)
            self.assertNotIn("guard _complete", script)

    def test_default_install_uses_withhold_name_and_user_directory(self):
        self.run_guard("install")
        if os.name == "nt":
            binary = self.root / "localappdata" / "withhold" / "bin" / "withhold.exe"
        else:
            binary = self.root / ".local" / "bin" / "withhold"
        self.assertTrue(binary.is_file())
        self.assertTrue(
            self.run_guard("version", binary=binary).stdout.startswith("withhold ")
        )

    def test_manual_uninstall_retains_ca_until_trust_can_be_verified(self):
        self.on()
        self.run_guard("uninstall", expected=1)
        self.assertTrue((self.root / "state" / "ca.key").exists())
        self.on()
        self.run_guard("uninstall", "--keep-files")

    def test_optional_launch_supplies_proxy_and_ca_environment(self):
        fixture = os.environ.get("WITHHOLD_TEST_NATIVE_FIXTURE")
        if not fixture:
            self.skipTest("native fixture required")
        self.on()
        editor = self.root / ("editor.exe" if os.name == "nt" else "editor")
        shutil.copy2(fixture, editor)
        env = dict(
            self.env, WITHHOLD_EDITOR_BIN=str(editor), NO_PROXY="*", no_proxy="*"
        )
        result = self.run_guard("launch", "--", "--editor-environment", env=env)
        values = json.loads(result.stdout)
        self.assertEqual(values["HTTP_PROXY"], f"http://127.0.0.1:{self.port}")
        self.assertEqual(values["NO_PROXY"], "localhost,127.0.0.1,::1")
        self.assertEqual(values["no_proxy"], values["NO_PROXY"])
        self.assertEqual(
            values["NODE_EXTRA_CA_CERTS"], str(self.root / "state" / "ca.crt")
        )

    def test_on_routes_independent_settings_only_clients_without_launch(self):
        fixture = os.environ.get("WITHHOLD_TEST_NATIVE_FIXTURE")
        if not fixture:
            self.fail("native fixture required")
        upstream_ca = self.root / "upstream.pem"
        upstream = subprocess.Popen(
            [fixture, "--root", str(upstream_ca)],
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(stop, upstream)
        urls = json.loads(upstream.stdout.readline())
        upstream.stdout.close()
        upstream.stderr.close()
        self.settings.write_text(
            json.dumps(
                {
                    "http.noProxy": ["*"],
                    "http.systemCertificates": False,
                    "http.fetchAdditionalSupport": False,
                    "http.webSocketAdditionalSupport": False,
                }
            )
        )
        result = self.run_guard(
            "on",
            "--debug",
            "--port",
            self.port,
            "--upstream-ca",
            upstream_ca,
            env=dict(self.env, WITHHOLD_TEST_ALLOW_HOSTS="127.0.0.1"),
        )
        self.assertIn("VS Code routing configured", result.stdout)
        self.assertIn("integration guide", result.stdout)
        self.assertNotIn("withhold launch", result.stdout)
        status = self.run_guard("status")
        self.assertIn("VS Code integration guide", status.stdout)
        self.assertNotIn("withhold launch", status.stdout)
        current = json.loads(self.settings.read_text())
        self.assertEqual(current["http.noProxy"], ["localhost", "127.0.0.1", "::1"])
        for key in (
            "http.systemCertificates",
            "http.fetchAdditionalSupport",
            "http.webSocketAdditionalSupport",
        ):
            self.assertTrue(current[key])
        client = self.root / "settings-client.py"
        # The synthetic client uses a private CA instead of modifying OS trust.
        # This tests settings-only CONNECT/redaction, not real editor integration.
        client.write_text(
            """import base64, http.client, json, ssl, sys
from pathlib import Path
from urllib.parse import urlsplit
settings = json.loads(Path(sys.argv[1]).read_text())
proxy, target = urlsplit(settings['http.proxy']), urlsplit(sys.argv[3])
context = ssl.create_default_context(cafile=sys.argv[2])
connection = http.client.HTTPSConnection(proxy.hostname, proxy.port, context=context, timeout=10)
connection.set_tunnel(target.hostname, target.port)
connection.request('POST', '/chat/completions', json.dumps({'input': 'token = sk_live_4eC39HqLyjWDarjtT1zdp7dc'}), {'Content-Type': 'application/json'})
response = connection.getresponse()
assert response.status == 200, response.status
sys.stdout.buffer.write(base64.b64decode(json.loads(response.read())['body_base64']))
connection.close()
"""
        )
        client_env = {
            key: value
            for key, value in self.env.items()
            if key.upper()
            not in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "NODE_EXTRA_CA_CERTS")
        }
        for name in ("first-workspace", "second-workspace"):
            workspace = self.root / name
            workspace.mkdir()
            request = subprocess.run(
                [
                    sys.executable,
                    str(client),
                    str(self.settings),
                    str(self.root / "state" / "ca.crt"),
                    urls["https"],
                ],
                cwd=workspace,
                env=client_env,
                text=True,
                capture_output=True,
                timeout=15,
            )
            self.assertEqual(request.returncode, 0, request.stderr)
            self.assertIn("<WITHHELD_", request.stdout)
            self.assertNotIn("sk_live_4eC39HqLyjWDarjtT1zdp7dc", request.stdout)
            self.assertEqual(list(workspace.iterdir()), [])
        report = json.loads(self.run_guard("status", "--json").stdout)
        live = report["traffic"]
        for key in (
            "connections",
            "received",
            "scan_attempts",
            "detected",
            "redacted",
            "written",
            "responses",
        ):
            self.assertEqual(live[key], 2, key)
        self.assertEqual(report["debug"]["write_failures"], 0)
        self.assertEqual(live["upstream_errors"], 0)
        self.run_guard("off")
        restored = json.loads(self.settings.read_text())
        self.assertEqual(restored["http.noProxy"], ["*"])
        self.assertFalse(restored["http.systemCertificates"])
        self.assertNotIn("http.proxy", restored)

    def test_help_is_available_with_broken_runtime_configuration(self):
        env = dict(
            self.env,
            WITHHOLD_INTEGRATION="invalid",
            WITHHOLD_MAX_BYTES="invalid",
            WITHHOLD_EDITOR_SETTINGS_DIR="../invalid",
            WITHHOLD_PII="invalid",
        )
        env.pop("HOME", None)
        env.pop("USERPROFILE", None)
        env["WITHHOLD_DIR"] = str(self.root / "uninitialized")
        for args in (
            ("--help",),
            ("help", "on"),
            ("serve", "--help"),
            ("launch", "-h"),
        ):
            result = self.run_guard(*args, env=env)
            self.assertIn("Usage:", result.stdout)
        self.assertFalse((self.root / "state" / "session.json").exists())
        for shell in ("bash", "zsh", "fish", "powershell"):
            result = self.run_guard("completion", shell, env=env)
            self.assertIn("withhold _complete", result.stdout)
        result = self.run_guard("_complete", "on", "--chat-mode", "b", env=env)
        self.assertEqual(result.stdout, "block\n")
        self.assertFalse((self.root / "uninitialized").exists())

    def test_off_restores_recorded_session_despite_invalid_environment(self):
        self.settings.write_text('{"keep":true}')
        self.on()
        env = dict(
            self.env,
            WITHHOLD_INTEGRATION="invalid",
            WITHHOLD_MAX_BYTES="invalid",
            WITHHOLD_EXTRA_HOST_REGEX="[",
            WITHHOLD_EDITOR_SETTINGS_DIR="../invalid",
            WITHHOLD_ON_STARTUP_TIMEOUT="invalid",
            WITHHOLD_PII="invalid",
        )
        self.run_guard("off", env=env)
        self.assertEqual(json.loads(self.settings.read_text()), {"keep": True})

    def test_doctor_reports_invalid_configuration_as_json(self):
        env = dict(self.env, WITHHOLD_MAX_BYTES="invalid")
        report = json.loads(
            self.run_guard("doctor", "--json", env=env, expected=1).stdout
        )
        self.assertFalse(report["ok"])
        self.assertEqual(
            next(row for row in report["checks"] if row["id"] == "request-cap")[
                "status"
            ],
            "FAIL",
        )

    def test_doctor_reports_missing_and_invalid_upstream_roots_as_json(self):
        path = self.root / "invalid-roots.pem"
        for content in (None, b"not a certificate"):
            if content is not None:
                path.write_bytes(content)
            report = json.loads(
                self.run_guard(
                    "doctor", "--json", "--upstream-ca", path, expected=1
                ).stdout
            )
            self.assertFalse(report["ok"])
            self.assertTrue(
                any(
                    row["status"] == "FAIL" and "upstream roots" in row["detail"]
                    for row in report["checks"]
                )
            )
            result = self.run_guard(
                "doctor", "--preflight", "--upstream-ca", path, expected=2
            )
            self.assertEqual(result.stdout, "")
            self.assertIn("upstream roots", result.stderr)

    def test_default_audit_outputs_are_private_and_live_in_state_directory(self):
        env = dict(self.env)
        env.pop("WITHHOLD_AUDIT")
        env.pop("WITHHOLD_HINT")
        self.run_guard("on", "--port", self.port, env=env)
        for name in ("audit.jsonl", "hints.log"):
            path = self.root / "state" / name
            self.assertTrue(path.is_file())
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_invalid_audit_destination_rolls_back_settings_before_startup(self):
        self.settings.write_text('{"keep":true}')
        self.run_guard("on", "--port", self.port, "--audit", self.root, expected=1)
        self.assertEqual(json.loads(self.settings.read_text()), {"keep": True})
        self.assertFalse((self.root / "state" / "session.json").exists())

    @unittest.skipUnless(os.name == "nt", "Windows editor shim execution")
    def test_windows_editor_shim_preserves_literal_arguments_and_environment(self):
        fixture = os.environ.get("WITHHOLD_TEST_NATIVE_FIXTURE")
        if not fixture:
            self.skipTest("native fixture required")
        self.on()
        editor = self.root / "editor install"
        shim = editor / "bin" / "code.cmd"
        cli = editor / "resources" / "app" / "out" / "cli.js"
        shim.parent.mkdir(parents=True)
        cli.parent.mkdir(parents=True)
        shim.write_text("@echo off\nexit /b 99\n")
        cli.write_text("fixture CLI")
        shutil.copy2(fixture, editor / "Code.exe")
        args = [
            "project with spaces",
            "x&echo unsafe",
            "%PATH%",
            'quoted"path',
            "--help",
        ]
        env = dict(
            self.env,
            WITHHOLD_EDITOR_BIN=str(shim),
            ELECTRON_RUN_AS_NODE="old",
            VSCODE_DEV="old",
        )
        report = json.loads(self.run_guard("launch", "--", *args, env=env).stdout)
        self.assertEqual(report["args"], [str(cli), *args])
        self.assertEqual(report["ELECTRON_RUN_AS_NODE"], "1")
        self.assertEqual(report["VSCODE_DEV"], "")
        self.assertEqual(report["HTTP_PROXY"], f"http://127.0.0.1:{self.port}")
        self.assertEqual(
            report["NODE_EXTRA_CA_CERTS"], str(self.root / "state" / "ca.crt")
        )

    def test_irrelevant_flags_are_rejected_without_starting_a_session(self):
        for command, flag in (
            ("status", "--observe"),
            ("on", "--trust=manual"),
            ("launch", "--max-bytes=1m"),
        ):
            result = self.run_guard(command, flag, expected=2)
            self.assertIn("not supported", result.stderr)
        self.assertFalse((self.root / "state" / "session.json").exists())

    def test_launch_refuses_a_different_editor_settings_directory(self):
        self.on()
        env = dict(self.env, WITHHOLD_EDITOR_SETTINGS_DIR="another-editor")
        result = self.run_guard("launch", env=env, expected=1)
        self.assertIn("application settings differ", result.stderr)

    def test_doctor_human_output_includes_recovery_and_summary(self):
        env = dict(self.env, WITHHOLD_MAX_BYTES="invalid")
        result = self.run_guard("doctor", env=env, expected=1)
        self.assertIn("Fix:", result.stdout)
        self.assertIn("failed.", result.stdout)
        self.assertIn("WITHHOLD_EDITOR_BIN", result.stdout)

    def test_usage_errors_explain_recovery_without_writing_state(self):
        for args in (
            ("on", "extra"),
            ("on", "--port"),
            ("on", "--porrt=8090"),
            ("doctor", "--bin-dir=anything"),
            ("version", "extra"),
            ("init-ca", "--port=8090"),
        ):
            with self.subTest(args=args):
                result = self.run_guard(*args, expected=2)
                self.assertEqual(result.stdout, "")
                self.assertIn("--help", result.stderr)
        self.assertFalse((self.root / "state" / "session.json").exists())

    def test_observe_start_and_reuse_warn_that_secrets_can_pass(self):
        for _ in range(2):
            result = self.on("--observe")
            self.assertIn("OBSERVE", result.stderr)
            self.assertIn("unchanged", result.stderr)

    def test_session_uses_frozen_configuration_and_explicit_debug_without_cli_replay(
        self,
    ):
        self.on("--debug", "--max-bytes", "8m", "--chat-mode", "block")
        path = self.root / "state" / "session.json"
        record = json.loads(path.read_text())
        self.assertTrue(record["debug"])
        self.assertNotIn("args", record)
        self.assertEqual(record["configuration"]["proxy"]["max_bytes"], "8m")
        self.assertEqual(record["configuration"]["protection"]["chat"], "block")
        self.on("--debug", "--max-bytes", "8m", "--chat-mode", "block")
        self.run_guard(
            "on",
            "--port",
            self.port,
            "--max-bytes",
            "8m",
            "--chat-mode",
            "block",
            expected=2,
        )
        self.assertEqual(json.loads(path.read_text()), record)
        status = json.loads(self.run_guard("status", "--json").stdout)
        self.assertTrue(status["debug"]["enabled"])

    def test_persistent_configuration_drives_workers_and_session_identity(self):
        path = self.root / "state" / "config.toml"
        text = (
            'schema = 1\nintegration = "vscode-copilot"\n'
            '[protection]\npii = ["email"]\n'
            f"[proxy]\nport = {self.port}\n"
        )
        path.write_text(text)
        self.run_guard("on")
        record_path = self.root / "state" / "session.json"
        record = json.loads(record_path.read_text())
        self.assertEqual(record["integration"], "vscode-copilot")
        self.assertEqual(record["configuration"]["protection"]["pii"], ["email"])
        self.assertNotIn(self.env["WITHHOLD_PLACEHOLDER_KEY"], record_path.read_text())
        doctor = json.loads(self.run_guard("doctor", "--json").stdout)
        self.assertTrue(
            any("Alcatraz 0.23.0: email" in row["detail"] for row in doctor["checks"])
        )
        path.write_text(text.replace('"email"', '"aadhaar"'))
        self.run_guard("on", expected=2)
        self.assertEqual(json.loads(record_path.read_text()), record)
        self.run_guard("off")
        self.run_guard("on")
        self.assertEqual(
            json.loads(record_path.read_text())["configuration"]["protection"]["pii"],
            ["aadhaar"],
        )

    def test_config_command_is_read_only_and_reports_effective_overrides(self):
        path = self.root / "state" / "config.toml"
        path.write_text('schema = 1\n[proxy]\nmax_bytes = "8m"\n')
        before = path.read_bytes()
        env = dict(self.env, WITHHOLD_MAX_BYTES="16m", WITHHOLD_PII="email")
        result = self.run_guard("config", "--max-bytes", "24m", env=env)
        effective = json.loads(result.stdout)
        self.assertEqual(effective["proxy"]["max_bytes"], "24m")
        self.assertEqual(effective["protection"]["pii"], ["email"])
        self.assertEqual(path.read_bytes(), before)
        self.assertFalse((self.root / "state" / "session.json").exists())

    def test_invalid_config_refuses_startup_but_cannot_prevent_recovery(self):
        self.settings.write_text('{"keep":true}')
        path = self.root / "state" / "config.toml"
        path.write_text('schema = 1\n[protection]\npii = ["emails"]\n')
        self.run_guard("on", "--port", self.port, expected=2)
        self.assertEqual(self.settings.read_text(), '{"keep":true}')
        self.assertFalse((self.root / "state" / "session.json").exists())
        path.write_text("schema = 1\n")
        self.on()
        path.write_text("broken TOML =")
        self.run_guard("serve", "--help")
        env = dict(
            self.env,
            WITHHOLD_CONFIG=str(self.root / "missing-config.toml"),
            WITHHOLD_INTEGRATION="invalid",
            WITHHOLD_EDITOR_SETTINGS_DIR="../invalid",
        )
        self.run_guard("off", env=env)
        self.assertEqual(json.loads(self.settings.read_text()), {"keep": True})

    def test_configuration_selects_vscode_resource_without_environment_overrides(self):
        path = self.root / "state" / "config.toml"
        path.write_text(
            'schema = 1\n[application]\nsettings_dir = "ConfiguredCode"\n'
            f"[proxy]\nport = {self.port}\n"
        )
        configured = Path(
            json.loads(self.run_guard("status", "--json").stdout)["settings"]["path"]
        )
        configured.parent.mkdir(parents=True)
        configured.write_text('{"keep":"configured"}')
        self.run_guard("on")
        self.assertIn("http.proxy", json.loads(configured.read_text()))
        self.assertFalse(self.settings.exists())
        path.write_text("broken TOML =")
        self.run_guard("off")
        self.assertEqual(json.loads(configured.read_text()), {"keep": "configured"})

    def test_invalid_application_config_is_reported_without_changing_settings(self):
        path = self.root / "state" / "config.toml"
        path.write_text('schema = 1\n[application]\nsettings_dir = "../invalid"\n')
        self.run_guard("config", expected=2)
        report = json.loads(self.run_guard("doctor", "--json", expected=1).stdout)
        self.assertFalse(report["ok"])
        self.assertFalse(self.settings.exists())
        self.assertFalse((self.root / "state" / "session.json").exists())

    def test_catalog_ignores_broken_config_and_has_no_setup_side_effects(self):
        env = dict(
            self.env,
            WITHHOLD_DIR=str(self.root / "uninitialized"),
            WITHHOLD_CONFIG=str(self.root / "missing.toml"),
            WITHHOLD_INTEGRATION="invalid",
            WITHHOLD_EDITOR_SETTINGS_DIR="../invalid",
            WITHHOLD_MAX_BYTES="invalid",
        )
        catalog = json.loads(self.run_guard("integrations", "--json", env=env).stdout)
        self.assertEqual(catalog["schema"], 1)
        self.assertEqual(
            [entry["id"] for entry in catalog["integrations"]], ["vscode-copilot"]
        )
        self.assertIn(
            "docs/integrations/vscode-copilot.md",
            self.run_guard("integrations", env=env).stdout,
        )
        self.run_guard("integrations", "--config", "ignored.toml", env=env, expected=2)
        self.assertFalse((self.root / "uninitialized").exists())

    def test_toml_config_normalizes_application_options_and_drives_session(self):
        path = self.root / "state" / "config.toml"
        path.write_text(
            'schema = 1\nintegration = "vscode-copilot"\n'
            '[protection]\npii = ["email"] # Optional detection.\n'
            f"[proxy]\nport = {self.port}\n"
            '[application]\nbinary = "file-code"\nsettings_dir = "TOMLCode"\n'
        )
        before = path.read_bytes()
        env = dict(self.env, WITHHOLD_EDITOR_BIN="env-code")
        effective = json.loads(self.run_guard("config", env=env).stdout)
        self.assertEqual(effective["application"]["binary"], "env-code")
        self.assertNotIn("profile", effective["application"])
        self.assertEqual(effective["application"]["settings_dir"], "TOMLCode")
        configured = Path(
            json.loads(self.run_guard("status", "--json", env=env).stdout)["settings"][
                "path"
            ]
        )
        self.run_guard("on", env=env)
        self.assertIn("http.proxy", json.loads(configured.read_text()))
        record = json.loads((self.root / "state" / "session.json").read_text())
        self.assertEqual(
            record["configuration"]["application"], effective["application"]
        )
        self.assertEqual(record["configuration"]["protection"]["pii"], ["email"])
        self.assertEqual(path.read_bytes(), before)
        path.write_text('{"schema":1,"application":{"binary":"invalid"}}')
        self.run_guard("off", env=dict(env, WITHHOLD_EDITOR_SETTINGS_DIR="../invalid"))
        self.assertFalse(configured.exists())

    def test_default_configuration_discovers_only_toml(self):
        unrelated = self.root / "state" / "config.json"
        path = self.root / "state" / "config.toml"
        unrelated.write_text('{"schema":1,"protection":{"chat":"block"}}')
        self.assertEqual(
            json.loads(self.run_guard("config").stdout)["protection"]["chat"], "redact"
        )
        path.write_text(f"schema = 1\n[proxy]\nport = {self.port}\n")
        self.run_guard("on")
        self.run_guard("off")
        self.assertFalse(self.settings.exists())
        self.assertEqual(
            unrelated.read_text(), '{"schema":1,"protection":{"chat":"block"}}'
        )

    def test_json_configuration_is_rejected_before_startup_regardless_of_filename(self):
        for name in ("config.json", "config.toml", "settings"):
            with self.subTest(name=name):
                path = self.root / "state" / name
                path.write_text('{"schema":1,"application":{"binary":"PRIVATE"}}')
                for command in ("config", "on"):
                    result = self.run_guard(command, "--config", path, expected=2)
                    self.assertIn("invalid TOML", result.stderr)
                    self.assertNotIn("PRIVATE", result.stderr)
                self.assertFalse(self.settings.exists())
                self.assertFalse((self.root / "state" / "session.json").exists())
                path.unlink()

    def test_unknown_application_options_fail_before_startup(self):
        path = self.root / "state" / "config.toml"
        for option in ("unknown", "profile"):
            path.write_text(f'schema = 1\n[application]\n{option} = "PRIVATE"\n')
            result = self.run_guard("on", expected=2)
            self.assertNotIn("PRIVATE", result.stderr)
            self.assertFalse(self.settings.exists())
            self.assertFalse((self.root / "state" / "session.json").exists())

    def test_removed_flag_and_protection_aliases_are_rejected(self):
        self.run_guard("on", "--ca-dir", self.root / "other-state", expected=2)
        for flag in ("--chat-mode", "--inline-mode"):
            self.run_guard("on", flag, "warn", expected=2)
        self.assertFalse(self.settings.exists())
        self.assertFalse((self.root / "state" / "session.json").exists())
