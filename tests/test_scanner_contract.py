"""Scanner acceptance tests for the Go worker over a process boundary."""

from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import hmac
import json
import os
import random
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

WORKER = os.environ.get("WITHHOLD_TEST_SCANNER_WORKER")
CANARY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
PLACEHOLDER_KEY = "scanner-contract-test-only"


class ScannerProcess:
    def __init__(self, state: Path, worker: str, overrides=None):
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("WITHHOLD_")
        }
        for name in (
            "BETTERLEAKS_CONFIG",
            "BETTERLEAKS_CONFIG_TOML",
            "GITLEAKS_CONFIG",
            "GITLEAKS_CONFIG_TOML",
        ):
            env.pop(name, None)
        env.update(
            HOME=str(state),
            USERPROFILE=str(state),
            WITHHOLD_DIR=str(state / "withhold"),
            WITHHOLD_PLACEHOLDER_KEY=PLACEHOLDER_KEY,
        )
        if overrides:
            env.update(overrides)
        command = [str(Path(worker).resolve()), "--jsonl"]
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )

    def scan(self, body, *, max_bytes=None):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        request = {"body_base64": base64.b64encode(raw).decode()}
        if max_bytes is not None:
            request["max_bytes"] = max_bytes
        self.process.stdin.write((json.dumps(request) + "\n").encode())
        self.process.stdin.flush()
        timer = threading.Timer(30, self.process.kill)
        timer.daemon = True
        timer.start()
        try:
            line = self.process.stdout.readline()
        finally:
            timer.cancel()
            timer.join()
        if not line:
            raise AssertionError("scanner driver exited before reporting")
        report = json.loads(line)
        if "body_base64" in report:
            report["body"] = base64.b64decode(report.pop("body_base64"))
        return report

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        finally:
            self.process.stdout.close()
            self.process.stderr.close()


@unittest.skipUnless(WORKER, "native withhold-scanner required")
class ScannerContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="withhold-scanner-contract-")
        cls.drivers = {"native": ScannerProcess(Path(cls.tmp.name), WORKER)}

    @classmethod
    def tearDownClass(cls):
        for driver in cls.drivers.values():
            driver.close()
        cls.tmp.cleanup()

    def scan(self, body, status=None, **kwargs):
        report = self.drivers["native"].scan(body, **kwargs)
        if status is not None:
            self.assertEqual(report["status"], status)
        return report

    def test_clean_request_preserves_no_rewrite(self):
        report = self.scan({"input": "explain recursion"}, "clean")
        self.assertNotIn("body", report)
        self.assertGreater(report["units"], 0)

    def test_debug_findings_are_opt_in_and_match_rewritten_placeholders(self):
        body = {"input": f"token = {CANARY} and dev@example.com"}
        ordinary = self.scan(body, "redacted")
        self.assertNotIn("debug_findings", ordinary)

        debug = ScannerProcess(
            Path(self.tmp.name),
            WORKER,
            {"WITHHOLD_PII": "email", "WITHHOLD_INTERNAL_DEBUG_FINDINGS": "1"},
        )
        self.addCleanup(debug.close)
        report = debug.scan(body)
        self.assertEqual(report["status"], "redacted")
        rows = report["debug_findings"]
        values = {row["detected_masked"]: row for row in rows}
        self.assertIn("sk_…", values)
        self.assertIn("dev…", values)
        self.assertIn("<WITHHELD_", values["sk_…"]["placeholder"])
        self.assertIn("<WITHHELD_", values["dev…"]["placeholder"])
        self.assertNotIn(CANARY, str(rows))
        self.assertNotIn("dev@example.com", str(rows))
        self.assertNotIn(CANARY.encode(), report["body"])
        self.assertNotIn(b"dev@example.com", report["body"])
        for finding in rows:
            self.assertIn(finding["placeholder"], report["body"].decode())
            self.assertTrue(finding["rule_ids"])

    def test_plain_secret_is_redacted_with_stable_placeholder(self):
        body = {"messages": [{"content": f"deploy {CANARY} now"}], "stream": True}
        first = self.scan(body, "redacted")
        second = self.scan(body, "redacted")
        self.assertEqual(first, second)
        digest = hmac.new(
            PLACEHOLDER_KEY.encode(), CANARY.encode(), hashlib.sha256
        ).hexdigest()
        placeholder = f"<WITHHELD_{digest[:16]}>"
        self.assertIn(placeholder.encode(), first["body"])
        self.assertNotIn(CANARY.encode(), first["body"])

    def test_allow_comments_cannot_suppress_detection(self):
        for suffix in (" # gitleaks:allow", " # betterleaks:allow"):
            self.scan({"input": f'token = "{CANARY}"{suffix}'}, "redacted")

    def test_base64_variants_are_redacted_and_reencoded(self):
        text = f"some text before {CANARY} and more text after"
        encoded = base64.b64encode(text.encode()).decode()
        variants = (
            encoded,
            encoded.rstrip("="),
            "\n".join(encoded[i : i + 16] for i in range(0, len(encoded), 16)),
            "data:text/plain;base64," + encoded,
        )
        for value in variants:
            report = self.scan({"blob": value}, "redacted")
            result = json.loads(report["body"])["blob"].split(",")[-1]
            decoded = base64.b64decode(result + "=" * (-len(result) % 4))
            self.assertNotIn(CANARY.encode(), decoded)
            self.assertIn(b"<WITHHELD_", decoded)

    def test_text_data_url_and_unicode_remain_scannable(self):
        report = self.scan(
            {"input": f"data:text/plain,hello%20{CANARY}%20world", "label": "你好 🌍"},
            "redacted",
        )
        self.assertNotIn(CANARY.encode(), report["body"])
        self.assertEqual(json.loads(report["body"])["label"], "你好 🌍")

    def test_key_value_context_finds_password(self):
        report = self.scan({"password": "hunter2secretval"}, "redacted")
        self.assertNotIn(b"hunter2secretval", report["body"])

    def test_secret_object_key_is_renamed(self):
        report = self.scan({CANARY: "some ordinary value"}, "redacted")
        self.assertNotIn(CANARY, json.loads(report["body"]))

    def test_renaming_key_collision_fails_closed(self):
        digest = hmac.new(
            PLACEHOLDER_KEY.encode(), CANARY.encode(), hashlib.sha256
        ).hexdigest()
        placeholder = f"<WITHHELD_{digest[:16]}>"
        self.scan({CANARY: "first value", placeholder: "second value"}, "scanner-error")

    def test_attachment_and_tool_output_are_redacted(self):
        report = self.scan(
            {
                "input": [
                    {
                        "type": "function_call_output",
                        "output": f'<attachment id="config.py">\ntoken = "{CANARY}"\n</attachment>',
                    }
                ]
            },
            "redacted",
        )
        self.assertNotIn(CANARY.encode(), report["body"])
        self.assertIn(b"<attachment", report["body"])

    def test_large_leaf_secret_across_chunk_boundary_is_redacted(self):
        text = "ordinary text " * 3510 + CANARY + " ordinary text" * 5000
        report = self.scan({"input": text}, "redacted")
        self.assertNotIn(CANARY.encode(), report["body"])
        self.assertGreater(report["stats"]["chunked_large"], 0)

    def test_skipped_media_is_counted_alongside_findings(self):
        report = self.scan(
            {"input": CANARY, "blob": "data:image/png;base64,AAAA"}, "redacted"
        )
        self.assertEqual(report["stats"]["sweep_unrewritable"], 0)

    def test_tool_descriptions_and_defaults_are_protected(self):
        report = self.scan(
            {"tools": [{"description": CANARY, "parameters": {"default": CANARY}}]},
            "redacted",
        )
        self.assertEqual(report["stats"]["skipped_tools"], 0)
        self.assertNotIn(CANARY.encode(), report["body"])

    def test_opaque_attachments_survive_redaction_without_residue_checks(self):
        binary = b"\x89PNG\r\n\x1a\n" + b"\xff" * 70000 + CANARY.encode()
        encoded = base64.b64encode(binary).decode()
        for attachment in (
            encoded,
            "data:image/png;base64," + encoded,
            "data:image/png," + CANARY,
        ):
            report = self.scan({"input": CANARY, "attachment": attachment}, "redacted")
            self.assertEqual(json.loads(report["body"])["attachment"], attachment)
            self.assertEqual(report["stats"]["sweep_unrewritable"], 0)

    def test_mime_typed_binary_payload_preserves_caption_protection(self):
        source = {"media_type": "image/png", "data": CANARY, "caption": CANARY}
        report = self.scan({"source": source}, "redacted")
        rewritten = json.loads(report["body"])["source"]
        self.assertEqual(rewritten["data"], CANARY)
        self.assertNotIn(CANARY, rewritten["caption"])

    def test_binary_signature_normalizes_whitespace_and_urlsafe_base64(self):
        encoded = base64.urlsafe_b64encode(b"\xff\xd8\xff" + b"\xff" * 128).decode()
        for attachment in (
            encoded,
            encoded.rstrip("="),
            "\n" * 256
            + "\u2003".join(encoded[i : i + 13] for i in range(0, len(encoded), 13)),
        ):
            report = self.scan({"input": CANARY, "attachment": attachment}, "redacted")
            self.assertEqual(json.loads(report["body"])["attachment"], attachment)
            self.assertEqual(report["stats"]["skipped_base64_blobs"], 1)
            self.assertEqual(report["stats"]["sweep_unrewritable"], 0)

    def test_invalid_binary_signature_tails_are_scanned_as_text(self):
        encoded = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\xff" * 128).decode()
        for attachment in (
            encoded + " => " + CANARY,
            encoded + "===",
            encoded.rstrip("=") + "=A",
            encoded + "!",
        ):
            report = self.scan({"input": CANARY, "attachment": attachment}, "redacted")
            self.assertEqual(report["stats"]["skipped_base64_blobs"], 0)
            self.assertNotIn(CANARY, json.loads(report["body"])["attachment"])

    def test_mime_exclusions_apply_only_to_payload_fields(self):
        for mime in ("image/png", "application/pdf", "application/zip"):
            source = {
                "mimeType": mime,
                "file_data": CANARY,
                "filename": CANARY,
                "caption": CANARY,
                "description": CANARY,
            }
            report = self.scan({"source": source}, "redacted")
            rewritten = json.loads(report["body"])["source"]
            self.assertEqual(rewritten["file_data"], CANARY)
            for key in ("filename", "caption", "description"):
                self.assertNotIn(CANARY, rewritten[key])
        report = self.scan({"media_type": "text/plain", "data": CANARY}, "redacted")
        self.assertNotIn(CANARY, json.loads(report["body"])["data"])

    def test_large_base64_text_roundtrips_after_secret_redaction(self):
        text = "ordinary text " * 9000 + CANARY + " after"
        report = self.scan(
            {"file_data": base64.b64encode(text.encode()).decode()}, "redacted"
        )
        decoded = base64.b64decode(json.loads(report["body"])["file_data"])
        self.assertNotIn(CANARY.encode(), decoded)
        self.assertIn(b"<WITHHELD_", decoded)

    def test_short_credential_key_and_later_array_entries_keep_context(self):
        self.scan({"token": "x1W9p4V7b2Y5j8Q0s6D3f9K2"}, "redacted")
        self.scan({"password": ["ordinary"] * 5 + ["hunter2secretval"]}, "redacted")

    def test_uninspectable_bodies_and_limit_keep_error_status(self):
        for body in (b"not json", b"\xff", ["not an object"]):
            self.scan(body, "skipped-not-json")
        report = self.scan(b'{"input":"hello"}', "over-cap", max_bytes=4)
        self.assertEqual(report["max_bytes"], 4)

    def test_lone_surrogate_fails_closed(self):
        self.scan(b'{"input":"ordinary text \\ud800"}', "scanner-error")

    def test_clean_scan_after_findings_contains_no_stale_result(self):
        self.scan({"input": CANARY}, "redacted")
        report = self.scan({"input": "explain this function"}, "clean")
        self.assertNotIn("findings", report)

    def test_rewrite_preserves_unicode_controls_numbers_and_object_order(self):
        body = {
            "z": CANARY,
            "text": "".join(chr(i) for i in range(256)) + " 你好 🌍 <>& /",
            "numbers": [0, -0.0, 1.0, 1e9, 1e16, 1e-4, 1e-5, 1e-7, 2**100],
            "types": [True, False, None, {}, []],
            "stream": 1,
            "a": "last value",
        }
        report = self.scan(body, "redacted")
        rewritten = json.loads(report["body"])
        digest = hmac.new(
            PLACEHOLDER_KEY.encode(), CANARY.encode(), hashlib.sha256
        ).hexdigest()
        expected = {**body, "z": f"<WITHHELD_{digest[:16]}>"}
        # Serialized equality also distinguishes booleans, integers and floats,
        # signed zero, and object order, unlike Python container equality.
        self.assertEqual(json.dumps(rewritten), json.dumps(expected))

    def test_duplicate_keys_fail_closed_without_disclosing_values(self):
        for raw in (
            '{"input":"' + CANARY + '","input":"ordinary content"}',
            '{"input":"ordinary content","input":"' + CANARY + '"}',
            '{"payload":{"input":"' + CANARY + '","input":"ordinary content"}}',
            '{"input":"' + CANARY + '","\\u0069nput":"ordinary content"}',
            '{"z":"first value","input":"' + CANARY + '","z":"last value"}',
            '{"input":"ordinary content","input":"ordinary content"}',
        ):
            with self.subTest(raw=raw):
                report = self.scan(raw.encode(), "scanner-error")
                self.assertEqual(
                    report,
                    {"status": "scanner-error", "reason": "duplicate JSON object key"},
                )

    def test_number_spellings_are_preserved_when_body_is_rewritten(self):
        for number in ("-0", "1E+09", "1e-04", "1.234000", "1e999"):
            with self.subTest(number=number):
                report = self.scan(
                    ('{"input":"' + CANARY + '","value":' + number + "}").encode(),
                    "redacted",
                )
                self.assertIn(b'"value":' + number.encode(), report["body"])
        for number in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(number=number):
                self.scan(
                    ('{"input":"' + CANARY + '","value":' + number + "}").encode(),
                    "skipped-not-json",
                )

    def test_quoted_and_nested_object_keys_have_distinct_writeback(self):
        for key in ("a.b", "a[b]", 'a"b', "a\\b", "你好 🌍"):
            with self.subTest(key=key):
                self.scan({key: CANARY, "a": {"b": "ordinary text"}}, "redacted")

    def test_nested_secret_keys_and_null_path_characters_are_rewritten_safely(self):
        self.scan({CANARY: {CANARY: {"input": CANARY}}}, "redacted")
        self.scan({"a\x00b": CANARY, "a": {"b": "ordinary text"}}, "redacted")

    def test_urlsafe_unpadded_base64_preserves_conventions(self):
        raw = ("\uffff " * 6 + CANARY + " trailing text").encode()
        encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        self.assertTrue("-" in encoded or "_" in encoded)
        result = self.scan({"blob": encoded}, "redacted")
        rewritten = json.loads(result["body"])["blob"]
        self.assertNotIn("=", rewritten)
        self.assertNotIn("+", rewritten)
        self.assertNotIn("/", rewritten)

    def test_base64_padding_and_whitespace_are_normalized(self):
        for suffix in ("", "=", "==", "===", "===="):
            value = (
                base64.b64encode(("filler " * 8 + CANARY + " tail").encode()).decode()
                + suffix
            )
            report = self.scan({"input": CANARY, "blob": value})
            self.assertIn(report["status"], ("redacted", "scanner-error"))
        encoded = base64.b64encode(("filler " * 8 + CANARY + " tail").encode()).decode()
        wrapped = "\u0085\u00a0".join(
            encoded[i : i + 8] for i in range(0, len(encoded), 8)
        )
        self.scan({"blob": wrapped}, "redacted")

    def test_large_media_and_unlabeled_base64_keep_skip_policy(self):
        media = "data:IMAGE/png;base64," + "A" * 70000
        self.scan({"input": CANARY, "media": media}, "redacted")
        binary = base64.b64encode(b"\xff" * 55000).decode() + " " + CANARY
        self.scan({"blob": binary}, "redacted")

    def test_large_unicode_leaf_and_attachment_case_keep_partition(self):
        self.scan({"input": "你好 🌍 " * 14000 + CANARY}, "redacted")
        for tag in ("attachment", "ATTACHMENT"):
            self.scan(
                {"input": f'<{tag} id="config.py">\n{CANARY}\n</{tag}>'}, "redacted"
            )

    def test_context_in_lists_and_repeated_findings_keep_counts(self):
        self.scan({"password": ["hunter2secretval", "hunter3secretval"]}, "redacted")
        self.scan({"input": [CANARY, CANARY, "ordinary text"]}, "redacted")

    def test_unicode_attachment_whitespace_and_invalid_url_bytes_are_scanned(self):
        self.scan({"input": f"data:İmage/png,{CANARY}"}, "redacted")
        self.scan(
            {
                "input": f'<attachment\u00a0id="config.py">\n{CANARY}\n</attachment\u0085>'
            },
            "redacted",
        )
        for encoded in ("%e2%82", "%ff%ff", "%ed%a0%80", "%f0%90%80", "%zz", "%"):
            self.scan(
                {"input": f"data:text/plain,{encoded}%20{CANARY}%20end"}, "redacted"
            )

    def test_character_thresholds_keep_unit_and_skip_counts(self):
        for size in (0, 7, 8, 63, 64, 65536, 65537):
            for character in ("x", "界"):
                with self.subTest(size=size, character=character):
                    self.scan({"x": character * size}, "clean")

    def test_invalid_json_and_excessive_nesting_fail_closed(self):
        for raw in (
            b'{"x":01}',
            b'{"x":true,}',
            b"{}{}",
            b'{"x":"bad\\x00"}',
            b"\xef\xbb\xbf{}",
        ):
            self.scan(raw, "skipped-not-json")
        raw = b'{"x":' + b"[" * 1200 + b"0" + b"]" * 1200 + b"}"
        report = self.drivers["native"].scan(raw)
        self.assertEqual(report["status"], "scanner-error")
        self.assertIn("deeply nested", report["reason"])

    def test_seeded_request_shapes_are_scanned_fail_closed(self):
        rng = random.Random(83921)
        for i in range(80):
            secret = i % 3 == 0
            text = (
                f"deploy {CANARY} now" if secret else "explain this ordinary function"
            )
            if i % 4 == 0:
                text = base64.b64encode(text.encode()).decode()
            nested = text
            for _ in range(rng.randrange(1, 5)):
                nested = (
                    {rng.choice(["text", "content", "quoted.key", "你好"]): nested}
                    if rng.choice([True, False])
                    else [False, None, nested]
                )
            with self.subTest(case=i):
                report = self.scan({"input": nested, "stream": bool(i % 2)})
                expected = ("redacted", "scanner-error") if secret else ("clean",)
                self.assertIn(report["status"], expected)
                if report["status"] == "redacted":
                    self.assertNotIn(CANARY.encode(), report["body"])

    def test_persisted_placeholder_key_is_stable_across_processes(self):
        with tempfile.TemporaryDirectory(prefix="guard-pepper-contract-") as td:
            state = Path(td)
            reports = []
            for _ in range(2):
                driver = ScannerProcess(
                    state,
                    WORKER,
                    overrides={"WITHHOLD_PLACEHOLDER_KEY": ""},
                )
                try:
                    reports.append(driver.scan({"input": CANARY}))
                finally:
                    driver.close()
            self.assertEqual(reports[0], reports[1])
            self.assertEqual(reports[0]["status"], "redacted")
            path = state / ".config/withhold/placeholder-key"
            self.assertEqual(len(path.read_bytes().strip()), 64)
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_native_pipeline_does_not_require_betterleaks_cli(self):
        driver = ScannerProcess(
            Path(self.tmp.name),
            WORKER,
            overrides={"BETTERLEAKS_BIN": str(Path(self.tmp.name) / "missing-cli")},
        )
        try:
            self.assertEqual(driver.scan({"input": CANARY})["status"], "redacted")
        finally:
            driver.close()

    def test_concurrent_native_workers_publish_one_complete_placeholder_key(self):
        with tempfile.TemporaryDirectory(prefix="withhold-native-key-") as td:
            drivers = [
                ScannerProcess(
                    Path(td),
                    WORKER,
                    overrides={"WITHHOLD_PLACEHOLDER_KEY": ""},
                )
                for _ in range(3)
            ]
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                    reports = list(
                        executor.map(
                            lambda driver: driver.scan({"input": CANARY}), drivers
                        )
                    )
                self.assertTrue(all(report == reports[0] for report in reports))
                self.assertEqual(reports[0]["status"], "redacted")
                self.assertEqual(
                    len(
                        (Path(td) / ".config/withhold/placeholder-key")
                        .read_bytes()
                        .strip()
                    ),
                    64,
                )
            finally:
                for driver in drivers:
                    driver.close()

    def test_config_environment_cannot_replace_stock_rules(self):
        path = Path(self.tmp.name) / "empty-rules.toml"
        path.write_text('title = "empty rules"\n')
        for variable in (
            "BETTERLEAKS_CONFIG",
            "GITLEAKS_CONFIG",
            "BETTERLEAKS_CONFIG_TOML",
            "GITLEAKS_CONFIG_TOML",
        ):
            with self.subTest(variable=variable):
                value = path.read_text() if variable.endswith("_TOML") else str(path)
                driver = ScannerProcess(
                    Path(self.tmp.name), WORKER, overrides={variable: value}
                )
                try:
                    report = driver.scan({"input": CANARY})
                    self.assertEqual(report["status"], "redacted")
                    password = "H7m2Q9v4K6r1D8x5"
                    report = driver.scan(
                        {"input": f"psql://dbuser:{password}@db.internal:5432/app"}
                    )
                    self.assertEqual(report["status"], "redacted")
                    self.assertNotIn(password.encode(), report["body"])
                finally:
                    driver.close()


if __name__ == "__main__":
    unittest.main()
