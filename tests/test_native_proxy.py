"""Process-level native transport checks with loopback upstreams and private CAs.

Build cmd/withhold and tests/nativefixture; set WITHHOLD_TEST_NATIVE and
WITHHOLD_TEST_NATIVE_FIXTURE to their absolute paths. The native processes receive
an empty PATH, isolated home/state, and no system trust or editor changes.
"""

from __future__ import annotations

import base64
import contextlib
import gzip
import hashlib
import hmac
import http.client
import json
import os
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import unittest
import zlib
from pathlib import Path
from urllib.parse import urlsplit

SECRET = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
BODY = json.dumps({"messages": [{"content": f"deploy {SECRET} now"}]}).encode()
NATIVE = os.environ.get("WITHHOLD_TEST_NATIVE", "")
FIXTURE = os.environ.get("WITHHOLD_TEST_NATIVE_FIXTURE", "")


def stop(process):
    process.terminate()
    try:
        process.wait(8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(5)


def exact(sock, n):
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError("connection closed")
        data.extend(chunk)
    return bytes(data)


def read_headers(sock):
    data = b""
    while not data.endswith(b"\r\n\r\n"):
        data += exact(sock, 1)
        if len(data) > 65536:
            raise ValueError("oversized response headers")
    return data


class WebSocket:
    """Minimal client exercising fragmentation and permessage-deflate on wire."""

    def __init__(self, sock, authority, path, compression=False, benchmark=False):
        self.sock = sock
        key = base64.b64encode(os.urandom(16))
        headers = (
            f"GET {path} HTTP/1.1\r\nHost: {authority}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key.decode()}\r\nSec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Protocol: withhold-test\r\n"
        )
        if compression:
            headers += (
                "Sec-WebSocket-Extensions: permessage-deflate; "
                "client_no_context_takeover; server_no_context_takeover\r\n"
            )
        if benchmark:
            headers += "X-Withhold-Benchmark: websocket\r\n"
        sock.sendall(headers.encode() + b"\r\n")
        response = read_headers(sock)
        assert b" 101 " in response, response
        digest = hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
        assert base64.b64encode(digest) in response
        assert b"withhold-test" in response
        if compression:
            assert b"permessage-deflate" in response

    @staticmethod
    def frames(body, kind=1, fragmented=False, compressed=False):
        if compressed:
            compressor = zlib.compressobj(wbits=-15)
            body = (compressor.compress(body) + compressor.flush(zlib.Z_SYNC_FLUSH))[
                :-4
            ]
        parts = [body]
        if fragmented:
            middle = max(1, len(body) // 2)
            parts = [body[:middle], body[middle:]]
        frames = bytearray()
        for index, part in enumerate(parts):
            first = (kind if index == 0 else 0) | (
                0x80 if index == len(parts) - 1 else 0
            )
            if compressed and index == 0:
                first |= 0x40
            n = len(part)
            if n < 126:
                length = bytes([0x80 | n])
            elif n <= 65535:
                length = b"\xfe" + struct.pack("!H", n)
            else:
                length = b"\xff" + struct.pack("!Q", n)
            mask = os.urandom(4)
            payload = bytes(value ^ mask[i % 4] for i, value in enumerate(part))
            frames.extend(bytes([first]) + length + mask + payload)
        return bytes(frames)

    def send(self, body, kind=1, fragmented=False, compressed=False):
        self.sock.sendall(self.frames(body, kind, fragmented, compressed))

    def receive(self):
        result = b""
        compressed = False
        while True:
            first, second = exact(self.sock, 2)
            n = second & 127
            if n == 126:
                n = struct.unpack("!H", exact(self.sock, 2))[0]
            elif n == 127:
                n = struct.unpack("!Q", exact(self.sock, 8))[0]
            payload = exact(self.sock, n)
            if first & 15 == 8:
                raise EOFError("WebSocket closed")
            if first & 15 in (9, 10):
                continue
            compressed |= bool(first & 0x40)
            result += payload
            if first & 0x80:
                if compressed:
                    result = zlib.decompressobj(-15).decompress(
                        result + b"\x00\x00\xff\xff"
                    )
                return result


@unittest.skipUnless(NATIVE, "set WITHHOLD_TEST_NATIVE to the standalone Go executable")
class NativeProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not FIXTURE:
            raise RuntimeError(
                "WITHHOLD_TEST_NATIVE_FIXTURE must accompany WITHHOLD_TEST_NATIVE"
            )
        cls.temp = tempfile.TemporaryDirectory(prefix="withhold-native-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.empty_path = cls.root / "no-tools"
        cls.empty_path.mkdir()
        cls.env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("WITHHOLD_", "BETTERLEAKS_", "GITLEAKS_"))
        }
        cls.env.update(
            PATH=str(cls.empty_path),
            HOME=str(cls.root),
            USERPROFILE=str(cls.root),
            APPDATA=str(cls.root / "appdata"),
            XDG_CONFIG_HOME=str(cls.root / "config"),
            WITHHOLD_DIR=str(cls.root / "ca"),
            WITHHOLD_TEST_ALLOW_HOSTS="127.0.0.1",
            WITHHOLD_PLACEHOLDER_KEY="native-process-test-only",
        )
        result = subprocess.run(
            [NATIVE, "init-ca"], env=cls.env, capture_output=True, timeout=15
        )
        if result.returncode:
            raise RuntimeError(result.stderr.decode())
        cls.upstream_root = cls.root / "upstream.crt"
        cls.fixture = subprocess.Popen(
            [FIXTURE, "--root", str(cls.upstream_root)],
            env=cls.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        cls.addClassCleanup(stop, cls.fixture)
        cls.addClassCleanup(cls.fixture.stdout.close)
        cls.urls = json.loads(cls.fixture.stdout.readline())
        cls.trust = ssl.create_default_context(cafile=str(cls.root / "ca" / "ca.crt"))

    def setUp(self):
        self.direct("/reset")

    def direct(self, path, body=None):
        parsed = urlsplit(self.urls["http"])
        with contextlib.closing(
            http.client.HTTPConnection(parsed.hostname, parsed.port)
        ) as c:
            c.request("POST" if body is not None else "GET", path, body)
            r = c.getresponse()
            data = r.read()
            return data if body is not None else json.loads(data or "null")

    @contextlib.contextmanager
    def proxy(self, *args, overrides=None, trust_upstream=True):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        state = self.root / str(time.monotonic_ns())
        state.mkdir()
        env = dict(
            self.env,
            WITHHOLD_AUDIT=str(state / "audit"),
            WITHHOLD_HINT=str(state / "hint"),
        )
        env.update(overrides or {})
        log = (state / "log").open("wb")
        command = [NATIVE, "serve", "--port", str(port)]
        if "--debug" in args:
            # Hard links retain the fixture key's private Windows ACL while
            # giving each trace its own log directory. The CA is read-only.
            for name in ("ca.crt", "ca.key"):
                (state / name).hardlink_to(self.root / "ca" / name)
            command += ["--dir", str(state)]
        if trust_upstream:
            command += ["--upstream-ca", str(self.upstream_root)]
        process = subprocess.Popen(
            command + list(args), env=env, stdout=log, stderr=log
        )
        try:
            deadline = time.monotonic() + 15
            while True:
                if process.poll() is not None:
                    self.fail((state / "log").read_text())
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        self.fail("native proxy did not listen")
                    time.sleep(0.02)
            self.native_process = process
            yield port, state
        finally:
            stop(process)
            log.close()

    def request(
        self,
        port,
        body=BODY,
        path="/chat/completions",
        method="POST",
        headers=None,
        secure=False,
    ):
        headers = {"Content-Type": "application/json", **(headers or {})}
        if secure:
            target = urlsplit(self.urls["https"])
            c = http.client.HTTPSConnection(
                "127.0.0.1", port, context=self.trust, timeout=10
            )
            c.set_tunnel(target.hostname, target.port)
            url = path
        else:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            url = self.urls["http"] + path
        with contextlib.closing(c):
            c.request(method, url, body, headers)
            r = c.getresponse()
            return r.status, dict(r.getheaders()), r.read()

    def tunnel(self, port, alpn="http/1.1"):
        upstream = urlsplit(self.urls["https"])
        authority = upstream.netloc
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        sock.sendall(
            f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode()
        )
        self.assertIn(b" 200 ", read_headers(sock))
        trust = ssl.create_default_context(cafile=str(self.root / "ca" / "ca.crt"))
        trust.set_alpn_protocols([alpn])
        try:
            secure = trust.wrap_socket(sock, server_hostname=upstream.hostname)
        except Exception:
            sock.close()
            raise
        self.addCleanup(secure.close)
        return secure, authority

    def decoded(self, data):
        return base64.b64decode(json.loads(data)["body_base64"])

    def debug_lines(self, state):
        text = (state / "debug-findings.log").read_text(encoding="utf-8")
        self.assertNotIn(SECRET, text)
        self.assertNotIn("private-url-value", text)
        self.assertNotIn('"event":', text)
        return text.splitlines()

    def wait_for_debug_lines(self, state, count, timeout=2):
        deadline = time.monotonic() + timeout
        while True:
            lines = self.debug_lines(state)
            if len(lines) >= count or time.monotonic() >= deadline:
                return lines
            time.sleep(0.01)

    def test_debug_https_proves_detection_redaction_write_and_response(self):
        with self.proxy("--debug") as (port, state):
            status, _, data = self.request(port, secure=True)
            self.assertEqual(status, 200)
            forwarded = self.decoded(data)
            self.assertNotIn(SECRET.encode(), forwarded)
            self.assertEqual(
                self.request(port, body=b'{"input":"ordinary content"}')[0], 200
            )
            self.assertEqual(
                self.request(
                    port,
                    body=None,
                    method="GET",
                    path="/private-url-value?credential=private-url-value",
                )[0],
                200,
            )
            lines = self.debug_lines(state)
            self.assertEqual(len(lines), 1, lines)
            self.assertIn('REDACTED "sk_…" → <WITHHELD_', lines[0])
            self.assertIn("sent (HTTP 200)", lines[0])
            placeholder = lines[0].split(" → ")[1].split(" | ")[0]
            self.assertIn(placeholder.encode(), forwarded)

    def test_debug_upstream_failure_does_not_claim_body_was_written(self):
        with self.proxy("--debug", trust_upstream=False) as (port, state):
            self.assertEqual(self.request(port, secure=True)[0], 502)
            lines = self.debug_lines(state)
            self.assertEqual(len(lines), 1, lines)
            self.assertIn('REDACTED "sk_…"', lines[0])
            self.assertIn("send unconfirmed; upstream failed", lines[0])
            self.assertNotIn(" | sent", lines[0])
            self.assertFalse(self.direct("/stats"))

    def test_debug_transport_denial_remains_blocked_in_observe_mode(self):
        with self.proxy("--debug", "--observe", "--max-bytes", "32") as (port, state):
            self.assertEqual(self.request(port)[0], 413)
            # Transport refusal happened before detection: it belongs in the
            # ordinary audit, not in the human findings file.
            self.assertEqual(self.debug_lines(state), [])
            self.assertFalse(self.direct("/stats"))

    def test_debug_websocket_findings_are_human_readable_without_traffic_noise(self):
        for mode in ("redact", "block", "observe"):
            options = {
                "redact": [],
                "block": ["--chat-mode", "block"],
                "observe": ["--observe", "--chat-mode", "block"],
            }[mode]
            with (
                self.subTest(mode=mode),
                self.proxy("--debug", *options) as (port, state),
            ):
                sock, authority = self.tunnel(port)
                ws = WebSocket(sock, authority, "/chat/completions", compression=True)
                ws.send(BODY, fragmented=True, compressed=True)
                if mode == "block":
                    with self.assertRaises((EOFError, OSError)):
                        ws.receive()
                else:
                    forwarded = ws.receive()
                    if mode == "observe":
                        self.assertEqual(forwarded, BODY)
                    else:
                        self.assertNotIn(SECRET.encode(), forwarded)
                        self.assertIn(b"<WITHHELD_", forwarded)
                        ws.send(b"not JSON")
                        ws.send(b'{"input":"ordinary content"}')
                        self.assertEqual(ws.receive(), b'{"input":"ordinary content"}')
                sock.close()
                # The response relay can echo before the sender logs its
                # completed upstream write.
                lines = self.wait_for_debug_lines(state, 1)
                self.assertEqual(len(lines), 1, lines)
                self.assertIn("/WS", lines[0])
                self.assertIn('"sk_…"', lines[0])
                if mode == "redact":
                    self.assertIn("REDACTED", lines[0])
                    self.assertTrue(lines[0].endswith(" | sent"))
                    placeholder = lines[0].split(" → ")[1].split(" | ")[0]
                    self.assertIn(placeholder.encode(), forwarded)
                elif mode == "block":
                    self.assertIn("BLOCKED", lines[0])
                    self.assertTrue(lines[0].endswith(" | not sent"))
                    self.assertNotIn(" → ", lines[0])
                else:
                    self.assertIn("OBSERVE", lines[0])
                    self.assertIn("ORIGINAL sent; NOT redacted", lines[0])
                    self.assertNotIn(" → ", lines[0])

    def test_aadhaar_redaction_and_block_policy_with_private_audit(self):
        value = "2341 2341 2346"
        body = json.dumps({"input": "aadhaar: " + value}).encode()
        with self.proxy(overrides={"WITHHOLD_PII": "aadhaar"}) as (port, state):
            for secure in (False, True):
                status, _, data = self.request(port, body=body, secure=secure)
                self.assertEqual(status, 200)
                rewritten = self.decoded(data)
                self.assertTrue(value.encode() not in rewritten, "Aadhaar survived")
                self.assertIn(b"<WITHHELD_", rewritten)
            audit = (state / "audit").read_text()
            self.assertIn("pii-aadhaar", audit)
            self.assertNotIn(value, audit + (state / "hint").read_text())
        self.direct("/reset")
        with self.proxy(
            "--chat-mode", "block", overrides={"WITHHOLD_PII": "aadhaar"}
        ) as (
            port,
            _,
        ):
            status, _, _ = self.request(port, body=body)
            self.assertEqual(status, 429)
            self.assertFalse(self.direct("/stats"))

    def test_persistent_config_enables_pii_without_environment_selection(self):
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            config = Path(temporary) / "config.toml"
            config.write_text('schema = 1\n[protection]\npii = ["email"]\n')
            with self.proxy("--config", str(config)) as (port, state):
                config.write_text("schema = 1\n[protection]\npii = []\n")
                body = json.dumps(
                    {"contact": "dev@example.com", "input": SECRET}
                ).encode()
                status, _, data = self.request(port, body=body)
                self.assertEqual(status, 200)
                rewritten = self.decoded(data)
                self.assertNotIn(b"dev@example.com", rewritten)
                self.assertNotIn(SECRET.encode(), rewritten)
                self.assertIn("pii-email", (state / "audit").read_text())

    def test_http_and_verified_connect_redact_without_runtime_tools(self):
        with self.proxy() as (port, state):
            for secure in (False, True):
                with self.subTest(secure=secure):
                    status, _, data = self.request(port, secure=secure)
                    self.assertEqual(status, 200, data)
                    redacted = self.decoded(data)
                    self.assertNotIn(SECRET.encode(), redacted)
                    self.assertRegex(redacted, rb"<WITHHELD_[0-9a-f]{16}>")
            audit = (state / "audit").read_text()
            self.assertNotIn(SECRET, audit + (state / "hint").read_text())
            row = json.loads(audit.splitlines()[0])
            self.assertEqual(
                list(row),
                [
                    "ts",
                    "host",
                    "api",
                    "surface",
                    "surface_provisional",
                    "mode",
                    "action",
                    "rule_ids",
                    "findings",
                    "placeholders",
                    "units",
                    "stats",
                    "method",
                    "path",
                ],
            )
            self.assertEqual(row["action"], "forwarded")

    def test_database_uris_and_multipart_credentials_protect_upstream(self):
        aws_id = "AKIA4X7Q2W3K7MNDZBXP"
        aws_secret = "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"
        db_password = "H7m2Q9v4K6r1D8x5"
        cases = (
            ({"input": aws_id}, (aws_id,)),
            (
                {"AWS_ACCESS_KEY_ID": aws_id, "AWS_SECRET_ACCESS_KEY": aws_secret},
                (aws_id, aws_secret),
            ),
            (
                {"input": f"DB_URI=psql://dbuser:{db_password}@db.internal:5432/app"},
                (db_password,),
            ),
        )
        with self.proxy() as (port, state):
            for secure in (False, True):
                for body, values in cases:
                    with self.subTest(secure=secure, case=tuple(body)):
                        status, _, data = self.request(
                            port, body=json.dumps(body).encode(), secure=secure
                        )
                        self.assertEqual(status, 200)
                        forwarded = self.decoded(data)
                        self.assertIn(b"<WITHHELD_", forwarded)
                        for value in values:
                            self.assertNotIn(value.encode(), forwarded)
            logs = (state / "audit").read_text() + (state / "hint").read_text()
            for value in (aws_id, aws_secret, db_password):
                self.assertNotIn(value, logs)

            self.direct("/reset")
            many = (
                "AWS_ACCESS_KEY_ID="
                + aws_id
                + " "
                + " ".join(
                    f"AWS_SECRET_ACCESS_KEY={aws_secret[:37]}{i:03d}"
                    for i in range(100)
                )
            )
            status, _, _ = self.request(port, body=json.dumps({"input": many}).encode())
            self.assertEqual(status, 429)
            self.assertFalse(self.direct("/stats"))

        self.direct("/reset")
        with self.proxy("--chat-mode", "block") as (port, _):
            for body, _ in cases:
                status, _, _ = self.request(port, body=json.dumps(body).encode())
                self.assertEqual(status, 429)
            self.assertFalse(self.direct("/stats"))

    def test_clean_bytes_and_observe_payloads_are_preserved(self):
        clean = (
            b'{ "messages": [{"content":"explain recursion"}], "n":9007199254740993 }'
        )
        with self.proxy() as (port, _):
            status, _, data = self.request(port, clean)
            self.assertEqual(status, 200)
            self.assertEqual(self.decoded(data), clean)
        with self.proxy("--observe", "--chat-mode", "block") as (port, state):
            status, _, data = self.request(port)
            self.assertEqual(status, 200)
            self.assertEqual(self.decoded(data), BODY)
            self.assertIn("would-block", (state / "audit").read_text())

    def test_blocks_normal_and_streaming_without_upstream_disclosure(self):
        with self.proxy("--chat-mode", "block") as (port, _):
            for streaming in (False, True):
                body = json.dumps(
                    {"stream": streaming, "messages": [{"content": SECRET}]}
                ).encode()
                status, headers, data = self.request(port, body)
                self.assertEqual(status, 200 if streaming else 429)
                self.assertEqual(headers["X-Withhold-Block"], "1")
                self.assertIn(b"withhold_blocked", data)
                self.assertEqual(b"data: [DONE]" in data, streaming)
            self.assertFalse(self.direct("/stats"))

    def test_duplicate_keys_never_reach_http_upstream(self):
        bodies = (
            '{"input":"' + SECRET + '","input":"ordinary content"}',
            '{"payload":{"input":"' + SECRET + '"},"payload":null}',
            '{"input":"' + SECRET + '","\\u0069nput":"ordinary content"}',
        )
        with self.proxy() as (port, state):
            for secure in (False, True):
                for body in bodies:
                    with self.subTest(secure=secure, body=body):
                        status, headers, data = self.request(
                            port, body=body.encode(), secure=secure
                        )
                        self.assertEqual(status, 429)
                        self.assertEqual(headers["X-Withhold-Block"], "1")
                        self.assertIn(b"scanner-error", data)
                        self.assertNotIn(SECRET.encode(), data)
            self.assertFalse(self.direct("/stats"))
            self.assertNotIn(SECRET, (state / "audit").read_text())

    def test_inline_completion_paths_forward_clean_and_block_secrets(self):
        paths = (
            "/v1/engines/copilot-codex/completions",
            "/v1/engines/gpt-41-copilot/completions?request=synthetic",
        )
        clean = b'{ "prompt":"ordinary source code", "stream":true }'
        with self.proxy() as (port, state):
            for secure in (False, True):
                for path in paths:
                    with self.subTest(secure=secure, path=path):
                        status, _, data = self.request(
                            port, body=clean, path=path, secure=secure
                        )
                        self.assertEqual(status, 200)
                        self.assertEqual(self.decoded(data), clean)
                        for streaming in (False, True):
                            body = json.dumps(
                                {"prompt": SECRET, "stream": streaming}
                            ).encode()
                            status, headers, data = self.request(
                                port, body=body, path=path, secure=secure
                            )
                            self.assertEqual(status, 200 if streaming else 429)
                            self.assertEqual(headers["X-Withhold-Block"], "1")
                            self.assertIn(b"secret-found", data)
                            self.assertEqual(b"data: [DONE]" in data, streaming)
            self.assertEqual(len(self.direct("/stats")), 4)
            rows = [
                json.loads(line) for line in (state / "audit").read_text().splitlines()
            ]
            self.assertTrue(rows)
            self.assertTrue(all(row["surface"] == "inline" for row in rows))
            self.assertTrue(all(row["api"] == "completions" for row in rows))

    def test_bodyless_nonpost_unknown_path_and_extra_provider_policy(self):
        with self.proxy() as (port, _):
            self.assertEqual(
                self.request(port, b"", method="GET", path="/models")[0], 200
            )
            self.assertEqual(self.request(port, method="PUT")[0], 429)
            self.assertEqual(self.request(port, path="/unknown")[0], 429)
            self.assertEqual(
                self.request(port, headers={"Content-Type": "text/plain"})[0], 429
            )
            self.assertEqual(len(self.direct("/stats")), 1)
        with self.proxy(
            "--extra-hosts", "127.0.0.1", overrides={"WITHHOLD_TEST_ALLOW_HOSTS": ""}
        ) as (port, _):
            status, _, data = self.request(port, path="/custom-api")
            self.assertEqual(status, 200)
            self.assertNotIn(SECRET.encode(), self.decoded(data))

    def test_compression_charset_caps_and_malformed_encoding(self):
        with self.proxy("--max-bytes", "8k") as (port, _):
            for encoding, payload in [
                ("gzip", gzip.compress(BODY)),
                ("deflate", zlib.compress(BODY)),
                ("deflate", self.direct("/encode/raw-deflate", BODY)),
                ("br", self.direct("/encode/br", BODY)),
                ("zstd", self.direct("/encode/zstd", BODY)),
                ("deflate, gzip", gzip.compress(zlib.compress(BODY))),
            ]:
                status, _, data = self.request(
                    port, payload, headers={"Content-Encoding": encoding}
                )
                self.assertEqual(status, 200, data)
                entry = json.loads(data)
                self.assertNotIn("Content-Encoding", entry["headers"])
                self.assertNotIn(
                    SECRET.encode(), base64.b64decode(entry["body_base64"])
                )
            encoded = BODY.decode().encode("utf-16")
            status, _, data = self.request(
                port,
                encoded,
                headers={"Content-Type": "application/json; charset=utf-16"},
            )
            self.assertEqual(status, 200, data)
            self.assertNotIn(SECRET.encode(), self.decoded(data))
            before = len(self.direct("/stats"))
            self.assertEqual(
                self.request(
                    port,
                    gzip.compress(b"x" * 9000),
                    headers={"Content-Encoding": "gzip"},
                )[0],
                429,
            )
            self.assertEqual(
                self.request(port, b"invalid", headers={"Content-Encoding": "gzip"})[0],
                429,
            )
            self.assertEqual(self.request(port, b"x" * 9000)[0], 413)
            self.assertEqual(len(self.direct("/stats")), before)

    def test_upstream_tls_requires_a_trusted_certificate(self):
        with self.proxy(trust_upstream=False) as (port, _):
            self.assertEqual(
                self.request(port, b'{"text":"explain recursion"}', secure=True)[0], 502
            )
            self.assertFalse(self.direct("/stats"))

    def test_sse_first_event_streams_before_upstream_completion(self):
        with self.proxy() as (port, _):
            with contextlib.closing(
                http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            ) as c:
                c.request(
                    "POST",
                    self.urls["http"] + "/v1/messages",
                    b'{"stream":true}',
                    {"Content-Type": "application/json", "X-Test-Stream": "1"},
                )
                r = c.getresponse()
                self.assertEqual(r.readline(), b"data: first\n")
                # The fixture waits for release before writing the final event.
                # A buffering proxy times out here instead of passing this check.
                self.direct("/release")
                self.assertIn(b"[DONE]", r.read())

    def test_twenty_mib_image_passes_unchanged_while_text_is_redacted(self):
        raw = b"\x89PNG\r\n\x1a\n" + b"\xff" * (20 * 1024 * 1024 - 8)
        image = "data:image/png;base64," + base64.b64encode(raw).decode()
        body = {"image": image, "input": f"deploy {SECRET} now"}
        digest = hmac.new(
            self.env["WITHHOLD_PLACEHOLDER_KEY"].encode(),
            SECRET.encode(),
            hashlib.sha256,
        ).hexdigest()
        expected = {**body, "input": f"deploy <WITHHELD_{digest[:16]}> now"}
        expected_hash = hashlib.sha256(
            json.dumps(expected, separators=(",", ":")).encode()
        ).hexdigest()
        with self.proxy() as (port, _):
            status, _, data = self.request(
                port,
                json.dumps(body).encode(),
                secure=True,
                headers={"X-Withhold-Benchmark": "redacted"},
            )
            self.assertEqual(status, 200, data)
            self.assertEqual(json.loads(data)["sha256"], expected_hash)

    def test_open_response_streams_do_not_exhaust_inspection_capacity(self):
        with self.proxy() as (port, _), contextlib.ExitStack() as streams:
            for _ in range(6):
                client = streams.enter_context(
                    contextlib.closing(
                        http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    )
                )
                client.request(
                    "POST",
                    self.urls["http"] + "/v1/messages",
                    b'{"stream":true}',
                    {"Content-Type": "application/json", "X-Test-Stream": "1"},
                )
                response = streams.enter_context(
                    contextlib.closing(client.getresponse())
                )
                self.assertEqual(response.status, 200)
                self.assertEqual(response.readline(), b"data: first\n")
            # Each upload has finished, while all six responses are still open.
            status, _, body = self.request(port)
            self.assertEqual(status, 200, body)
            self.assertNotIn(SECRET.encode(), self.decoded(body))

    def test_connect_authority_cannot_be_changed_inside_tls(self):
        with self.proxy() as (port, _):
            sock, _ = self.tunnel(port)
            sock.sendall(
                b"GET /models HTTP/1.1\r\nHost: api.githubcopilot.com:443\r\nConnection: close\r\n\r\n"
            )
            self.assertIn(b" 421 ", read_headers(sock))
            self.assertFalse(self.direct("/stats"))

    def test_fragmented_compressed_websocket_redaction_and_nonjson_drop(self):
        with self.proxy() as (port, _):
            # A prior HTTPS request initializes upstream HTTP/2 negotiation.
            # Subsequent WebSocket handshakes must still use HTTP/1.1.
            self.assertEqual(
                self.request(port, b'{"text":"explain recursion"}', secure=True)[0], 200
            )
            sock, authority = self.tunnel(port)
            ws = WebSocket(sock, authority, "/chat/completions", compression=True)
            ws.send(BODY, fragmented=True, compressed=True)
            redacted = ws.receive()
            self.assertNotIn(SECRET.encode(), redacted)
            self.assertIn(b"<WITHHELD_", redacted)
            ws.send(b"not json")
            clean = b'{"messages":[{"content":"explain recursion"}]}'
            ws.send(clean, fragmented=True)
            self.assertEqual(ws.receive(), clean)
            self.assertEqual(len(self.direct("/stats")), 3)

    def test_websocket_binary_and_block_findings_stop_session(self):
        for binary in (False, True):
            with (
                self.subTest(binary=binary),
                self.proxy("--chat-mode", "block") as (port, _),
            ):
                sock, authority = self.tunnel(port)
                ws = WebSocket(sock, authority, "/chat/completions")
                ws.send(b"binary" if binary else BODY, kind=2 if binary else 1)
                with self.assertRaises((EOFError, OSError)):
                    ws.receive()
                self.assertFalse(self.direct("/stats"))

    def test_duplicate_keys_stop_websocket_without_upstream_disclosure(self):
        body = ('{"input":"' + SECRET + '","input":"ordinary content"}').encode()
        with self.proxy() as (port, _):
            sock, authority = self.tunnel(port)
            ws = WebSocket(sock, authority, "/chat/completions", compression=True)
            ws.send(body, fragmented=True, compressed=True)
            with self.assertRaises((EOFError, OSError)):
                ws.receive()
            self.assertFalse(self.direct("/stats"))

    def test_websocket_decoded_cap_stops_compression_expansion(self):
        with self.proxy("--max-bytes", "1k") as (port, _):
            sock, authority = self.tunnel(port)
            ws = WebSocket(sock, authority, "/chat/completions", compression=True)
            ws.send(
                json.dumps({"text": "x" * 9000}).encode(),
                compressed=True,
                fragmented=True,
            )
            with self.assertRaises((EOFError, OSError)):
                ws.receive()
            self.assertFalse(self.direct("/stats"))

    def test_websocket_observe_forwards_original_messages(self):
        with self.proxy("--observe", "--chat-mode", "block") as (port, state):
            sock, authority = self.tunnel(port)
            ws = WebSocket(sock, authority, "/chat/completions", compression=True)
            for kind, body in [(1, BODY), (1, b"not json"), (2, b"binary")]:
                ws.send(body, kind=kind, compressed=True)
                self.assertEqual(ws.receive(), body)
            self.assertNotIn(SECRET, (state / "audit").read_text())

    def test_http_chunked_bodies_are_inspected(self):
        with self.proxy() as (port, _):
            with contextlib.closing(
                http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            ) as c:
                c.request(
                    "POST",
                    self.urls["http"] + "/chat/completions",
                    iter([BODY[:10], BODY[10:]]),
                    {"Content-Type": "application/json"},
                    encode_chunked=True,
                )
                response = c.getresponse()
                self.assertEqual(response.status, 200)
                self.assertNotIn(SECRET.encode(), self.decoded(response.read()))

    @unittest.skipUnless(os.name == "posix", "child process inspection uses POSIX ps")
    def test_worker_crashes_block_without_disclosure_and_later_recover(self):
        with self.proxy() as (port, state):
            for _ in range(2):
                self.assertEqual(
                    self.request(port, b'{"text":"explain recursion"}')[0], 200
                )
            result = subprocess.run(
                ["ps", "-axo", "pid=,ppid="],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )
            children = [
                int(fields[0])
                for line in result.stdout.splitlines()
                if len(fields := line.split()) == 2
                and int(fields[1]) == self.native_process.pid
            ]
            self.assertEqual(len(children), 1)
            for pid in children:
                os.kill(pid, signal.SIGKILL)
            before = len(self.direct("/stats"))
            for _ in children:
                self.assertEqual(self.request(port)[0], 429)
            self.assertEqual(len(self.direct("/stats")), before)
            status, _, data = self.request(port)
            self.assertEqual(status, 200, data)
            self.assertNotIn(SECRET.encode(), self.decoded(data))
            self.assertNotIn(SECRET, (state / "audit").read_text())

    def test_invalid_configuration_refuses_startup_and_existing_ca_is_preserved(self):
        key_path = self.root / "ca" / "ca.key"
        before = key_path.read_bytes()
        result = subprocess.run(
            [NATIVE, "init-ca"], env=self.env, capture_output=True, timeout=5
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(key_path.read_bytes(), before)
        for args in [
            ("--port", "0"),
            ("--max-bytes", "0"),
            ("--extra-host-regex", "["),
            ("--extra-hosts", "http://bad"),
            ("--chat-mode", "invalid"),
        ]:
            result = subprocess.run(
                [NATIVE, "serve", *args], env=self.env, capture_output=True, timeout=5
            )
            self.assertEqual(result.returncode, 2, result.stderr)

    def test_http2_connect_inspects_before_http2_upstream(self):
        def frame(kind, flags, stream, payload):
            return (
                len(payload).to_bytes(3, "big")
                + bytes([kind, flags])
                + struct.pack("!I", stream)
                + payload
            )

        def text(value):
            data = value.encode()
            self.assertLess(len(data), 127)
            return bytes([len(data)]) + data

        with self.proxy() as (port, _):
            sock, authority = self.tunnel(port, "h2")
            self.assertEqual(sock.selected_alpn_protocol(), "h2")
            block = (
                b"\x83\x87\x01"
                + text(authority)
                + b"\x04"
                + text("/chat/completions")
                + b"\x0f\x10"
                + text("application/json")
                + b"\x0f\x0d"
                + text(str(len(BODY)))
            )
            sock.sendall(
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                + frame(4, 0, 0, b"")
                + frame(1, 4, 1, block)
                + frame(0, 1, 1, BODY)
            )
            result = b""
            while True:
                header = exact(sock, 9)
                n = int.from_bytes(header[:3], "big")
                kind, flags = header[3:5]
                stream = int.from_bytes(header[5:], "big")
                payload = exact(sock, n)
                self.assertNotIn(kind, (3, 7), payload)
                if kind == 4 and not flags & 1:
                    sock.sendall(frame(4, 1, 0, b""))
                if kind == 0 and stream == 1:
                    result += payload
                if stream == 1 and flags & 1:
                    break
            entry = json.loads(result)
            self.assertEqual(entry["proto"], "HTTP/2.0")
            self.assertNotIn(SECRET.encode(), base64.b64decode(entry["body_base64"]))


if __name__ == "__main__":
    unittest.main()
