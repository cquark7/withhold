"""Unit+e2e tests for tools/proof/proxy_logger.py (stdlib unittest only).

Run: python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent / "tools" / "proof" / "proxy_logger.py"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def echo_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(b"ECHO:" + data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


class ProxyLoggerTest(unittest.TestCase):
    def test_connect_tunnel_echoes_and_logs(self):
        async def scenario():
            echo_srv = await asyncio.start_server(echo_server, "127.0.0.1", 0)
            echo_port = echo_srv.sockets[0].getsockname()[1]
            proxy_port = free_port()
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl")
            tmp.close()
            log_path = tmp.name
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                str(HARNESS),
                "--bind",
                "127.0.0.1",
                "--port",
                str(proxy_port),
                "--log",
                log_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                # wait for listen
                for _ in range(50):
                    try:
                        r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
                        w.close()
                        break
                    except OSError:
                        await asyncio.sleep(0.1)
                else:
                    self.fail("proxy did not start")
                # CONNECT to echo server through proxy (with Proxy-Authorization to test redaction)
                r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
                req = (
                    f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{echo_port}\r\n"
                    f"Proxy-Authorization: Basic c2VjcmV0OnNlY3JldA==\r\n"
                    f"\r\n"
                )
                w.write(req.encode())
                await w.drain()
                resp = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), timeout=5)
                self.assertIn(b"200", resp, f"expected 200, got {resp!r}")
                w.write(b"hello")
                await w.drain()
                data = await asyncio.wait_for(r.read(1024), timeout=5)
                self.assertIn(b"hello", data, f"echo failed, got {data!r}")
                w.close()
                await asyncio.sleep(0.5)
            finally:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except TimeoutError:
                    proc.kill()
                echo_srv.close()
                await echo_srv.wait_closed()
            # verify log
            lines = Path(log_path).read_text(encoding="utf-8").splitlines()
            events = [json.loads(l) for l in lines if l.strip()]
            kinds = {e.get("event") for e in events}
            self.assertIn("proxy_start", kinds)
            self.assertIn("connect_attempt", kinds)
            self.assertIn("connect_ok", kinds)
            self.assertIn("close", kinds)
            # Proxy-Authorization VALUE must never appear in log
            blob = "\n".join(lines)
            self.assertNotIn("c2VjcmV0OnNlY3JldA", blob)
            # attempt must record presence boolean + correct target
            attempts = [e for e in events if e.get("event") == "connect_attempt"]
            self.assertTrue(
                any(
                    a.get("target_host") == "127.0.0.1"
                    and a.get("target_port") == echo_port
                    and a.get("has_proxy_auth") is True
                    for a in attempts
                )
            )
            Path(log_path).unlink(missing_ok=True)

        asyncio.run(scenario())

    def test_non_connect_gets_400(self):
        async def scenario():
            spec = importlib.util.spec_from_file_location("proxy_logger", str(HARNESS))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            events = []

            class FakeLogger:
                async def emit(self, obj):
                    events.append(obj)

            async def on_client(r, w):
                await mod.handle_client(r, w, FakeLogger())

            srv = await asyncio.start_server(on_client, "127.0.0.1", 0)
            port = srv.sockets[0].getsockname()[1]
            try:
                r, w = await asyncio.open_connection("127.0.0.1", port)
                w.write(
                    b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
                )
                await w.drain()
                resp = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), timeout=5)
                self.assertIn(b"400", resp)
                w.close()
            finally:
                srv.close()
                await srv.wait_closed()
            self.assertIn("bad_request", [e.get("event") for e in events])

        asyncio.run(scenario())

    def test_connect_fail_logs_502(self):
        async def scenario():
            proxy_port = free_port()
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl")
            tmp.close()
            log_path = tmp.name
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                str(HARNESS),
                "--port",
                str(proxy_port),
                "--log",
                log_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                for _ in range(50):
                    try:
                        r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
                        w.close()
                        break
                    except OSError:
                        await asyncio.sleep(0.1)
                # CONNECT to a port that is (almost certainly) closed
                closed_port = free_port()
                r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
                w.write(
                    f"CONNECT 127.0.0.1:{closed_port} HTTP/1.1\r\nHost: x\r\n\r\n".encode()
                )
                await w.drain()
                resp = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), timeout=5)
                self.assertIn(b"502", resp)
                w.close()
                await asyncio.sleep(0.5)
            finally:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except TimeoutError:
                    proc.kill()
            events = [
                json.loads(l)
                for l in Path(log_path).read_text().splitlines()
                if l.strip()
            ]
            self.assertIn("connect_fail", {e.get("event") for e in events})
            Path(log_path).unlink(missing_ok=True)

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
