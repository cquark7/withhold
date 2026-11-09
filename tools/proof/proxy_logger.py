#!/usr/bin/env python3
"""CONNECT-only logging forward proxy (stdlib only, no MITM, no decryption).

Purpose: check that VS Code Copilot routes through http.proxy by logging each
CONNECT host:port without touching TLS bytes.

This is a development diagnostic, not a scanner or proof of body inspection.
Logs contain connection metadata and error text; use synthetic traffic only.

- Listens on 127.0.0.1:PORT (default 8080).
- Handles `CONNECT host:port` by TCP-tunneling to upstream and relaying bytes.
- Non-CONNECT requests get 400 (Copilot traffic is HTTPS => CONNECT only).
- Logs JSONL events: connect_attempt / connect_ok / connect_fail / close / bad_request.
- Never logs Proxy-Authorization values (presence boolean only).

Usage:
    python3 tools/proof/proxy_logger.py --port 8080 --log /tmp/proxy.jsonl
"""

import argparse
import asyncio
import datetime
import json
import sys


def now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


class JsonlLogger:
    def __init__(self, path: str):
        self.path = path
        self._lock = asyncio.Lock()
        self._fh = open(path, "a", encoding="utf-8")

    async def emit(self, obj: dict):
        obj = {"ts": now_iso(), **obj}
        line = json.dumps(obj, separators=(",", ":"))
        async with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self):
        try:
            self._fh.close()
        except Exception:
            pass


async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> int:
    total = 0
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
            total += len(data)
    except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception:
        pass
    return total


def parse_headers(raw: bytes) -> tuple[str, dict]:
    """Return (request_line, headers dict lowercased)."""
    text = raw.decode("iso-8859-1")  # infallible: every byte maps
    lines = text.split("\r\n")
    request_line = lines[0] if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    return request_line, headers


async def handle_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    logger: JsonlLogger,
):
    peer = client_writer.get_extra_info("peername")
    client_str = f"{peer[0]}:{peer[1]}" if peer else "unknown"
    upstream_writer: asyncio.StreamWriter | None = None
    target_host = ""
    target_port = 0
    started = asyncio.get_running_loop().time()
    bytes_c2s = 0
    bytes_s2c = 0
    try:
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = await asyncio.wait_for(client_reader.read(4096), timeout=15)
            if not chunk:
                break
            raw += chunk
            if len(raw) > 65536:
                break
        if not raw:
            client_writer.close()
            return
        request_line, headers = parse_headers(raw)
        parts = request_line.split()
        if len(parts) < 3:
            client_writer.write(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
            )
            await client_writer.drain()
            await logger.emit(
                {
                    "event": "bad_request",
                    "client": client_str,
                    "request_line": request_line[:200],
                }
            )
            client_writer.close()
            return
        method, target = parts[0].upper(), parts[1]
        has_proxy_auth = "proxy-authorization" in headers

        if method == "CONNECT":
            # target is host:port
            if ":" in target:
                target_host, port_s = target.rsplit(":", 1)
                try:
                    target_port = int(port_s)
                except ValueError:
                    target_port = 443
            else:
                target_host, target_port = target, 443
            await logger.emit(
                {
                    "event": "connect_attempt",
                    "client": client_str,
                    "target_host": target_host,
                    "target_port": target_port,
                    "has_proxy_auth": has_proxy_auth,
                }
            )
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(target_host, target_port), timeout=15
                )
            except Exception as e:
                await logger.emit(
                    {
                        "event": "connect_fail",
                        "client": client_str,
                        "target_host": target_host,
                        "target_port": target_port,
                        "error": f"{type(e).__name__}: {e}"[:300],
                    }
                )
                try:
                    client_writer.write(
                        b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
                    )
                    await client_writer.drain()
                except Exception:
                    pass
                client_writer.close()
                return
            try:
                client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await client_writer.drain()
            except Exception:
                pass
            await logger.emit(
                {
                    "event": "connect_ok",
                    "client": client_str,
                    "target_host": target_host,
                    "target_port": target_port,
                }
            )

            # Bidirectional relay. Count bytes each way.
            async def c2s():
                nonlocal bytes_c2s
                bytes_c2s = await relay(client_reader, upstream_writer)

            async def s2c():
                nonlocal bytes_s2c
                bytes_s2c = await relay(upstream_reader, client_writer)

            await asyncio.gather(c2s(), s2c())
        else:
            # Copilot traffic is HTTPS => CONNECT only.
            client_writer.write(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
            )
            await client_writer.drain()
            await logger.emit(
                {
                    "event": "bad_request",
                    "client": client_str,
                    "request_line": request_line[:200],
                }
            )
            client_writer.close()
    except TimeoutError:
        try:
            client_writer.close()
        except Exception:
            pass
    except Exception as e:
        try:
            await logger.emit(
                {
                    "event": "handler_error",
                    "client": client_str,
                    "target_host": target_host,
                    "target_port": target_port,
                    "error": f"{type(e).__name__}: {e}"[:300],
                }
            )
        except Exception:
            pass
        try:
            client_writer.close()
        except Exception:
            pass
    finally:
        dur_ms = int((asyncio.get_running_loop().time() - started) * 1000)
        try:
            if upstream_writer is not None:
                try:
                    upstream_writer.close()
                except Exception:
                    pass
            try:
                client_writer.close()
            except Exception:
                pass
        finally:
            try:
                await logger.emit(
                    {
                        "event": "close",
                        "client": client_str,
                        "target_host": target_host,
                        "target_port": target_port,
                        "bytes_c2s": bytes_c2s,
                        "bytes_s2c": bytes_s2c,
                        "duration_ms": dur_ms,
                    }
                )
            except Exception:
                pass


async def main_async(args):
    logger = JsonlLogger(args.log)
    await logger.emit({"event": "proxy_start", "bind": args.bind, "port": args.port})
    print(f"[proxy] listening on {args.bind}:{args.port}, log={args.log}", flush=True)

    async def on_client(r, w):
        await handle_client(r, w, logger)

    server = await asyncio.start_server(on_client, args.bind, args.port)
    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        pass
    finally:
        await logger.emit({"event": "proxy_stop"})
        logger.close()


def main():
    ap = argparse.ArgumentParser(description="CONNECT-only logging proxy (no MITM)")
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--log", default="/tmp/copilot-proxy.jsonl")
    args = ap.parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[proxy] stopped", flush=True)


if __name__ == "__main__":
    sys.exit(main())
