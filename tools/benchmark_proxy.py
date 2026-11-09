#!/usr/bin/env python3
"""Measure the complete native HTTPS proxy with synthetic loopback traffic."""

import argparse
import base64
import concurrent.futures
import contextlib
import gzip
import hashlib
import hmac
import http.client
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tests.test_native_proxy import SECRET, NativeProxyTests, WebSocket  # noqa: E402


def processes(parent):
    rows = subprocess.check_output(
        ["ps", "-axo", "pid=,ppid=,rss="], text=True, timeout=5
    )
    table = [tuple(map(int, row.split())) for row in rows.splitlines() if row.strip()]
    owned = {parent}
    for _ in range(4):
        owned.update(pid for pid, ppid, _ in table if ppid in owned)
    selected = [(pid, rss) for pid, _, rss in table if pid in owned]
    return {
        "rss_mib": round(sum(rss for _, rss in selected) / 1024, 2),
        "processes": len(selected),
    }


def summary(timings, wall):
    return {
        "samples": len(timings),
        "p50_ms": round(statistics.median(timings), 3),
        "p95_ms": round(sorted(timings)[math.ceil(len(timings) * 0.95) - 1], 3),
        "requests_per_second": round(len(timings) / wall, 2),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--large-mib", type=int, default=31)
    parser.add_argument("--idle-seconds", type=int, default=62)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.samples < 2 or not 1 <= args.large_mib <= 31 or args.idle_seconds < 61:
        parser.error("samples >=2, large-mib 1..31, idle-seconds >=61 required")
    if platform.system() not in ("Darwin", "Linux"):
        parser.error("RSS sampling currently supports macOS/Linux ps only")
    fixture = NativeProxyTests
    fixture.setUpClass()
    test = fixture()
    result = {
        "schema": 2,
        "scope": "synthetic HTTPS CONNECT and WebSockets; proxy plus every scanner child",
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "binary_bytes": Path(os.environ["WITHHOLD_TEST_NATIVE"]).stat().st_size,
        "memory_method": "summed ps RSS every 100ms and after each workload phase; shared pages counted per process; short peaks can be missed",
        "warmup": 3,
        "results": [],
        "compressed": [],
        "media": [],
        "websocket": [],
        "concurrent": [],
    }
    samples = []
    halt = threading.Event()
    try:
        start = time.perf_counter()
        with test.proxy() as (port, _):
            result["startup_ms"] = round((time.perf_counter() - start) * 1000, 2)
            parent = test.native_process.pid
            result["startup_memory"] = processes(parent)

            def monitor():
                while not halt.is_set():
                    samples.append(processes(parent))
                    halt.wait(0.1)

            sampler = threading.Thread(target=monitor)
            sampler.start()
            target = urlsplit(test.urls["https"])

            def connection():
                c = http.client.HTTPSConnection(
                    "127.0.0.1", port, context=test.trust, timeout=30
                )
                c.set_tunnel(target.hostname, target.port)
                return c

            def send(c, body, kind, encoding=None, expected_sha256=None):
                started = time.perf_counter()
                headers = {
                    "Content-Type": "application/json",
                    "X-Withhold-Benchmark": kind,
                }
                if encoding:
                    headers["Content-Encoding"] = encoding
                c.request(
                    "POST",
                    "/chat/completions",
                    body,
                    headers,
                )
                response = c.getresponse()
                data = response.read()
                report = json.loads(data)
                if response.status != 200 or not report.get("safe"):
                    raise RuntimeError("benchmark request failed inspection")
                if expected_sha256 and report.get("sha256") != expected_sha256:
                    raise RuntimeError(
                        "attachment or surrounding text changed unexpectedly"
                    )
                return (time.perf_counter() - started) * 1000

            try:
                with contextlib.closing(connection()) as c:
                    result["first_request_ms"] = round(
                        send(c, b'{"input":"explain this function"}', "clean"), 3
                    )
                    for size in (2048, 128 * 1024, 1024 * 1024):
                        for kind in ("clean", "redacted"):
                            text = (
                                "Explain this function and suggest a clearer name.\n"
                                * (size // 48 + 1)
                            )[:size]
                            if kind == "redacted":
                                text += f'\ntoken = "{SECRET}"\n'
                            body = json.dumps({"input": text}).encode()
                            for _ in range(3):
                                send(c, body, kind)
                            began = time.perf_counter()
                            times = [send(c, body, kind) for _ in range(args.samples)]
                            result["results"].append(
                                {
                                    "case": kind,
                                    "text_bytes": size,
                                    "payload_bytes": len(body),
                                    "concurrency": 1,
                                    **summary(times, time.perf_counter() - began),
                                }
                            )
                    result["post_serial"] = processes(parent)
                    image = (
                        "data:image/png;base64,"
                        + base64.b64encode(
                            b"\x89PNG\r\n\x1a\n" + b"\xff" * (20 * 1024 * 1024 - 8)
                        ).decode()
                    )
                    digest = hmac.new(
                        test.env["WITHHOLD_PLACEHOLDER_KEY"].encode(),
                        SECRET.encode(),
                        hashlib.sha256,
                    ).hexdigest()[:16]
                    for kind in ("clean", "redacted"):
                        prompt = "Explain this image."
                        source = {
                            "image": image,
                            "input": prompt
                            if kind == "clean"
                            else prompt + " " + SECRET,
                        }
                        body = json.dumps(source).encode()
                        expected = {
                            **source,
                            "input": prompt + " <WITHHELD_" + digest + ">",
                        }
                        expected_hash = hashlib.sha256(
                            body
                            if kind == "clean"
                            else json.dumps(expected, separators=(",", ":")).encode()
                        ).hexdigest()
                        phase_start = len(samples)
                        for _ in range(3):
                            send(c, body, kind, expected_sha256=expected_hash)
                        began = time.perf_counter()
                        times = [
                            send(c, body, kind, expected_sha256=expected_hash)
                            for _ in range(args.samples)
                        ]
                        after = processes(parent)
                        result["media"].append(
                            {
                                "case": kind,
                                "attachment_bytes": 20 * 1024 * 1024,
                                "payload_bytes": len(body),
                                "concurrency": 1,
                                "upstream_sha256_verified": True,
                                "after": after,
                                "observed_high_water": max(
                                    samples[phase_start:] + [after],
                                    key=lambda v: v["rss_mib"],
                                ),
                                **summary(times, time.perf_counter() - began),
                            }
                        )
                    del image, source, expected, body
                    for kind in ("clean", "redacted"):
                        text = "explain this function. " * 48000
                        if kind == "redacted":
                            text += f'\ntoken = "{SECRET}"\n'
                        body = json.dumps({"input": text}).encode()
                        wire = gzip.compress(body, mtime=0)
                        for _ in range(3):
                            send(c, wire, kind, "gzip")
                        began = time.perf_counter()
                        times = [
                            send(c, wire, kind, "gzip") for _ in range(args.samples)
                        ]
                        result["compressed"].append(
                            {
                                "case": kind,
                                "encoding": "gzip",
                                "payload_bytes": len(body),
                                "wire_bytes": len(wire),
                                **summary(times, time.perf_counter() - began),
                            }
                        )
                    body = json.dumps(
                        {"input": "explain this function. " * 48000}
                    ).encode()

                    def burst(_):
                        with contextlib.closing(connection()) as client:
                            return send(client, body, "clean")

                    for concurrency in (3, 6):
                        # Warm additional workers before collecting the burst.
                        with concurrent.futures.ThreadPoolExecutor(
                            max_workers=concurrency
                        ) as executor:
                            list(executor.map(burst, range(concurrency)))
                            began = time.perf_counter()
                            times = list(
                                executor.map(burst, range(args.samples * concurrency))
                            )
                        result["concurrent"].append(
                            {
                                "payload_bytes": len(body),
                                "concurrency": concurrency,
                                **summary(times, time.perf_counter() - began),
                            }
                        )
                    result["post_burst"] = processes(parent)
                    for compressed in (False, True):
                        sock, authority = test.tunnel(port)
                        try:
                            ws = WebSocket(
                                sock,
                                authority,
                                "/chat/completions",
                                compression=compressed,
                                benchmark=True,
                            )
                            for size in (2048, 128 * 1024):
                                for kind in ("clean", "redacted"):
                                    text = (
                                        "explain this function. " * (size // 20 + 1)
                                    )[:size]
                                    if kind == "redacted":
                                        text += f'\ntoken = "{SECRET}"\n'
                                    body = json.dumps({"input": text}).encode()
                                    # Prepare fresh masked frames outside the timer;
                                    # Python masking is not native proxy work.
                                    frames = [
                                        ws.frames(
                                            body, fragmented=True, compressed=compressed
                                        )
                                        for _ in range(args.samples + 3)
                                    ]
                                    times = []
                                    for i, frame in enumerate(frames):
                                        began = time.perf_counter()
                                        sock.sendall(frame)
                                        reply = ws.receive()
                                        elapsed = (time.perf_counter() - began) * 1000
                                        if (
                                            SECRET.encode() in reply
                                            or (
                                                kind == "redacted"
                                                and b"<WITHHELD_" not in reply
                                            )
                                            or (kind == "clean" and reply != body)
                                        ):
                                            raise RuntimeError(
                                                "WebSocket inspection failed"
                                            )
                                        if i >= 3:
                                            times.append(elapsed)
                                    result["websocket"].append(
                                        {
                                            "case": kind,
                                            "text_bytes": size,
                                            "payload_bytes": len(body),
                                            "compressed": compressed,
                                            "fragmented": True,
                                            "client_frame_encoding_timed": False,
                                            **summary(times, sum(times) / 1000),
                                        }
                                    )
                        finally:
                            sock.close()
                    body = json.dumps(
                        {
                            "input": "explain this function. "
                            * (args.large_mib * 1024 * 1024 // 23)
                        }
                    ).encode()
                    result["large_request"] = {
                        "payload_bytes": len(body),
                        "latency_ms": round(send(c, body, "clean"), 3),
                    }
                    result["post_large"] = processes(parent)
                    wire = gzip.compress(body, mtime=0)
                    result["large_compressed_request"] = {
                        "payload_bytes": len(body),
                        "wire_bytes": len(wire),
                        "latency_ms": round(send(c, wire, "clean", "gzip"), 3),
                    }
                    result["post_large_compressed"] = processes(parent)
                    result["observed_high_water"] = max(
                        samples
                        + [
                            result["post_burst"],
                            result["post_large"],
                            result["post_large_compressed"],
                        ],
                        key=lambda value: value["rss_mib"],
                    )
                    print(
                        "Requests complete; measuring default worker idle reclamation.",
                        file=sys.stderr,
                        flush=True,
                    )
                    idle_end = time.monotonic() + args.idle_seconds
                    while time.monotonic() < idle_end:
                        time.sleep(min(30, max(0, idle_end - time.monotonic())))
                    result["idle_seconds"] = args.idle_seconds
                    result["after_idle"] = processes(parent)
                    with contextlib.closing(connection()) as restarted:
                        result["restart_request_ms"] = round(
                            send(
                                restarted,
                                b'{"input":"explain this function"}',
                                "clean",
                            ),
                            3,
                        )
                    result["after_restart"] = processes(parent)
            finally:
                halt.set()
                sampler.join()
    finally:
        test.doCleanups()
        fixture.doClassCleanups()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
