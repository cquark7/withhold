#!/usr/bin/env python3
"""Verify native executables and archives, then safely extract and optionally run."""

import argparse
import hashlib
import json
import os
import platform
import re
import socket
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

try:
    from tools.package_native import (
        TARGETS,
        artifact_name,
        validate_version,
    )
except ModuleNotFoundError:
    from package_native import (
        TARGETS,
        artifact_name,
        validate_version,
    )

MAX_ENTRY = 128 * 1024 * 1024


def host_target() -> str:
    system = {"Darwin": "darwin", "Linux": "linux", "Windows": "windows"}.get(
        platform.system()
    )
    # Windows may run an x64 Python on ARM. Require a native Python for --run.
    machine = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(platform.machine().lower())
    return f"{system}-{machine}"


def checksums(directory: Path, version: str) -> dict[str, str]:
    path = directory / "SHA256SUMS"
    if not path.is_file() or path.stat().st_size > 65536:
        raise ValueError("missing or oversized SHA256SUMS")
    allowed = {artifact_name(target, version) for target in TARGETS}
    result = {}
    for row in path.read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", row)
        if not match or match[2] not in allowed or match[2] in result:
            raise ValueError("invalid or duplicate checksum entry")
        result[match[2]] = match[1]
    if not result:
        raise ValueError("empty SHA256SUMS")
    return result


def verify(directory: Path, target: str, version: str) -> dict[str, bytes]:
    name = artifact_name(target, version)
    digest = checksums(directory, version).get(name)
    path = directory / name
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing archive or archive symlink")
    with path.open("rb") as stream:
        if not digest or hashlib.file_digest(stream, "sha256").hexdigest() != digest:
            raise ValueError("archive checksum mismatch")
    binary = "withhold.exe" if target.startswith("windows-") else "withhold"
    expected = {
        binary,
        "README.md",
        "LICENSE",
        "THIRD_PARTY_NOTICES.txt",
        "CONTRACTS.md",
        "BUILD.json",
    }
    files, modes = {}, {}

    def add(name, mode, size, read):
        if name not in expected or name in files:
            raise ValueError("unexpected or duplicate archive member")
        wanted = 0o755 if name == binary else 0o644
        if mode != stat.S_IFREG | wanted:
            raise ValueError("archive member type or permission mismatch")
        limit = MAX_ENTRY if name == binary else 1024 * 1024
        if not 0 < size <= limit:
            raise ValueError("invalid archive member size")
        files[name], modes[name] = read(), wanted
        if len(files[name]) != size:
            raise ValueError("archive member size mismatch")

    if target.startswith("windows-"):
        with zipfile.ZipFile(path) as source:
            for info in source.infolist():
                if info.compress_type != zipfile.ZIP_DEFLATED or info.flag_bits & 1:
                    raise ValueError("archive requires unencrypted Deflate members")
                add(
                    info.filename,
                    info.external_attr >> 16,
                    info.file_size,
                    lambda: source.read(info),
                )
    else:
        with tarfile.open(path, "r:gz") as source:
            for info in source:
                if not info.isfile() or info.pax_headers or info.linkname:
                    raise ValueError("archive requires regular files")
                add(
                    info.name,
                    stat.S_IFREG | info.mode,
                    info.size,
                    lambda: source.extractfile(info).read(),
                )
    if set(files) != expected:
        raise ValueError("archive contents are incomplete")
    metadata = json.loads(files["BUILD.json"])
    if (
        not isinstance(metadata, dict)
        or metadata.get("schema") != 1
        or metadata.get("version") != version
        or metadata.get("target") != target
        or not re.fullmatch(
            r"go[0-9]+\.[0-9]+(?:\.[0-9]+)?", str(metadata.get("go_version", ""))
        )
        or not re.fullmatch(r"[0-9a-f]{64}", str(metadata.get("source_sha256", "")))
        or metadata.get("build") != {"cgo": False, "trimpath": True, "vcs": False}
        or not isinstance(metadata.get("files"), dict)
        or set(metadata["files"]) != expected - {"BUILD.json"}
    ):
        raise ValueError("invalid build metadata")
    for name, info in metadata["files"].items():
        if info != {
            "sha256": hashlib.sha256(files[name]).hexdigest(),
            "size": len(files[name]),
            "mode": modes[name],
        }:
            raise ValueError("content differs from build metadata")
    return files


def extract(files: dict[str, bytes], destination: Path):
    # Members have already been reduced to fixed basenames. Never use extractall.
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        path = destination / name
        with path.open("xb") as stream:
            stream.write(data)
        path.chmod(0o755 if name in ("withhold", "withhold.exe") else 0o644)


def smoke(destination: Path, target: str, version: str):
    if target != host_target():
        raise ValueError(
            "--run requires the matching native OS and Python architecture"
        )
    binary = (
        destination / ("withhold.exe" if target.startswith("windows-") else "withhold")
    ).resolve()
    with tempfile.TemporaryDirectory(prefix="withhold-archive-test-") as temporary:
        root = Path(temporary)
        empty = root / "empty-path"
        empty.mkdir()
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("WITHHOLD_", "BETTERLEAKS_", "GITLEAKS_"))
        }
        env.update(
            HOME=str(root),
            USERPROFILE=str(root),
            APPDATA=str(root / "appdata"),
            XDG_CONFIG_HOME=str(root / "config"),
            PATH=str(empty),
            WITHHOLD_DIR=str(root / "state"),
            WITHHOLD_PLACEHOLDER_KEY="isolated-archive-smoke",
        )
        # Reserve a free non-listening port so doctor never probes a user service.
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = str(reservation.getsockname()[1])
            for args in (
                ("version",),
                ("--help",),
                ("setup", "--trust", "manual"),
                ("doctor", "--json", "--port", port),
            ):
                result = subprocess.run(
                    [str(binary), *args],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=True,
                )
                if (
                    args == ("version",)
                    and result.stdout.strip()
                    != f"withhold {version} (betterleaks 1.10.1)"
                ):
                    raise ValueError("extracted executable version mismatch")
                if args[0] == "doctor":
                    report = json.loads(result.stdout)
                    if report.get("schema") != 2 or not report.get("ok"):
                        raise ValueError("extracted executable failed native doctor")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--targets", nargs="+", choices=TARGETS, default=TARGETS)
    parser.add_argument("--extract", type=Path, required=True)
    parser.add_argument(
        "--run",
        action="store_true",
        help="execute smoke checks; only a matching host target is allowed",
    )
    args = parser.parse_args()
    try:
        validate_version(args.version)
        if len(set(args.targets)) != len(args.targets):
            raise ValueError("targets must be unique")
        if args.run and args.targets != [host_target()]:
            raise ValueError("--run requires exactly the matching native target")
        for target in args.targets:
            files = verify(args.artifacts, target, args.version)
            destination = args.extract / target
            extract(files, destination)
            if args.run:
                smoke(destination, target, args.version)
            print(
                f"Verified {target}"
                + (" and executed extracted runtime" if args.run else "")
            )
    except (
        ValueError,
        OSError,
        tarfile.TarError,
        zipfile.BadZipFile,
        subprocess.SubprocessError,
    ) as error:
        parser.exit(1, f"verification failed: {error}\n")


if __name__ == "__main__":
    main()
