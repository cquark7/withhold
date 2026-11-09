#!/usr/bin/env python3
"""Build deterministic native executables, archives, notices, and a SHA-256 manifest."""

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

try:
    from tools.native_notices import build_notices
except ModuleNotFoundError:
    from native_notices import build_notices

ROOT = Path(__file__).resolve().parent.parent
TARGETS = (
    "darwin-amd64",
    "darwin-arm64",
    "linux-amd64",
    "linux-arm64",
    "windows-amd64",
    "windows-arm64",
)
_NUMBER = r"(?:0|[1-9][0-9]*)"
_IDENTIFIER = rf"(?:{_NUMBER}|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
_VERSION = re.compile(
    rf"v?{_NUMBER}\.{_NUMBER}\.{_NUMBER}(?:-{_IDENTIFIER}(?:\.{_IDENTIFIER})*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


def validate_version(value: str) -> str:
    if len(value) > 128 or (value != "dev" and not _VERSION.fullmatch(value)):
        raise ValueError("version must be SemVer (optionally prefixed with v), or dev")
    return value


def artifact_name(target: str, version: str) -> str:
    validate_version(version)
    if target not in TARGETS:
        raise ValueError("unsupported target")
    suffix = ".zip" if target.startswith("windows-") else ".tar.gz"
    return f"withhold-{version}-{target}{suffix}"


def binary_name(target: str, version: str) -> str:
    validate_version(version)
    if target not in TARGETS:
        raise ValueError("unsupported target")
    return (
        f"withhold-{version}-{target}{'.exe' if target.startswith('windows-') else ''}"
    )


def notices_name(target: str, version: str) -> str:
    validate_version(version)
    if target not in TARGETS:
        raise ValueError("unsupported target")
    return f"withhold-{version}-{target}-NOTICES.txt"


def standalone_notices(license_text: bytes, notices: bytes) -> bytes:
    return b"withhold license\n\n" + license_text + b"\n\n" + notices


def source_digest() -> str:
    """Fingerprint runtime source and dependencies, including uncommitted edits."""
    paths = [ROOT / "go.mod", ROOT / "go.sum"]
    paths += [
        p
        for directory in ("cmd", "internal")
        for p in (ROOT / directory).rglob("*.go")
        if not p.name.endswith("_test.go")
    ]
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def archive_document(relative_path: str, version: str) -> bytes:
    """Resolve links for the archive's flat layout, retaining bundled references."""
    source = ROOT / relative_path
    bundled = {
        ROOT / "docs" / "usage.md": "README.md",
        ROOT / "CONTRACTS.md": "CONTRACTS.md",
        ROOT / "LICENSE": "LICENSE",
    }
    ref = quote(version, safe="") if version.startswith("v") else "main"

    def rewrite(match):
        destination = urlsplit(match[2])
        if destination.scheme or destination.netloc or not destination.path:
            return match[0]
        target = (source.parent / unquote(destination.path)).resolve()
        relative = target.relative_to(ROOT).as_posix()
        if not target.exists():
            raise ValueError(f"documentation link does not exist: {relative}")
        link = bundled.get(target)
        if link is None:
            link = f"https://github.com/cquark7/withhold/blob/{ref}/{quote(relative)}"
        if destination.fragment:
            link += "#" + destination.fragment
        return match[1] + link + ")"

    text = re.sub(
        r"(\[[^\]\n]*\]\()([^)\s]+)\)",
        rewrite,
        source.read_text(encoding="utf-8"),
    )
    return text.encode("utf-8")


def archive(
    binary: Path,
    output: Path,
    target: str,
    version: str,
    *,
    go_version: str,
    notices: bytes,
):
    if not notices.strip():
        raise ValueError("dependency notices are required")
    path = output / artifact_name(target, version)
    binary_name = "withhold.exe" if target.startswith("windows-") else "withhold"
    content = [
        (binary_name, binary.read_bytes(), 0o755),
        ("LICENSE", (ROOT / "LICENSE").read_bytes(), 0o644),
        ("THIRD_PARTY_NOTICES.txt", notices, 0o644),
        ("README.md", archive_document("docs/usage.md", version), 0o644),
        ("CONTRACTS.md", archive_document("CONTRACTS.md", version), 0o644),
    ]
    metadata = {
        "schema": 1,
        "version": version,
        "target": target,
        "go_version": go_version,
        "source_sha256": source_digest(),
        "build": {"cgo": False, "trimpath": True, "vcs": False},
        "files": {
            name: {
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "mode": mode,
            }
            for name, data, mode in content
        },
    }
    content.append(
        (
            "BUILD.json",
            (json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode(),
            0o644,
        )
    )
    if target.startswith("windows-"):
        with zipfile.ZipFile(path, "x") as result:
            for name, data, mode in content:
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (0o100000 | mode) << 16
                result.writestr(
                    info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9
                )
    else:
        # Suppress the gzip source filename and wall-clock header timestamp.
        with (
            path.open("xb") as raw,
            gzip.GzipFile(
                filename="", fileobj=raw, mode="wb", mtime=0, compresslevel=9
            ) as compressed,
        ):
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
            ) as result:
                for name, data, mode in content:
                    info = tarfile.TarInfo(name)
                    info.size, info.mode = len(data), mode
                    result.addfile(info, io.BytesIO(data))
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--version", default=os.environ.get("WITHHOLD_VERSION", "dev"))
    parser.add_argument("--targets", nargs="+", choices=TARGETS, default=TARGETS)
    args = parser.parse_args()
    try:
        version = validate_version(args.version)
    except ValueError as error:
        parser.error(str(error))
    if len(set(args.targets)) != len(args.targets):
        parser.error("targets must be unique")
    args.output.mkdir(parents=True, exist_ok=True)
    if any(args.output.iterdir()):
        parser.error("output directory must be empty to avoid mixing builds")
    checksums = []
    # Ambient build flags and workspaces must not change a release silently.
    base_env = dict(
        os.environ,
        GOFLAGS="",
        GOWORK="off",
        GOEXPERIMENT="",
        CGO_ENABLED="0",
        GOAMD64="v1",
        GOARM64="v8.0",
    )
    go_version = subprocess.check_output(
        ["go", "env", "GOVERSION"], cwd=ROOT, env=base_env, text=True
    ).strip()
    with tempfile.TemporaryDirectory(prefix="withhold-release-") as temporary:
        for target in sorted(args.targets):
            goos, goarch = target.split("-")
            executable = "withhold.exe" if goos == "windows" else "withhold"
            binary = Path(temporary) / target / executable
            binary.parent.mkdir()
            env = dict(base_env, GOOS=goos, GOARCH=goarch)
            subprocess.run(
                [
                    "go",
                    "build",
                    "-trimpath",
                    "-buildvcs=false",
                    f"-ldflags=-s -w -X main.version={version}",
                    "-o",
                    str(binary),
                    "./cmd/withhold",
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            notices = build_notices(binary, cwd=ROOT, env=env)
            artifact = archive(
                binary,
                args.output,
                target,
                version,
                go_version=go_version,
                notices=notices,
            )
            standalone = args.output / binary_name(target, version)
            standalone.write_bytes(binary.read_bytes())
            standalone.chmod(0o755)
            notice_file = args.output / notices_name(target, version)
            notice_file.write_bytes(
                standalone_notices((ROOT / "LICENSE").read_bytes(), notices)
            )
            for path in (artifact, standalone, notice_file):
                checksums.append(
                    (hashlib.sha256(path.read_bytes()).hexdigest(), path.name)
                )
    manifest = "".join(f"{digest}  {name}\n" for digest, name in checksums)
    (args.output / "SHA256SUMS").write_text(manifest, encoding="ascii")
    print(f"Packaged {len(args.targets)} native builds in {args.output}")


if __name__ == "__main__":
    main()
