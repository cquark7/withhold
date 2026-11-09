"""Validate standalone archive contents and actual executable compression."""

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import tools.package_native as packaging
from tools.check_docs import check_links
from tools.native_notices import build_notices
from tools.package_native import (
    ROOT,
    archive,
    binary_name,
    notices_name,
    standalone_notices,
    validate_version,
)
from tools.verify_native import extract, host_target, smoke, verify, verify_release

VERSION = "0.0.0-test"
NOTICES = b"Synthetic dependency license and copyright notice\n"


class NativeArchiveTests(unittest.TestCase):
    def test_packager_publishes_binaries_notices_and_archives_for_all_targets(self):
        def build(command, **kwargs):
            self.assertEqual(command[:2], ["go", "build"])
            Path(command[command.index("-o") + 1]).write_bytes(b"synthetic binary")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                patch.object(
                    sys,
                    "argv",
                    ["package_native", "--output", str(root), "--version", VERSION],
                ),
                patch.object(
                    packaging.subprocess, "check_output", return_value="go1.26.10\n"
                ),
                patch.object(packaging.subprocess, "run", side_effect=build),
                patch.object(packaging, "build_notices", return_value=NOTICES),
            ):
                packaging.main()
            self.assertEqual(len((root / "SHA256SUMS").read_text().splitlines()), 18)
            for target in packaging.TARGETS:
                with self.subTest(target=target):
                    verify_release(root, target, VERSION)

    def test_archive_documentation_links_work_in_the_flat_layout(self):
        for target in ("linux-amd64", "windows-arm64"):
            with (
                self.subTest(target=target),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                binary = root / "fixture-binary"
                binary.write_bytes(b"synthetic executable")
                version = "v0.1.0-rc.1"
                path = archive(
                    binary,
                    root,
                    target,
                    version,
                    go_version="go1.26.10",
                    notices=NOTICES,
                )
                self.manifest(root, path)
                files = verify(root, target, version)
                destination = root / "extracted"
                extract(files, destination)
                for name in ("README.md", "CONTRACTS.md"):
                    self.assertEqual(check_links(destination / name, destination), [])
                guide = files["README.md"]
                self.assertIn(b"(CONTRACTS.md#scope-and-traffic-policy)", guide)
                self.assertIn(
                    b"https://github.com/cquark7/withhold/blob/v0.1.0-rc.1/docs/configuration.md",
                    guide,
                )

    def test_windows_archive_compresses_binary_and_ships_native_instructions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "withhold.exe"
            binary.write_bytes(b"synthetic executable content\n" * 8192)
            path = archive(
                binary,
                root,
                "windows-arm64",
                VERSION,
                go_version="go1.26.10",
                notices=NOTICES,
            )
            with zipfile.ZipFile(path) as result:
                info = result.getinfo("withhold.exe")
                self.assertEqual(info.compress_type, zipfile.ZIP_DEFLATED)
                self.assertLess(info.compress_size, info.file_size // 2)
                self.assertEqual(result.read("withhold.exe"), binary.read_bytes())
                self.assertEqual(
                    set(result.namelist()),
                    {
                        "withhold.exe",
                        "LICENSE",
                        "THIRD_PARTY_NOTICES.txt",
                        "README.md",
                        "CONTRACTS.md",
                        "BUILD.json",
                    },
                )
                self.assertEqual(result.read("THIRD_PARTY_NOTICES.txt"), NOTICES)
                self.assertIn(b"withhold setup", result.read("README.md"))

    def test_unix_archive_preserves_executable_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "withhold"
            binary.write_bytes(b"synthetic executable")
            path = archive(
                binary,
                root,
                "linux-amd64",
                VERSION,
                go_version="go1.26.10",
                notices=NOTICES,
            )
            with tarfile.open(path) as result:
                self.assertEqual(result.getmember("withhold").mode, 0o755)
                self.assertEqual(
                    set(result.getnames()),
                    {
                        "withhold",
                        "LICENSE",
                        "THIRD_PARTY_NOTICES.txt",
                        "README.md",
                        "CONTRACTS.md",
                        "BUILD.json",
                    },
                )
                self.assertEqual(
                    result.extractfile("withhold").read(), binary.read_bytes()
                )

    def test_versions_cannot_inject_paths_or_build_flags(self):
        for value in (
            "",
            "../1.0.0",
            "1.0.0 -X main.version=bad",
            "1.0.0\n",
            "1.0.0;true",
            "01.0.0",
            "1.0.0-01",
            "1.0.0/extra",
            "é",
            "1.0",
            "-s",
            "1.0.0+",
            "v" * 129,
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_version(value)
        for value in ("dev", "1.0.0", "v1.2.3-rc.1+build.01"):
            self.assertEqual(validate_version(value), value)

    def test_standalone_release_matches_archive_and_checksums_for_every_target(self):
        for target in (
            "darwin-amd64",
            "darwin-arm64",
            "linux-amd64",
            "linux-arm64",
            "windows-amd64",
            "windows-arm64",
        ):
            with (
                self.subTest(target=target),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                binary = root / "source-binary"
                binary.write_bytes(b"synthetic executable")
                artifact = archive(
                    binary,
                    root,
                    target,
                    VERSION,
                    go_version="go1.26.10",
                    notices=NOTICES,
                )
                standalone = root / binary_name(target, VERSION)
                standalone.write_bytes(binary.read_bytes())
                notices = root / notices_name(target, VERSION)
                notices.write_bytes(
                    standalone_notices((ROOT / "LICENSE").read_bytes(), NOTICES)
                )
                paths = (artifact, standalone, notices)

                def manifest():
                    (root / "SHA256SUMS").write_text(
                        "".join(
                            f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
                            for p in paths
                        )
                    )

                manifest()
                verify_release(root, target, VERSION)
                for path in (standalone, notices):
                    original = path.read_bytes()
                    path.write_bytes(original + b"modified")
                    manifest()  # Matching checksums must not hide a different executable or notices.
                    with self.assertRaises(ValueError):
                        verify_release(root, target, VERSION)
                    path.write_bytes(original)
                    manifest()
                    checksum = (root / "SHA256SUMS").read_text()
                    (root / "SHA256SUMS").write_text(
                        checksum.replace(hashlib.sha256(original).hexdigest(), "0" * 64)
                    )
                    with self.assertRaises(ValueError):
                        verify_release(root, target, VERSION)
                    manifest()
                (root / "SHA256SUMS").write_text(
                    f"{hashlib.sha256(artifact.read_bytes()).hexdigest()}  {artifact.name}\n"
                )
                with self.assertRaises(ValueError):
                    verify_release(root, target, VERSION)

    @staticmethod
    def manifest(root, path):
        (root / "SHA256SUMS").write_text(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
        )

    def test_archive_bytes_ignore_source_permissions_times_and_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "withhold"
            binary.write_bytes(b"synthetic executable")
            for target in ("linux-arm64", "windows-amd64"):
                first, second = root / (target + "1"), root / (target + "2")
                first.mkdir()
                second.mkdir()
                a = archive(
                    binary,
                    first,
                    target,
                    VERSION,
                    go_version="go1.26.10",
                    notices=NOTICES,
                )
                binary.chmod(0o700)
                os.utime(binary, (123456789, 123456789))
                b = archive(
                    binary,
                    second,
                    target,
                    VERSION,
                    go_version="go1.26.10",
                    notices=NOTICES,
                )
                self.assertEqual(a.read_bytes(), b.read_bytes())
                self.manifest(first, a)
                files = verify(first, target, VERSION)
                metadata = json.loads(files["BUILD.json"])
                self.assertEqual(metadata["target"], target)
                self.assertEqual(metadata["version"], VERSION)
                destination = first / "extracted"
                extract(files, destination)
                self.assertEqual(
                    (
                        destination / next(n for n in files if n.startswith("withhold"))
                    ).read_bytes(),
                    binary.read_bytes(),
                )
                with self.assertRaises(FileExistsError):
                    extract(files, destination)

    def test_verifier_rejects_corrupt_missing_and_duplicate_checksums(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "withhold"
            binary.write_bytes(b"synthetic executable")
            path = archive(
                binary,
                root,
                "linux-amd64",
                VERSION,
                go_version="go1.26.10",
                notices=NOTICES,
            )
            self.manifest(root, path)
            manifest = root / "SHA256SUMS"
            original = manifest.read_text()
            for value in (
                "",
                original * 2,
                "0" * 64 + f"  {path.name}\n",
                original.replace(path.name, "../outside"),
            ):
                manifest.write_text(value)
                with self.subTest(value=value), self.assertRaises(ValueError):
                    verify(root, "linux-amd64", VERSION)

    def test_verifier_refuses_unsafe_members_modes_and_content_changes(self):
        for kind in (
            "path",
            "symlink",
            "mode",
            "content",
            "missing",
            "duplicate",
            "metadata",
            "missing-notices",
            "changed-notices",
        ):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                binary = root / "withhold"
                binary.write_bytes(b"synthetic executable")
                path = archive(
                    binary,
                    root,
                    "linux-amd64",
                    VERSION,
                    go_version="go1.26.10",
                    notices=NOTICES,
                )
                with tarfile.open(path) as source:
                    entries = [
                        (info, source.extractfile(info).read()) for info in source
                    ]
                info, data = entries[0]
                if kind == "path":
                    info.name = "../guard"
                elif kind == "symlink":
                    info.type, info.linkname = tarfile.SYMTYPE, "outside"
                elif kind == "mode":
                    info.mode = 0o6755
                elif kind == "content":
                    entries[0] = info, data.replace(b"synthetic", b"corrupted")
                elif kind == "missing":
                    entries.pop()
                elif kind == "duplicate":
                    entries.append(entries[0])
                elif kind == "metadata":
                    info, data = entries[-1]
                    data = data.replace(b"linux-amd64", b"linux-arm64")
                    entries[-1] = info, data
                elif kind == "missing-notices":
                    entries = [
                        (i, d)
                        for i, d in entries
                        if i.name != "THIRD_PARTY_NOTICES.txt"
                    ]
                elif kind == "changed-notices":
                    entries = [
                        (
                            i,
                            d.replace(b"Synthetic", b"Corrupted")
                            if i.name == "THIRD_PARTY_NOTICES.txt"
                            else d,
                        )
                        for i, d in entries
                    ]
                with tarfile.open(path, "w:gz") as output:
                    for info, data in entries:
                        output.addfile(info, io.BytesIO(data))
                self.manifest(root, path)
                with self.assertRaises(ValueError):
                    verify(root, "linux-amd64", VERSION)

    @unittest.skipUnless(
        os.environ.get("WITHHOLD_TEST_NATIVE"), "native executable required"
    )
    def test_extracted_native_executable_runs_with_empty_path_and_temporary_home(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = Path(os.environ["WITHHOLD_TEST_NATIVE"])
            version = subprocess.check_output(
                [str(binary), "version"], text=True
            ).split()[1]
            notices = build_notices(
                binary, cwd=ROOT, env=dict(os.environ, GOWORK="off", GOFLAGS="")
            )
            self.assertIn(b"github.com/betterleaks/betterleaks v1.10.0", notices)
            self.assertIn(b"Mozilla Public License", notices)
            self.assertNotIn(str(ROOT).encode(), notices)
            path = archive(
                binary,
                root,
                host_target(),
                version,
                go_version="go1.26.10",
                notices=notices,
            )
            self.manifest(root, path)
            files = verify(root, host_target(), version)
            extract(files, root / "extracted")
            smoke(root / "extracted", host_target(), version)
