"""Exercise the POSIX bootstrap with local release fixtures, never live downloads."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.package_native import (
    ROOT,
    archive,
    binary_name,
    notices_name,
    standalone_notices,
)
from tools.verify_native import host_target

VERSION = "v0.1.0-rc.1"
COMMIT = "a" * 40
NOTICES = b"Synthetic notices\n"


@unittest.skipIf(os.name == "nt", "the bootstrap targets macOS and Linux")
class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="withhold-installer-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.release = self.root / "release"
        self.release.mkdir()
        self.env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("WITHHOLD_", "GH_", "GITHUB_"))
        }
        self.env.update(
            HOME=str(self.root / "home"),
            TMPDIR=str(self.root),
            PATH=str(self.tools) + os.pathsep + os.environ["PATH"],
            FIXTURE_RELEASE=str(self.release),
            FIXTURE_LOG=str(self.root / "calls.jsonl"),
            FIXTURE_SYSTEM="Linux",
            FIXTURE_MACHINE="x86_64",
            FIXTURE_VERSION=VERSION,
        )
        self.bin = Path(self.env["HOME"]) / ".local" / "bin" / "withhold"
        self.script(
            self.tools / "uname",
            "import os, sys\n"
            "print(os.environ['FIXTURE_SYSTEM' if sys.argv[1] == '-s' else 'FIXTURE_MACHINE'])\n",
        )
        self.script(
            self.tools / "curl",
            """import json, os, shutil, sys
from pathlib import Path
from urllib.parse import urlsplit
args = sys.argv[1:]
with open(os.environ['FIXTURE_LOG'], 'a') as log:
    log.write(json.dumps(['curl', *args]) + '\\n')
url = args[-1]
if url.endswith('/releases/latest'):
    if os.environ.get('FIXTURE_NO_LATEST'):
        sys.exit(1)
    print(os.environ.get('FIXTURE_REDIRECT', 'https://github.com/cquark7/withhold/releases/tag/' + os.environ['FIXTURE_VERSION']), end='')
else:
    if os.environ.get('FIXTURE_DOWNLOAD_FAIL'):
        sys.exit(1)
    shutil.copyfile(Path(os.environ['FIXTURE_RELEASE']) / Path(urlsplit(url).path).name, args[args.index('-o') + 1])
""",
        )
        self.script(
            self.tools / "gh",
            """import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['FIXTURE_LOG'], 'a') as log:
    log.write(json.dumps(['gh', *args]) + '\\n')
if args[:2] != ['attestation', 'verify'] or Path(args[2]).name == os.environ.get('FIXTURE_VERIFY_FAIL'):
    sys.exit(1)
""",
        )
        self.binary = self.root / "withhold"
        self.script(
            self.binary,
            """import os, shutil, sys
from pathlib import Path
assert sys.argv[1:3] == ['install', '--bin-dir'], 'installer must not setup trust or start a session'
if os.environ.get('FIXTURE_INSTALL_FAIL'):
    sys.exit('run withhold off before upgrading the executable')
target = Path(sys.argv[3]) / 'withhold'
target.parent.mkdir(parents=True, exist_ok=True)
shutil.copyfile(sys.argv[0], target)
""",
        )
        self.make_release("linux-amd64")

    @staticmethod
    def script(path, source):
        path.write_text(f"#!{sys.executable}\n{source}")
        path.chmod(0o755)

    def make_release(self, target, version=VERSION):
        archive_path = archive(
            self.binary,
            self.release,
            target,
            version,
            go_version="go1.26.10",
            notices=NOTICES,
        )
        binary = self.release / binary_name(target, version)
        binary.write_bytes(self.binary.read_bytes())
        notices = self.release / notices_name(target, version)
        notices.write_bytes(
            standalone_notices((ROOT / "LICENSE").read_bytes(), NOTICES)
        )
        (self.release / "SHA256SUMS").write_text(
            "".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                for path in (archive_path, binary, notices)
            )
        )
        (self.release / "native-release.sigstore.json").write_text("fixture only")

    def run_installer(self, *args, success=True):
        result = subprocess.run(
            ["/bin/sh", str(ROOT / "install.sh"), *args],
            env=self.env,
            cwd=self.root,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        self.assertFalse(list(self.root.glob("withhold-install.*")))
        return result

    def calls(self):
        path = self.root / "calls.jsonl"
        return (
            [json.loads(line) for line in path.read_text().splitlines()]
            if path.exists()
            else []
        )

    def isolate_path_without_gh(self, *, shasum_only=False):
        (self.tools / "gh").unlink()
        for name in ("awk", "grep", "sed", "mktemp", "rm", "chmod", "mkdir", "cp"):
            (self.tools / name).symlink_to(shutil.which(name))
        hash_tool = (
            "sha256sum" if not shasum_only and shutil.which("sha256sum") else "shasum"
        )
        (self.tools / hash_tool).symlink_to(shutil.which(hash_tool))
        self.env["PATH"] = str(self.tools)

    def test_latest_install_works_without_gh_and_preserves_notices(self):
        self.isolate_path_without_gh()
        result = self.run_installer()
        self.assertTrue(self.bin.is_file())
        self.assertTrue(all(args[0] == "curl" for args in self.calls()))
        self.assertTrue(self.calls()[0][-1].endswith("/releases/latest"))
        self.assertIn("do not verify the publisher", result.stdout)
        docs = (
            Path(self.env["HOME"]) / ".local/share/withhold" / VERSION / "linux-amd64"
        )
        self.assertEqual(
            (docs / notices_name("linux-amd64", VERSION)).read_bytes(),
            standalone_notices((ROOT / "LICENSE").read_bytes(), NOTICES),
        )
        self.assertTrue((docs / "SHA256SUMS").is_file())
        self.assertFalse((docs / "native-release.sigstore.json").exists())
        self.assertFalse((Path(self.env["HOME"]) / ".config").exists())
        self.assertIn("withhold setup", result.stdout)

    @unittest.skipUnless(shutil.which("shasum"), "shasum is unavailable")
    def test_installer_supports_shasum_without_sha256sum(self):
        self.isolate_path_without_gh(shasum_only=True)
        self.run_installer("--version", VERSION)
        self.assertTrue(self.bin.is_file())

    @unittest.skipUnless(
        os.environ.get("WITHHOLD_TEST_NATIVE"), "native executable required"
    )
    def test_installer_runs_real_binary_without_gh_in_isolated_state(self):
        target = host_target()
        system, arch = target.split("-")
        if system not in ("darwin", "linux"):
            self.skipTest("installer supports macOS and Linux")
        self.env.update(
            FIXTURE_SYSTEM={"darwin": "Darwin", "linux": "Linux"}[system],
            FIXTURE_MACHINE={"arm64": "arm64", "amd64": "x86_64"}[arch],
            WITHHOLD_DIR=str(self.root / "state"),
            XDG_CONFIG_HOME=str(self.root / "config"),
        )
        self.release = self.root / "native-release"
        self.release.mkdir()
        self.env["FIXTURE_RELEASE"] = str(self.release)
        self.binary.write_bytes(Path(os.environ["WITHHOLD_TEST_NATIVE"]).read_bytes())
        self.make_release(target)
        self.isolate_path_without_gh()
        self.run_installer("--version", VERSION)
        self.assertTrue(self.bin.is_file())
        self.assertTrue((self.root / "state" / "config.toml").is_file())
        result = subprocess.run(
            [str(self.bin), "version"],
            env=self.env,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("withhold ", result.stdout)

    def test_pinned_version_commit_custom_directory_and_all_unix_targets(self):
        for system, machine, target in (
            ("Darwin", "arm64", "darwin-arm64"),
            ("Darwin", "x86_64", "darwin-amd64"),
            ("Linux", "aarch64", "linux-arm64"),
        ):
            with self.subTest(target=target):
                self.make_release(target)
                self.env.update(FIXTURE_SYSTEM=system, FIXTURE_MACHINE=machine)
                destination = self.root / f"bin with spaces {target}"
                self.run_installer(
                    "--version",
                    VERSION,
                    "--commit",
                    COMMIT,
                    "--bin-dir",
                    str(destination),
                )
                self.assertTrue((destination / "withhold").is_file())
                verifications = [args for args in self.calls() if args[0] == "gh"][-3:]
                self.assertEqual(len(verifications), 3)
                for args in verifications:
                    self.assertEqual(args[args.index("--source-digest") + 1], COMMIT)
                    self.assertEqual(
                        args[args.index("--source-ref") + 1], f"refs/tags/{VERSION}"
                    )
                    self.assertEqual(args[args.index("--repo") + 1], "cquark7/withhold")
                    self.assertEqual(
                        args[args.index("--signer-workflow") + 1],
                        "cquark7/withhold/.github/workflows/native-artifacts.yml",
                    )
                    self.assertIn("--deny-self-hosted-runners", args)
        self.assertFalse(
            any(args[-1].endswith("/releases/latest") for args in self.calls())
        )

    def test_failed_provenance_never_runs_binary(self):
        for subject in (
            binary_name("linux-amd64", VERSION),
            notices_name("linux-amd64", VERSION),
            "SHA256SUMS",
        ):
            with self.subTest(subject=subject):
                self.env["FIXTURE_VERIFY_FAIL"] = subject
                result = self.run_installer("--verify-provenance", success=False)
                self.assertIn("provenance verification failed", result.stderr)
                self.assertFalse(self.bin.exists())

    def test_requested_provenance_without_commit_verifies_every_file(self):
        self.run_installer("--verify-provenance")
        verifications = [args for args in self.calls() if args[0] == "gh"]
        self.assertEqual(len(verifications), 3)
        self.assertEqual(
            {Path(args[3]).name for args in verifications},
            {
                binary_name("linux-amd64", VERSION),
                notices_name("linux-amd64", VERSION),
                "SHA256SUMS",
            },
        )
        self.assertTrue(all("--source-digest" not in args for args in verifications))
        self.assertTrue(
            (
                Path(self.env["HOME"])
                / ".local/share/withhold"
                / VERSION
                / "linux-amd64"
                / "native-release.sigstore.json"
            ).is_file()
        )

    def test_bad_or_duplicate_checksum_never_installs(self):
        path = self.release / "SHA256SUMS"
        original = path.read_text()
        lines = original.splitlines(keepends=True)
        for contents in (
            original + lines[1],
            original + lines[2],
            original.replace(lines[1], ""),
            original.replace(lines[2], ""),
            "0" * 64 + lines[1][64:] + lines[2],
            lines[1] + "0" * 64 + lines[2][64:],
        ):
            with self.subTest(contents=contents):
                path.write_text(contents)
                self.run_installer(success=False)
                self.assertFalse(self.bin.exists())

    def test_network_failures_and_active_session_refusal_preserve_install(self):
        self.bin.parent.mkdir(parents=True)
        self.bin.write_text("existing executable")
        for flag in (
            "FIXTURE_NO_LATEST",
            "FIXTURE_DOWNLOAD_FAIL",
            "FIXTURE_INSTALL_FAIL",
        ):
            with self.subTest(flag=flag):
                self.env[flag] = "1"
                self.run_installer(success=False)
                self.assertEqual(self.bin.read_text(), "existing executable")
                del self.env[flag]

    def test_invalid_arguments_are_rejected_before_network_or_install(self):
        for args in (
            ("--version", "../bad"),
            ("--version", "v1.0.0\nv2.0.0"),
            ("--version", "v01.0.0"),
            ("--version", "v1.0.0-01"),
            ("--version", "1.0.0"),
            ("--version", "v1.0.0+" + "a" * 128),
            ("--commit", COMMIT + "\n"),
            ("--commit", "abc"),
            ("--bin-dir", "relative"),
            ("--version",),
            ("--unknown",),
        ):
            with self.subTest(args=args):
                self.run_installer(*args, success=False)
                self.assertFalse(self.calls())
        self.assertFalse(self.bin.exists())

    def test_help_and_unsupported_platform_do_not_contact_github(self):
        self.run_installer("--help")
        self.env["FIXTURE_SYSTEM"] = "FreeBSD"
        self.run_installer(success=False)
        self.env.update(FIXTURE_SYSTEM="Linux", FIXTURE_MACHINE="riscv64")
        self.run_installer(success=False)
        self.assertFalse(self.calls())

    def test_unexpected_latest_redirect_is_rejected(self):
        self.env["FIXTURE_REDIRECT"] = "https://example.com/releases/tag/v1.0.0"
        self.run_installer(success=False)
        self.assertEqual(len(self.calls()), 1)
        self.assertFalse(self.bin.exists())

    def test_latest_redirect_rejects_other_encoded_characters(self):
        self.env["FIXTURE_REDIRECT"] = (
            "https://github.com/cquark7/withhold/releases/tag/v1.2.3%2Fother"
        )
        self.run_installer(success=False)
        self.assertEqual(len(self.calls()), 1)
        self.assertFalse(self.bin.exists())

    def test_latest_redirect_decodes_semver_build_separator(self):
        version = "v1.2.3+build.1"
        self.make_release("linux-amd64", version)
        self.env["FIXTURE_REDIRECT"] = (
            "https://github.com/cquark7/withhold/releases/tag/v1.2.3%2Bbuild.1"
        )
        self.run_installer()
        self.assertTrue(self.bin.is_file())
        self.assertTrue(any(version in args[-1] for args in self.calls()))

    def test_missing_gh_only_blocks_requested_provenance(self):
        self.isolate_path_without_gh()
        for args in (("--verify-provenance",), ("--commit", COMMIT)):
            with self.subTest(args=args):
                result = self.run_installer(*args, success=False)
                self.assertIn("https://cli.github.com/", result.stderr)
                self.assertFalse(self.calls())
                self.assertFalse(self.bin.exists())
