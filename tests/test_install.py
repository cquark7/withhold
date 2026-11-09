"""Exercise the POSIX bootstrap with local release fixtures, never live downloads."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.package_native import archive

ROOT = Path(__file__).resolve().parent.parent
VERSION = "v0.1.0-rc.1"
COMMIT = "a" * 40


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
            self.tools / "gh",
            """import json, os, shutil, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['FIXTURE_LOG'], 'a') as log:
    log.write(json.dumps(args) + '\\n')
if args[0] == 'api':
    if os.environ.get('FIXTURE_NO_LATEST'):
        sys.exit(1)
    print(os.environ['FIXTURE_VERSION'])
elif args[:2] == ['release', 'download']:
    if os.environ.get('FIXTURE_DOWNLOAD_FAIL'):
        sys.exit(1)
    destination = Path(args[args.index('--dir') + 1])
    for index, arg in enumerate(args):
        if arg == '--pattern':
            name = args[index + 1]
            shutil.copyfile(Path(os.environ['FIXTURE_RELEASE']) / name, destination / name)
elif args[:2] == ['attestation', 'verify']:
    if Path(args[2]).name == os.environ.get('FIXTURE_VERIFY_FAIL'):
        sys.exit(1)
else:
    sys.exit('unexpected gh operation')
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

    def make_release(self, target):
        path = archive(
            self.binary,
            self.release,
            target,
            VERSION,
            go_version="go1.26.10",
            notices=b"Synthetic notices\n",
        )
        (self.release / "SHA256SUMS").write_text(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
        )
        (self.release / "native-release.sigstore.json").write_text("fixture only")
        return path

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

    def test_latest_install_verifies_both_subjects_and_preserves_notices(self):
        result = self.run_installer()
        self.assertTrue(self.bin.is_file())
        calls = self.calls()
        self.assertEqual(
            calls[0],
            ["api", "repos/cquark7/withhold/releases/latest", "--jq", ".tag_name"],
        )
        verifications = [
            args for args in calls if args[:2] == ["attestation", "verify"]
        ]
        self.assertEqual(len(verifications), 2)
        for args in verifications:
            self.assertIn("--deny-self-hosted-runners", args)
            self.assertEqual(args[args.index("--repo") + 1], "cquark7/withhold")
            self.assertEqual(
                args[args.index("--source-ref") + 1], f"refs/tags/{VERSION}"
            )
            self.assertEqual(
                args[args.index("--signer-workflow") + 1],
                "cquark7/withhold/.github/workflows/native-artifacts.yml",
            )
        docs = (
            Path(self.env["HOME"]) / ".local/share/withhold" / VERSION / "linux-amd64"
        )
        self.assertEqual(
            (docs / "THIRD_PARTY_NOTICES.txt").read_bytes(), b"Synthetic notices\n"
        )
        self.assertTrue((docs / "native-release.sigstore.json").is_file())
        self.assertFalse((Path(self.env["HOME"]) / ".config").exists())
        self.assertIn("withhold setup", result.stdout)

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
                verification = self.calls()[-1]
                self.assertEqual(
                    verification[verification.index("--source-digest") + 1], COMMIT
                )
        self.assertFalse(any(args[0] == "api" for args in self.calls()))

    def test_failed_provenance_never_extracts_or_runs(self):
        # If extraction is attempted at all, record it independently of installation.
        self.script(
            self.tools / "tar",
            "import os\nfrom pathlib import Path\nPath(os.environ['HOME']).mkdir(parents=True, exist_ok=True)\n(Path(os.environ['HOME']) / 'extraction-attempted').touch()\n",
        )
        for subject in (f"withhold-{VERSION}-linux-amd64.tar.gz", "SHA256SUMS"):
            with self.subTest(subject=subject):
                self.env["FIXTURE_VERIFY_FAIL"] = subject
                result = self.run_installer(success=False)
                self.assertIn("provenance verification failed", result.stderr)
                self.assertFalse(self.bin.exists())
                self.assertFalse(
                    (Path(self.env["HOME"]) / "extraction-attempted").exists()
                )

    def test_bad_or_duplicate_checksum_never_installs(self):
        path = self.release / "SHA256SUMS"
        original = path.read_text()
        for contents in (original * 2, "0" * 64 + original[64:], ""):
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

    def test_missing_gh_gives_actionable_guidance(self):
        # An isolated PATH prevents accidentally using a real authenticated gh.
        self.env["PATH"] = str(self.tools)
        (self.tools / "gh").unlink()
        result = self.run_installer(success=False)
        self.assertIn("https://cli.github.com/", result.stderr)
        self.assertFalse(self.bin.exists())
