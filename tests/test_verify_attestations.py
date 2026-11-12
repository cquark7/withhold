"""Verify that every artifact is checked and failures stop a release."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "verify_attestations.sh"


@unittest.skipIf(os.name == "nt", "attestations are verified on Ubuntu runners")
class VerifyAttestationsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="withhold-attestations-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.calls = self.root / "calls"
        self.calls.mkdir()
        gh = self.root / "gh"
        gh.write_text(
            "#!/bin/sh\n"
            'for last in "$@"; do :; done\n'
            'printf "%s\\n" "$@" > "$CALLS_DIR/$(basename "$last")"\n'
            'case "$last" in *bad*) exit 1;; esac\n',
            encoding="utf-8",
        )
        gh.chmod(0o755)
        self.env = dict(
            os.environ,
            PATH=str(self.root) + os.pathsep + os.environ["PATH"],
            CALLS_DIR=str(self.calls),
            GITHUB_REPOSITORY="example/withhold",
            GITHUB_SHA="a" * 40,
        )
        self.env.pop("WITHHOLD_ATTESTATION_SOURCE_REF", None)

    def verify(self, *artifacts):
        return subprocess.run(
            ["bash", str(SCRIPT), "bundle with spaces.json", *artifacts],
            cwd=ROOT,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=15,
        )

    def assert_calls(self, artifacts, *, source_ref=None):
        self.assertEqual({path.name for path in self.calls.iterdir()}, set(artifacts))
        for artifact in artifacts:
            args = (self.calls / artifact).read_text().splitlines()
            expected = [
                "attestation",
                "verify",
                "--repo",
                "example/withhold",
                "--signer-workflow",
                "example/withhold/.github/workflows/native-artifacts.yml",
                "--source-digest",
                "a" * 40,
                "--deny-self-hosted-runners",
                "--bundle",
                "bundle with spaces.json",
            ]
            if source_ref:
                expected.extend(("--source-ref", source_ref))
            expected.extend(("--", artifact))
            self.assertEqual(args, expected)

    def test_checks_every_artifact_and_preserves_policy(self):
        artifacts = ("first", "artifact with spaces", "third")
        result = self.verify(*artifacts)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_calls(artifacts)

    def test_a_failed_artifact_fails_the_run_after_checking_all_files(self):
        self.env["WITHHOLD_ATTESTATION_SOURCE_REF"] = "refs/tags/v1.0.0"
        artifacts = ("first", "bad artifact", "third", "fourth", "fifth")
        result = self.verify(*artifacts)
        self.assertNotEqual(result.returncode, 0)
        self.assert_calls(artifacts, source_ref="refs/tags/v1.0.0")

    def test_rejects_an_empty_artifact_list(self):
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(self.calls.iterdir()), [])
