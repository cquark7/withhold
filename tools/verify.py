#!/usr/bin/env python3
"""Run the full local verification gate with isolated acceptance binaries."""

import argparse
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(command, *, env=None):
    print("+ " + shlex.join(map(str, command)), flush=True)
    subprocess.run(command, cwd=ROOT, env=env, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--race", action="store_true", help="enable Go's race detector")
    args = parser.parse_args()
    try:
        with tempfile.TemporaryDirectory(prefix="withhold-verify-") as temporary:
            environment = dict(os.environ)
            suffix = ".exe" if os.name == "nt" else ""
            for variable, name, source in (
                (
                    "WITHHOLD_TEST_SCANNER_WORKER",
                    "withhold-scanner",
                    "./cmd/withhold-scanner",
                ),
                ("WITHHOLD_TEST_NATIVE", "withhold", "./cmd/withhold"),
                (
                    "WITHHOLD_TEST_NATIVE_FIXTURE",
                    "withhold-native-fixture",
                    "./tests/nativefixture",
                ),
            ):
                binary = Path(temporary) / (name + suffix)
                run(
                    ["go", "build", "-trimpath", "-o", str(binary), source],
                    env=dict(environment, CGO_ENABLED="0"),
                )
                environment[variable] = str(binary)
            run(
                ["go", "test", *(["-race"] if args.race else []), "./..."],
                env=environment,
            )
            run(["go", "vet", "./..."])
            unformatted = subprocess.check_output(
                ["gofmt", "-l", "cmd", "internal", "tests/nativefixture"],
                cwd=ROOT,
                text=True,
            )
            if unformatted:
                print("Go files need formatting:\n" + unformatted, file=sys.stderr)
                return 1
            run(
                [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"],
                env=environment,
            )
            run([sys.executable, "-m", "ruff", "check", "."])
            run([sys.executable, "-m", "ruff", "format", "--check", "."])
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"Verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
