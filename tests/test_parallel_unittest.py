"""Exercise parallel release test scheduling and failure propagation."""

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class ParallelUnittestTests(unittest.TestCase):
    def run_fixture(self, *, fail):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "parallel_fixture.py").write_text(
                textwrap.dedent(
                    """\
                    import os
                    import time
                    import unittest
                    from pathlib import Path

                    root = Path(os.environ["SHARD_FIXTURE_DIR"])

                    class Fixture(unittest.TestCase):
                        def rendezvous(self, own, other):
                            (root / own).touch()
                            deadline = time.monotonic() + 10
                            while not (root / other).exists():
                                if time.monotonic() > deadline:
                                    self.fail("workers did not run concurrently")
                                time.sleep(0.01)

                        def test_a(self):
                            self.rendezvous("a", "b")

                        def test_b(self):
                            self.rendezvous("b", "a")

                        def test_c(self):
                            (root / "c").touch()
                            self.assertNotEqual(os.environ["SHARD_FIXTURE_FAIL"], "1")
                    """
                ),
                encoding="utf-8",
            )
            env = dict(
                os.environ,
                PYTHONPATH=os.pathsep.join(
                    (str(root), os.environ.get("PYTHONPATH", ""))
                ),
                SHARD_FIXTURE_DIR=str(root),
                SHARD_FIXTURE_FAIL="1" if fail else "0",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tools.parallel_unittest",
                    "--workers",
                    "2",
                    "parallel_fixture",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertTrue(all((root / name).exists() for name in ("a", "b", "c")))
            return result

    def test_runs_all_cases_concurrently(self):
        result = self.run_fixture(fail=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Shard 1/2", result.stdout)
        self.assertIn("Shard 2/2", result.stdout)

    def test_failure_in_one_shard_fails_the_run(self):
        result = self.run_fixture(fail=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL: test_c", result.stdout)

    def test_unknown_module_fails(self):
        result = subprocess.run(
            [sys.executable, "-m", "tools.parallel_unittest", "no_such_test_module"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no_such_test_module", result.stderr)
