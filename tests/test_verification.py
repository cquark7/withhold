"""The full gate must enable scanner-worker coverage in Go as well as Python."""

import os
import unittest
from unittest import mock

from tools import verify


class VerificationTests(unittest.TestCase):
    def test_go_tests_receive_the_built_acceptance_binaries(self):
        with (
            mock.patch("sys.argv", ["verify.py", "--race"]),
            mock.patch.object(verify, "run") as run,
            mock.patch.object(verify.subprocess, "check_output", return_value=""),
        ):
            self.assertEqual(verify.main(), 0)
        go_test = next(
            call for call in run.call_args_list if call.args[0][:2] == ["go", "test"]
        )
        self.assertIn("-race", go_test.args[0])
        environment = go_test.kwargs["env"]
        suffix = ".exe" if os.name == "nt" else ""
        for variable, binary in (
            ("WITHHOLD_TEST_SCANNER_WORKER", "withhold-scanner"),
            ("WITHHOLD_TEST_NATIVE", "withhold"),
            ("WITHHOLD_TEST_NATIVE_FIXTURE", "withhold-native-fixture"),
        ):
            self.assertTrue(environment[variable].endswith(binary + suffix))


if __name__ == "__main__":
    unittest.main()
