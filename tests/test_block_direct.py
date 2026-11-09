"""Check manual firewall command selection and cleanup with stateful stubs.

These tests do not validate real firewall integration or routing coverage.
Every external firewall/DNS command is a PATH-injected stub; no sudo or network.
"""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
SCRIPT = HERE / "tools" / "proof" / "block_direct.sh"

DIG_STUB = r"""#!/bin/bash
# canned answers: first host -> A+AAAA; every other host -> only A
RECORD="${2:-}"
HOST="${3:-}"
if [ "$HOST" = "api.githubcopilot.com" ]; then
  if [ "$RECORD" = "A" ]; then echo "140.82.112.3"; fi
  if [ "$RECORD" = "AAAA" ]; then echo "2606:db00::1"; fi
else
  echo "140.82.112.9"
fi
"""

IPTABLES_STUB = r"""#!/bin/bash
tool="${0##*/}"
echo "$tool $*" >> "$IPT_LOG"
rules="$IPT_LOG.$tool.rules"
touch "$rules"
if [ "$1" != "-S" ]; then
  case "$4" in
    *:*) [ "$tool" = ip6tables ] || exit 2 ;;
    *) [ "$tool" = iptables ] || exit 2 ;;
  esac
fi
case "$1" in
  -C) grep -Fxq -- "${*:2}" "$rules" ;;
  -A) printf '%s\n' "${*:2}" >> "$rules" ;;
  -D)
    [ "${FAIL_DELETE:-0}" != 1 ] || exit 1
    grep -Fxq -- "${*:2}" "$rules" || exit 1
    grep -Fxv -- "${*:2}" "$rules" > "$rules.next" || true
    mv "$rules.next" "$rules"
    ;;
  -S)
    [ "${FAIL_LIST:-0}" != 1 ] || exit 1
    sed 's/^/-A /' "$rules"
    ;;
  *) exit 2 ;;
esac
"""

PFCTL_STUB = r"""#!/bin/bash
echo "$*" >> "$PF_LOG"
if [ "$1" = "-q" ]; then shift; fi
case "$1" in
  -s) if [ -f "$PF_ENABLED" ]; then echo "Status: Enabled"; else echo "Status: Disabled"; fi ;;
  -e) [ "${FAIL_PF_ENABLE:-0}" != 1 ] || exit 1; touch "$PF_ENABLED" ;;
  -d) rm -f "$PF_ENABLED" ;;
esac
exit 0
"""


def write_stub(dir_: Path, name: str, body: str):
    p = dir_ / name
    p.write_text(body)
    p.chmod(0o755)
    return p


def run(args, stubs: Path, env_extra: dict):
    env = dict(os.environ)
    env["PATH"] = f"{stubs}:{env['PATH']}"
    env.update(env_extra)
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )


@unittest.skipIf(os.name == "nt", "manual firewall tooling targets macOS/Linux")
class BlockDirectTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.stubs = Path(self.tmp.name) / "stubs"
        self.stubs.mkdir()
        write_stub(self.stubs, "dig", DIG_STUB)
        write_stub(self.stubs, "iptables", IPTABLES_STUB)
        write_stub(self.stubs, "ip6tables", IPTABLES_STUB)
        write_stub(self.stubs, "pfctl", PFCTL_STUB)
        self.state = Path(self.tmp.name) / "state"
        self.ipt_log = self.stubs / "ipt.log"
        self.pf_log = self.stubs / "pf.log"
        self.pf_enabled_flag = self.stubs / "pf.enabled"

    def tearDown(self):
        self.tmp.cleanup()

    def env(self, **extra):
        e = {
            "IPT_LOG": str(self.ipt_log),
            "PF_LOG": str(self.pf_log),
            "PF_ENABLED": str(self.pf_enabled_flag),
            "WITHHOLD_STATE": str(self.state),
        }
        e.update(extra)
        return e

    def test_macos_on_resolves_a_and_aaaa_and_records_state(self):
        r = run(["macos-on"], self.stubs, self.env())
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        rules = [ln for ln in r.stdout.splitlines() if "block drop quick" in ln]
        # A and AAAA both blocked
        self.assertTrue(any("140.82.112.3" in ln for ln in rules), r.stdout)
        self.assertTrue(any("2606:db00::1" in ln for ln in rules), r.stdout)
        self.assertTrue(self.state.exists())
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode) & 0o777, 0o600)
        self.assertIn("pf_was=disabled", self.state.read_text())

    def test_macos_off_restores_exact_state(self):
        run(["macos-on"], self.stubs, self.env())
        self.assertTrue(self.pf_enabled_flag.exists())
        r = run(["macos-off"], self.stubs, self.env())
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        self.assertFalse(self.state.exists())
        # pf disabled only because WE enabled it
        self.assertFalse(self.pf_enabled_flag.exists())
        pf_log = self.pf_log.read_text()
        self.assertIn("-a withhold-proof -F rules", pf_log)
        self.assertIn("-d", pf_log)

    def test_linux_on_uses_all_protocol_drops(self):
        r = run(["linux-on"], self.stubs, self.env())
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        log = self.ipt_log.read_text()
        self.assertIn("iptables -A OUTPUT -d 140.82.112.3 -j DROP", log)
        self.assertIn("ip6tables -A OUTPUT -d 2606:db00::1 -j DROP", log)
        self.assertNotIn("--dport", log)  # All traffic to each destination is affected.
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode) & 0o777, 0o600)

    def test_linux_off_removes_exactly_what_on_added(self):
        run(["linux-on"], self.stubs, self.env())
        r = run(["linux-off"], self.stubs, self.env())
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        self.assertFalse(self.state.exists())
        # Exactly one deletion per recorded IP, with neither family left behind.
        checks = self.ipt_log.read_text()
        for ip in ("140.82.112.3", "2606:db00::1"):
            self.assertEqual(checks.count(f"-D OUTPUT -d {ip} -j DROP"), 1, checks)
        for tool in ("iptables", "ip6tables"):
            self.assertEqual(Path(f"{self.ipt_log}.{tool}.rules").read_text(), "")

    def test_macos_off_preserves_an_already_enabled_firewall(self):
        self.pf_enabled_flag.touch()
        self.assertEqual(run(["macos-on"], self.stubs, self.env()).returncode, 0)
        self.assertEqual(run(["macos-off"], self.stubs, self.env()).returncode, 0)
        self.assertTrue(self.pf_enabled_flag.exists())

    def test_macos_enable_failure_retains_cleanup_state(self):
        result = run(["macos-on"], self.stubs, self.env(FAIL_PF_ENABLE="1"))
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.state.exists())
        self.assertEqual(run(["macos-off"], self.stubs, self.env()).returncode, 0)

    def test_linux_off_uses_recorded_ips_after_dns_changes(self):
        self.assertEqual(run(["linux-on"], self.stubs, self.env()).returncode, 0)
        dig = self.stubs / "dig"
        dig.write_text(
            DIG_STUB.replace("140.82.112.", "192.0.2.").replace(
                "2606:db00::1", "2001:db8::1"
            )
        )
        result = run(["linux-off"], self.stubs, self.env())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.state.exists())

    def test_linux_cleanup_failures_retain_state(self):
        for failure in ("FAIL_DELETE", "FAIL_LIST"):
            with self.subTest(failure=failure):
                self.assertEqual(
                    run(["linux-on"], self.stubs, self.env()).returncode, 0
                )
                result = run(["linux-off"], self.stubs, self.env(**{failure: "1"}))
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(self.state.exists())
                self.assertEqual(
                    run(["linux-off"], self.stubs, self.env()).returncode, 0
                )

    def test_strict_abort_on_unresolved_host(self):
        # Refuse an incomplete snapshot before applying rules.
        dig = self.stubs / "dig"
        dig.write_text(DIG_STUB.replace('else\n  echo "140.82.112.9"', "else\n  :"))
        dig.chmod(0o755)
        r = run(["linux-on"], self.stubs, self.env())
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("ABORT", r.stderr)
        self.assertFalse(self.state.exists())

    def test_allow_partial_override(self):
        dig = self.stubs / "dig"
        dig.write_text(DIG_STUB.replace('else\n  echo "140.82.112.9"', "else\n  :"))
        dig.chmod(0o755)
        r = run(["linux-on"], self.stubs, self.env(ALLOW_PARTIAL="1"))
        self.assertEqual(r.returncode, 0, r.stderr[-400:])


if __name__ == "__main__":
    unittest.main()
