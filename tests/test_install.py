"""Exercise the POSIX bootstrap with local release fixtures, never live downloads."""

import hashlib
import io
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from tools.package_native import (
    ROOT,
    archive,
    artifact_name,
)
from tools.verify_native import host_target

VERSION = "v0.1.0-rc.1"
COMMIT = "a" * 40
NOTICES = b"Synthetic notices\n"
REAL_CURL = shutil.which("curl")


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
            FIXTURE_INSTALLER=str(ROOT / "install.sh"),
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
outputs = iter(Path(args[i + 1]) for i, arg in enumerate(args) if arg == '--output')
for url in (arg for arg in args if arg.startswith('https://')):
    output = next(outputs, None)
    if url.endswith('/install.sh') and os.environ.get('FIXTURE_PARTIAL_BOOTSTRAP'):
        partial = Path(os.environ['FIXTURE_INSTALLER']).read_text().rsplit('\\nmain "$@"', 1)[0]
        sys.stdout.write(partial + '\\n')
        print('curl: (28) download timed out', file=sys.stderr)
        sys.exit(28)
    if os.environ.get('FIXTURE_CURL_EXIT'):
        print(os.environ.get('FIXTURE_HTTP_STATUS', '000') + ' ' + url)
        sys.exit(int(os.environ['FIXTURE_CURL_EXIT']))
    if url.endswith('/releases/latest'):
        if os.environ.get('FIXTURE_NO_LATEST'):
            sys.exit(1)
        url = os.environ.get('FIXTURE_REDIRECT', 'https://github.com/cquark7/withhold/releases/tag/' + os.environ['FIXTURE_VERSION'])
    else:
        if os.environ.get('FIXTURE_DOWNLOAD_FAIL'):
            sys.exit(1)
        source = Path(os.environ['FIXTURE_RELEASE']) / Path(urlsplit(url).path).name
        if output is None:
            sys.stdout.buffer.write(source.read_bytes())
        else:
            shutil.copyfile(source, output)
    if '--write-out' in args:
        print('200 ' + url)
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
        (self.release / "SHA256SUMS").write_text(
            f"{hashlib.sha256(archive_path.read_bytes()).hexdigest()}  {archive_path.name}\n"
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

    def assert_download_policy(self, calls, *, maximum="600", terminal=False):
        for args in calls:
            if args[0] != "curl":
                continue
            for option, value in (
                ("--proto", "=https"),
                ("--proto-redir", "=https"),
                ("--connect-timeout", "10"),
                ("--max-time", maximum),
                ("--retry", "2"),
                ("--retry-max-time", "60"),
                ("--speed-limit", "1024"),
                ("--speed-time", "30"),
            ):
                self.assertEqual(args[args.index(option) + 1], value)
            self.assertIn("--show-error", args)
            self.assertIn("--fail", args)
            self.assertIn("--fail-early", args)
            self.assertIn("--location", args)
            self.assertIn("--output", args)
            self.assertIn("--progress-bar" if terminal else "--silent", args)
            self.assertNotIn("--silent" if terminal else "--progress-bar", args)
            for option in ("--insecure", "--ipv4", "--ipv6", "--resolve", "--noproxy"):
                self.assertNotIn(option, args)

    def bootstrap_examples(self):
        for name in ("README.md", "docs/usage.md"):
            document = (ROOT / name).read_text()
            yield name, re.search(r"```sh\n(.*?)\n```", document, re.DOTALL)[1]
        workflow = (ROOT / ".github/workflows/native-artifacts.yml").read_text()
        heredoc = workflow.split("cat > release-notes.md <<EOF\n", 1)[1].split(
            "\n          EOF", 1
        )[0]
        rendered = subprocess.run(
            ["/bin/sh", "-c", "cat <<EOF\n" + textwrap.dedent(heredoc) + "\nEOF"],
            env=dict(
                self.env,
                GITHUB_REPOSITORY="cquark7/withhold",
                RELEASE_VERSION=VERSION,
                GITHUB_SHA=COMMIT,
                GITHUB_SERVER_URL="https://github.com",
                GITHUB_RUN_ID="1",
            ),
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        yield (
            "release notes",
            re.search(r"```sh\n(.*?)\n```", rendered.stdout, re.DOTALL)[1],
        )

    def run_bootstrap(self, example, *, success=True):
        # Exercise the documented pipeline, not unrelated post-install commands.
        command = example.split("\nexport PATH=", 1)[0]
        result = subprocess.run(
            ["/bin/sh", "-c", command],
            env=self.env,
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def assert_bootstrap_policy(self, args, *, bounded=True):
        if bounded:
            for option, value in (
                ("--proto", "=https"),
                ("--connect-timeout", "10"),
                ("--max-time", "120"),
            ):
                self.assertEqual(args[args.index(option) + 1], value)
        else:
            for option in (
                "--proto",
                "--proto-redir",
                "--connect-timeout",
                "--max-time",
            ):
                self.assertNotIn(option, args)
        self.assertTrue(any(arg.startswith("https://") for arg in args), args)
        self.assertIn("-fsSL", args)
        self.assertNotIn("--retry", args)
        self.assertNotIn("--output", args)

    def serve_release(
        self, *, stall_first_address=False, responses=None, redirect_assets=False
    ):
        """Use real curl with a private TLS server and no external networking."""
        if not REAL_CURL or not shutil.which("openssl"):
            self.skipTest("curl and openssl are required for loopback download checks")
        config = self.root / "tls.cnf"
        config.write_text(
            "[req]\nprompt = no\ndistinguished_name = dn\n"
            "[dn]\nCN = localhost\n[extensions]\n"
            "subjectAltName = DNS:localhost,DNS:github.com,DNS:release-assets.githubusercontent.com\n"
            "basicConstraints = critical,CA:TRUE\n"
            "keyUsage = critical,digitalSignature,keyEncipherment,keyCertSign\n"
            "extendedKeyUsage = serverAuth\n"
        )
        certificate, key = self.root / "tls.pem", self.root / "tls.key"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-config",
                str(config),
                "-extensions",
                "extensions",
                "-keyout",
                str(key),
                "-out",
                str(certificate),
            ],
            check=True,
            capture_output=True,
            timeout=15,
        )
        requests = []
        self.download_connections = []
        self.download_methods = []
        connections = self.download_connections
        methods = self.download_methods
        release = self.release
        responses = {} if responses is None else responses

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_HEAD(self):
                self.respond(head=True)

            def do_GET(self):
                self.respond()

            def respond(self, *, head=False):
                name = self.path.rsplit("/", 1)[-1]
                requests.append(name)
                methods.append(self.command)
                asset_redirect = (
                    redirect_assets
                    and self.headers["Host"] == "github.com"
                    and name not in ("latest", VERSION)
                )
                queued = responses.get(name, [])
                status = queued.pop(0) if queued and not asset_redirect else 200
                if name == "latest" or asset_redirect:
                    status, body = 302, b""
                elif name == VERSION:
                    body = b"release page"
                else:
                    body = (
                        (release / name).read_bytes()
                        if status == 200
                        else b"unavailable"
                    )
                self.send_response(status)
                if name == "latest":
                    self.send_header(
                        "Location", f"/cquark7/withhold/releases/tag/{VERSION}"
                    )
                elif asset_redirect:
                    self.send_header(
                        "Location",
                        f"https://release-assets.githubusercontent.com/assets/{name}",
                    )
                if status >= 400:
                    self.send_header("Connection", "close")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if not head:
                    self.wfile.write(body)

            def log_message(self, *args):
                pass

        class Server(ThreadingHTTPServer):
            address_family = socket.AF_INET6
            daemon_threads = True

            def server_bind(self):
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                super().server_bind()

            def get_request(self):
                connection, address = super().get_request()
                connections.append(address)
                return connection, address

        server = Server(("::1", 0), Handler)
        self.addCleanup(server.server_close)
        port = server.server_port
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def stop():
            server.shutdown()
            thread.join(timeout=5)

        self.addCleanup(stop)
        if stall_first_address:
            # A full, unaccepted loopback queue drops further SYNs. IPv4-mapped
            # IPv6 and ::1 give curl two addresses of the same family, so this
            # exercises sequential address timeout rather than dual-stack racing.
            blackhole = socket.socket()
            self.addCleanup(blackhole.close)
            blackhole.bind(("127.0.0.1", port))
            blackhole.listen(1)
            for _ in range(10):
                client = socket.socket()
                self.addCleanup(client.close)
                client.settimeout(0.1)
                try:
                    client.connect(("127.0.0.1", port))
                except TimeoutError:
                    break
            else:
                self.fail("could not fill the isolated connection queue")
        self.script(
            self.tools / "curl",
            f"""import json, os, subprocess, sys
from urllib.parse import urlsplit
args = sys.argv[1:]
with open(os.environ['FIXTURE_LOG'], 'a') as log:
    log.write(json.dumps(['curl', *args]) + '\\n')
assert all(urlsplit(arg).hostname == 'github.com' for arg in args if arg.startswith('https://'))
addresses = {"[::ffff:127.0.0.1],[::1]" if stall_first_address else "[::1]"!r}
sys.exit(subprocess.call([{REAL_CURL!r}, '-q', '--noproxy', '*',
    '--cacert', {str(certificate)!r}, '--resolve', 'localhost:{port}:' + addresses,
    '--connect-to', 'github.com:443:localhost:{port}',
    '--connect-to', 'release-assets.githubusercontent.com:443:localhost:{port}', *args]))
""",
        )
        return requests

    def isolate_path_without_gh(self, *, shasum_only=False):
        (self.tools / "gh").unlink()
        for name in (
            "awk",
            "grep",
            "sed",
            "mktemp",
            "rm",
            "chmod",
            "mkdir",
            "cp",
            "tar",
            "gzip",
        ):
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
        self.assertIn("--head", self.calls()[0])
        self.assertIn("do not verify the publisher", result.stdout)
        docs = (
            Path(self.env["HOME"]) / ".local/share/withhold" / VERSION / "linux-amd64"
        )
        self.assertEqual(
            (docs / "LICENSE").read_bytes(), (ROOT / "LICENSE").read_bytes()
        )
        self.assertEqual((docs / "THIRD_PARTY_NOTICES.txt").read_bytes(), NOTICES)
        self.assertTrue((docs / "SHA256SUMS").is_file())
        self.assertFalse((docs / "native-release.sigstore.json").exists())
        self.assertFalse((Path(self.env["HOME"]) / ".config").exists())
        self.assertIn("withhold setup", result.stdout)

    def test_every_download_is_bounded_and_stages_do_not_pollute_metadata(self):
        result = self.run_installer("--verify-provenance")
        self.assert_download_policy(self.calls())
        downloads = [args for args in self.calls() if args[0] == "curl"]
        self.assertEqual(len(downloads), 2)
        self.assertEqual(
            [Path(arg).name for arg in downloads[1] if arg.startswith("https://")],
            [
                artifact_name("linux-amd64", VERSION),
                "SHA256SUMS",
                "native-release.sigstore.json",
            ],
        )
        stages = (
            "Finding latest release…",
            f"Downloading withhold {VERSION} for linux-amd64…",
            "Verifying signed provenance…",
            "Verifying SHA-256 checksums…",
            f"Installing to {self.bin}…",
        )
        positions = [result.stderr.index(stage) for stage in stages]
        self.assertEqual(positions, sorted(positions))
        for stage in stages:
            self.assertNotIn(stage, result.stdout)
        self.assertIn(f"Installed withhold to {self.bin}", result.stdout)

    def test_progress_bars_are_enabled_only_for_interactive_stderr(self):
        import pty

        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        result = subprocess.run(
            ["/bin/sh", str(ROOT / "install.sh"), "--version", VERSION],
            env=self.env,
            cwd=self.root,
            stdout=subprocess.PIPE,
            stderr=slave,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assert_download_policy(self.calls(), terminal=True)

    def test_download_errors_identify_failure_and_preserve_existing_install(self):
        self.bin.parent.mkdir(parents=True)
        self.bin.write_text("existing executable")
        for status, http, detail in (
            (5, "000", "DNS lookup failed"),
            (6, "000", "DNS lookup failed"),
            (7, "000", "connection failed"),
            (28, "000", "connection or download timed out after limited retries"),
            (22, "404", "release file not found (HTTP 404)"),
            (22, "429", "GitHub rate limit reached (HTTP 429)"),
            (22, "503", "server returned HTTP 503"),
            (35, "000", "HTTPS verification or TLS handshake failed"),
            (60, "000", "HTTPS verification or TLS handshake failed"),
            (23, "200", "cannot write the download"),
            (18, "200", "download failed (curl exit 18)"),
        ):
            with self.subTest(status=status, http=http):
                self.env.update(FIXTURE_CURL_EXIT=str(status), FIXTURE_HTTP_STATUS=http)
                result = self.run_installer("--version", VERSION, success=False)
                self.assertIn(
                    f"Downloading withhold {VERSION} for linux-amd64: {detail}",
                    result.stderr,
                )
                self.assertIn("nothing was installed", result.stderr)
                self.assertNotIn("Installing to", result.stderr)
                self.assertEqual(self.bin.read_text(), "existing executable")

    def test_bootstrap_examples_stream_installer_with_expected_curl_policy(self):
        shutil.copyfile(ROOT / "install.sh", self.release / "install.sh")
        for name, example in self.bootstrap_examples():
            with self.subTest(example=name):
                before = len(self.calls())
                self.run_bootstrap(example)
                calls = self.calls()[before:]
                self.assertTrue(calls[0][-1].endswith("/install.sh"))
                self.assert_bootstrap_policy(calls[0], bounded=name != "README.md")
                self.assert_download_policy(calls[1:])
                self.assertTrue(self.bin.is_file())
                if name == "release notes":
                    self.assertIn(
                        f"/releases/download/{VERSION}/install.sh", calls[0][-1]
                    )
                    self.assertFalse(
                        any(args[-1].endswith("/latest") for args in calls)
                    )

    def test_truncated_bootstrap_never_calls_install_entry_point(self):
        self.env["FIXTURE_PARTIAL_BOOTSTRAP"] = "1"
        for name, example in self.bootstrap_examples():
            with self.subTest(example=name):
                before = len(self.calls())
                result = self.run_bootstrap(example)
                self.assertIn("curl: (28) download timed out", result.stderr)
                self.assertEqual(len(self.calls()) - before, 1)
                self.assertFalse(self.bin.exists())

    def test_real_curl_moves_past_a_stalled_address_within_connection_budget(self):
        requests = self.serve_release(stall_first_address=True)
        started = time.monotonic()
        self.run_installer("--version", VERSION)
        self.assertLess(time.monotonic() - started, 20)
        self.assertEqual(requests.count(artifact_name("linux-amd64", VERSION)), 1)
        self.assertEqual(len(requests), 2)
        self.assertEqual(len(self.download_connections), 1)
        self.assertTrue(self.bin.is_file())

    def test_latest_discovery_uses_head_and_release_files_share_one_connection(self):
        requests = self.serve_release()
        self.run_installer("--verify-provenance")
        self.assertEqual(requests[:2], ["latest", VERSION])
        self.assertEqual(self.download_methods, ["HEAD", "HEAD", "GET", "GET", "GET"])
        self.assertEqual(len(self.download_connections), 2)
        self.assertTrue(self.bin.is_file())

    def test_release_redirects_reuse_github_and_asset_connections(self):
        requests = self.serve_release(redirect_assets=True)
        self.run_installer("--version", VERSION, "--verify-provenance")
        self.assertEqual(len(requests), 6)
        self.assertEqual(len(self.download_connections), 2)
        self.assertEqual(len([args for args in self.calls() if args[0] == "curl"]), 1)

    def test_failed_batch_member_stops_downloads_and_preserves_install(self):
        self.bin.parent.mkdir(parents=True)
        self.bin.write_text("existing executable")
        responses = {}
        requests = self.serve_release(responses=responses)
        subjects = [
            artifact_name("linux-amd64", VERSION),
            "SHA256SUMS",
            "native-release.sigstore.json",
        ]
        for index, subject in enumerate(subjects):
            with self.subTest(subject=subject):
                requests.clear()
                responses[subject] = [404]
                result = self.run_installer(
                    "--version", VERSION, "--verify-provenance", success=False
                )
                self.assertEqual(requests, subjects[: index + 1])
                self.assertIn("release file not found (HTTP 404)", result.stderr)
                self.assertNotIn("Verifying", result.stderr)
                self.assertEqual(self.bin.read_text(), "existing executable")
        self.assertFalse(any(args[0] == "gh" for args in self.calls()))

    def test_real_curl_retries_transient_http_failure_but_not_missing_files(self):
        artifact = artifact_name("linux-amd64", VERSION)
        responses = {artifact: [503]}
        requests = self.serve_release(responses=responses)
        self.run_installer("--version", VERSION)
        self.assertEqual(requests.count(artifact), 2)
        self.assertEqual(self.bin.read_bytes(), self.binary.read_bytes())
        requests.clear()
        responses[artifact] = [404]
        result = self.run_installer("--version", VERSION, success=False)
        self.assertIn("release file not found (HTTP 404)", result.stderr)
        self.assertEqual(requests, [artifact])
        self.assertEqual(self.bin.read_bytes(), self.binary.read_bytes())

    def test_real_bootstrap_streams_the_installer_once(self):
        Path(self.env["HOME"]).mkdir()
        (self.release / "install.sh").write_text('touch "$HOME/bootstrap-ran"\n')
        requests = self.serve_release()
        _, example = next(self.bootstrap_examples())
        self.run_bootstrap(example)
        self.assertEqual(requests, ["install.sh"])
        self.assertTrue((Path(self.env["HOME"]) / "bootstrap-ran").is_file())

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
                verifications = [args for args in self.calls() if args[0] == "gh"][-2:]
                self.assertEqual(len(verifications), 2)
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
            artifact_name("linux-amd64", VERSION),
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
        self.assertEqual(len(verifications), 2)
        self.assertEqual(
            {Path(args[3]).name for args in verifications},
            {
                artifact_name("linux-amd64", VERSION),
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
            original + lines[0],
            "",
            "0" * 64 + lines[0][64:],
        ):
            with self.subTest(contents=contents):
                path.write_text(contents)
                self.run_installer(success=False)
                self.assertFalse(self.bin.exists())

    def test_missing_archive_notices_do_not_replace_an_existing_installation(self):
        path = self.release / artifact_name("linux-amd64", VERSION)
        with tarfile.open(path, "r:gz") as source:
            members = [
                (info, source.extractfile(info).read())
                for info in source
                if info.name != "THIRD_PARTY_NOTICES.txt"
            ]
        with tarfile.open(path, "w:gz") as output:
            for info, data in members:
                output.addfile(info, io.BytesIO(data))
        (self.release / "SHA256SUMS").write_text(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
        )
        self.bin.parent.mkdir(parents=True)
        self.bin.write_text("existing executable")
        result = self.run_installer(success=False)
        self.assertIn("THIRD_PARTY_NOTICES.txt", result.stderr)
        self.assertEqual(self.bin.read_text(), "existing executable")

    def test_archive_members_cannot_write_outside_the_private_directory(self):
        path = self.release / artifact_name("linux-amd64", VERSION)
        with tarfile.open(path, "r:gz") as source:
            members = [(info, source.extractfile(info).read()) for info in source]
        with tarfile.open(path, "w:gz") as output:
            for info, data in members:
                output.addfile(info, io.BytesIO(data))
            info = tarfile.TarInfo("../escaped")
            data = b"unexpected content"
            info.size = len(data)
            output.addfile(info, io.BytesIO(data))
        (self.release / "SHA256SUMS").write_text(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
        )
        self.run_installer("--version", VERSION)
        self.assertTrue(self.bin.is_file())
        self.assertFalse((self.root / "escaped").exists())

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

    def test_missing_archive_tools_fail_before_download(self):
        self.isolate_path_without_gh()
        for tool in ("tar", "gzip"):
            with self.subTest(tool=tool):
                link = self.tools / tool
                link.unlink()
                result = self.run_installer("--version", VERSION, success=False)
                self.assertIn(f"{tool} is required", result.stderr)
                self.assertFalse(self.calls())
                self.assertFalse(self.bin.exists())
                link.symlink_to(shutil.which(tool))
