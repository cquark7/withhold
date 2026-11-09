# Using withhold

withhold is a local privacy guard with explicit coding-agent integrations. Builds
target macOS, Linux, and Windows on x64/ARM64. Currently only
[desktop VS Code + GitHub Copilot](integrations/vscode-copilot.md) is integrated.
Use the [integration catalog](integrations/README.md) for support and setup. Read the
[protection limits](../CONTRACTS.md#scope-and-traffic-policy) before setup.

## Installation

### Build from source

From a trusted checkout with Go 1.26.10:

```sh
go build -trimpath -o withhold ./cmd/withhold
./withhold install
export PATH="$HOME/.local/bin:$PATH"
```

Windows PowerShell: `go build -trimpath -o withhold.exe ./cmd/withhold`, then
`.\withhold.exe install`. Add the printed directory to your user PATH.
Installation copies the executable; it does not change trust or editor settings.

### macOS and Linux downloads

Install [GitHub CLI](https://cli.github.com/), `tar`, and a SHA-256 utility
(`shasum` or `sha256sum`). Choose a published tag from
[Releases](https://github.com/cquark7/withhold/releases); if none is available,
build from source. Download and review the installer before running it:

```sh
curl -fsSL https://raw.githubusercontent.com/cquark7/withhold/main/install.sh -o install.sh
less install.sh
sh install.sh --help
# Replace the example with a published tag.
sh install.sh --version v0.1.0-rc.1
export PATH="$HOME/.local/bin:$PATH"
```

Without `--version`, the installer selects the latest **non-prerelease**; RCs
must be selected explicitly. `--bin-dir` chooses an absolute destination.
`--commit FULL_SHA` also pins binary provenance; obtain that commit independently
from a trusted announcement. For a pinned bootstrap, fetch the script from that
reviewed commit instead of `main`.

The installer verifies archive and checksum-manifest provenance and SHA-256
before extraction/execution. There is no unsigned fallback. It requires no
sudo and does not edit PATH, trust, or editor settings. Release API access may
require `gh auth login`. Downloads/verification contact GitHub and signing
services, not a project telemetry service. License/docs/verification evidence
are saved under `~/.local/share/withhold/VERSION/TARGET`.

### Windows and manual downloads

Use GitHub CLI to download and verify an archive before extracting it. This
PowerShell example requires a published tag and independently obtained commit:

```powershell
$version = "v0.1.0-rc.1" # Replace with a published tag.
$commit = "FULL_COMMIT_SHA"
$target = "windows-amd64" # Use windows-arm64 on ARM64.
$archive = "withhold-$version-$target.zip"
gh release download $version --repo cquark7/withhold --pattern $archive --pattern native-release.sigstore.json
if ($LASTEXITCODE -ne 0) { throw "Download failed" }
gh attestation verify $archive --repo cquark7/withhold --signer-workflow cquark7/withhold/.github/workflows/native-artifacts.yml --source-ref "refs/tags/$version" --source-digest $commit --deny-self-hosted-runners --bundle native-release.sigstore.json
if ($LASTEXITCODE -ne 0) { throw "Verification failed; do not extract" }
Expand-Archive $archive -DestinationPath "withhold-$version-$target"
Set-Location "withhold-$version-$target"
.\withhold.exe install
```

Add the printed directory (normally `%LOCALAPPDATA%\withhold\bin`) to your user
PATH. Unix archives use `.tar.gz` and `darwin`/`linux` with `amd64`/`arm64`;
the same attestation checks apply. Verify `SHA256SUMS` separately if using it.
Keep the license/notices and verification bundle. Checksums alone do not prove
origin; attestations do not establish security, OS notarization, or compatibility.

## Start and stop

### Try the local pipeline first

```sh
withhold demo
withhold demo --json
```

No account or setup is required. The demo sends a fixed synthetic value through
the bundled scanner and an HTTPS proxy to a local receiver. It verifies a
`<WITHHELD_…>` replacement and a blocked request that never reaches that receiver.
It uses ephemeral loopback ports, an isolated worker, and a temporary CA trusted
only in memory, then removes its temporary files. No provider, editor settings,
or real trust store is used. A failure returns 1, not a simulated success.

This demonstrates local enforcement, **not** editor routing, real-provider
compatibility, WebSocket coverage, or every supported payload format. See the
[integration validation matrix](integrations/vscode-copilot.md#validation-and-support-matrix).

### Configure the application

```sh
withhold setup
withhold doctor
withhold on
# Follow your integration's application startup/restart instructions.
withhold status
withhold off
```

These commands use the configured integration (default `vscode-copilot`). Run
`withhold integrations` to list this build's adapters. Select one with
`--integration NAME` or the [user config](configuration.md); stop the current
session before switching. Application settings, coverage, and restart requirements
belong to its [integration guide](integrations/README.md), not the shared proxy.

The guard does not restart at login/reboot. If its process exits, settings remain
managed until `off` restores them. Restart applications after toggling if connections
are cached. A running listener does not prove expected traffic is inspected;
check the provider/surface in audit records.

### Certificate trust

| Platform | Setup |
| --- | --- |
| macOS | Current user's login Keychain. |
| Linux | Current user's NSS databases; requires NSS `certutil` (e.g. `libnss3-tools`). |
| Windows | Manual CA import; setup prints the certificate path. |

`withhold setup --trust manual` creates the CA without installing trust.
Import `ca.crt` into the appropriate user/application trust store, subject to your
organization's policy. Protect `ca.key`: the CA can intercept traffic that trusts it.

OS trust does not necessarily cover a harness's networking runtime. Follow its
integration guide for additional roots or launch-time configuration; never
disable TLS verification as a workaround. `doctor` cannot verify manual imports.

## Configuration and diagnostics

No configuration file is required. Use `withhold help COMMAND` for flags and
defaults, or the [configuration reference](configuration.md) for persistent
settings. Stop and restart a background session to change its options.

`withhold config --example` prints a commented TOML starter without reading your
configuration or writing files. Redirect it only to a new file; review before
using it. `withhold config` without `--example` still prints effective **JSON**.

```sh
withhold on --pii email,phone
withhold status --json
withhold doctor --json
```

The default state directory is `~/.config/withhold`; `WITHHOLD_DIR` overrides
it. `audit.jsonl` contains decisions/metadata and `hints.log` readable summaries,
not detected values. Both may still reveal local paths and usage.

`status` reports value-free traffic counters even without `--debug`:

| Coverage state | Evidence in this authenticated session |
| --- | --- |
| `unavailable` | No authenticated process; no traffic evidence is available. |
| `awaiting-traffic` | Running, but no HTTP requests or WebSocket messages observed. CONNECT alone is insufficient. |
| `traffic-observed` | Traffic arrived, but no supported body completed inspection. |
| `inspected` | At least one supported body completed inspection, not necessarily every request. |

`scan_attempts` includes failures; `inspected` requires a successful scanner
result on a supported route. `passthrough` includes uninspected policy passes
and bodyless requests. Observe mode may inspect but forwards original sensitive
content: `coverage.observe` makes this explicit. Review integration exceptions,
especially embeddings and token exchange; do not infer full coverage from counts.
Status JSON schema 4 separates `coverage`, `traffic`, and finding-log `debug` health.

For temporary debugging, run `withhold off`, then `withhold on --debug`:

```sh
withhold status
tail -F "${WITHHOLD_DIR:-$HOME/.config/withhold}/debug-findings.log"
```

Windows: use `Get-Content -Wait` with the path printed by status. Findings show
masked prefixes, replacements, and send/block outcomes—not request bodies.
`sent` means a completed transport write, not model consumption. An empty log
does not establish coverage; check status counters. Findings are sensitive:
use synthetic data and remove the file and its `.1` backup after testing.

`serve` runs in the foreground without managing application settings; stop with
Ctrl-C. `init-ca` creates CA files without trust setup. `completion SHELL`
prints bash/zsh/fish/PowerShell completion without editing shell configuration.

## Upgrade and rollback

For an upgrade that changes state/configuration formats, use the installed
executable and original state directory to run `off` and `uninstall` before
setting up the replacement. Preserve state/backups until settings restoration
and trust removal succeed.

1. Quit the integrated application and run `withhold off`. Keep state and the previous executable.
2. Verify the replacement, then run its `install` command (or the pinned installer)
   using the same state/binary directories. Installation refuses active sessions.
3. Run `withhold version`, `withhold doctor`, and `withhold on`; restart the application as its guide requires.
4. To roll back, stop the session, reinstall the previous verified binary, and
   repeat doctor/on. Do not delete CA or recovery state during an upgrade.

## Recovery and removal

| Problem | Action |
| --- | --- |
| No latest download | Select a published tag with `--version`, or build from source. |
| Verification failure | Stop; check the expected tag/commit and update GitHub CLI. Do not bypass it. |
| Certificate errors | Check `doctor` and the integration trust guide. Private upstream PKI uses `--upstream-ca FILE`. |
| Port occupied | Check `status`; stop your session or choose `on --port 8090`. Foreign listeners are never stopped. |
| Running, no expected traffic | Check application routing, host scope, and runtime location against the integration guide. |
| Startup/restore failure | Keep state/backups, inspect `proxy.log`, repair invalid application settings, and retry `off`. |

Run `withhold off`, then `withhold uninstall` to restore settings and remove
automatically managed CA trust. For manual trust, remove the CA from **every**
store where you imported it, then use `withhold uninstall --keep-files`.
Keep state until restoration/removal is verified. Uninstall leaves the installed
binary, logs, and editor settings in place; remove retained files yourself.
Never share CA/placeholder keys, `session.json`, settings backups, or raw
captures. Use [private security reporting](../SECURITY.md) for sensitive problems.
