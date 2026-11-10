# Using withhold

withhold is a local privacy guard with explicit coding-agent integrations. Builds
target macOS, Linux, and Windows on x64/ARM64. Currently only
[desktop VS Code + GitHub Copilot](integrations/vscode-copilot.md) is integrated.
Use the [integration catalog](integrations/README.md) for support and setup. Read the
[protection limits](../CONTRACTS.md#scope-and-traffic-policy) before setup.

## Installation

### macOS and Linux downloads

These instructions apply to releases with standalone binaries. The v0.1.0
installer still requires GitHub CLI and uses archives instead.

The installer needs `curl` and a SHA-256 utility (`shasum` or `sha256sum`). Go,
Python, GitHub CLI, and archive extraction tools are not required.

```sh
curl -fsSL https://github.com/cquark7/withhold/releases/latest/download/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
withhold version
withhold demo
```

To download and review the script before running it:

```sh
curl -fsSL https://github.com/cquark7/withhold/releases/latest/download/install.sh -o install.sh
less install.sh
sh install.sh --help
sh install.sh
```

To install a specific release that includes standalone binaries, choose its tag:

```sh
curl -fsSL https://github.com/cquark7/withhold/releases/download/VERSION/install.sh | sh -s -- --version VERSION
```

Replace `VERSION` in both places with the same tag, such as `v1.2.3`. Without
`--version`, the installer selects the latest **non-prerelease**; RCs must be
selected explicitly. `--bin-dir` chooses an absolute destination. Older releases
without standalone binaries, including v0.1.0, have their own archive-based
installer and instructions.

The installer checks the executable and license/notice file against the release's
SHA-256 manifest before running the executable. This detects corrupt downloads,
but a checksum downloaded alongside a substituted file does **not** authenticate
who built it. For stronger verification, install [GitHub CLI](https://cli.github.com/)
and add `--verify-provenance` to check the signed record against the repository,
release workflow, and tag. Use `--commit FULL_SHA` to also pin an independently
trusted source commit; this implies `--verify-provenance`. A requested provenance
check fails closed; it never falls back to checksums. A pinned installation also
requires a trusted copy of the installer itself, such as one reviewed at that
commit. After reviewing and saving `install.sh`, for example, run
`sh install.sh --verify-provenance` or
`sh install.sh --version VERSION --commit FULL_SHA`. See
[GitHub's attestation guide](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
for what the signed record establishes.

Installation requires no sudo and does not edit PATH, trust, or editor settings.
Downloads contact GitHub; optional provenance verification may also contact
signing services. Notices and verification evidence are saved under
`~/.local/share/withhold/VERSION/TARGET`.

### Windows and manual downloads

Download the Windows executable and matching notice file from
[Releases](https://github.com/cquark7/withhold/releases/latest). This PowerShell
example downloads them and checks their SHA-256 hashes before installation:

```powershell
$version = "vX.Y.Z" # Replace with a published tag that has standalone binaries.
$target = "windows-amd64" # Use windows-arm64 on ARM64.
$binary = "withhold-$version-$target.exe"
$notices = "withhold-$version-$target-NOTICES.txt"
$base = "https://github.com/cquark7/withhold/releases/download/$version"
foreach ($file in @($binary, $notices, "SHA256SUMS")) {
    Invoke-WebRequest "$base/$file" -OutFile $file -UseBasicParsing -ErrorAction Stop
}
foreach ($file in @($binary, $notices)) {
    $rows = @(Get-Content SHA256SUMS | Where-Object {
        $_ -match '^([0-9a-f]{64})  (.+)$' -and $Matches[2] -ceq $file
    })
    if ($rows.Count -ne 1) { throw "Missing or duplicate checksum for $file" }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant() -cne $rows[0].Substring(0, 64)) {
        throw "Checksum mismatch for $file; do not run it"
    }
}
```

For optional signed provenance, before running the executable, use GitHub CLI
and an independently trusted commit:

```powershell
$commit = "FULL_COMMIT_SHA" # Replace with an independently trusted commit.
Invoke-WebRequest "$base/native-release.sigstore.json" -OutFile native-release.sigstore.json -UseBasicParsing -ErrorAction Stop
foreach ($file in @($binary, $notices, "SHA256SUMS")) {
    gh attestation verify $file --repo cquark7/withhold --signer-workflow cquark7/withhold/.github/workflows/native-artifacts.yml --source-ref "refs/tags/$version" --source-digest $commit --deny-self-hosted-runners --bundle native-release.sigstore.json
    if ($LASTEXITCODE -ne 0) { throw "Provenance verification failed; do not run" }
}
```

After verification, install the downloaded executable:

```powershell
& ".\$binary" install
if ($LASTEXITCODE -ne 0) { throw "Installation failed" }
```

Add the printed directory (normally `%LOCALAPPDATA%\withhold\bin`) to your user
PATH, and keep the notice file with the executable.

For a manual macOS/Linux download, select the `darwin` or `linux` executable
for your CPU, its matching notices, and `SHA256SUMS`. Compare the hashes from
`shasum -a 256 FILE` (or `sha256sum FILE`) with the matching manifest entries.
Then run `chmod +x FILE` and `./FILE install`, replacing `FILE` with the
downloaded executable's name. Archives are available as well.
Attestations do not establish that software is safe or compatible, and do not
provide macOS notarization or Windows code signing.

### Build from source

From a trusted checkout with Go 1.26 or later (Go may automatically download
the toolchain suggested by `go.mod`):

```sh
git clone https://github.com/cquark7/withhold.git
cd withhold
go build -trimpath -o withhold ./cmd/withhold
./withhold install
export PATH="$HOME/.local/bin:$PATH"
```

Windows PowerShell: `go build -trimpath -o withhold.exe ./cmd/withhold`, then
`.\withhold.exe install`. Add the printed directory to your user PATH.
Installation copies the executable and creates an absent default configuration;
it does not overwrite existing config or change trust or editor settings.

## Scan local text

`scan` finds secrets and optional PII locally without rewriting input, starting a
proxy, or requiring setup. Output identifies the rule and original location,
not detected values or source excerpts.

```sh
withhold scan .env
withhold scan src config
withhold scan . --pii email,phone
withhold scan . --confidence medium
withhold scan . --secrets=false --pii all
withhold scan - < message.txt
withhold scan --text 'dev@example.com' --pii email
withhold scan . --exclude ./generated --json
withhold scan . --no-default-excludes
```

Paths may be files or recursive directories. Options may precede or follow paths;
use `--` for names beginning with `-`, and `./-` for a file named `-`. Positional
arguments are never guessed to be text. With no paths, redirected stdin is read;
interactive use requires a target or `--text`. Explicit `-` may accompany files
but can appear only once. `--text` cannot accompany paths/stdin. Prefer files or
stdin for real sensitive data: arguments can enter shell history/process listings.

Secrets default on. PII uses the [configured selection](configuration.md), off by
default; `--pii off`, `--pii all`, or categories override it. `--secrets=false`
requires at least one PII category. The selected TOML file is strictly validated,
without editor discovery. No state, logs, keys, settings, or trust are written.

`--confidence low|medium|high` delegates a minimum confidence to Betterleaks for
offline secret findings. It overrides `[scan].confidence` in TOML; the default is
`""` (no minimum), and `--confidence=` clears a configured minimum. `medium`
includes medium/high findings; `high` includes high findings. Unclassified
findings remain included, along with components of accepted multipart findings.
PII and proxy protection are unaffected. Higher thresholds can hide real secrets;
confidence is a heuristic, not credential validation.

Path scans use the bundled Betterleaks path prefilter before opening files or
entering directories. This skips `node_modules`, upstream-selected vendored
packages, common lockfiles, and other generated paths. The same scope applies to
explicit targets and PII-only scans. Use `--no-default-excludes` to include those
paths. Local Betterleaks configuration and project ignore files are not loaded.

Otherwise, directory scans include hidden/gitignored text such as `.env`, prune
`.git` directories, and skip symlinks, nonregular files, binary/document/archive
content, and invalid UTF-8. Explicit unsupported inputs are errors. Repeat
`--exclude PATH` for literal files/subtrees relative to your working directory;
these exclusions win over explicit targets even with `--no-default-excludes` and
are not globs. Skipped counts describe entries or pruned subtree roots, not every
descendant file; `default-excluded` counts bundled prefilter skips. Empty
selections say `No eligible text inputs`; skipped or unreadable content is never
presented as inspected.

Human findings look like `.env:12:19  secret  aws-access-token`. Lines and UTF-8
byte columns start at 1. Full-match locations can include nonsecret context;
decoded findings identify their encoded source span. Filepaths may be private.
This scans literal source text, including `.json` files, not the proxy's JSON
extraction or routing policy; results are not an exact proxy-request simulation.

`--json` streams one schema-1 object with `detectors`, `findings`, `summary`,
`errors`, and `errors_omitted`. Each finding contains `source`, nullable `path`,
`rule_id`, `kind`, byte `start`/`end`, `start_line`/`start_column`,
`end_line`/`end_column`, and `encoded`. Byte ranges are zero-based and half-open;
end line/column positions are exclusive. `summary.complete` must be true before
treating the report as finished; truncated JSON is not a completed report.
`detectors.confidence` records the selected minimum (empty means none); the
schema remains 1 with this additive metadata field.

Exit **0** means complete without findings; **1** complete with findings; **2**
invalid usage/configuration or incomplete/failed scanning. Errors take precedence.
Read failures, oversized text, timeouts, worker failures, and finding limits are
errors, not clean results. The per-input defaults are `--max-bytes 32m` (ceiling
`128m`) and `--scan-timeout 10s`, also inherited from the file's `proxy.max_bytes`
and `proxy.scan_timeout`. `WITHHOLD_MAX_BYTES` and `WITHHOLD_PII` apply; unrelated
proxy/editor environment overrides do not. Inputs are bounded, with up to three
reused workers and 10,000 findings per input; see the
[inspection contract](../CONTRACTS.md#offline-text-inspection) for limits.

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

Installation creates a starter at `~/.config/withhold/config.toml` (or
`WITHHOLD_DIR/config.toml`) if absent; `withhold config --init` creates it for
an existing installation without overwriting an existing file. Edit the file to
change settings; commented defaults continue to follow built-in updates. Use
`withhold config` to view effective TOML settings for a new session, or
`withhold config --json` for machine-readable JSON. A
running session retains its previous settings: stop with `withhold off`, then
start with `withhold on`. See the [configuration reference](configuration.md)
for precedence, custom paths, and privacy considerations.

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
| Verification failure | Stop; check the expected tag and checksum. For provenance failures, check the commit and GitHub CLI version. Do not bypass verification. |
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
