# VS Code + GitHub Copilot

Integration ID: `vscode-copilot` (default).

This is the supported **desktop VS Code** integration, not a general Copilot
provider switch. Other editors, remote extension hosts, separate user-data
stores, WSL, containers, and browser editors need their own integration/setup.
The [shared behavior contract](../../CONTRACTS.md) also applies.

## Setup and operation

### Validation and support matrix

| Local desktop environment | Build targets | Trust requirements |
| --- | --- | --- |
| macOS | x64, ARM64 | Current-user login Keychain; restart VS Code. |
| Linux | x64, ARM64 | Current-user NSS; extension runtimes may need additional roots. |
| Windows | x64, ARM64 | Manual current-user/application CA import. |

The integration covers local desktop VS Code. Remote extension hosts, WSL,
containers, browser editors, and separate user-data stores need their own setup.
Token exchange passes through uninspected; chat, inline, and embeddings policies
are described in the traffic contract below.

After setup, use `withhold status` and audit surfaces to confirm inspection of
your editor's traffic. `demo` checks the local scanner/proxy pipeline; `doctor`
checks local configuration and trust metadata. Real routing depends on the
editor's networking runtime and certificate trust.

### Configure and start

Install withhold using the [usage guide](../usage.md#installation), and start
with a working Copilot account. `setup` creates an HTTPS inspection CA and
changes current-user certificate trust on macOS/Linux. Review
[certificate trust](../usage.md#certificate-trust) first.

```sh
withhold setup --integration vscode-copilot
withhold doctor --integration vscode-copilot
withhold on --integration vscode-copilot
# Open VS Code normally; restart it once after initial CA setup.
withhold status
withhold off
```

VS Code's default User store supplies application-scoped network settings to
local workspaces and named User profiles. The `code` CLI and a special launcher
are not required for ordinary launches when the editor trusts the CA. Separate
user-data stores and remote extension hosts do not inherit this setup.
Reload windows after toggling if connections are cached. A listener or an empty
findings log does not prove Copilot traffic is inspected; check audit surfaces.

Linux NSS trust may cover Chromium but not Node-based extensions. Configure
their trusted roots or use `withhold launch -- .`, which supplies proxy and
`NODE_EXTRA_CA_CERTS` environment. Fully quit VS Code first so the environment
takes effect; restart normally after `off` to clear it. On Windows, import the
CA into the current user's trusted root store before use. Never disable TLS
verification. `doctor` cannot verify manual imports.

## Application configuration

The shared [config envelope](../configuration.md) accepts these fields under
`application` **only when this integration is selected**:

```toml
schema = 1
integration = "vscode-copilot"

[application]
binary = "code"
settings_dir = "Code"
```

| Field | Default and meaning |
| --- | --- |
| `binary` | `"code"`; executable override for optional `launch`. |
| `settings_dir` | `"Code"`; local directory relative to the platform settings root. |

Settings roots are `~/Library/Application Support` (macOS),
`${XDG_CONFIG_HOME:-~/.config}` (Linux), and `%APPDATA%` (Windows, with a
home-relative fallback). The file is `SETTINGS_ROOT/Code/User/settings.json` by
default. Overrides select a resource; they do not certify another editor.

Environment overrides take precedence over file settings:

| Variable | Setting |
| --- | --- |
| `WITHHOLD_EDITOR_BIN` | `application.binary`. |
| `WITHHOLD_EDITOR_SETTINGS_DIR` | `application.settings_dir`. |

`proxy.suspicion_pattern` defaults to case-insensitive `copilot`. Select this
integration with `integration = "vscode-copilot"`, `WITHHOLD_INTEGRATION`, or
`--integration`; there is no separate provider/editor-profile selector.

Managed keys are `http.proxy`, `http.proxySupport`, `http.proxyStrictSSL`,
`http.noProxy`, `http.systemCertificates`, `http.fetchAdditionalSupport`, and
`http.webSocketAdditionalSupport`, plus their `settingsSync.ignoredSettings`
entries. Bypass lists are loopback-only; TLS verification stays enabled.
`off` restores only managed keys, preserving unrelated/mid-session edits.

## Traffic contract

Guarded hosts:

- `api.githubcopilot.com`
- `api.enterprise.githubcopilot.com`
- `proxy.enterprise.githubcopilot.com`
- `telemetry.enterprise.githubcopilot.com`
- `origin-tracker.githubusercontent.com`
- `embeddings.vscode-cdn.net`
- Hostnames ending in `.individual.githubcopilot.com` or `.business.githubcopilot.com`

`api.github.com` token exchange passes through unscanned. Other unscoped hosts
are audited; provider-looking hosts are blocked for POST/PUT/PATCH or any request
not provably bodyless. Unrelated traffic passes through.

Scoped `/v1/engines/{model}/completions` uses inline policy (`model` is one
nonempty segment). Paths ending in `/chat/completions` or `/responses`, or
containing `/v1/messages`, use chat policy except on `proxy.*` hosts, which use
inline policy. Unknown built-in paths are rejected during inspection. Explicit
extra hosts/patterns accept unknown paths under chat policy. Queries do not
affect routing.

| Surface | Default | Inspection failure |
| --- | --- | --- |
| Chat | Redact and forward (`redact`). | Block. |
| Inline | Block findings. | Block; choosing `redact` permits placeholders in code. |
| Embeddings host | Redact when possible. | Forward unscanned and audit `embeddings-unscanned`. |

HTTP scanning requires a JSON POST, except embeddings POSTs attempt JSON
scanning regardless of content type. Non-POST requests pass only when provably
bodyless. Embeddings permits bodied non-POST requests unscanned. Observe mode
does not enforce these format/method policies. Shared wire-size and intake
limits remain unconditional, including embeddings and observe mode.

Policy blocks return HTTP 429 with
`{"error":{"code":"withhold_blocked","message":"Request blocked by withhold: ..."}}`.
Recognized streaming requests instead receive HTTP 200 SSE with an error event
and `data: [DONE]`. Both include `x-withhold-block: 1`.
