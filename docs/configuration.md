# Configuration

withhold reads **TOML only** from `WITHHOLD_DIR/config.toml`, defaulting to
`~/.config/withhold/config.toml`. No file is required. Select a different file
with `--config FILE` or `WITHHOLD_CONFIG`; an explicitly selected file must exist.
Every selected file is parsed as TOML, regardless of its name. No alternate
default filenames or working-directory files are discovered or auto-edited.

Comments explain security choices and sections separate shared policy from
integration settings. JSON is reserved for machine-readable CLI output, internal
state, and IPC; it is not accepted as user configuration. `withhold config`
prints effective settings as JSON, not a configuration-file template.

Get a commented TOML starter with `withhold config --example`. It prints defaults
for the current platform and selected integration, not your effective settings.
Use `--integration NAME` (or `WITHHOLD_INTEGRATION`) to select an adapter without
reading an existing config. Other overrides are rejected with `--example`.
Save the output as UTF-8 to a **new** file, review it, then select it with
`--config FILE` or place it at the default path; do not overwrite an existing config.

```toml
schema = 1
integration = "vscode-copilot"

[protection]
chat = "redact"
inline = "block" # Avoid inserting placeholders into code.
pii = ["email"] # Optional; secrets always stay enabled.

[proxy]
port = 8080
max_bytes = "32m"
scan_timeout = "10s"
```

Precedence is **explicit flags → environment → file → defaults**. Extra hosts
and regexes merge across sources. `withhold config` prints normalized effective
settings, including selected-integration defaults; review local paths/provider
names before sharing. Stop with `off` and restart with `on` to change a session.
Recovery uses recorded integration/resource details even with broken config.

## Shared file fields

Configuration uses schema 1, at most 1 MiB. Unknown/duplicate/uppercase keys,
invalid types, excessive nesting, and nonregular files (including
symlinks) are rejected. TOML dates/times and nonfinite numbers are unsupported;
use strings for durations and paths. Omitted fields use defaults.

| Field | Default and accepted values |
| --- | --- |
| `schema` | Required: integer `1`. |
| `integration` | `"vscode-copilot"`; list available IDs with `withhold integrations`. |
| `protection.chat` | `"redact"` (redact/forward); also `"block"`. |
| `protection.inline` | `"block"`; also `"redact"`, which can insert placeholders into code. |
| `protection.observe` | `false`; `true` forwards original sensitive content. |
| `protection.pii` | `[]` (off); categories below, `["all"]`, or `["off"]`. |
| `proxy.port` | `8080`; loopback port from 1 to 65535. |
| `proxy.max_bytes` | `"32m"`; positive bytes or binary `k`/`m`/`g` suffix, at most `"128m"`. |
| `proxy.scan_timeout` | `"10s"`; positive Go duration, including queue/worker startup. |
| `proxy.extra_hosts` | `[]`; additional bare provider hostnames. |
| `proxy.extra_host_regex` | `[]`; full-host Go RE2 patterns. |
| `proxy.suspicion_pattern` | Selected traffic profile's default; pattern for unscoped provider-looking hosts. |
| `proxy.upstream_ca` | Unset; additional PEM roots, without disabling TLS verification. |
| `application` | Selected integration's typed settings; see its [guide](integrations/README.md). |
| `trust` | `"system"` (current-user trust) on macOS/Linux, `"manual"` on Windows. |
| `startup_timeout` | `"60s"`; duration from 1 to 600 seconds. |
| `audit`, `hint` | `WITHHOLD_DIR/audit.jsonl`, `WITHHOLD_DIR/hints.log`. |

Integration-specific settings live in `[application]`, not in shared policy or
proxy fields. The selected adapter owns their schema/defaults and rejects unknown
fields. There are no per-agent top-level flags, arbitrary plugin paths, includes,
or inheritance. One selected integration per file/session keeps precedence clear.

PII categories are `aadhaar`, `credit-card`, `email`, `ip-address`, `phone`, and
`us-ssn`; read their [format limits](../CONTRACTS.md#pii-coverage).
Invalid selections fail rather than silently disabling protection.

Prefer absolute paths for logs, config, and upstream roots: relative paths use
the invoking working directory. Application resource paths follow the selected
integration's documented rules.

## Flags and environment

Use `withhold help COMMAND` for applicable flags. `--integration NAME` selects
an adapter for `setup`, `on`, `serve`, `doctor`, `config`, and optional `launch`.
`off` restores the recorded session, not a newly selected integration.
`--debug` is session-only on `on`/`serve`, not a file field.

| Variable | Setting |
| --- | --- |
| `WITHHOLD_DIR` | State/CA/log/config directory; `--dir`. |
| `WITHHOLD_CONFIG` | Explicit config file; `--config` overrides it. |
| `WITHHOLD_INTEGRATION` | Integration ID; `--integration` overrides it. |
| `WITHHOLD_PII` | `off`, `all`, or comma-separated categories; `--pii`. |
| `WITHHOLD_ENFORCE` | `observe` selects audit-only policy; other values enforce. Prefer the file boolean. |
| `WITHHOLD_MAX_BYTES` | Body cap; `--max-bytes`. |
| `WITHHOLD_EXTRA_HOSTS` | Comma-separated hosts; repeatable `--extra-hosts`. |
| `WITHHOLD_EXTRA_HOST_REGEX` | Newline-separated full-host patterns; repeatable `--extra-host-regex`. |
| `WITHHOLD_ON_STARTUP_TIMEOUT` | Numeric seconds (1–600), unlike the file's duration string. |
| `WITHHOLD_AUDIT`, `WITHHOLD_HINT` | Log destinations; `--audit`/`--hint`. |
| `WITHHOLD_PLACEHOLDER_KEY` | Secret HMAC-key override; never log/share it. |

Harness-specific environment overrides are documented in the
[integration guides](integrations/README.md).

## Local state

The default state directory is `~/.config/withhold`. `session.json` records
authenticated ownership, the integration, the absolute managed resource, and
frozen effective configuration. `proxy.log` holds background process diagnostics.
Application backups and ownership markers use `.withhold-*` suffixes.

The fixed placeholder-key file is `~/.config/withhold/placeholder-key`;
`WITHHOLD_DIR` does not relocate it. If key persistence fails, a process-random key
is used. Preserve the key to keep placeholder identities stable.

Configuration, state, and private protocol formats use strict schemas without
automatic migration. When a replacement changes these formats, stop the current
session and remove its managed trust using the current executable and original
state directory. Preserve state and backups until restoration and trust removal
succeed.

`WITHHOLD_TEST_ALLOW_HOSTS` is an isolated-test scope override, not a provider setting.
`WITHHOLD_INTERNAL_*` worker variables are private implementation details.
All project environment variables use `WITHHOLD_*`, without alternate-prefix aliases.
