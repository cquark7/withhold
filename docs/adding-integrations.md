# Adding an integration

Every adapter must supply a commented TOML application example for
`withhold config --example --integration NAME`, and a profile suspicion default
for effective configuration. Make traffic customization adapter-owned and
include normalized defaults in its settings where appropriate. Keep its support matrix explicit:
record live-tested application versions and dates, or mark that validation as
not recorded; never substitute fixture success for real application validation.

An integration is a tested harness setup plus a traffic contract, not merely a
provider hostname or launcher executable. Start with the
[architecture boundaries](architecture.md) and [shared contract](../CONTRACTS.md).

## 1. Establish the interception boundary

Document the harness/version/platform, networking runtime, trust requirements,
provider APIs, and routing mechanism. Prove that ordinary requests actually
traverse the guard. Do not equate OpenAI-compatible JSON, proxy environment
support, or an editor fork with established coverage.

Prefer reversible native proxy/base-URL settings when supported. Hooks/plugins
must delegate inspection to shared Withhold behavior; prompt-only instructions
are not a security boundary. The current runtime supports HTTP(S)/WebSocket
proxy integrations. A genuinely different lifecycle or transport needs an
explicit, tested capability, not a flag that claims unsupported protection.

## 2. Implement a small adapter

Create `internal/integrations/<name>/` with files by responsibility:

| File | Responsibility |
| --- | --- |
| `config.go` | Typed application settings and `Configure(raw, getenv)` normalization. |
| `traffic.go` | `policy.Profile`: host/path classification, streaming detection, error framing. |
| `codec.go` (optional) | Route-owned `policy.RPCCodec`: bounded protobuf decoding, scanner projection, verified write-back, content/control classification. |
| `settings.go` | `integration.Application`: resolve/read/apply/restore application resources. |
| `launch.go` | Optional `integration.Launcher`, only when supported. |
| `*_test.go` | Adapter-specific regression tests using synthetic data. |

Use `config.DecodeObject` for strict typed application decoding; do not accept
unknown fields, nulls, duplicates, or case-insensitive aliases. Resolve defaults
and environment once in `Configure`; a nil getter must use only supplied values.
Never put credentials in public config, catalog metadata, or diagnostics.

Keep Connect framing out of adapters: `internal/connectrpc` and the shared proxy
own complete-envelope admission and scan-before-release. A codec must honor
`policy.DecodeLimits.Context`, per-representation size bounds, and `Reserve`
before retaining decoded input, propagating capacity errors unchanged. Project
all supported model/context text into the existing scanner; preserve structural
identifiers, reject unresolved references/integrity, and verify write-back.
`Message.HasContent` must not claim model inspection for a handshake/control-only
message. `policy.RequestBlocker` can frame errors before a body is decodable;
late failures abort the response rather than forge a successful end of stream.

`Application.Resolve` returns an absolute recovery anchor and optional binary.
`Apply` receives the loopback port and CA directory. Record backups/ownership
before mutation. `Restore` must operate from that anchor even with missing or
invalid current configuration, preserve unrelated edits, and retain recovery
artifacts on failure. For multiple files, own a bounded private manifest at the
anchor. Do not make the core rediscover paths or understand a harness's format.

Implement `Launcher` only if useful. Preserve argument boundaries and exit codes,
avoid a shell, and never disable TLS. Launch is not evidence of interception.
VS Code-family adapters can reuse `internal/editorsettings`; keep each editor's
settings directory, additional managed keys, and Windows executable metadata in
its adapter. Other harnesses need not implement editor settings at all.

## 3. Register once

Add one explicit `definition` to `internal/integrations/registry.go` containing:

- Stable ID, display name, and integration-document path.
- Typed settings normalizer.
- Traffic and application factories.

Both factories receive the normalized settings, so adapter-specific provider or
endpoint choices can drive routing and application setup without global fields.

The CLI's `--integration`, catalog, and completion use that registry. Do not add
agent-specific branches to CLI, shared config, session, proxy, policy, or scanner
packages. Reuse traffic profiles independently of harness setup when justified;
no general plugin framework is required.

## 4. Test the contract, including failure paths

- Config defaults, file/environment precedence, frozen child settings, strict
  rejection, and value-free TOML errors, including rejection of JSON file input.
- Guarded/unknown/suspicious/passthrough hosts and paths; JSON/streaming error
  framing; actual request bytes received upstream, not model responses.
- Apply/restore with unrelated edits, partial setup, malformed backups, stale
  discovery, child startup failure, and ownership conflicts.
- Optional launch with literal arguments/exit status, or its explicit absence.
- HTTP/TLS/WebSocket protocols actually claimed; shared wire/capacity limits
  remain unconditional, including any documented inspection-policy exceptions.

`internal/testintegration` demonstrates different routing, error framing, config
format, and a launcher-free application. It is test-only and never selectable
in shipped builds. Registry, import-boundary, proxy, and session tests ensure the
core does not require Copilot-specific behavior. Run the full
[contribution gates](../CONTRIBUTING.md#verify-changes) with isolated acceptance
binaries. Do not run live provider checks or alter real settings/trust by default.

## 5. Document support precisely

Add `docs/integrations/<id>.md` using the existing guide's structure:

1. Supported harness/platform/runtime and exclusions.
2. Setup, verification, restart, recovery, and optional launch.
3. Typed application config, defaults, path semantics, and environment aliases.
4. Traffic contract: hosts, paths, surfaces, passthrough, exceptions, and blocks.

Link it from the integration index. Change `CONTRACTS.md` only for shared
guarantees; keep harness/provider details in the adapter guide. Update support
claims only after verification. No new runtime dependency is needed for a normal
Go adapter; Python remains test/development-only.
