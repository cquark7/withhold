# Architecture

withhold is a single Go executable with process-isolated scanning. Its core is
provider- and harness-independent; only the VS Code/Copilot adapter is registered. There is
no dynamically loaded plugin system or general multi-agent support claim.

```text
CLI/config → integration registry → managed session or foreground proxy
                                       ↓
request → transport intake → scanner pool → policy → upstream or local error
                                ↓
                     private scanner child processes
```

## Package boundaries

| Package | Responsibility |
| --- | --- |
| `cmd/withhold`, `internal/config` | CLI composition, strict TOML config and precedence. |
| `internal/proxy` | Bounded HTTP/TLS/WebSocket transport, forwarding, audit/findings. |
| `internal/policy` | Traffic contracts and shared enforcement decisions. |
| `internal/scanner` | JSON extraction, rewriting, placeholders, residue verification. |
| `internal/detector`, `internal/pii` | Offline secret and selected PII recognizers. |
| `internal/worker`, `internal/scanpool` | Private process protocol, key resolution, admission/deadlines. |
| `internal/session`, `internal/control` | Harness-independent sessions, authenticated ownership, trust/recovery. |
| `internal/integration` | Reversible application-setup and optional-launch contracts. |
| `internal/integrations/copilot` | Copilot routes/errors, typed VS Code config, settings, and optional launch. |
| `internal/integrations` | Single explicit registry: factories, settings normalization, catalog metadata. |
| `internal/certstore`, `internal/localstate`, `internal/jsonmeta` | CA issuance, private files, bounded metadata extraction. |

Adapters supply traffic classification/error framing and reversible current-user
application setup. Scanning does not read endpoints, editor paths, or ambient
configuration: PII selection and key resolution are injected. Launch is optional,
not the protection mechanism. `internal/testintegration` tests these contracts
with different paths/errors/settings; it is not linked into the product.
Import-boundary tests protect this separation.

## Extension model and decisions

- **Harness is not provider.** One stable integration ID selects tested setup and
  traffic behavior together. `policy.Profile` and `integration.Application` are
  separate contracts: a future harness can reuse an established provider profile
  without sharing application settings. Extract a shared profile when actual
  reuse exists, not by introducing a speculative provider × agent matrix.
- **Thin adapters, shared enforcement.** Adapters own host/path classification,
  protocol-compatible errors, typed application settings, and reversible setup.
  Core transport owns admission/TLS/forwarding; policy owns decisions; scanners
  see bytes and injected detector options, never a harness ID.
- **One registry, one CLI.** New integrations register once in
  `internal/integrations/registry.go`. The catalog and completion consume it;
  help points to it. Keep the lifecycle commands and `--integration` selector
  consistent rather than adding per-agent verbs or boolean selectors.
  Recovery commands use the recorded integration, not a new selector.
- **Adapter-owned configuration.** `[application]` is opaque to shared config
  but strictly decoded into an adapter's typed settings. Defaults and only that
  adapter's environment overrides normalize before fingerprinting and persistence.
  Children consume frozen settings without rereading overrides. New settings
  need no fields in the CLI, config envelope, session manager, or scanner.
  Both traffic and application factories receive normalized adapter settings,
  so harness-specific endpoint/provider choices need no shared config fields.
- **TOML for humans, JSON for machines.** User files have one strict TOML schema
  and one default filename, `config.toml`. JSON is the internal representation
  shared by typed adapter settings, frozen session records, and machine-readable
  CLI output, not an alternate file format. Do not add fallback formats, renamed-option aliases,
  or older private-protocol readers without an established support requirement.
- **Optional launch, explicit routing.** `integration.Launcher` is optional.
  Applications receive port/CA setup context, and record an absolute recovery
  anchor before mutation. Multi-file adapters can own a manifest at that anchor.
  Current sessions manage reversible application configuration; a future
  launch-only or native-hook lifecycle should add a focused capability with tests
  when required, not pretend the existing proxy covers it.
- **Static, reviewed integrations.** No dynamic plugin loader, arbitrary setup
  scripts, auto-detection, hot reload, or concurrent multi-agent supervisor.
  Single-integration sessions keep ownership and recovery understandable. State
  lives under `~/.config/withhold`; `_session-serve` consumes a complete frozen
  session record, not replayed CLI flags. Session-only debug is an explicit field.
  The control protocol has one signed schema, without negotiation
  or fallback readers. Recovery safeguards are current behavior, not a migration layer.

This follows RTK's [thin-adapter approach](https://github.com/rtk-ai/rtk/blob/master/docs/guide/getting-started/supported-agents.md)
and discoverable selection pattern, not its optimization-specific fail-open or
prompt-only integration tiers. Instructions telling a model to avoid secrets
are not an enforceable egress integration. Do not copy RTK's engine or proxy code.

See [Adding an integration](adding-integrations.md) for the implementation and
test checklist, and the [documentation index](README.md) for ownership of docs.

## Scanner process boundary

The proxy launches itself as `_scanner --body`. Up to three serial workers start
lazily, communicate through private stdin/stdout, and retire after 60 idle seconds.
Sequential traffic reuses one worker. Deadlines include queueing, startup, scan,
and pipe I/O; timeouts kill/reap children. Crashes or invalid replies discard the
worker. There is no external-detector fallback or worker listening socket.

Frames have a four-byte big-endian length and a 128 MiB payload limit in each
direction. Body requests contain an eight-byte signed big-endian cap followed
by original bytes. Schema-1 greetings identify `withhold-scanner` and betterleaks
`1.10.0`; enabled PII also identifies Alcatraz `0.23.0` and selected categories.
Clients require matching metadata. Replies contain `schema: 1` and `report`;
rewritten bytes use `body_base64`. Strict validation rejects unknown fields,
invalid counters/statuses, and unsafe diagnostics before policy uses them.

`cmd/withhold-scanner` exposes this protocol for development. `--jsonl` accepts
`body_base64` and optional `max_bytes`; no-argument detector mode accepts framed
UTF-8 text and returns private `RuleID`/`Secret`/`Match` findings. Raw findings
must never enter ordinary diagnostics. Scanner statuses and runtime guarantees
are covered by the [behavior contract](../CONTRACTS.md).
