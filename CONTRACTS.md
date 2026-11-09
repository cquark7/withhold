# Behavior contract

These are the observable guarantees and limits of withhold. Changes require
matching tests and documentation. For operation and settings, see
[usage](docs/usage.md) and [configuration](docs/configuration.md).
Harness-specific guarantees and inspection-policy exceptions live in the
[integration contracts](docs/integrations/README.md). Both layers apply; an
integration cannot relax the shared transport, privacy, or recovery guarantees.

## Scope and traffic policy

withhold reduces **accidental disclosure in supported request bodies** routed
through its proxy. Headers, URL queries, responses, deliberate bypass, and
provider-side handling are outside its protection. Scanning is local and offline.

An integration selects a coding harness and a tested traffic contract together.
It defines guarded hosts, request paths/surfaces, intentional passthrough,
suspicious-host classification, and local error framing. Unknown integration
IDs fail; naming an executable or adding an extra host does not establish support
for another agent. `withhold integrations` lists only reviewed built-ins.

Unscoped hosts are audited; suspicious hosts are blocked for POST/PUT/PATCH or
any request not provably bodyless. Unrelated traffic passes through. Unknown
guarded paths fail closed unless the integration explicitly supports them.

| Surface | Default | Inspection failure |
| --- | --- | --- |
| Chat | Redact and forward (`redact`) | Block. |
| Inline | Block findings | Block. Choosing `redact` permits placeholders in code. |
| Observe mode | Forward original content; audit would-be decisions | Policy failures are audit-only; transport failures remain enforced. |

HTTP scanning normally requires a JSON POST. Non-POST requests pass only when provably
bodyless: no transfer encoding and no positive, malformed, or unknown body
length. Any format, method, or inspection-failure exception must be explicit in
the integration contract. Observe mode does not enforce these format/method policies.

## Scanning and redaction

The scanner walks JSON string leaves and object keys, including tool schemas,
arguments, results, defaults, and examples. Numeric scalars are not text.
Duplicate object keys (including escape-equivalent names), invalid Unicode
surrogates, nesting above 1,000 levels, and key-rename collisions fail closed.
Rewriting preserves object order and scalar types, not original formatting.

Secret detection uses bundled betterleaks 1.10.0 rules and Go regular
expressions, without credential validation, repository configuration, or
allow-comment suppression. AWS access-key IDs are detected without requiring a
secret-key component; credential URIs also recognize `psql://`. Multipart
components are all redacted, so nonsecret identifiers can be included. Findings
with 100 or more component combinations fail as incomplete. Synthetic detector
self-tests must pass before startup and whenever a worker starts.

### PII coverage

PII is off by default. Selected Alcatraz 0.23.0 recognizers use their upstream
patterns/scores, pass category-specific canaries, and share the secret rewrite
and verification pipeline. Shape/checksum matches do not establish identity or
issuance; false positives are possible. There is no custom confidence cutoff.

| Category | Coverage and exclusions |
| --- | --- |
| `aadhaar` | Twelve digits or three space-separated groups, Verhoeff checksum; no hyphens/masked values. |
| `email` | Common ASCII addresses and plus tags; no quoted/international local parts or mailbox check. |
| `phone` | US/Brazilian patterns and international `+` numbers; no numbering-plan validation; some extensions/domestic formats are excluded. |
| `credit-card` | Upstream prefixes and Luhn check; no Mastercard 2-series or 19-digit numbers. |
| `us-ssn` | Bare/dashed values with range and repeated/sequential filters; no space-separated values. |
| `ip-address` | IPv4 and expanded IPv6; no compressed IPv6; mapped addresses may return only IPv4. |

### Extraction limits

- Standalone text below eight characters is skipped; PII lowers that floor to
  two. Long text uses 48 KiB windows with 4 KiB overlap.
- Eligible keys and values of at most 4,096 characters are also scanned
  together. Array elements retain their key context.
- UTF-8 base64 text is decoded, scanned, rewritten, and re-encoded. Whitespace,
  URL-safe alphabets, and unpadded variants are accepted. Extraction attempts
  start at 64 characters for secrets or 24 with PII; round-trip checks use 24.
- Declared image/audio/video/font, octet-stream, PDF/ZIP/gzip/WASM payloads and
  recognized PNG/JPEG/GIF/PDF/ZIP/gzip/WASM/WebP/WAV base64 signatures are opaque.
  They skip detection and residue checks at any size. MIME metadata is only a
  client hint: mislabeled text can be excluded. There is no OCR or extraction
  from documents/archives; surrounding text is still inspected.
- Other non-UTF-8 base64 blobs from 64 characters through 64 KiB can be skipped
  as unrewritable. With findings present, block mode rejects that residue; redact
  mode forwards with a warning. Unknown large blobs retain text scanning.
- Joined detector input above 128 MiB fails closed. Opaque bytes still count
  toward transport limits.

Placeholders are `<WITHHELD_` + 16 lowercase HMAC-SHA256 hex digits + `>`.
Key resolution uses `WITHHOLD_PLACEHOLDER_KEY`, then the private installation
file `~/.config/withhold/placeholder-key`, then a process-random key.
Persisted keys are published atomically. Placeholders are stable with the same
key and are never rehydrated in responses. Stable markers reveal repeated values;
they are pseudonymous, not anonymous. Verification checks protected text
and keys for discovered values and URL/base64 variants; failure blocks rewriting.

## Transport and failures

The proxy listens on IPv4 loopback. It supports absolute-form HTTP and HTTPS
CONNECT, HTTP/1.1, negotiated HTTP/2, and WebSockets. CONNECT authority, inner
authority, and TLS SNI must agree. Upstream TLS verification stays enabled;
upstream connections do not chain through environment-configured proxies.
Responses, including SSE, stream without inspection.

Every forwarded guarded HTTP body must pass wire-size and intake admission
limits, including unsupported formats/methods allowed by policy exceptions.
The default cap is 32 MiB, configurable up to 128 MiB. Intake allows six jobs
and 64 MiB of retained input; worker admission independently allows six jobs
and 64 MiB of framed input. These are admission budgets, not process RSS limits.

Wire overflow, failed reads, and exhausted intake capacity (including during
decoding) return HTTP 413 without forwarding, including policy exceptions/observe.
Gzip, deflate, Brotli, Zstandard, stacked encodings, and declared charsets are
decoded before inspection. Decoded size overflow and scanner failures follow
the inspection policy above. Scanner capacity is never reported as clean.
Redacted HTTP bodies become UTF-8 JSON with corrected length and stale encoding,
digest, and trailer headers removed; clean/observe bodies retain wire bytes.
Upload admission is released when transport closes the request body, not when
its response stream ends.

Client WebSocket messages are bounded, reassembled, and decompressed before
inspection; server messages pass through. Redact mode forwards verified rewrites;
block mode stops on findings. Non-JSON text is dropped without closing the
session. Binary/unscannable messages, unknown guarded paths, and scanner errors
stop it. Observe mode forwards originals instead of enforcing policy; transport
and capacity failures still stop the session. Panics abort flows, never create
an uninspected fallback. Shutdown closes connections and reaps workers.

Policy blocks use the selected integration's tested error response protocol.
Streaming detection and local error framing never change scanning or admission.

## Local state and recovery

`setup` creates an EC P-256 CA and configures current-user trust; manual imports
are the user's responsibility. Existing or partial CA files are not overwritten.
Private keys/state use mode 0600 on POSIX or protected current-user Windows ACLs.
Leaf certificates expire within 24 hours or at CA expiry.

`on` backs up and applies application settings, records effective configuration,
and starts an authenticated session. Startup failure attempts rollback. Reuse
requires the same binary, configuration, resource, and private-key fingerprint.
There is no hot reload or login/reboot service.

`off` attempts settings restoration even if shutdown/authentication fails. Only
an authenticated identity/PID/build can be stopped; foreign listeners are not
signalled. Recorded resources remain recoverable with broken current config.
Restore changes only managed keys, preserving unrelated/mid-session edits;
invalid settings/backups are preserved. Failed restore retains recovery data.
CA files are deleted only after verified trust removal. Uninstall does not
delete logs, application settings, or the installed executable.

Application settings and restart/trust requirements belong to the integration.
The recorded resource is an absolute recovery anchor; restoration must not
depend on current application discovery or configuration. There is one active
integration per state directory; switching requires `off` before `on`.
Launch is optional; unsupported launch returns a usage error. When supported,
arguments after `--` and the application's exit status are preserved.

User configuration is TOML only: `DIR/config.toml`, or an explicit file selected
with `--config` or `WITHHOLD_CONFIG`. Only that file is read, regardless of filename;
JSON input is rejected and no alternate default filenames are discovered.
Configuration uses schema 1 and strict typed validation;
integration-owned `application` settings are validated by the selected adapter.
Unknown keys, duplicate keys, nulls, invalid types, and unsupported TOML value
types fail rather than silently changing protection. Configuration is never
discovered from a project directory or rewritten automatically.

## Diagnostics and interfaces

Project environment variables use `WITHHOLD_*`; test-only overrides use
`WITHHOLD_TEST_*`, and private worker settings use `WITHHOLD_INTERNAL_*`.
There are no alternate-prefix aliases. Standard proxy/CA environment variables
keep their standard names. Product-owned HTTP headers use `X-Withhold-*`;
private control routes use `/_withhold/v1/`.

Human output is concise and factual: startup confirms a running proxy and
configured routing, not verified inspection coverage. Policy terms remain
`redact` and `block`; branding does not change machine status/action vocabulary.

Help, version, completion, and integration discovery do not read runtime
configuration, initialize trust, change settings, or start
workers. Usage/configuration errors return 2, operation/check failures 1, and
success 0. `doctor --preflight` is silent on success and returns 2 on failure.
JSON commands write one object: configuration schema 1, status schema 4, doctor
schema 2, integration catalog schema 1, demo schema 1. Schema changes must be explicit.
`config` prints effective settings as JSON,
not placeholder keys, but local paths/provider names may be private.

`config --example` instead prints a commented TOML starter without reading files,
discovering application settings, or exporting ambient overrides. Integration
selection is flag, environment, then default; other flags are rejected rather
than ignored. Each adapter owns its example application section.

`demo` exercises the bundled scanner and the proxy's HTTPS CONNECT, redaction,
and block paths using fixed synthetic inputs and ephemeral IPv4 loopback ports.
It checks actual upstream bytes and the absence of an upstream blocked request.
Its temporary CA is trusted only by the demo's in-memory clients; TLS verification
stays enabled. It ignores existing configuration, isolates the worker's home/key,
and removes temporary files. It never contacts a provider, changes application
settings or trust stores, or validates actual application routing/compatibility.
Local port, scanner, policy, TLS, verification, or cleanup failures return 1.

Authenticated status exposes value-free `traffic` counters even without debug
logging. `coverage.state` is `unavailable` without an authenticated session,
`awaiting-traffic` before HTTP requests/WebSocket messages, `traffic-observed`
before a supported body completes inspection, and `inspected` afterward.
CONNECT alone and failed scans do not establish inspection. `scan_attempts`
counts starts; `inspected` counts successful clean/redacted results on supported
routes, including blocked findings and observe-mode scans. `passthrough` counts
uninspected policy passes, including bodyless requests and integration exceptions.
These are request/message decisions, not a percentage of all application traffic.
`coverage.observe` identifies audit-only sessions; `inspected` is not a claim of
enforcement or complete coverage. `debug` separately reports finding-log health.
Private authenticated health uses only signed schema 4, including these counters;
older schemas are rejected without negotiation or fallback readers.

Scanner statuses are `clean`, `redacted`, `skipped-not-json`, `over-cap`,
`over-cap-decoded`, `scanner-error`, and `finding-without-secret`. Successful
reports contain `units`/`stats`; rewrites add `body_base64`, `rule_ids`,
`findings`, and `placeholders`. Errors use fixed `reason` values; cap reports
add `size`/`max_bytes`. Opt-in masked debug findings are never raw findings.

Audit JSONL fields are `ts`, `host`, `api`, `surface`, `surface_provisional`,
`mode`, `action`, `rule_ids`, `findings`, `placeholders`, `units`, `stats`,
`method`, `path`, in that order. UTC timestamps, rule IDs and counts contain no
finding values. Methods are capped at 16 characters; paths at 200, without
query/fragment. Actions include `blocked`, `forwarded`, `passthrough`,
`would-block`, `would-redact`, and `killed-on-error`. Paths/usage metadata can
still be sensitive. Audit/hint writes after startup are best-effort.

`--debug` writes only finding summaries: masked value (first three Unicode
characters plus ellipsis, or `***` for shorter values), replacement when applied,
surface/host, and send/block/failure outcome. Control characters are escaped;
bodies, headers, URL paths/queries, and arbitrary error text are omitted.
Each detected value is summarized once per request/message, with at most 128
entries plus an omitted-count line. `sent` requires a completed transport write,
not just response headers; it says nothing about model consumption.

Log destinations and rotation backups must be private, regular, writable files
at startup. Audit/hint/findings rotate at 10 MiB to one `.1` backup. Findings
write failures do not change policy: stderr warns, status reports health/lost
summaries, and traffic counters continue. Authenticated status counters reset
per process and count events, not values. Empty findings or CONNECT activity
alone do not establish inspection coverage. Foreground `serve` has no managed
session record. Private worker framing is described in [architecture](docs/architecture.md).
