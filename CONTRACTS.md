# Behavior contract

These are the observable guarantees and limits of withhold. Changes require
matching tests and documentation. For operation and settings, see
[usage](docs/usage.md) and [configuration](docs/configuration.md).
Harness-specific guarantees live in the
[agent-specific guarantees](docs/integrations/README.md). Both layers apply; an
agent cannot relax the shared transport, privacy, or recovery guarantees.

## Scope and traffic policy

withhold reduces **accidental disclosure in supported request bodies** routed
through its proxy. Headers, URL queries, responses, deliberate bypass, and
provider-side handling are outside its protection. Scanning is local and offline.

Each supported agent identifies a coding harness and its tested traffic contract.
It defines guarded hosts, request paths/surfaces, intentional passthrough,
suspicious-host classification, and local error framing. Unknown agent IDs fail;
naming an executable or adding an extra host does not establish support for
another agent. `withhold agents` lists only reviewed built-ins.

One proxy composes the selected agent profiles. Overlapping guarded/passthrough
claims fail closed independent of order. Passthrough cannot override another
profile's guarded or suspicious host.
Unambiguous routes retain their adapter's error protocol.

Unscoped hosts are audited; suspicious hosts are blocked for POST/PUT/PATCH or
any request not provably bodyless. Unrelated traffic passes through. Unknown
guarded paths fail closed unless the integration explicitly supports them.

| Surface | Default | Inspection failure |
| --- | --- | --- |
| Chat | Redact and forward (`redact`) | Block. |
| Inline | Block findings | Block. Choosing `redact` permits placeholders in code. |
| Observe mode | Forward original content; audit would-be decisions | Policy failures are audit-only; transport failures remain enforced. |

Guarded JSON routes require a JSON POST for inspection. Non-POST requests on
these routes pass only when provably bodyless, with no transfer encoding or
positive, malformed, or unknown body length. Observe mode audits format, method, and inspection failures.

## Offline text inspection

- **Input:** Reads literal UTF-8 from `--text`, files, directories, or stdin.
  Arguments are paths; `--text` selects only its literal value, ignores implicit
  stdin, and cannot be combined with path arguments. Otherwise stdin is read once
  when selected explicitly with `-` or when neither `--text` nor a path is
  supplied and stdin is redirected. Inputs are never changed or joined, and
  proxy JSON extraction is not applied.
- **Detection and config:** Secrets are on by default; PII is optional, and both
  cannot be disabled. TOML is validated without application discovery. Precedence
  is flags, `WITHHOLD_PII`/`WITHHOLD_MAX_BYTES`, file, then defaults; other
  editor/proxy environment overrides do not apply. Scans need no setup, session,
  trust, editor, or placeholder key and write no state or logs.
- **Confidence:** `--confidence` overrides `[scan].confidence`; values are `low`,
  `medium`, `high`, or empty (no minimum), trimmed and lowercased. `--confidence=`
  clears the config value. Betterleaks keeps unclassified findings and components
  of accepted multipart findings. Higher thresholds can hide real secrets; PII
  and proxy detection are unaffected.
- **Discovery:** Hidden and Git-ignored text is included, subject to Betterleaks'
  bundled exclusions. They apply to explicit targets and PII-only scans;
  `--no-default-excludes` disables them. `.git` is always pruned. Discovered
  symlinks are not followed; explicit symlinks/nonregular inputs are errors.
  Repeatable `--exclude PATH` skips literal paths relative to the working
  directory, including explicit targets. Project ignore files and local detector
  config are not loaded. Binary, invalid UTF-8, document, and archive content is
  skipped. Skip counts cover entries or pruned subtree roots, not descendants.
- **Limits:** Each input defaults to 32 MiB (128 MiB maximum), a 10-second
  deadline, and 10,000 findings. Read/walk failures, timeouts, overflow, worker
  failures, explicit unsupported inputs, or hitting a limit make the run
  incomplete. Intentional exclusions and discovered unsupported entries are
  summarized but do not make it incomplete.
- **Reports:** Findings identify source, rule/category, and location, never values
  or excerpts. Full-match locations may include context; encoded findings refer
  to source containers. Byte ranges are zero-based/half-open; lines and byte
  columns are one-based with exclusive end positions. Output is deterministic.
  JSON streams one schema-1 report; only 128 error details are included and
  `errors_omitted` counts the rest. Missing/truncated output is incomplete. Exit
  codes are **0** for complete without findings, **1** with findings, and **2**
  for invalid usage/config or incomplete scans; errors take precedence.

## Scanning and redaction

The scanner walks JSON string leaves and object keys, including tool schemas,
arguments, results, defaults, and examples. Numeric scalars are not text.
Duplicate object keys (including escape-equivalent names), invalid Unicode
surrogates, nesting above 1,000 levels, and key-rename collisions fail closed.
Rewriting preserves object order and scalar types, not original formatting.

Secret detection uses bundled Betterleaks v2 rules and Go regular
expressions, without credential validation, repository configuration, or
allow-comment suppression. AWS access-key IDs are detected without requiring a
secret-key component; credential URIs also recognize `psql://`. Multipart
components are all redacted, so nonsecret identifiers can be included. A complete
set of 100 component combinations can be redacted. If Betterleaks truncates the
set, the request is blocked. Synthetic detector self-tests must pass before
startup and whenever a worker starts.

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

- Standalone text below eight characters is skipped. PII lowers that floor to
  two. Longer leaves remain intact during detection.
- Eligible keys up to 4,096 bytes and values up to 4,096 characters are also
  scanned together. Array elements retain their key context. Small `value`
  strings also get their enclosing key and a sibling `name` as credential
  context where applicable. Escaped JSON matches map back to the original text.
- Whole-leaf UTF-8 Base64 text and textual Base64 data URLs can be decoded,
  scanned, rewritten, and re-encoded. Re-encoding preserves a detectable
  URL-safe alphabet, the padding convention, and data URL prefixes. It
  normalizes whitespace and uses the standard alphabet when the original
  alphabet is ambiguous. Whole-leaf extraction and residue checks use a
  24-byte minimum and always check textual data URLs. Bare Base64 leaves are
  also checked as literal credentials, with eligible field context.
- Betterleaks also detects encoded content inside text. A finding that cannot
  be mapped to writable text or a supported whole-leaf rewrite blocks the
  request, even if a separate copy of the value can be redacted.
- Declared image/audio/video/font, octet-stream, PDF/ZIP/gzip/WASM payloads and
  recognized PNG/JPEG/GIF/PDF/ZIP/gzip/WASM/WebP/WAV base64 signatures are opaque.
  They skip detection and residue checks at any size. MIME metadata is only a
  client hint: mislabeled text can be excluded. There is no OCR or extraction
  from documents/archives; surrounding text is still inspected.
- Unknown Base64 blobs that decode to non-UTF-8 bytes are scanned as literal
  text. Their decoded bytes count as unscanned residue. With findings present,
  block mode rejects that residue and redact mode can forward with a warning.
- Joined detector input above 128 MiB fails closed. Opaque bytes still count
  toward transport limits.
- Secret scans with a line longer than 64 KiB have a separate work limit.
  Each candidate is charged the longest line's size against a 4 GiB budget
  per detector pass. Exhausting the budget returns an incomplete scan even when
  the input fits the byte limit.

Placeholders are `<WITHHELD_` + 16 lowercase HMAC-SHA256 hex digits + `>`.
Key resolution uses `WITHHOLD_PLACEHOLDER_KEY`, then the private installation
file `~/.config/withhold/placeholder-key`, then a process-random key.
Persisted keys are published atomically. Placeholders are stable with the same
key and are never rehydrated in responses. Stable markers reveal repeated values;
they are pseudonymous, not anonymous. Verification checks protected text
and keys for discovered values and URL/Base64 variants. A known finding with an
incomplete or unverifiable rewrite blocks enforced routes.

## Transport and failures

The proxy listens on IPv4 loopback, defaulting to `127.0.0.1:8451`; `--port`
or `proxy.port` selects another port. It supports absolute-form HTTP and HTTPS
CONNECT, HTTP/1.1, negotiated HTTP/2, and WebSockets. CONNECT authority, inner
authority, and TLS SNI must agree. Upstream TLS verification stays enabled;
upstream connections do not chain through environment-configured proxies.
Responses, including SSE, stream without inspection.

Every forwarded guarded HTTP body must pass wire-size and intake admission
limits, including unsupported formats or methods forwarded in observe mode.
The default cap is 32 MiB, configurable up to 128 MiB. Intake allows six jobs
and 64 MiB of retained input; worker admission independently allows six jobs
and 64 MiB of framed input. These are admission budgets, not process RSS limits.

Wire overflow, failed reads, and exhausted intake capacity (including during
decoding) return HTTP 413 without forwarding, including in observe mode.
Gzip, deflate, Brotli, Zstandard, stacked encodings, and declared charsets are
decoded before inspection. Decoded size overflow and scanner failures follow
the inspection policy above. Scanner capacity is never reported as clean.
Redacted HTTP bodies become UTF-8 JSON with corrected length and stale encoding,
digest, and trailer headers removed; clean/observe bodies retain wire bytes.
Typed RPC adapters may rewrite clean capability handshakes to negotiate a
supported wire format, as documented by the integration; model content is
unchanged. Observe mode retains the original handshake too.
Upload admission is released when transport closes the request body, not when
its response stream ends.

Integrations may opt individual routes into a typed Connect/protobuf codec.
Each message must carry its inspectable content; upload-local content caches and
server-side content references are not supported.
Unary bodies are inspected before opening upstream; streaming bodies are
reassembled into complete envelopes and inspected before releasing any of that
message's payload. Duplex routes require HTTP/2 on both sides. Responses still
stream uninspected. Connect GET/query payloads, JSON/gRPC alternates, request
trailers, and HTTP-compressed envelope streams are not supported by this
capability. Audit-only unsupported transports remain finite, admitted uploads;
they never use an unbounded raw duplex fallback.

Connect streams are bounded by `max_bytes` for cumulative inbound **and**
released wire bytes, 10,000 messages, a 30-minute lifetime, and a five-minute
message-read deadline. Envelope lengths/flags, outer decompression caps, and
aggregate admission remain unconditional in observe mode. Codec/projection and
scanner inspection use the configured scan deadline; adapters must reserve
retained decoded input before allocation. Intake jobs are held while a complete
message is decoded/scanned/released, not while waiting for the next envelope.
Only approved original bytes or verified protobuf rewrites are released;
unsupported schemas never authorize an enforcing-mode fallback.

A failure before response headers uses a local error (HTTP 413 for upload
admission failures). After response headers, a failed stream is aborted/reset,
not ended successfully or spliced with an error inside a partial upstream
envelope. Streaming finding summaries report release as send-unconfirmed:
reading an upload buffer is not evidence of a completed network write. Scanned
control identifiers/handshakes alone do not establish inspected-content coverage.
Cursor opts into this capability for its documented Connect routes; see the
Cursor agent guide for the accepted request subset.

Client WebSocket messages are bounded, reassembled, and decompressed before
inspection; server messages pass through. Redact mode forwards verified rewrites;
block mode stops on findings. Non-JSON text is dropped without closing the
session. Binary/unscannable messages, unknown guarded paths, and scanner errors
stop it. Observe mode forwards originals instead of enforcing policy; transport
and capacity failures still stop the session. Panics abort flows, never create
an uninspected fallback. Shutdown closes connections and reaps workers.

Policy blocks use the selected agent's tested error response protocol.
Streaming detection and local error framing never change scanning or admission.

## Local state and recovery

`setup AGENT...` creates an EC P-256 CA, configures current-user trust, and saves
the exact agent set in the selected config without replacing unrelated settings
or comments. It does not start a session or configure application routing.
Missing names use the saved set; there is no implicit default or detection. When
neither names nor a saved set exist, `setup` returns 2, lists registered agent
IDs/names with an example command, and makes no state or trust changes. `agents`
prints the same current catalog with HTTPS guide URLs.
Manual imports
are the user's responsibility. Existing or partial CA files are not overwritten.
Private keys/state use mode 0600 on POSIX or protected current-user Windows ACLs.
Windows privacy checks require a protected DACL containing only the current
user's full-control entry, independent of descriptor bookkeeping metadata.
Leaf certificates expire within 24 hours or at CA expiry.

`on [AGENT...]` uses the named set or saved defaults, without saving an override.
Names are deduplicated/sorted and replace rather than append. All application
resources must be distinct and pass preflight before mutation. Missing setup
prints an actionable setup command; activation never silently installs trust.
`on` backs up and applies all application settings, records effective configuration,
and starts an authenticated session. The child reads its private ownership record
only after the parent finishes publishing its PID, and rejects a different PID.
Startup failure attempts rollback of all applications, continuing after individual
restore failures and retaining recovery data until restoration succeeds.
Reuse requires the same binary, configuration, resource set, and private-key fingerprint.
There is no hot reload or login/reboot service.

`off` attempts settings restoration even if shutdown/authentication fails. Only
an authenticated identity/PID/build can be stopped; foreign listeners are not
signalled. Recorded resources remain recoverable with broken current config.
Restore changes only managed keys, preserving unrelated/mid-session edits;
invalid settings/backups are preserved. Failed restore retains recovery data.
CA files are deleted only after verified trust removal. Uninstall does not
delete logs, application settings, or the installed executable.
Installation refuses to replace the executable while any session record remains,
including interrupted or unverified sessions, so the current binary remains
available for recovery.

Application settings and restart/trust requirements belong to the integration.
The recorded resource is an absolute recovery anchor; restoration must not
depend on current application discovery or configuration. There is one active
agent set per state directory; switching requires `off` before `on`.
`off` accepts no agent names and restores every recorded resource. `doctor` uses
the active session, otherwise saved targets; explicit names diagnose those targets.
Status distinguishes saved/active agents and reports application settings/backups
separately. Inspection counters remain session-wide, not originating-agent attribution.
Launch is optional; unsupported launch returns a usage error. When supported,
arguments after `--` and the application's exit status are preserved.

User configuration is TOML only: `DIR/config.toml`, or an explicit file selected
with `--config` or `WITHHOLD_CONFIG`. Only that file is read, regardless of filename;
JSON input is rejected and no alternate default filenames are discovered.
Configuration uses schema 1 and strict typed validation;
adapter-owned `applications.AGENT` settings are validated by each adapter.
Unknown keys, duplicate keys, nulls, invalid types, and unsupported TOML value
types fail rather than silently changing protection. Configuration is never
discovered from a project directory. Installation creates an absent default
config containing only schema 1 and commented examples; an existing file is
never overwritten. With `WITHHOLD_CONFIG` selected, installation leaves both
that path and the default path alone. `config --init` explicitly creates a
missing selected file without overwriting an existing file. Omitted settings
continue to use the current built-in defaults.

The macOS/Linux release installer checks the archive's SHA-256 before reading
the executable and license notices, but checksums obtained from the same release
do not authenticate their publisher. `--verify-provenance` additionally requires
GitHub CLI and verifies signed provenance for the archive and the manifest;
`--commit` implies that verification and pins the source commit. Requested
provenance failures never fall back to checksum-only installation.

The README quickstart pipes the installer from an HTTPS URL to `sh` using curl's
default timeout and redirect behavior; it does not retry the script download.
The usage guide's review and pinned-install commands set explicit limits and
restrict redirects to HTTPS. Release downloads also use HTTPS, with bounded
timeouts and retries; a failed download stops before verification or installation.
curl uses the normal proxy and CA settings, and shows progress only on interactive
stderr.

## Diagnostics and interfaces

Project environment variables use `WITHHOLD_*`; test-only overrides use
`WITHHOLD_TEST_*`, and private worker settings use `WITHHOLD_INTERNAL_*`.
There are no alternate-prefix aliases. Standard proxy/CA environment variables
keep their standard names. Product-owned HTTP headers use `X-Withhold-*`;
private control routes use `/_withhold/v1/`.

Human output is concise and factual: startup confirms a running proxy and
configured routing, not verified inspection coverage. Policy terms remain
`redact` and `block`; branding does not change machine status/action vocabulary.

Help, version, completion, and agent discovery do not read runtime
configuration, initialize trust, change settings, or start
workers. Version reports the release build version when supplied, otherwise the
main module version from Go build metadata when available, or `dev` for local
builds without a module version. Usage/configuration errors return 2, operation/check failures 1, and
success 0, except for the documented `scan` exit codes above. `doctor --preflight`
is silent on success and returns 2 on failure.
JSON commands write one object: configuration schema 1 (plural `agents` and
`applications`, with no singular compatibility fields), status schema 6, doctor
schema 4, agent catalog schema 3, and scan schema 1.
Schema changes must be explicit.
`config` prints a reloadable TOML snapshot of the effective public configuration,
including adapter-owned defaults; `config --json` prints the same settings as
JSON. Neither includes placeholder keys, but local paths/provider names may be
private. Saving a snapshot pins its values rather than inheriting future defaults.
These views describe the configuration for a new session, not necessarily a
running session with previously frozen settings.

`config --example` instead prints a commented TOML starter without reading files,
discovering application settings, or exporting ambient overrides. Integration
selection is positional names only, with no implicit agent; other flags are
rejected rather than ignored. Each adapter owns its example application section.
`config --init` accepts only agent names, `--dir`, and `--config`; it does not read an
existing config or snapshot unrelated environment overrides.

Authenticated status exposes value-free `traffic` counters even without debug
logging. `coverage.state` is `unavailable` without an authenticated session,
`awaiting-traffic` before HTTP requests/WebSocket messages, `traffic-observed`
before a supported body completes inspection, and `inspected` afterward.
CONNECT alone and failed scans do not establish inspection. `scan_attempts`
counts starts; `inspected` counts successful clean/redacted results on supported
routes, including blocked findings and observe-mode scans. `passthrough` counts
uninspected policy passes, including bodyless requests and integration passthrough routes.
These are request/message decisions, not a percentage of all application traffic.
`blocked` counts one decision per affected HTTP request or streaming message,
not secrets or unique application actions. Fixed `block_reasons` distinguish
findings, unsupported/unscannable traffic, intake/read/size limits, suspicious
unscoped hosts, inspection failures, and other. `upstream_errors` counts failed
HTTP round trips, WebSocket handshakes, and WebSocket message writes once each;
fixed `upstream_reasons` distinguish cancellation, timeout, TLS verification, DNS,
and other/unknown. Raw error text and destinations never enter these counters.
`coverage.observe` identifies audit-only sessions; `inspected` is not a claim of
enforcement or complete coverage. `debug` separately reports finding-log health.
Private authenticated health uses only signed schema 5, including these counters;
older schemas are rejected without negotiation or fallback readers.

`status` marks an unreadable recovery record or a recorded session without an
authenticated listener as a recovery problem, returns 1, and reports `ok: false`
in JSON. `status --details` shows additional diagnostics and the latest private,
value-free session summary. It is captured before authenticated shutdown and may
omit late events; it is unavailable after an interrupted session or failed save.
Starting a new session replaces the prior summary with an unavailable marker
before application changes; unrelated or unsafe files are never overwritten.
Snapshot write failure warns but does not prevent restoration.

Scanner statuses are `clean`, `redacted`, `skipped-not-json`, `over-cap`,
`over-cap-decoded`, `scanner-error`, `redaction-failed`, and
`finding-without-secret`. Successful reports contain `units` and `stats`.
Rewrites add `body_base64`, `rule_ids`, `findings`, and `placeholders`. Errors
use fixed `reason` values. Cap reports add `size` and `max_bytes`. Opt-in masked debug findings are never raw findings.

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
