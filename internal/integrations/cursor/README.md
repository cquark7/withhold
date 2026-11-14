# Cursor request codecs

This package backs the registered, deliberately bounded Cursor integration.
The [user guide](../../../docs/integrations/cursor.md) records its live-tested
scope. Unknown RPCs still block; there is no metadata/auth passthrough allowlist
or claim that every Cursor feature works.

## Compatibility model and schema provenance

`schema.json` records reviewed wire definitions extracted read-only from Cursor
3.30.8's installed workbench bundle. Its version and SHA-256 identify the source;
they are **not runtime acceptance criteria**. The codec does not discover Cursor,
read its version, or require an exact build. Earlier subsets and later clients
using the same supported protocol shapes can use the same codec.

Run `python3 tools/extract_cursor_schema.py --check` to compare an installed macOS
application with the reviewed definitions. `--app PATH` selects another local
application bundle. The check ignores source-version/hash differences and accepts
older schema subsets. New fields, enum variants, or changed field semantics
require review. Extraction resolves generated symbols rather than assuming their
minified names. Without `--check`, it replaces the development snapshot; review
that diff before expanding supported content. No application code is executed.
`--auxiliary --check` checks `auxiliary-schema.json`, including older releases
without newer auxiliary RPCs. Its transitive descriptors are provenance only:
`auxiliaryFields` explicitly limits which fields are accepted at runtime.
`--agent --check` checks `agent-schema.json`. This snapshot contains complete
descriptors only for explicitly selected message types, without transitive
extraction. `agentFields` separately admits reviewed fields; missing child
descriptors never authorize opaque forwarding.

There is no claim that arbitrary future versions work. Unknown content cannot be
silently passed through just because the editor's major version is unchanged.
Only 3.30.8 supplied the current source snapshot; fixture compatibility is not
live compatibility evidence for that or other editor versions.

## Codec boundary

`DecodeRunInference` accepts one unframed protobuf `RunInferenceClientMessage`
containing a full `invoke_model` request (inline or nested gzip/Zstandard), or
reviewed run/control messages. Adjacent text content parts are projected as one
logical string so a secret split across segment boundaries is still scanned;
rewrites collapse changed text into the first populated part. Image and file
parts retain their positions; their string data and metadata use the shared
scanner, including UTF-8 base64 inspection and opaque media-signature exclusions.
There is no OCR, document extraction, or fetching of referenced URLs.
Per-text-part provider options, logs, delta bases/seeds, and cached fingerprints
remain rejected. The codec never guesses the contents of arbitrary byte fields.
For `RunInference`, write-back sets `supports_delta_invocations` and
`supports_delta_base_seeds` to false in each run handshake. This requests full
model payloads rather than implementing a second conversation cache. It does not
disable HTTP/2 or modify editor settings. The server's response determines what
Cursor sends; an unexpected delta/seed still blocks rather than bypassing scanning.
Provider reasoning in history is scanned and preserved with its signature;
findings in that immutable content block.
Connect envelopes/compression and duplex forwarding are handled by shared
transport, dispatched through `policy.RPCCodec`, not through Cursor branches.

`ScanInput` produces an ordered JSON text projection for the existing scanner or
scanner pool. String map keys supply detector key/value context. Numeric fields
remain protobuf data, not strings; compressed bytes are explicitly decoded.
`Rewrite` maps scanner replacements back to the original wire fields, corrects
nested compressed lengths, then decodes again and checks the projection.

Apart from these two handshake capability flags, clean bodies retain their exact
bytes, including compression, field order,
explicit defaults, and nonminimal valid encodings. Rewritten bodies preserve
unmodified fields byte-for-byte. Schema and map keys are not discarded through
protobuf-to-JSON conversion. Structural identifiers are inspected but cannot be
rewritten; a finding there must block, not corrupt client/server references.

Reviewed route coverage:

| RPC | Supported request subset |
| --- | --- |
| `InferenceService/RunInference` | Full invocations and reviewed run/control messages; native duplex HTTP/2. |
| `AgentService/Run` | Inline user/context messages, typed prefetched history graphs and their same-stream replay, blob-backed prompt/extra-context/text-read content, split request-context parts, common tool history, rules/skills/git/project-layout/MCP context, completed shell/read/write/delete/grep/directory/diagnostics/text-MCP results, request-context results, prewarming, and controls; native duplex HTTP/2. Inline user/system prompts are rewritable; other Agent text, map keys, and content-addressed history remain immutable, so findings there block even in `redact` mode. Unresolved blob references, KV exchange, chunked shell output, and unreviewed tool/interaction variants remain unsupported. |
| `AiService/NameTab` | Inline/rich conversation text, attached code-chunk lines, tool argument/content strings, and reviewed terminal/MCP result fields. Recognized PNG/JPEG/GIF/WebP image bytes are opaque and preserved; their text descriptions are inspected. Other context trees, BYOK credentials, and blob references remain unsupported. |
| `AgentService/UpdateConversationMetadata` | Name/workspace paths are inspected and rewritable; conversation ID is immutable. |
| `AiService/ClassifyAgentAutoReview` | Reviewed classifier args, inline conversation/file context, structured tool arguments. |
| `AiService/StreamCpp` | Inline file windows and selections, context items, additional visible file ranges, versions, and hash metadata. Existing file-sync state and updates are rejected. Content is inspected but not rewritten, so positions and hashes cannot be invalidated. |

All these paths reject Connect GET/query payloads and unreviewed wire shapes.
Unknown paths on Cursor service domains block even for bodyless GETs. There is
no fallback to an uninspected alternate format.

Still rejected:

- Deltas, delta seeds, cached/config fingerprints, and byte-valued run logs.
- Agent blob-backed variants outside the typed graph described below, including
  references available only on the server or another HTTP request, and `KvClientMessage`.
- `ExecClientMessage.shell_stream`, including clean-looking fragments. Scanning
  each chunk independently would miss secrets crossing message boundaries.
- Agent SSE/polling and separate append/write channels.
- Unknown fields/enums, duplicate singular fields/oneofs/map keys, and defaulted
  map entries. The codec rejects these rather than changing their semantics.
- Text parts with per-part provider options, assistant text parts,
  native provider content, and lineage tags.
- Static-prefix lengths, content digests, and byte fields other than explicitly
  decoded compressed requests, reviewed Agent blob fields, and recognized opaque
  `ImageProto.data`.

### Prefetched Agent history

Each accepted prefetched blob has a 32-byte SHA-256 ID matching its original
value. The referencing field selects its protobuf decoder. Supported graph edges
are state-to-todo/summary/plan/turn, turn-to-user-message/step or shell
command/output, and user-message-to-state snapshot. Steps may contain assistant
text, thinking text, or reviewed shell/read/edit/delete/glob/grep/directory/
todo/lint/text-MCP tool history. Inline definitions and results are inspected;
this does not authorize running a remote subagent or an arbitrary tool variant.

Every uploaded blob must be reachable and inspected, including reused blobs
interpreted as multiple expected types. Unknown child fields, malformed data,
missing references, changed hashes, and unused uploads reject the envelope.
Identical duplicate uploads are accepted. Repeated references do not amplify
the scanner projection. Wire and graph depth/field/projection limits apply,
with an additional limit of 4,096 uploads and typed blob nodes per envelope.

Prompt/rich-text blob IDs, extra-context blobs, and historical text-read content
blob IDs select UTF-8 decoding, as established by the installed hydrators and
text-read serializer. Binary read blobs remain unsupported. Split request context
selects separate protobuf decoders for rules, skills, custom-subagent definitions,
and MCP definitions/instructions; dynamic context is inspected inline. All four
references must resolve, with declared byte lengths matching original blob data.
Unreviewed MCP filesystem/meta-tool options are still rejected.

Native Agent streams retain independent copies of resolved uploads, bounded by
4,096 unique IDs and `max_bytes` including their IDs. Retention reserves aggregate
intake bytes before copying, without holding an intake job between envelopes.
Every later reference is decoded and scanned afresh in its expected type,
including its reachable children. This caches bytes, not clean-content decisions;
observe-mode findings do not make a replay trusted. Identical uploads do not
consume storage again, and an unused upload is rejected even if already known.

State is discarded when the HTTP upload closes, including early upstream
completion, cancellation, and failure. Another request or retry must supply its
complete graph. The stateless decoder likewise requires self-contained input.
Root prompt-message JSON, summary archives, file-state content, and KV exchanges
remain rejected. Some installed editor code also uses non-content-addressed local
file-state IDs; the SHA-256 rule does not claim to describe all Cursor storage.

Per-message wire, decoded, projection, and rewritten representations are capped
at the supplied limit (at most 128 MiB), with 64 nesting levels and 100,000 fields.
The shared transport additionally enforces cumulative inbound/released caps,
aggregate input admission, cancellation, inspection deadlines, backpressure, and
stream lifetime/message limits. Scanned handshakes do not establish model-content
coverage; opaque images alone do not establish inspected-text coverage either.
A codec error never authorizes enforcing-mode fallback forwarding.
Completed MCP text items are also inspected together so boundaries cannot hide
a secret. Agent clean bytes, including read-result sizes/hashes, are preserved;
this does not establish support for prior server-side state or a normal session.

## Application lifecycle

The typed Cursor adapter resolves a separate `Cursor/User/settings.json` store.
It reuses `internal/editorsettings` for JSONC settings, private backups,
managed-key restoration, platform roots, and shell-free launching. It manages
`cursor.general.disableHttp2 = false` in addition to the common proxy/TLS keys;
HTTP/1 is not a workaround for missing content coverage. Recovery uses the
recorded resource even when current configuration/discovery is invalid. This is
fixture-tested code, not evidence that all Cursor networking runtimes honor it.

## Evidence and scope

The manually validated local workflow is Agent/Auto model egress through
`RunInference`: clean follow-ups, follow-ups after redaction, file context,
file edits, and file-context secret redaction. Isolated worker/HTTP2 tests include
history and signed assistant reasoning and assert actual upstream bytes.
Tab/file-sync and remote Agent features are outside the initial support scope.

An isolated development probe used the existing scanner worker and verified
synthetic prompt/file text, shell-result text, and tool arguments through plain,
gzip, and Zstandard request variants. Decoded output had placeholders instead of
the canaries; a rescan was clean, and clean wire bytes were preserved. Durable
regressions were added after that probe succeeded.

An isolated transport probe, followed by durable regression tests, exercised
HTTPS CONNECT and native HTTP/2 duplex operation with the existing scanner
worker. The first message and upstream response flowed before upload EOF; a
later fragmented secret was redacted in actual upstream protobuf bytes. Tests
also cover later blocks/errors/panics, truncated/oversized envelopes, aggregate
admission, observe behavior, and rejecting HTTP/1 upstream fallback.

The registered support boundary is local Agent/Auto model egress, not every
Cursor feature. Tab completion, cloud agents, computer use, file synchronization,
and alternate write channels are outside this scope. Their stateful payloads
remain rejected rather than being guessed or passed through. If support is added
later, file-sync hashes and edit offsets require reconstructing the relevant
baseline; isolated string rewriting is unsafe.

Manual validation used Cursor 3.30.8 on macOS Apple silicon with a synthetic
workspace and an enforcing loopback proxy. The prompts and file workflows listed
in the user guide completed; value-free audit records showed the corresponding
`RunInference` requests were scanned and redacted before forwarding. This does
not establish coverage for every route, Cursor version, or platform.
