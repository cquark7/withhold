# Cursor integration prototype

This package is **not registered** and is not selectable by the product CLI.
It includes protocol, route, and application adapters, not a usable full Cursor
integration. Unknown RPCs still block; there is no metadata/auth passthrough
allowlist or claim that an ordinary editor session currently works.

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

There is no claim that arbitrary future versions work. Unknown content cannot be
silently passed through just because the editor's major version is unchanged.
Only 3.30.8 supplied the current source snapshot; fixture compatibility is not
live compatibility evidence for that or other editor versions.

## Codec boundary

`DecodeRunInference` accepts one unframed protobuf `RunInferenceClientMessage`
containing a full `invoke_model` request (inline or nested gzip/Zstandard), or
reviewed run/control messages. Text-only content parts are projected as one
logical string so a secret split across segment boundaries is still scanned;
rewrites collapse changed text into the first populated part. Per-part provider
options and image/file variants remain rejected. Logs, delta bases/seeds, and
cached fingerprints remain rejected. The codec never guesses the contents of
arbitrary byte fields.
Connect envelopes/compression and duplex forwarding are handled by shared
transport, dispatched through `policy.RPCCodec`, not through Cursor branches.

`ScanInput` produces an ordered JSON text projection for the existing scanner or
scanner pool. String map keys supply detector key/value context. Numeric fields
remain protobuf data, not strings; compressed bytes are explicitly decoded.
`Rewrite` maps scanner replacements back to the original wire fields, corrects
nested compressed lengths, then decodes again and checks the projection.

Clean bodies retain their exact bytes, including compression, field order,
explicit defaults, and nonminimal valid encodings. Rewritten bodies preserve
unmodified fields byte-for-byte. Schema and map keys are not discarded through
protobuf-to-JSON conversion. Structural identifiers are inspected but cannot be
rewritten; a finding there must block, not corrupt client/server references.

Prototype route coverage:

| RPC | Supported request subset |
| --- | --- |
| `InferenceService/RunInference` | Full invocations and reviewed run/control messages; native duplex HTTP/2. |
| `AiService/NameTab` | Inline/rich conversation text and selected metadata; not attached context, tool-result trees, BYOK credentials, or blob references. |
| `AgentService/UpdateConversationMetadata` | Name/workspace paths are inspected and rewritable; conversation ID is immutable. |
| `AiService/ClassifyAgentAutoReview` | Reviewed classifier args, inline conversation/file context, structured tool arguments. |
| `AiService/StreamCpp` | Limited fully inline file/context-free variants; existing file state, updates, and hashes are rejected. Content is inspected but not rewritten, so offsets cannot be corrupted. |

All these paths reject Connect GET/query payloads and unreviewed wire shapes.
Unknown paths on Cursor service domains block even for bodyless GETs. There is
no fallback to an uninspected alternate format.

Still rejected:

- Deltas, delta seeds, cached/config fingerprints, and byte-valued run logs.
- Unknown fields/enums, duplicate singular fields/oneofs/map keys, and defaulted
  map entries. The codec rejects these rather than changing their semantics.
- Text parts with per-part provider options, image/file content, assistant text
  parts, reasoning, native provider content, and lineage tags.
- Static-prefix lengths, content digests, and byte fields other than the decoded
  compressed request.

Per-message wire, decoded, projection, and rewritten representations are capped
at the supplied limit (at most 128 MiB), with 64 nesting levels and 100,000 fields.
The shared transport additionally enforces cumulative inbound/released caps,
aggregate input admission, cancellation, inspection deadlines, backpressure, and
stream lifetime/message limits. Scanned handshakes do not establish model-content
coverage. A codec error never authorizes enforcing-mode fallback forwarding.

## Application lifecycle

The typed Cursor adapter resolves a separate `Cursor/User/settings.json` store.
It reuses `internal/editorsettings` for JSONC settings, private backups,
managed-key restoration, platform roots, and shell-free launching. It manages
`cursor.general.disableHttp2 = false` in addition to the common proxy/TLS keys;
HTTP/1 is not a workaround for missing content coverage. Recovery uses the
recorded resource even when current configuration/discovery is invalid. This is
fixture-tested code, not evidence that all Cursor networking runtimes honor it.

## Evidence and remaining work

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

Full registration still requires delta/cache/blob integrity, byte-valued agent
logs, signed/native/media content, full Tab/file-sync/indexing paths,
SSE/poll write channels and auxiliary/auth route coverage. Static inspection of
the installed always-local extension found file-sync upload hashes and
offset-based updates; neither may be rewritten as isolated strings.

An explicitly authorized controlled live probe used a synthetic workspace and
six content-bearing requests (within the 20-request budget). It observed prompt
content on RunInference and NameTab; a supported RunInference invocation was
redacted. The temporary diagnostic adapter deliberately passed unknown routes
and unsupported messages through for observation, so this is not evidence of
complete live enforcement. Cursor settings were restored byte-for-byte and
managed keys were verified; no trust-store changes were made. Full live
inspection/redaction coverage and actual cross-version compatibility remain
unverified.
