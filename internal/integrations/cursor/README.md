# Cursor request codecs

The [user guide](../../../docs/integrations/cursor.md) owns setup, live-tested
workflows, and exclusions. This package inspects self-contained model requests
through `RunInference`, reviewed auxiliary/startup calls, and a bounded inline
`StreamCpp` subset. It does not implement `AgentService/Run`, blob/history replay,
or file synchronization. Unsupported guarded traffic blocks.

## Schema maintenance

The three JSON snapshots record wire definitions extracted read-only from the
Cursor workbench bundle. Each records its source version and SHA-256; these are
provenance, not runtime acceptance criteria. Inference and auxiliary definitions
come from 3.30.8; startup/control definitions come from 3.30.14. This does not
establish live compatibility with either version beyond the user guide's record.

Compare an installed macOS application with the reviewed definitions:

```sh
python3 tools/extract_cursor_schema.py --check
python3 tools/extract_cursor_schema.py --auxiliary --check
python3 tools/extract_cursor_schema.py --control --check
```

`--app PATH` selects another application bundle. No application code is executed.
Checks accept older schema subsets and ignore version/hash differences; new
fields, enum variants, and changed field definitions require review.

Without `--check`, extraction refreshes only the message names already listed in
the selected snapshot. It never recursively imports unreviewed child types.
To add a needed message, add its name with an empty field list, extract, and
review the descriptors before updating the Go field permissions. There is no
second extraction inventory to synchronize. Reachability tests reject unused
embedded messages; shared protobuf types are defined once in `schema.json`.

Complete field definitions are retained for each selected message so drift is
visible, but definitions do not grant forwarding permission. `supportedField`,
`auxiliaryFields`, and `controlFields` reject unresolved content and integrity
semantics, including references whose contents are not in the message.

## Inspection and write-back

`DecodeRunInference` accepts one unframed `RunInferenceClientMessage`: a full
`invoke_model` request, nested gzip/Zstandard content, or reviewed run/control
messages. Shared transport owns Connect framing, outer compression, admission,
deadlines, cancellation, backpressure, and scan-before-release.

The codec projects text into ordered JSON for the existing scanner:

- Numeric fields remain protobuf data, not detector text.
- String map keys supply detector key/value context.
- Adjacent text parts are joined so segment boundaries cannot hide a secret.
- File/image string data uses shared base64 inspection and opaque-media rules.
  There is no OCR, document extraction, or fetching of referenced URLs.
- Provider-signed reasoning is inspected but immutable; findings there block.

`Rewrite` maps replacements back to original wire fields, corrects nested
compressed lengths, and decodes the result again to verify the projection.
Unmodified fields retain their exact bytes, including nonminimal encodings.
Identifiers cannot be rewritten independently of their references.

Clean `RunInference` handshakes disable `supports_delta_invocations` and
`supports_delta_base_seeds`, requesting full model payloads instead of maintaining
a conversation cache. Other clean bytes are unchanged. Observe mode retains the
original handshake too. Unexpected deltas, seeds, or fingerprints still block.

## Route boundary

| RPC | Accepted subset |
| --- | --- |
| `InferenceService/RunInference` | Full invocations and reviewed run/control messages over duplex HTTP/2. This is the recorded live Agent/Auto workflow. |
| `AiService/NameTab` | Inline/rich conversation text, code-chunk lines, tool argument/content strings, and reviewed terminal/MCP results. Recognized PNG/JPEG/GIF/WebP image bytes are opaque; descriptions are inspected. Other context trees, credentials, and blob references block. |
| `AgentService/UpdateConversationMetadata` | Rewritable names/workspace paths; immutable conversation IDs. |
| `AiService/ClassifyAgentAutoReview` | Reviewed classifier args, conversation/file context, and structured tool arguments. |
| `AiService/StreamCpp` | Inline file windows, selections, context items, visible ranges, versions, and hashes. Content is inspected but immutable because rewriting could invalidate positions/hashes. File-sync state and updates block. Live Tab compatibility is unverified. |

Startup/control routes are listed in `control.go`. Their strings are inspected
and immutable; there is no host-wide metadata or authentication exemption.
Unknown paths block even for bodyless GETs. Connect GET/query payloads,
unreviewed formats/fields/enums, duplicate singular fields/oneofs/map keys, and
defaulted map entries are rejected rather than normalized or passed through.

Wire, decoded, projection, and rewritten representations are capped at the
supplied limit (at most 128 MiB), with 64 nesting levels and 100,000 fields.
Shared transport additionally bounds cumulative inbound/released bytes and
stream lifetime/message count. Scanned handshakes or opaque images alone do not
establish inspected-text coverage.

## Application lifecycle

The adapter owns a separate `Cursor/User/settings.json` store and reuses
`internal/editorsettings` for backup, managed-key restoration, and launching.
It manages `cursor.general.disableHttp2 = false` alongside proxy/TLS keys;
HTTP/1 is not a workaround for unsupported content. Recovery uses the recorded
resource even when current discovery/configuration is invalid.
