# Cursor request-boundary integration research

Research date: **2026-11-13**. This is contributor research, **not a shipped
integration or a protection guarantee**. Cursor is not registered in
`withhold integrations`.

## Required boundary

Content leaving the local Cursor client for model processing must pass through
withhold's scanner before forwarding. Hook-only coverage is not sufficient:
missing a tool-result or alternate context path defeats that requirement.

Use a CA-based proxy, with explicit support for Cursor's request formats.
A local proxy cannot inspect new content produced entirely on Cursor's backend,
retroactively sanitize existing server-side conversation/index state, or guard
the execution of cloud agents.

## Compared with VS Code/Copilot

| Concern | Existing VS Code/Copilot adapter | Cursor desktop |
| --- | --- | --- |
| Request bodies | Supported JSON HTTP POSTs and JSON WebSocket messages. | Binary protobuf, Connect envelopes, and streaming RPCs. |
| Inspection timing | Finite request buffered before upstream opens. | Duplex calls need bounded message-by-message inspection without waiting for request EOF. |
| Endpoints | Reviewed chat, inline, and embeddings routes. | Agent, Tab, file synchronization, indexing, and auxiliary model calls need separate review. |
| Errors | Adapter-owned JSON/SSE blocks. | Connect-compatible unary and streaming errors. |
| Setup | Reversible VS Code proxy settings and CA trust. | Similar settings/trust mechanisms may be reused, but routing must be validated independently. |
| Hooks | Not the interception boundary. | Native hooks exist, but do not expose the complete assembled model request. |

Cursor's official networking documentation describes HTTP/2 bidirectional
streaming and HTTP/1.1 SSE fallback. Tab and codebase-search services include
HTTP/2-only endpoints. Disabling HTTP/2 is therefore not a complete integration
strategy and does not make protobuf bodies into ordinary JSON.

The documented hook schemas are insufficient for request-boundary protection:

- `beforeSubmitPrompt`, `beforeReadFile`, and `beforeTabFileRead` support
  blocking, not replacement of their prompt/file content.
- `preToolUse.updated_input` is tool-specific input mutation, not inspection of
  all resulting content.
- `postToolUse.updated_mcp_tool_output` replaces MCP results, not generic
  built-in tool results. `afterShellExecution` is observational.
- Session and compaction hooks do not provide an enforceable model-request gate.
- Hook loading and desktop/CLI/cloud execution differ. An installed hook is
  not evidence that every request crossed it.

## Installed application and routing evidence

The installed macOS application was **Cursor 3.30.8**, with bundled VS Code
**1.128.0**. Static inspection found Connect transports, generated protobuf
descriptions, and separate agent/Tab/file-sync routes.

An explicitly authorized, metadata-only live control experiment used the
existing withhold CA and shared proxy transport, a separate ephemeral IPv4
loopback listener, and a dedicated synthetic workspace. The existing
VS Code/Copilot session was left running on its original port.

The first launch did not select the intended workspace and was stopped; it
does not count as a valid workspace-isolated tool test. The corrected test used
`--classic`, an explicit `.code-workspace` file, a verified test-workspace window
title, and absolute fixture paths before submitting anything. CLI folder
arguments alone are not sufficient evidence of the selected project when the
Agents Window is restored.

Observed traffic included:

- `agentn.api5.cursor.sh/agent.v1.AgentService/Run`, using HTTP/2 and
  `application/connect+proto`. Its initial envelope had the compression flag.
- In the corrected workspace test,
  `agentn.global.api5.cursor.sh/aiserver.v1.InferenceService/RunInference`,
  using HTTP/2 and gzip-compressed Connect protobuf messages. Bounded in-memory
  decompression found the synthetic prompt, file-content, and shell-output
  markers in outbound messages. The upstream returned HTTP 200.
- Unary `application/proto` requests, over HTTP/1.1 and HTTP/2.
- The synthetic prompt marker also appeared in auxiliary `NameTab` and
  `UpdateConversationMetadata`/`ClassifyAgentAutoReview` requests during the
  initial controls. Protecting only the main agent RPC would miss these
  disclosures.
- General API traffic on `api2.cursor.sh`, agent traffic on
  `agentn.api5.cursor.sh`, and other requests on `api3.cursor.sh` and
  `api4.cursor.sh`.

This demonstrates that the shared CA/proxy transport can receive the observed
Cursor traffic, including the tested file and shell results. Matching known
synthetic markers is **not** general secret detection/redaction, complete
routing, Tab inspection, or successful handling of every RPC.

The probe recorded metadata and fixed sentinel labels only, not request bodies,
authentication headers, or transcripts. No new trust was installed. Temporary
network settings were restored byte-for-byte after the completed routing passes.

## Protocol traps to address before implementation

1. **Separate channels.** Installed definitions include native duplex `Run`,
   server-streaming `RunSSE`/`RunPoll`, and a `BidiService/BidiAppend` route.
   `RunSSE` takes a request ID: inspecting that request alone does not inspect
   the separate content-bearing write channel.
2. **Nested bytes and blobs.** `AgentRunRequest` carries prefetched blobs;
   `UserMessage` has text/rich-text blob IDs as well as inline text.
   `GetBlobResult.blob_data` and conversation-state fields are byte-valued.
   Ordinary protobuf-to-JSON base64 conversion does not establish inspection of
   the underlying content. Blob/reference integrity must survive rewriting.
3. **Streaming and compression.** Decode complete Connect messages, including
   per-message compression, before releasing their payloads upstream. Reading a
   duplex request to EOF before forwarding can deadlock it. Define cross-frame
   logical-text handling and cumulative stream limits explicitly.
4. **Schema drift.** Preserve field presence, oneofs, repeated/duplicate-field
   semantics, and nontext data. Reject unsupported present fields or encodings,
   rather than dropping unknown data or forwarding it uninspected. A recent
   Cursor support report associated an outdated proxy adapter with corrupted
   protobuf requests.
5. **Inference deltas and nested compression.** Installed `RunInference`
   definitions include full/compressed requests, delta-base seeds, prefix/request
   SHA-256 fields, and gzip/Zstandard request encodings inside the RPC itself.
   Outer Connect decompression alone is insufficient. Redaction must preserve
   or correctly renegotiate delta/cache integrity, not leave stale digests.
6. **Alternate payload locations.** Connect supports unary GET payloads in URL
   queries. The existing shared contract excludes query inspection; supported
   model-data RPCs must either inspect that transport explicitly or reject it,
   never treat it as an ordinary bodyless passthrough.

Schema-free recursive UTF-8 searching through protobuf length-delimited fields
is not a sound redaction strategy: the same wire type represents text, nested
messages, bytes, and structured identifiers.

## Implementation direction

- Reuse CA issuance, CONNECT/HTTP2 handling, upstream TLS verification, private
  state/recovery, authenticated sessions, scanner workers, detectors,
  placeholders, and policy decisions.
- Add a focused request-codec/stream capability at the integration boundary.
  Keep generic framing/admission in shared transport code. Dispatch on that
  capability, not Cursor IDs, hosts, or RPC names in the core.
- Keep Cursor options, hosts, routes, message schemas, embedded-byte/blob
  semantics, and RPC errors in `internal/integrations/cursor/`.
- Extract the actually reusable JSONC/settings restoration mechanics from
  Copilot when needed. Do not make the Cursor adapter depend on Copilot.
- Preserve unconditional intake/worker/wire limits and verified rewriting.
  Unknown content paths and inspection failures must block.
- Before registration, use isolated HTTPS/HTTP2 fixtures to assert actual
  upstream bytes and no release of rejected messages. Cover compressed and
  fragmented frames, later tool results, cancellation, retries/fallbacks,
  auxiliary model calls, Tab/file-sync, and schema drift.
- Record exact live-tested versions and distinguish connection/routing evidence
  from successful inspection. Do not implement an unscanned passthrough
  exception simply to make the editor work.

## Implementation progress

An unregistered [codec prototype](../../internal/integrations/cursor/README.md)
now decodes full `RunInference` invocation messages, projects reviewed text into
the existing scanner, and reconstructs verified protobuf rewrites, including
nested gzip/Zstandard. An isolated scanner-worker probe validated synthetic
prompt/file text, shell results, and tool arguments before durable regression
tests were added. Clean wire bytes are preserved.

The extracted schema is a provenance baseline, **not an exact editor-version
requirement**. Runtime decoding follows supported protocol shapes; the extraction
check accepts unchanged schemas and older subsets regardless of version/hash.
Unknown content and unresolved integrity semantics fail closed. Compatibility
across actual editor versions has not been established by this codec probe.

The prototype now uses shared Connect/duplex transport and a typed route codec
capability. An isolated HTTPS CONNECT/HTTP2 scanner-worker probe verified
response-before-upload-EOF and redaction of a fragmented later message in actual
upstream bytes before durable transport tests were added. Reviewed auxiliary
request subsets are inspected too; unknown routes and cache/blob variants block.
Shared editor JSONC backup/restore and launching are extracted for the Cursor and
Copilot application adapters, with isolated settings tests.

Read-only inspection of the installed always-local extension found full file
uploads carrying SHA-256 hashes and incremental file-sync updates carrying edit
offsets, replacement strings, and expected file lengths. It retries failed
incremental updates via full-document upload in that source build. This is not
proof that a proxy can safely rewrite those updates or rely on that fallback in
other versions.

This is still not a registered or full Cursor integration. Delta/cache/blob/log
semantics, signed/native/media content, full Tab/file-sync/indexing, alternate
write channels, and auxiliary/auth routing need further work and live redaction
validation. A limited authorized probe observed prompt-bearing RunInference and
NameTab requests and redacted one supported RunInference invocation. Its
diagnostic adapter passed unsupported traffic through, so it did not establish
complete enforcement. Temporary settings were restored byte-for-byte; no trust
store changes or raw captures were made.

## Sources

- [Cursor hooks and schemas](https://cursor.com/docs/hooks)
- [Cursor network configuration](https://cursor.com/docs/enterprise/network-configuration)
- [Cursor safety controls](https://cursor.com/docs/enterprise/llm-safety-and-controls)
- [Cursor support: CLI window selection and `--classic`](https://forum.cursor.com/t/cli-command-on-mac-no-longer-opens-the-current-folder/160164)
- [Connect protocol specification](https://connectrpc.com/docs/protocol/)
- [Cursor support: outdated proxy adapter and protobuf failures](https://forum.cursor.com/t/agent-conversation-state-corrupted-server-side-since-oct-23-all-requests-fail-protobuf-decode-multiple-request-ids/176177)
- [ctxcop harness guide](https://github.com/webflow/ctxcop/blob/01ad3adf0c82ca6689afa1aa0aa4758690108258/docs/harnesses.md#cursor):
  secondary evidence only; its implementation was not used.

See [Adding an integration](../adding-integrations.md) and the
[shared contract](../../CONTRACTS.md) for project requirements.
