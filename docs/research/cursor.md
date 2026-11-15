# Cursor request-boundary rationale

Research used Cursor **3.30.8** (bundled VS Code **1.128.0**) and public networking
and hook documentation. The [user guide](../integrations/cursor.md) owns the live
validation record; [codec notes](../../internal/integrations/cursor/README.md)
own the implemented route and field boundary.

## Why a proxy, not hooks

Content must pass through inspection at the outbound request boundary, including
file context and tool results. Cursor's hooks do not expose the complete assembled
model request:

- `beforeSubmitPrompt`, `beforeReadFile`, and `beforeTabFileRead` can block, not
  replace prompt/file content.
- `preToolUse.updated_input` changes tool-specific input, not all resulting
  context. `postToolUse.updated_mcp_tool_output` covers MCP results, not generic
  built-in tool results. `afterShellExecution` is observational.
- Session/compaction hooks are not an enforceable model-request gate, and hook
  loading differs between desktop, CLI, and cloud execution.

A CA-based proxy can inspect supported local egress. It cannot sanitize existing
server-side state, inspect content created solely on the backend, or control
cloud-agent execution.

## Routing evidence

A metadata-only routing probe observed HTTP/2 Connect streams on rotating Cursor
service subdomains, unary protobuf over HTTP/1.1 and HTTP/2, and gzip-compressed
outbound envelopes. Synthetic prompt/file/shell markers appeared in
`InferenceService/RunInference`. Prompt markers also appeared in `NameTab`,
`UpdateConversationMetadata`, and `ClassifyAgentAutoReview`: inspecting only the
main model RPC would miss these disclosures.

The separate `AgentService/Run` route was observed too, but that observation does
not establish a working inspected workflow for its stateful protocol. It remains
blocked. The supported Agent/Auto workflow uses full `RunInference` invocations.

Routing evidence is not proof of general detection, redaction, or full editor
compatibility. Manual tests must verify the synthetic workspace/window: restored
Agents windows can ignore CLI folder arguments. An explicit `.code-workspace`
file and verified window title avoid confusing the test target.

## Protocol constraints

| Constraint | Consequence |
| --- | --- |
| Native duplex HTTP/2 | Inspect complete messages before release without waiting for upload EOF. Disabling HTTP/2 does not turn protobuf into JSON. |
| Nested gzip/Zstandard | Outer Connect decompression is insufficient; decode declared nested model payloads too. |
| Deltas, fingerprints, and content-addressed references | Negotiate full inference payloads. Block unresolved cache/reference forms instead of inventing a conversation-state subsystem. |
| File-sync hashes and incremental edit offsets | Rewriting isolated strings can corrupt integrity or miss secrets assembled across edits. These routes remain unsupported. |
| Separate SSE/polling write channels | Inspecting a request ID alone does not inspect content sent through an append channel. Alternate channels block. |
| Connect GET/query payloads | Reject them; the shared protection contract excludes URL-query inspection. |
| Unknown wire shapes | Fail closed. A length-delimited field can be text, a message, bytes, or an identifier; recursive UTF-8 guessing is not safe redaction. |

Clean supported content retains its wire bytes except the documented handshake
capability flags. Identifiers, provider-signed reasoning, and position/hash-bound
inline context cannot be rewritten blindly. Isolated tests assert upstream bytes
and the absence of blocked content; they do not expand the live support claim.

## Sources

- [Cursor hooks and schemas](https://cursor.com/docs/hooks)
- [Cursor network configuration](https://cursor.com/docs/enterprise/network-configuration)
- [Cursor safety controls](https://cursor.com/docs/enterprise/llm-safety-and-controls)
- [Cursor support: CLI window selection and `--classic`](https://forum.cursor.com/t/cli-command-on-mac-no-longer-opens-the-current-folder/160164)
- [Connect protocol specification](https://connectrpc.com/docs/protocol/)
- [Cursor support: outdated proxy adapter and protobuf failures](https://forum.cursor.com/t/agent-conversation-state-corrupted-server-side-since-oct-23-all-requests-fail-protobuf-decode-multiple-request-ids/176177)
