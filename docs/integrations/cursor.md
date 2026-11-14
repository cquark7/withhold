# Cursor

Agent ID: `cursor`. Select agents explicitly; there is no implicit default.

This integration targets **local Cursor Agent/Auto model requests** through
Withhold's HTTPS proxy. It is not a claim that every Cursor feature or network
request is covered. The [shared behavior contract](../../CONTRACTS.md) applies.

## Validation and scope

| Environment | Validation |
| --- | --- |
| macOS, Apple silicon; Cursor 3.30.8 | Manually tested 2026-11-14 with an enforcing loopback proxy. Clean chat and follow-up, prompt-secret redaction and follow-up, `@README.md` context, file edit/read/follow-up/cleanup, and a synthetic secret in mentioned file context completed. |
| Other platforms or Cursor versions | Settings and transport have isolated tests; live routing validation is not recorded. |

The live test confirmed that the tested model requests were inspected and
redacted before forwarding. It did not validate every Cursor route. Tab
completion, file synchronization, remote/cloud agents, OCR/document extraction,
and server-side conversation or index state are outside this initial scope.
Unsupported Cursor service calls and request shapes fail closed and may make
other editor features unavailable. Do not add passthrough exceptions to work
around a blocked call.

## Setup

Read the shared [installation and certificate-trust guide](../usage.md) before
setup. Prepare Cursor and save it as your default agent set:

```sh
withhold setup cursor
withhold doctor
withhold on
# Fully quit and reopen Cursor after setup.
withhold status
withhold off
```

Activation (`on`) manages Cursor's user `settings.json` and the proxy/TLS settings.
HTTP/2 remains enabled because the supported model routes use duplex Connect
streams. TLS verification is not disabled. `off` restores the recorded managed
settings while preserving unrelated edits.

Optional launch uses Cursor's CLI:

```sh
withhold launch cursor -- .
```

## Application configuration

The selected application settings are:

```toml
schema = 1
agents = ["cursor"]

[applications.cursor]
binary = "cursor"
settings_dir = "Cursor"
```

| Field | Default and meaning |
| --- | --- |
| `binary` | `"cursor"`; executable used by optional `launch`. |
| `settings_dir` | `"Cursor"`; local directory under the platform application-settings root. |

`WITHHOLD_EDITOR_BIN` and `WITHHOLD_EDITOR_SETTINGS_DIR` override these fields.
For multiple editors, prefer namespaced file settings: global editor overrides
apply to each selected editor, and shared settings resources are rejected.
The managed settings file is `Cursor/User/settings.json` under the platform
settings root.

## Traffic contract

All `cursor.sh` and `cursor.com` hosts and subdomains are guarded. Reviewed
Connect/protobuf routes use the shared bounded decoder, scanner, and verified
write-back:

| Route subset | Behavior |
| --- | --- |
| `InferenceService/RunInference` | Full model invocations and reviewed run/control messages over native duplex HTTP/2. The handshake disables delta invocations and delta-base seeds so each model request carries inspectable content. Unexpected deltas, seeds, or fields block. |
| `AgentService/Run` | Reviewed inline content, common tool history/results, and typed same-upload history references. Unresolved references, KV exchange, chunked shell output, and unreviewed variants block. |
| `AiService/NameTab`, `AgentService/UpdateConversationMetadata`, `AiService/ClassifyAgentAutoReview`, `AiService/StreamCpp` | Reviewed typed subsets only. Immutable identifiers or position/hash-bound content cannot be rewritten; findings there block. |
| Selected startup/control methods | Only explicitly described protobuf fields are accepted. |

Chat findings are redacted by default; inline findings are blocked by default.
Unknown paths on Cursor service hosts, unsupported encodings, and unreviewed
protobuf fields fail closed. This can interrupt unsupported background or
interactive features. The full route and field boundary is maintained in the
[codec notes](../../internal/integrations/cursor/README.md).

Withhold scans request content before forwarding. It cannot inspect content
created solely on Cursor's backend, sanitize prior server-side state, or control
remote/cloud agent execution.
