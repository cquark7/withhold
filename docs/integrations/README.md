# Integrations

An integration pairs a **coding harness** (its setup, trust, and lifecycle) with
a **traffic profile** (provider hosts, APIs, and error protocol). Sharing an API
or being a VS Code fork does not make an agent supported automatically.

| Integration ID | Harness | Platforms | Contract and setup |
| --- | --- | --- | --- |
| `vscode-copilot` (default) | Desktop VS Code + GitHub Copilot | macOS, Linux, Windows; [trust requirements](vscode-copilot.md#validation-and-support-matrix) | [Guide](vscode-copilot.md) |

Only this integration is currently shipped. Codex, Cursor, OpenCode, remote
extension hosts, WSL, containers, and browser editors are not established
integrations. No dynamic plugins are loaded.

```sh
withhold integrations             # Available in this build; no setup required.
withhold integrations --json      # Versioned machine-readable catalog.
withhold setup --integration vscode-copilot
withhold doctor --integration vscode-copilot
withhold on --integration vscode-copilot
withhold off                     # Restores the recorded integration/resource.
```

Set `integration` in the [user config](../configuration.md) to avoid repeating
the selector. One integration runs per state directory; stop before switching.
Foreground `serve` uses the same selector but does not configure the application.
It does not establish routing or trust by itself.

Every integration contract supplements the [shared contract](../../CONTRACTS.md).
For implementing one, see [Adding an integration](../adding-integrations.md).
