# Supported agents

Each supported agent combines a **coding harness** (its setup, trust, and
lifecycle) with a **tested traffic scope** (provider hosts, APIs, and error
protocol). Sharing an API or being a VS Code fork does not make an agent
supported automatically.

| Agent ID | Harness | Platforms | Contract and setup |
| --- | --- | --- | --- |
| `cursor` | Cursor desktop, bounded local Agent/Auto egress | Live validation recorded for macOS Apple silicon; other platforms not recorded | [Guide](cursor.md) |
| `vscode-copilot` | Desktop VS Code + GitHub Copilot | macOS, Linux, Windows; [trust requirements](vscode-copilot.md#validation-and-support-matrix) | [Guide](vscode-copilot.md) |

Codex, OpenCode, remote extension hosts, WSL, containers, and browser editors
are not currently supported agents. No dynamic plugins are loaded.

Cursor support is deliberately limited; see its guide for the validated workflow
and fail-closed exclusions.

```sh
withhold agents                      # Supported in this build; no setup required.
withhold agents --json               # Versioned machine-readable catalog.
withhold setup cursor vscode-copilot # Prepare and save the default set.
withhold on                          # Enable that set on one shared proxy.
withhold doctor                      # Diagnose the active set, otherwise saved.
withhold off                         # Restore all recorded application resources.
withhold on cursor                   # Session-only replacement; defaults unchanged.
```

There is no implicit default agent or installation-based detection. Selection is
an explicit set: named targets replace, never append. Setup saves `agents` in
the [user config](../configuration.md); application overrides live under
`[applications.AGENT]`. One active set runs per state directory; stop before
changing it. Repeating `on` with the same set and settings is idempotent.
Foreground `serve AGENT...` uses the same selection but does not configure
applications or trust.

All agent profiles enforce their own boundaries on the shared proxy. Overlapping
route claims fail closed rather than selecting a profile by order. One adapter's
passthrough cannot override another adapter's guarded or suspicious host.
Session-wide inspection counters are not attribution to individual agents.

Each agent's documented scope supplements the [shared contract](../../CONTRACTS.md).
For adding agent support, see [Adding an integration](../adding-integrations.md).
