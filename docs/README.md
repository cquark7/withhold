# Withhold documentation

| Need | Read |
| --- | --- |
| Install, operate, diagnose, recover, or remove Withhold | [Usage](usage.md) |
| Inspect local text, files, or directories for secrets/PII | [Offline scan](usage.md#scan-local-text) |
| Choose a supported coding agent | [Agent catalog](integrations/README.md) |
| Set shared policy, limits, and agent options | [Configuration](configuration.md) |
| Understand protection guarantees and limits | [Shared contract](../CONTRACTS.md), then the selected agent's documented scope |
| Understand package boundaries and design choices | [Architecture](architecture.md) |
| Implement another harness | [Adding an integration](adding-integrations.md) |
| Develop, verify, or release | [Contributing](../CONTRIBUTING.md) · [Releasing](releasing.md) |
| Ask a question or report a problem | [Support](../SUPPORT.md) · [Security reports](../SECURITY.md) |

Shared docs describe the tool, not an editor. Each agent guide owns its
setup/configuration, traffic contract, inspection-policy exceptions, and recovery
details. The CLI catalog points to those guides; unsupported agents are not
listed as supported.
