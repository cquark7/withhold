# Getting help

Find setup instructions, troubleshoot a connection, or ask the community.
Questions, reproducible bug reports, and focused contributions are welcome.

## Start here

1. Run `withhold version`, `withhold status`, and `withhold doctor`.
2. Check the [integration guide](docs/integrations/vscode-copilot.md) for trust,
   restart, and platform requirements.
3. Search [existing issues](https://github.com/cquark7/withhold/issues).
4. Open a [bug report](https://github.com/cquark7/withhold/issues/new?template=bug_report.yml)
   with a minimal reproduction using synthetic data. For a question, use the
   [question form](https://github.com/cquark7/withhold/issues/new?template=question.yml).

Review diagnostics before sharing: local paths, hostnames, usage metadata, and
settings may be private. Never post real credentials, CA keys, session records,
settings backups, finding logs, or raw request captures.

## Restore normal editor access

Run `withhold off` with the same `WITHHOLD_DIR` used for the session. Preserve
local recovery state until restoration succeeds. Follow
[recovery and removal](docs/usage.md#recovery-and-removal) for interrupted
sessions, manual trust, and CA cleanup.

## Security reports

Follow [SECURITY.md](SECURITY.md) and report vulnerabilities privately.
Public issues should not contain exploit details.

## Propose a change

Use a [feature request](https://github.com/cquark7/withhold/issues/new?template=feature_request.yml)
for a workflow improvement or an
[integration proposal](https://github.com/cquark7/withhold/issues/new?template=integration_request.yml)
for another coding agent. Describe the concrete problem and a small first step.
Opening an issue does not imply a delivery commitment.
