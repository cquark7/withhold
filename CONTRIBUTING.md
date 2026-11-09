# Contributing

Contributions are welcome. Focused changes with a clear reproduction are
easiest to review. Please follow
the [community guidelines](CODE_OF_CONDUCT.md); report vulnerabilities using
[SECURITY.md](SECURITY.md).

## Your first contribution

- Improve an installation, trust, or recovery explanation you found confusing.
- Add a minimal synthetic regression case for a false positive or missed format.
- Investigate an issue marked
  [good first issue](https://github.com/cquark7/withhold/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22good%20first%20issue%22)
  or [help wanted](https://github.com/cquark7/withhold/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22help%20wanted%22).
- Research a proposed integration using public networking/setup documentation.

For a small fix, open a pull request directly. Discuss larger behavior changes,
new integrations, or dependencies in an issue before investing substantial work.
Describe the concrete problem, resulting behavior, and verification in the PR.
Never include real credentials or private captures, even in test fixtures.

## Development setup

Use Go 1.26 or later, Python 3.11+, and Ruff. Python is used for acceptance tests and
development tools, not by the installed application.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
```

On Windows, use `.venv\Scripts\python.exe` instead of `.venv/bin/python`.
The `go` directive in `go.mod` sets the minimum Go version; `toolchain` suggests
the development version. CI and release builds select Go 1.26.10 explicitly.

## Verify changes

```sh
.venv/bin/python tools/verify.py
```

This builds all three acceptance binaries in a temporary directory, sets
`WITHHOLD_TEST_SCANNER_WORKER`, `WITHHOLD_TEST_NATIVE`, and
`WITHHOLD_TEST_NATIVE_FIXTURE`, then runs Go tests/vet/format checks and Python
tests/lint/format checks. Add `--race` to enable Go's race detector.
Running Python tests without these paths skips process-level coverage.

Documentation-only work can first run `.venv/bin/python tools/check_docs.py`.
Before submitting, run the full gate above. CI uses isolated fixtures; successful
checks do not establish live editor/provider compatibility.

Workflow and installer checks also run in CI:

```sh
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
sh -n install.sh
bash -n tools/proof/block_direct.sh
```

Tests use synthetic values, isolated homes, private CAs, and loopback fixtures.
Do not contact live providers or change real trust stores/editor settings during
routine verification. Assert the bytes received upstream, not model responses.

## Project layout

| Location | Purpose |
| --- | --- |
| `cmd/withhold/` | Product executable and CLI composition. |
| `internal/` | Private Go runtime packages; unit tests live beside their code. |
| `cmd/withhold-scanner/` | Development entry point for the scanner protocol. |
| `tests/` | Python acceptance/tool tests and the Go upstream fixture. |
| `tools/` | Verification, packaging, notices, benchmarks, and manual diagnostics. |

See [architecture](docs/architecture.md) for package boundaries and
[Adding an integration](docs/adding-integrations.md) for the extension workflow.
Integrations register once, own typed application options and traffic contracts,
reuse scanning/redaction, and keep transport limits unconditional. Do not add
harness/provider branches to shared config, session, transport, or scanning.

## Change guidelines

- Update [CONTRACTS.md](CONTRACTS.md) for shared observable changes, or the selected
  [integration contract](docs/integrations/README.md) for harness-specific ones,
  together with regression tests.
- Keep help, completion, JSON output, and exit codes consistent. Help must work
  with invalid runtime configuration; `launch --` arguments remain literal.
- Keep detected values out of ordinary diagnostics. Debug findings are opt-in,
  masked, private, and limited to detected values and send outcomes.
- Keep the voice quiet and factual: no banners, jokes about secrets, or blanket
  protection claims. Use `withhold` for the product and `<WITHHELD_…>` for markers;
  retain standard terms such as redact/block and standard proxy variables.
- Describe current behavior, not implementation history. Keep setup/recovery in
  [usage](docs/usage.md), shared settings in [configuration](docs/configuration.md),
  harness-specific instructions in its integration guide, and
  maintainer release procedures in [releasing](docs/releasing.md).

The synthetic loopback benchmark is `tools/benchmark_proxy.py`; build fixtures
and set the three test paths above before running it. Its RSS measurements sum
processes and may double-count shared pages or miss short peaks.

`tools/proof/` contains manual network diagnostics, not protection checks.
Its firewall helper also blocks the proxy's upstream traffic; use only in
disposable environments. Stub tests do not establish real firewall integration.

## Dependency maintenance

Dependabot groups routine Go, Actions, and Python development-tool updates into
monthly pull requests, with at most one routine PR per ecosystem. Security alerts
and the weekly reachable-vulnerability workflow provide separate signals.
Review updates before merging; detector versions, canaries, worker negotiation,
and behavior documentation must stay consistent. Updates are never auto-merged.
