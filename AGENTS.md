# Agent instructions

- Read `CONTRIBUTING.md` and the relevant section of `CONTRACTS.md` before
  changing behavior.
- Describe behavior directly in comments, tests, and documentation; do not use
  ticket, milestone, or review IDs as explanations.
- Do not run live Copilot E2E checks or change editor settings or trust stores
  without an explicit user request. Tests must use isolated state and ports.
- Go is the only product runtime. Python is limited to tests and development tools.
- Set the `GUARD_TEST_*` binary paths as described in `CONTRIBUTING.md` so the
  process-level acceptance tests run instead of being skipped.
- Before reporting a change complete, run:

  ```bash
  go test ./... && go vet ./... && test -z "$(gofmt -l cmd internal tests/nativefixture)" && python3 -m unittest discover -s tests -q && ruff check . && ruff format --check .
  ```
