# Working on withhold

Build a privacy tool people can trust and enjoy using: strong enforcement,
an elegant CLI, reliable recovery, and a small operational footprint.

## Working style

- Read `CONTRIBUTING.md` and relevant sections of `CONTRACTS.md` before changing
  behavior. Consult `docs/architecture.md` for ownership and boundaries.
- Own the requested outcome through implementation and verification. Give a
  brief, proportional plan for substantial work; ask only about consequential
  ambiguity, risk, or scope expansion, not routine implementation choices.
- Optimize for implementation time and token usage: inspect owning code and
  affected callers, parallelize independent checks, reuse existing patterns,
  and avoid repeated broad searches or expensive full-suite runs.
- Challenge clumsy UX or unnecessary complexity. Recommend the simpler design
  rather than merely implementing the first suggested interface.
- Prefer the smallest maintainable solution that serves common workflows.
  Do not turn bounded work into exhaustive feature coverage or build speculative
  frameworks and machinery for hypothetical agents.

## Product and CLI craft

- Design around what users want to do, not internal architecture. Publicly,
  users choose **agents**; integrations and traffic profiles are implementation
  concepts. Prefer actions as commands, targets as positional arguments, and
  flags as modifiers. Brevity should remove ceremony, not sacrifice clarity.
- Preserve a coherent lifecycle: `setup AGENT...` saves defaults; `on` uses
  them; `on AGENT...` overrides only that session; `off` restores every recorded
  application. Selection is explicit, never guessed from installed programs.
- Backward compatibility is not a goal by itself. Breaking changes are welcome
  when they improve UX or architecture. Keep one clean current design rather
  than accumulating aliases, legacy selectors, dual formats, or migration
  readers without an explicit requirement. Explain breaks and preserve recovery
  data; removing baggage must never discard user state.
- Keep defaults centralized in `internal/config` and align help, completion,
  examples, machine-readable schemas, exit codes, and documentation.
- Ship a clearly bounded, useful workflow. Do not make support for every harness
  feature a prerequisite for a narrower integration. Unsupported guarded traffic
  must remain fail-closed, not acquire passthrough workarounds.
- State support precisely: tested workflows, versions, platforms, and exclusions.
  A running listener, clean fixture, or successful model response is not proof
  of routing, inspection, or complete protection.

## Engineering boundaries

- Go is the only product runtime. Prefer writing tests in Go.
  Python was used previously for tests and development tools.
  Keep the installed experience a self-contained Go binary.
- Use thin adapters and shared enforcement. Register agents centrally; keep
  harness-specific settings, routes, codecs, and error protocols in adapters,
  not branches in shared config, session, proxy, policy, or scanning code.
- Treat privacy, bounded resource use, cancellation, TLS verification, and
  recoverable application changes as product requirements, not optional polish.
  Performance claims need measurements; protection claims need outbound evidence.
- Keep disposable probes, binaries, captures, and logs outside the repository.
  Retain a diagnostic tool only when it has ongoing value and a deliberate
  interface. Do not resurrect removed temporary helpers.
- Describe behavior directly in comments, tests, and documentation; do not use
  ticket, milestone, or review IDs as explanations. Keep docs about current
  behavior rather than implementation history.

## Tests, safety, and verification

- Add only meaningful tests: observable contracts, realistic regressions,
  security boundaries, and consequential failure/recovery paths. Extend existing
  fixtures where practical; avoid redundant permutations, implementation-detail
  assertions, and tests added merely to increase coverage.
- For egress enforcement, assert actual upstream bytes and that blocked content
  never arrives. For lifecycle changes, cover partial failure and restoration
  that preserves unrelated edits. Match test depth to the change's risk.
- Never run live provider/harness E2E checks or change real editor settings or
  trust stores without explicit authorization. Routine tests use synthetic
  content, isolated homes/state, private CAs, and ephemeral loopback ports.
  An exception for one debugging session is not standing permission.
- Run focused checks while iterating. For code, tooling, or test changes, run
  the full gate before reporting completion:

  ```sh
  .venv/bin/python tools/verify.py
  ```

  This builds isolated acceptance binaries and sets
  `WITHHOLD_TEST_SCANNER_WORKER`, `WITHHOLD_TEST_NATIVE`, and
  `WITHHOLD_TEST_NATIVE_FIXTURE`. Do not report process-level verification when
  those tests were skipped. Add focused race checks when concurrency changes.

- For documentation/instructions-only changes, check affected references and run
  `.venv/bin/python tools/check_docs.py` and `git diff --check`; do not rebuild
  the runtime solely for prose. Follow `CONTRIBUTING.md` for additional relevant
  installer, workflow, packaging, and platform checks.

## Delivery

- Inspect the final diff. Preserve unrelated edits and report only observed
  results, with remaining risks or unverified support stated plainly.
- Be concise: explain consequential decisions and blockers, then finish with the
  outcome and verification. Avoid routine narration or repeated summaries.
- Commit, push, or release only when asked. Use focused Conventional Commits;
  call out intentional breaking changes and do not add attribution trailers.
