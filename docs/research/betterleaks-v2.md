# Betterleaks v1.10.1 to v2 RC9

The baseline withhold build embeds Betterleaks `v1.10.1` (`39d5bdc`).
The migrated build embeds `v2.0.0-rc.9` (`e07e69b`), the newest v2 tag
listed by the Go module proxy on November 22, 2026. The comparisons use
the two pinned SDK versions with Go’s standard regex engine. The Mac’s
standalone `betterleaks` reported `1.8.1` during the investigation.
[RC9 release](https://github.com/betterleaks/betterleaks/releases/tag/v2.0.0-rc.9) · [v1.10.1 release](https://github.com/betterleaks/betterleaks/releases/tag/v1.10.1) · [Go version index](https://proxy.golang.org/github.com/betterleaks/betterleaks/v2/@v/list) · [withhold module](../../go.mod)

## Major changes from v1.10.1 to RC9

| Area | Change |
| --- | --- |
| Go SDK | `/v2` requires Go 1.26.0, which withhold already targets. `scan.Scanner` snapshots config and replaces the mutable `detect.Detector`. `Scan(ctx, source, callback)` supplies a summary and error, serializes callbacks, and stops on a callback error. Finding order is unspecified. `ScanString` cannot return scan errors. Regex selection is per scanner and defaults to Go stdlib. Regexes compile lazily unless `WithPrecompile()` is used. Logging is opt-in through `slog`. [Tagged SDK guide](https://github.com/betterleaks/betterleaks/blob/v2.0.0-rc.9/docs/v2_migration.md#go-sdk-changes) |
| Rules and config | `Config.Rules` is a slice with string patterns, `Rule.ID`, `ValueGroup`, and value-type components. Old TOML allowlists and entropy/token-efficiency fields give way to expressions. Unknown fields are rejected, specificity defaults to zero, and an override replaces the inherited rule. The source owns the prefilter. v1.10.x already made target-local config loading opt-in. v2 removes that opt-in and the `GITLEAKS_*` aliases. [v1.10.0 notes](https://github.com/betterleaks/betterleaks/releases/tag/v1.10.0) · [Tagged config migration](https://github.com/betterleaks/betterleaks/blob/v2.0.0-rc.9/docs/v2_migration.md#configuration-changes) |
| Findings and reports | Go findings use `Match.Value`, `Match.Full`, and `Location`. `DecodeDepth` and `Encodings` replace generated decode tags and are reported independently for components. `ComponentSetsTruncated` records actual omission at the 100-combination cap. CLI JSON has a schema envelope and JSONL finishes with a scan summary. Baseline suppression and CSV, SARIF, JUnit, and template reports are removed. Ignore fingerprints change from locations to exact-value SHA-256 or optional HMAC. [Tagged report types](https://github.com/betterleaks/betterleaks/blob/v2.0.0-rc.9/report/finding.go) · [Tagged report and ignore migration](https://github.com/betterleaks/betterleaks/blob/v2.0.0-rc.9/docs/v2_migration.md#report-changes) |
| Rules and decoding | The tagged rule sets contain 466 IDs in v1.10.1 and 475 in RC9, with 15 added and six removed or renamed. RC9 adds Anthropic OAuth access and refresh, Cal.com, and Jina AI detection. Earlier candidates add Tailscale, Labelbox, and Mapbox coverage and extend generic API-key and password patterns for structured JSON and XML. Several client/public-key IDs disappear, and `cloudflare-api-key` becomes `cloudflare-api-key.1`. Stock AWS detection makes the secret-key component optional. The decoder adds padded URL-safe and unpadded standard Base64 alongside padded standard and raw URL-safe. It still uses candidate and printable-ASCII heuristics. [v1 rules](https://github.com/betterleaks/betterleaks/blob/v1.10.1/config/betterleaks.toml) · [RC9 rules](https://github.com/betterleaks/betterleaks/blob/v2.0.0-rc.9/config/betterleaks.toml) · [RC5 release](https://github.com/betterleaks/betterleaks/releases/tag/v2.0.0-rc.5) · [RC9 codec](https://github.com/betterleaks/betterleaks/blob/v2.0.0-rc.9/internal/codec/base64.go) |
| Performance and dependencies | The scanner uses bounded fragment scheduling, keyword dispatch and search windows, lazy compilation, and a detection-only import path. Git, archive, remote source, provider analysis, and RE2/Wazero packages are imported separately. The RC9 SDK-only package graph still includes `regexp2` for local tokenization. v2’s CLI defaults to RE2. Package reachability and packaged binary size matter more to withhold than the contents of upstream’s `go.mod`. [RC6 release](https://github.com/betterleaks/betterleaks/releases/tag/v2.0.0-rc.6) · [Tagged scanner](https://github.com/betterleaks/betterleaks/blob/v2.0.0-rc.9/scan/scanner.go) · [Tagged tokenizer](https://github.com/betterleaks/betterleaks/blob/v2.0.0-rc.9/internal/tokenizer/tokenizer.go) |
| CLI, sources, and credential operations | Local paths can select filesystem scanning directly. Findings print by default and `-o` selects JSON or JSONL by extension. Detection stays offline by default for local sources, like v1.10.1. `-v` now requests provider validation, `-a` adds provider identity and permission analysis, and `revoke` is a separate explicit command. Earlier discussion described default provider requests, which changed before RC9. Git history uses go-git v5 in-process, with changes to revision/ref selection, merge coverage, and patch hooks. Filesystem scanning drops MIME-based skips and the prefilter drops `.git` and a broad document/executable extension group. withhold uses its own CLI and file intake. [Upstream discussion](https://github.com/betterleaks/betterleaks/discussions/360) · [Tagged CLI migration](https://github.com/betterleaks/betterleaks/blob/v2.0.0-rc.9/docs/v2_migration.md#cli-changes) |

## Findings that change the migration

- **Detection and rewrite need a shared representation.** The v1.10.1
  withhold worker rewrites padded URL-safe and unpadded standard Base64 when
  the whole JSON leaf is encoded. In a synthetic probe it reported `redacted`
  and returned a JSON string containing an inline double-Base64 token unchanged.
  The SDK found the decoded value, while write-back and residue checks missed
  the inline container. RC9 also found the test token in an inline padded
  URL-safe container that v1 missed. Mapping only `Match.Value` and `Match.Full`
  would carry the gap forward.
  [Extraction](../../internal/scanner/extract.go) · [Write-back](../../internal/scanner/scanner.go) · [Residue checks](../../internal/scanner/content.go)
- **Reader fragmentation changes coverage.** The RC9 SDK found an AWS
  access-key ID in a whole fragment at byte column 124,991. `sources.Reader`
  missed it when its 100,000-byte read plus 25,000-byte lookahead split the ID.
  Reader boundaries can also split multipart pairs or encoded containers.
  The baseline withhold scanner also splits long leaves with fixed overlap.
  [Reader boundary source](https://github.com/betterleaks/betterleaks/blob/v2.0.0-rc.9/sources/internal/stream/reader.go) · [withhold extraction](../../internal/scanner/extract.go)
- **Structured text gains depend on what reaches the SDK.** RC9 caught the
  synthetic credential under `api_key.value` in literal JSON, and generic
  credentials in nested XML and password CDATA. The baseline native JSON leaf
  projection loses the outer key for `api_key.value`, and the SDK missed the
  test value on that projection.
  [RC5 release](https://github.com/betterleaks/betterleaks/releases/tag/v2.0.0-rc.5) · [JSON projection](../../internal/scanner/extract.go)
- **RC9 can distinguish a complete multipart result at the cap.** The stock
  AWS rule produced 100 sets without truncation and 100 sets with truncation
  from 101 candidates. The withhold `psql` regex and keyword patch found a
  synthetic `PSQL://` password. An empty `WithAllowSignatures()` kept an AWS
  finding on a `betterleaks:allow` line. RC9 detected both Anthropic OAuth token
  types in the same SDK probe.
  [RC9 multipart implementation](https://github.com/betterleaks/betterleaks/blob/v2.0.0-rc.9/scan/components.go) · [RC9 options](https://github.com/betterleaks/betterleaks/blob/v2.0.0-rc.9/scan/options.go)

## withhold migration results

The scanner keeps long leaves in one fragment, gives a nested `value` its
enclosing key as context, and traces findings to the scan input. Whole-leaf
Base64 rewrites preserve decodable content and verify the emitted bytes.
An inline or nested encoded finding that lacks a verified rewrite blocks
enforced requests, including on Copilot embeddings. The scanner inspects
non-UTF-8 Base64 candidates as literal text, which restored detection of
standalone Anthropic OAuth tokens that resemble URL-safe Base64.
[Scanning contract](../../CONTRACTS.md#scanning-and-redaction)

The synthetic benchmarks ran on an Apple M3 Pro with Go 1.26.11 and private
loopback HTTPS. Proxy percentiles use 10 warm requests per case. The two
supplemental workloads use three requests each and verify the exact upstream
SHA-256 of the expected rewritten body. RSS sums the proxy and its children,
counts shared pages in each process, and samples every 100 ms.
[Proxy benchmark](../../tools/benchmark_proxy.py)

| Measurement | v1.10.1 | v2 RC9 |
| --- | ---: | ---: |
| Proxy startup | 133 ms | 74 ms |
| First clean request | 36.1 ms | 18.6 ms |
| 1 MiB redacted, p50 / p95 | 57.3 / 59.9 ms | 50.5 / 53.1 ms |
| 1 MiB clean, p50 / p95 | 31.5 / 33.1 ms | 33.0 / 50.6 ms |
| 31 MiB clean | 626 ms | 533 ms |
| 1 MiB Base64 text with one finding, median | 73.5 ms | 65.0 ms |
| 30 MiB text with about 30,700 findings, median | 4.87 s | 3.48 s |
| Dense workload, peak sampled RSS | 803 MiB | 730 MiB |
| Full proxy benchmark, peak sampled RSS | 774 MiB | 771 MiB |
| Stripped darwin-arm64 binary | 19,981,042 bytes | 15,225,666 bytes |
| Packaged third-party notices | 231,978 bytes | 99,244 bytes |
| Linked Go modules | 53 | 16 |

The standalone SDK probe took 2.26 s on a warm 32 MiB dense fragment and
0.30 s with Reader and four workers. Reader missed the boundary AWS finding
with both one and four workers, so the proxy uses one whole fragment and one
SDK worker per process. In that probe, eager compilation added about 13 ms
to initialization and shaved about 0.2 ms from the first scan. Production
uses lazy compilation and the tests precompile the stock rules.
[Detector options](../../internal/detector/detector.go) · [Boundary regression](../../internal/scanner/detection_test.go)

Offline inspection's small clean fixture increased from 0.60 µs to 5.08 µs
per operation. The 40 KiB source fixture improved from 185 µs to 170 µs.
The SDK's error-returning scan path adds 16 allocations per operation in
these fixtures. These are medians of three runs.
[Offline benchmark](../../internal/detector/inspect_test.go)
