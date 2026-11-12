# Releasing

Build reproducible native binaries and archives, verify their contents, and publish them
with signed provenance. Record the checks for each target and integration.

## Review before publication

- Run the [verification gate](../CONTRIBUTING.md#verify-changes) on the intended
  source. Review source and archives for credentials, personal paths, captured
  requests, CA keys, settings backups, and runtime records. Synthetic detector
  fixtures still need review; do not blanket-ignore test findings.
- Check reachable dependency vulnerabilities:
  `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...`.
  Resolve or explicitly assess findings.
- Enable and monitor GitHub private vulnerability reporting as part of public
  repository setup, and verify the link in [SECURITY.md](../SECURITY.md).
- Review dependency licenses/notices and linked source availability. Automatic
  collection is not legal clearance; the project's MIT license does not replace
  dependency terms.
- Record commit, date, toolchain, OS/CPU, commands, and skips. Keep local evidence
  distinct from hosted CI and live-provider validation.

## Local builds

Use the same Go toolchain as CI (currently Go 1.26.10) and fresh output directories
when checking reproducibility. For a matching macOS ARM64 host:

```sh
go mod verify
python3 tools/package_native.py --version v1.2.3 --targets darwin-arm64 --output dist/packages
python3 tools/verify_native.py --artifacts dist/packages --version v1.2.3 --targets darwin-arm64 --extract dist/verified --run
```

Choose your host target for `--run`; cross-built files can be inspected without
execution. Repeat packaging into another empty directory and compare
`SHA256SUMS`. Builds disable CGO/VCS stamping, trim paths, and normalize archive
metadata. Reproducibility requires identical source, toolchain, and settings.

Archives contain the executable, usage README, behavior contract, license,
`THIRD_PARTY_NOTICES.txt`, and `BUILD.json` with target/version/build settings,
source/dependency digest, and file hashes/modes. Notices come from exact modules
recorded in the binary plus Go/toolchain notices. Missing/empty/replaced or
mismatched dependency sources/licenses fail packaging. The archive verifier
checks exact regular-file contents/modes before safe extraction; it does not
authenticate the publisher.

`SHA256SUMS` covers the six platform archives. Distribute each executable with
the license and dependency notices included in its archive.

## Hosted builds and publication

`.github/workflows/native-artifacts.yml` accepts manual SemVer builds and pushed
`v`-prefixed SemVer tags. It first checks reachable Go vulnerabilities; a failed
scan stops the build. It tests on six matching OS/CPU runners, compares two
builds per target, verifies the archives and extracted binaries, and attests
the archives, `SHA256SUMS`, and the release's `install.sh`.
The collector alone signs; only publication can write releases.
Actions track their current major version tags, and checkout does not retain Git credentials.
Acceptance tests and per-file provenance checks run in bounded parallel workers;
any failed check stops collection or publication.

Before publishing a tag:

1. Configure the `release` environment with required reviewers and tag deployment
   restrictions; protect tag creation/movement with repository rulesets.
2. Confirm runner availability and repository eligibility for GitHub attestations.
3. Review the intended commit/version and applicable evidence below. Tag/push
   only as an explicit release action, never routine verification.

Manual dispatch uploads a verified `native-release` workflow artifact, not a
GitHub Release. Individual `native-TARGET` artifacts are unsigned intermediates;
do not distribute them. Attestation failure must stop distribution.

Tag runs in `cquark7/withhold` independently re-verify repository, workflow, tag,
and source commit before creating a draft with six archives, checksum manifest, `install.sh`, and
`native-release.sigstore.json`, then publishing it. Upload failure
leaves a draft; inspect before retrying. Existing releases are not overwritten.
Prereleases are not marked latest; installers must select RC tags explicitly.

The stable bootstrap URL is
`https://github.com/cquark7/withhold/releases/latest/download/install.sh`.
Each release also has a version-specific installer URL. The script resolves the
latest stable archive unless `--version` is supplied; document pinned installs with
both a version-specific script URL and `--version`.

After publication, verify the published archive as a consumer using an
independently trusted source commit and the [download instructions](usage.md#installation).
Exercise the checksum-only installer without GitHub CLI and a pinned-commit
installer in isolated state. The former checks integrity, not publisher identity.
Retain provenance, build URL, hashes, and verification results. Signing
establishes origin/integrity, not OS trust or provider compatibility.

## Evidence for support claims

| Area | Required evidence |
| --- | --- |
| Platforms | Execution on matching macOS/Linux/Windows x64 and ARM64, not cross-compilation alone. |
| Memory | Acceptance budgets, repeated cap-sized rewrites/attachments/expansion/concurrency; 64 MiB admission is not an RSS cap. |
| Trust/launch | Disposable Keychain/NSS integration, Windows manual trust, real editor launch/restore. |
| Provider | Dated editor/Copilot versions, chat/inline/embeddings/tool schemas, false-positive review. Live checks require an explicit request. |
| Maintenance | Supported versions/platforms, monitored private reporting, consumer upgrade/rollback verification. |
