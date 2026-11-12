#!/usr/bin/env bash
set -euo pipefail

bundle=${1:?expected an attestation bundle and at least one artifact}
shift
if [[ $# -eq 0 ]]; then
  printf '%s\n' 'expected at least one artifact' >&2
  exit 2
fi

options=(
  --repo "$GITHUB_REPOSITORY"
  --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/native-artifacts.yml"
  --source-digest "$GITHUB_SHA"
  --deny-self-hosted-runners
  --bundle "$bundle"
)
if [[ -n ${WITHHOLD_ATTESTATION_SOURCE_REF:-} ]]; then
  options+=(--source-ref "$WITHHOLD_ATTESTATION_SOURCE_REF")
fi

printf '%s\0' "$@" |
  xargs -0 -n 1 -P 4 gh attestation verify "${options[@]}" --
