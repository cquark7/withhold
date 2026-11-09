#!/bin/sh
# Download and verify withhold. Trust setup and editor changes are separate commands.
set -eu

main() (
    repo=cquark7/withhold
    version=
    commit=
    bin_dir=${HOME:?HOME must be set}/.local/bin
    usage() {
        cat <<'EOF'
Install withhold on macOS or Linux (no sudo).
Usage: sh install.sh [--version vX.Y.Z] [--commit FULL_SHA] [--bin-dir DIR]

Requires GitHub CLI (gh with attestation support), tar, and sha256sum or shasum.
Defaults to the latest non-prerelease; pin --version for release candidates.
Verifies GitHub provenance and SHA-256 before extracting or running the binary.
Does not change shell files, certificate trust, or editor settings.
EOF
    }
    fail() { printf 'withhold installer: %s\n' "$*" >&2; exit 1; }
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --version|--commit|--bin-dir)
                [ "$#" -ge 2 ] && [ -n "$2" ] || fail "$1 requires a value"
                case "$1" in
                    --version) version=$2 ;;
                    --commit) commit=$2 ;;
                    --bin-dir) bin_dir=$2 ;;
                esac
                shift 2 ;;
            -h|--help) usage; exit 0 ;;
            *) fail "unknown option $1; use --help" ;;
        esac
    done
    case "$bin_dir" in /*) ;; *) fail '--bin-dir must be an absolute path' ;; esac
    if [ -n "$commit" ]; then
        [ "${#commit}" -eq 40 ] || fail '--commit must be a full lowercase Git commit SHA'
        case "$commit" in *[!0-9a-f]*) fail '--commit must be a full lowercase Git commit SHA' ;; esac
    fi
    case "$(uname -s)" in
        Darwin) os=darwin ;;
        Linux) os=linux ;;
        *) fail 'only macOS and Linux use this installer; see the Windows guide' ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64) arch=amd64 ;;
        arm64|aarch64) arch=arm64 ;;
        *) fail 'unsupported CPU; use an amd64 or arm64 build' ;;
    esac
    command -v gh >/dev/null 2>&1 || fail 'install GitHub CLI first: https://cli.github.com/'
    command -v tar >/dev/null 2>&1 || fail 'tar is required'
    if command -v sha256sum >/dev/null 2>&1; then
        hash=sha256sum
    elif command -v shasum >/dev/null 2>&1; then
        hash=shasum
    else
        fail 'sha256sum or shasum is required'
    fi
    if [ -z "$version" ]; then
        version=$(gh api "repos/$repo/releases/latest" --jq .tag_name) ||
            fail 'no latest release available; check gh authentication or pin --version vX.Y.Z (including prereleases)'
    fi
    number='(0|[1-9][0-9]*)'
    identifier="($number|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    printf '%s\n' "$version" | grep -Eq "^v$number\.$number\.$number(-$identifier(\.$identifier)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$" ||
        fail '--version must be a v-prefixed SemVer tag (for example v0.1.0-rc.1)'
    # Validate the entire value, including embedded newlines, before using it as a path.
    case "$version" in *[!0-9A-Za-z.+-]*) fail 'invalid version characters' ;; esac
    target=$os-$arch
    archive=withhold-$version-$target.tar.gz
    temporary=$(mktemp -d "${TMPDIR:-/tmp}/withhold-install.XXXXXXXX") || fail 'cannot create a private temporary directory'
    trap 'rm -rf "$temporary"' EXIT
    trap 'exit 1' HUP INT TERM
    printf 'Downloading withhold %s for %s…\n' "$version" "$target"
    gh release download "$version" --repo "$repo" --dir "$temporary" \
        --pattern "$archive" --pattern SHA256SUMS --pattern native-release.sigstore.json ||
        fail 'download failed; no binary was installed'
    for subject in "$archive" SHA256SUMS; do
        if [ -n "$commit" ]; then
            set -- --source-digest "$commit"
        else
            set --
        fi
        gh attestation verify "$temporary/$subject" --repo "$repo" \
            --signer-workflow "$repo/.github/workflows/native-artifacts.yml" \
            --source-ref "refs/tags/$version" --deny-self-hosted-runners \
            --bundle "$temporary/native-release.sigstore.json" "$@" ||
            fail 'provenance verification failed; nothing was extracted or installed (update gh if flags are unsupported)'
    done
    expected=$(awk -v name="$archive" '$2 == name { count++; digest=$1 } END { if (count == 1) print digest }' "$temporary/SHA256SUMS")
    [ "${#expected}" -eq 64 ] || fail 'missing or duplicate archive checksum'
    case "$expected" in *[!0-9a-f]*) fail 'invalid archive checksum' ;; esac
    if [ "$hash" = sha256sum ]; then
        actual=$(sha256sum "$temporary/$archive")
    else
        actual=$(shasum -a 256 "$temporary/$archive")
    fi
    [ "${actual%% *}" = "$expected" ] || fail 'archive checksum mismatch; nothing was installed'
    tar -xzf "$temporary/$archive" -C "$temporary" \
        withhold LICENSE THIRD_PARTY_NOTICES.txt README.md CONTRACTS.md BUILD.json
    # The verified executable enforces the existing running-session upgrade guard.
    "$temporary/withhold" install --bin-dir "$bin_dir"
    docs="$HOME/.local/share/withhold/$version/$target"
    mkdir -p "$docs"
    for file in LICENSE THIRD_PARTY_NOTICES.txt README.md CONTRACTS.md BUILD.json SHA256SUMS native-release.sigstore.json; do
        cp "$temporary/$file" "$docs/$file"
    done
    printf '\nInstalled withhold. Release documentation and verification evidence: %s\n' "$docs"
    case ":${PATH:-}:" in
        *":$bin_dir:"*) ;;
        *) printf 'Add the install directory to PATH (no shell files were edited):\n  export PATH="%s:$PATH"\n' "$bin_dir" ;;
    esac
    printf '\nNext: review local HTTPS inspection, then run:\n  withhold setup\n  withhold doctor\n  withhold on\nOpen VS Code normally. Restart it once after initial certificate setup.\n'
)

# Keep execution last so a truncated bootstrap download cannot start installation.
main "$@"
