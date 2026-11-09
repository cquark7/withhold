#!/bin/sh
# Download and verify withhold. Trust setup and editor changes are separate commands.
set -eu

main() (
    repo=cquark7/withhold
    version=
    commit=
    provenance=false
    bin_dir=${HOME:?HOME must be set}/.local/bin
    usage() {
        cat <<'EOF'
Install withhold on macOS or Linux (no sudo).
Usage: sh install.sh [--version vX.Y.Z] [--bin-dir DIR] [--verify-provenance] [--commit FULL_SHA]

Requires curl and sha256sum or shasum. GitHub CLI is optional for provenance.
Defaults to the latest non-prerelease; pin --version for release candidates.
Checks SHA-256 before running the binary; checksums alone do not prove origin.
--verify-provenance also checks the signed release record using GitHub CLI.
--commit FULL_SHA implies --verify-provenance and pins the source commit.
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
            --verify-provenance) provenance=true; shift ;;
            -h|--help) usage; exit 0 ;;
            *) fail "unknown option $1; use --help" ;;
        esac
    done
    case "$bin_dir" in /*) ;; *) fail '--bin-dir must be an absolute path' ;; esac
    if [ -n "$commit" ]; then
        [ "${#commit}" -eq 40 ] || fail '--commit must be a full lowercase Git commit SHA'
        case "$commit" in *[!0-9a-f]*) fail '--commit must be a full lowercase Git commit SHA' ;; esac
        provenance=true
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
    command -v curl >/dev/null 2>&1 || fail 'curl is required'
    if [ "$provenance" = true ]; then
        command -v gh >/dev/null 2>&1 || fail 'provenance verification requires GitHub CLI: https://cli.github.com/'
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        hash=sha256sum
    elif command -v shasum >/dev/null 2>&1; then
        hash=shasum
    else
        fail 'sha256sum or shasum is required'
    fi
    if [ -z "$version" ]; then
        latest=$(curl -fsSL --proto '=https' --proto-redir '=https' -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest") ||
            fail 'no latest release available; check your connection or pin --version vX.Y.Z'
        case "$latest" in
            "https://github.com/$repo/releases/tag/"*)
                version=${latest#"https://github.com/$repo/releases/tag/"}
                # GitHub may percent-encode the SemVer build metadata separator.
                version=$(printf '%s' "$version" | sed 's/%2[Bb]/+/g') ;;
            *) fail 'unexpected latest release URL; pin --version vX.Y.Z' ;;
        esac
    fi
    [ "${#version}" -le 128 ] || fail 'version exceeds 128 characters'
    number='(0|[1-9][0-9]*)'
    identifier="($number|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    printf '%s\n' "$version" | grep -Eq "^v$number\.$number\.$number(-$identifier(\.$identifier)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$" ||
        fail '--version must be a v-prefixed SemVer tag (for example v0.1.0-rc.1)'
    # Validate the entire value, including embedded newlines, before using it as a path.
    case "$version" in *[!0-9A-Za-z.+-]*) fail 'invalid version characters' ;; esac
    target=$os-$arch
    binary=withhold-$version-$target
    notices=withhold-$version-$target-NOTICES.txt
    temporary=$(mktemp -d "${TMPDIR:-/tmp}/withhold-install.XXXXXXXX") || fail 'cannot create a private temporary directory'
    trap 'rm -rf "$temporary"' EXIT
    trap 'exit 1' HUP INT TERM
    printf 'Downloading withhold %s for %s…\n' "$version" "$target"
    base="https://github.com/$repo/releases/download/$version"
    for subject in "$binary" "$notices" SHA256SUMS; do
        curl -fsSL --proto '=https' --proto-redir '=https' -o "$temporary/$subject" "$base/$subject" ||
            fail 'download failed; this installer requires a release with standalone binaries'
    done
    if [ "$provenance" = true ]; then
        curl -fsSL --proto '=https' --proto-redir '=https' -o "$temporary/native-release.sigstore.json" "$base/native-release.sigstore.json" ||
            fail 'provenance download failed; nothing was installed'
        for subject in "$binary" "$notices" SHA256SUMS; do
            if [ -n "$commit" ]; then
                set -- --source-digest "$commit"
            else
                set --
            fi
            gh attestation verify "$temporary/$subject" --repo "$repo" \
                --signer-workflow "$repo/.github/workflows/native-artifacts.yml" \
                --source-ref "refs/tags/$version" --deny-self-hosted-runners \
                --bundle "$temporary/native-release.sigstore.json" "$@" ||
                fail 'provenance verification failed; nothing was installed (update gh if flags are unsupported)'
        done
    else
        printf 'Checking SHA-256 checksums; these do not verify the publisher.\n'
    fi
    for subject in "$binary" "$notices"; do
        expected=$(awk -v name="$subject" '$2 == name { count++; digest=$1 } END { if (count == 1) print digest }' "$temporary/SHA256SUMS")
        [ "${#expected}" -eq 64 ] || fail "missing or duplicate checksum for $subject"
        case "$expected" in *[!0-9a-f]*) fail "invalid checksum for $subject" ;; esac
        if [ "$hash" = sha256sum ]; then
            actual=$(sha256sum < "$temporary/$subject")
        else
            actual=$(shasum -a 256 < "$temporary/$subject")
        fi
        [ "${actual%% *}" = "$expected" ] || fail "checksum mismatch for $subject; nothing was installed"
    done
    chmod 700 "$temporary/$binary"
    # The executable enforces the existing running-session upgrade guard.
    "$temporary/$binary" install --bin-dir "$bin_dir"
    docs="$HOME/.local/share/withhold/$version/$target"
    mkdir -p "$docs"
    for file in "$notices" SHA256SUMS; do
        cp "$temporary/$file" "$docs/$file"
    done
    if [ "$provenance" = true ]; then
        cp "$temporary/native-release.sigstore.json" "$docs/native-release.sigstore.json"
    fi
    printf '\nInstalled withhold. Release documentation and verification evidence: %s\n' "$docs"
    case ":${PATH:-}:" in
        *":$bin_dir:"*) ;;
        *) printf 'Add the install directory to PATH (no shell files were edited):\n  export PATH="%s:$PATH"\n' "$bin_dir" ;;
    esac
    printf '\nNext: review local HTTPS inspection, then run:\n  withhold setup\n  withhold doctor\n  withhold on\nOpen VS Code normally. Restart it once after initial certificate setup.\n'
)

# Keep execution last so a truncated bootstrap download cannot start installation.
main "$@"
