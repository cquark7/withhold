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
    fetch() (
        label=$1; shift
        printf '%s…\n' "$label" >&2
        progress=--silent
        if [ -t 2 ]; then progress=--progress-bar; fi
        # curl shares the connection budget across resolved addresses, so a
        # stalled address does not consume the default multi-minute timeout.
        # Always write to a file: curl can then discard partial data on retry.
        if response=$(curl "$progress" --show-error --fail --fail-early --location \
            --proto '=https' --proto-redir '=https' \
            --connect-timeout 10 --max-time 600 \
            --retry 2 --retry-max-time 60 \
            --speed-limit 1024 --speed-time 30 \
            --write-out '%{http_code} %{url_effective}\n' "$@"); then
            printf '%s' "$response"
            return 0
        else
            status=$?
        fi
        http=$(printf '%s\n' "$response" | awk 'END { print $1 }')
        case "$status" in
            5|6) fail "$label: DNS lookup failed; check your connection and proxy settings; nothing was installed" ;;
            7) fail "$label: connection failed; check your connection and proxy settings; nothing was installed" ;;
            28) fail "$label: connection or download timed out after limited retries; check your connection and try again; nothing was installed" ;;
            22)
                case "$http" in
                    404) fail "$label: release file not found (HTTP 404); check the version and that the release includes standalone binaries; nothing was installed" ;;
                    429) fail "$label: GitHub rate limit reached (HTTP 429); try again later; nothing was installed" ;;
                    *) fail "$label: server returned HTTP $http after limited retries; try again later; nothing was installed" ;;
                esac ;;
            35|51|60) fail "$label: HTTPS verification or TLS handshake failed; check your CA and proxy configuration; nothing was installed" ;;
            23) fail "$label: cannot write the download; check free space and permissions; nothing was installed" ;;
            *) fail "$label: download failed (curl exit $status); nothing was installed" ;;
        esac
    )
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
    temporary=$(mktemp -d "${TMPDIR:-/tmp}/withhold-install.XXXXXXXX") || fail 'cannot create a private temporary directory'
    trap 'rm -rf "$temporary"' EXIT
    trap 'exit 1' HUP INT TERM
    if [ -z "$version" ]; then
        latest=$(fetch 'Finding latest release' --head --output /dev/null "https://github.com/$repo/releases/latest") || exit 1
        latest=${latest#* }
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
    base="https://github.com/$repo/releases/download/$version"
    # One curl process reuses connections across files and release redirects.
    set -- --output "$temporary/$binary" "$base/$binary" \
        --output "$temporary/$notices" "$base/$notices" \
        --output "$temporary/SHA256SUMS" "$base/SHA256SUMS"
    if [ "$provenance" = true ]; then
        set -- "$@" --output "$temporary/native-release.sigstore.json" "$base/native-release.sigstore.json"
    fi
    fetch "Downloading withhold $version for $target" "$@" >/dev/null || exit 1
    if [ "$provenance" = true ]; then
        printf 'Verifying signed provenance…\n' >&2
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
    printf 'Verifying SHA-256 checksums…\n' >&2
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
    printf 'Installing to %s/withhold…\n' "$bin_dir" >&2
    "$temporary/$binary" install --bin-dir "$bin_dir"
    docs="$HOME/.local/share/withhold/$version/$target"
    mkdir -p "$docs"
    for file in "$notices" SHA256SUMS; do
        cp "$temporary/$file" "$docs/$file"
    done
    if [ "$provenance" = true ]; then
        cp "$temporary/native-release.sigstore.json" "$docs/native-release.sigstore.json"
    fi
    printf '\nInstalled withhold to %s/withhold.\nRelease documentation and verification evidence: %s\n' "$bin_dir" "$docs"
    case ":${PATH:-}:" in
        *":$bin_dir:"*) ;;
        *) printf 'Add the install directory to PATH (no shell files were edited):\n  export PATH="%s:$PATH"\n' "$bin_dir" ;;
    esac
    printf '\nNext: review local HTTPS inspection, then run:\n  withhold setup\n  withhold doctor\n  withhold on\nOpen VS Code normally. Restart it once after initial certificate setup.\n'
)

# Keep execution last so a truncated bootstrap download cannot start installation.
main "$@"
