#!/bin/bash
# Manual destination-IP blocking for disposable development environments.
# Requires elevated privileges. These rules also match the local proxy's own
# upstream connections: this is NOT proof of routing or redaction coverage.
# DNS snapshots omit rotating hosts and hostname families; shared IPs can affect
# unrelated services. macOS requires this anchor in the active PF ruleset.
#
# Usage:
#   bash tools/proof/block_direct.sh status
#   sudo bash tools/proof/block_direct.sh macos-on
#   sudo bash tools/proof/block_direct.sh macos-off
#   sudo bash tools/proof/block_direct.sh linux-on
#   sudo bash tools/proof/block_direct.sh linux-off
#
# Always run the matching -off command after testing. Keep the state file until
# cleanup succeeds. Unit tests stub firewall commands; they do not validate OS
# firewall integration. The product's hostname scope is defined in CONTRACTS.md.
set -euo pipefail
HOSTS="api.githubcopilot.com origin-tracker.githubusercontent.com api.enterprise.githubcopilot.com proxy.enterprise.githubcopilot.com telemetry.enterprise.githubcopilot.com embeddings.vscode-cdn.net"
ANCHOR="withhold-proof"
STATE="${WITHHOLD_STATE:-${TMPDIR:-/tmp}/withhold-block-direct.state}"

resolve_ips() {
  for h in $HOSTS; do
    dig +short A "$h" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true
    dig +short AAAA "$h" 2>/dev/null | grep -E '^([0-9A-Fa-f]{0,4}:){1,7}[0-9A-Fa-f]{0,4}$' || true
  done | sort -u
}

strict_ips() {
  # Refuse an incomplete DNS snapshot unless explicitly requested.
  local missing=""
  for h in $HOSTS; do
    if [ -z "$(dig +short A "$h" 2>/dev/null; dig +short AAAA "$h" 2>/dev/null)" ]; then
      missing="$missing $h"
    fi
  done
  if [ -n "$missing" ] && [ "${ALLOW_PARTIAL:-0}" != "1" ]; then
    echo "[block] ABORT: unresolved hosts ($missing ); the block would be incomplete" >&2
    echo "[block] (ALLOW_PARTIAL=1 to override for offline testing)" >&2
    exit 1
  fi
  resolve_ips
}

pf_enabled() {
  pfctl -q -s info 2>/dev/null | grep -q "Status: Enabled"
}

firewall_for() {
  case "$1" in *:*) echo ip6tables ;; *) echo iptables ;; esac
}

case "${1:-status}" in
  -h|--help)
    echo "usage: $0 {status|macos-on|macos-off|linux-on|linux-off}"
    echo "Manual IP blocking also affects the local proxy; it does not prove coverage."
    ;;
  status)
    echo "[block] hosts: $HOSTS"
    echo "[block] resolved IPs (A+AAAA):"
    resolve_ips | sed 's/^/  /'
    echo "[block] state file: $STATE $([ -f "$STATE" ] && echo '(recorded state; inspect firewall rules)' || echo '(absent)')"
    echo "[block] WARNING: these rules also block proxy upstream traffic; they do not prove coverage."
    ;;
  macos-on)
    [ ! -e "$STATE" ] || { echo "[block] state exists; run macos-off first" >&2; exit 1; }
    IPS=$(strict_ips)
    [ -z "$IPS" ] && { echo "[block] no IPs resolved; aborting"; exit 1; }
    if pf_enabled; then PF_WAS=enabled; else PF_WAS=disabled; fi
    RULES=$(for ip in $IPS; do echo "block drop quick from any to $ip"; done)
    umask 077
    printf 'pf_was=%s\n' "$PF_WAS" > "$STATE"
    for ip in $IPS; do echo "$ip" >> "$STATE"; done
    echo "$RULES" | pfctl -a "$ANCHOR" -f - 2>&1
    if [ "$PF_WAS" = disabled ]; then pfctl -e 2>&1; fi
    echo "[block] pf anchor $ANCHOR applied ($PF_WAS pf state recorded):"
    echo "$RULES"
    echo "[block] check that the anchor is referenced by the active PF ruleset."
    echo "[block] inspect: pfctl -a $ANCHOR -s rules ; remove: sudo bash $0 macos-off"
    ;;
  macos-off)
    PF_WAS=$(head -1 "$STATE" 2>/dev/null | sed 's/^pf_was=//' || echo unknown)
    pfctl -a "$ANCHOR" -F rules 2>&1
    # Leave an already-enabled PF instance enabled.
    if [ "$PF_WAS" = disabled ]; then pfctl -d 2>&1; fi
    rm -f "$STATE"
    echo "[block] pf anchor $ANCHOR flushed; state removed"
    ;;
  linux-on)
    [ ! -e "$STATE" ] || { echo "[block] state exists; run linux-off first" >&2; exit 1; }
    command -v iptables >/dev/null
    command -v ip6tables >/dev/null
    IPS=$(strict_ips)
    [ -z "$IPS" ] && { echo "[block] no IPs resolved; aborting"; exit 1; }
    umask 077
    printf 'pf_was=na\n' > "$STATE"
    for ip in $IPS; do
      echo "$ip" >> "$STATE"
      firewall=$(firewall_for "$ip")
      "$firewall" -C OUTPUT -d "$ip" -j DROP -m comment --comment "$ANCHOR" 2>/dev/null \
        || "$firewall" -A OUTPUT -d "$ip" -j DROP -m comment --comment "$ANCHOR"
    done
    echo "[block] IPv4/IPv6 DROP rules applied for: $IPS"
    echo "[block] inspect iptables and ip6tables OUTPUT rules; remove: sudo bash $0 linux-off"
    ;;
  linux-off)
    # Remove recorded destinations first so DNS changes cannot hide them.
    command -v iptables >/dev/null
    command -v ip6tables >/dev/null
    if [ -f "$STATE" ]; then
      for ip in $(tail -n +2 "$STATE"); do
        firewall=$(firewall_for "$ip")
        "$firewall" -D OUTPUT -d "$ip" -j DROP -m comment --comment "$ANCHOR" 2>/dev/null || true
      done
    fi
    for firewall in iptables ip6tables; do
      # Listing failures must not be mistaken for an empty ruleset.
      rules=$("$firewall" -S OUTPUT)
      while echo "$rules" | grep -q -- "$ANCHOR"; do
        deleted=0
        for ip in $(resolve_ips); do
          [ "$(firewall_for "$ip")" = "$firewall" ] || continue
          if "$firewall" -D OUTPUT -d "$ip" -j DROP -m comment --comment "$ANCHOR" 2>/dev/null; then
            deleted=1
          fi
        done
        if [ "$deleted" = 0 ]; then
          echo "[block] helper rules remain; inspect $firewall -S OUTPUT. State retained." >&2
          exit 1
        fi
        rules=$("$firewall" -S OUTPUT)
      done
    done
    rm -f "$STATE"
    echo "[block] IPv4/IPv6 rules with comment $ANCHOR removed"
    ;;
  *)
    echo "usage: $0 {status|macos-on|macos-off|linux-on|linux-off}" >&2; exit 2;;
esac
