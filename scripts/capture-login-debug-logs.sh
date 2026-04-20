#!/usr/bin/env bash

set -euo pipefail

OUTPUT_ROOT="/var/tmp/aegisnas-login-debug"
SINCE="30 minutes ago"
SCENARIO="manual"

usage() {
  cat <<'EOF'
Usage:
  sudo bash scripts/capture-login-debug-logs.sh [--output DIR] [--since WINDOW] [--scenario NAME]

Examples:
  sudo bash scripts/capture-login-debug-logs.sh --scenario prelogin-baseline
  sudo bash scripts/capture-login-debug-logs.sh --scenario portal-local-failure --since "10 minutes ago"

This script captures separate files for appliance login-path debugging and R&D:
  - service logs from systemd journal
  - health endpoint output
  - network state
  - redacted config snapshots
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      OUTPUT_ROOT="$2"
      shift 2
      ;;
    --since)
      SINCE="$2"
      shift 2
      ;;
    --scenario)
      SCENARIO="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

umask 077

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
HOSTNAME_SHORT="$(hostname -s 2>/dev/null || hostname)"
OUT_DIR="${OUTPUT_ROOT%/}/${TIMESTAMP}-${SCENARIO}"

mkdir -p \
  "$OUT_DIR/summary" \
  "$OUT_DIR/network" \
  "$OUT_DIR/logs" \
  "$OUT_DIR/state"

run_capture() {
  local outfile="$1"
  shift
  if "$@" >"$outfile" 2>&1; then
    :
  else
    printf 'command failed: %q\n' "$*" >>"$outfile"
  fi
}

capture_service_log() {
  local unit="$1"
  run_capture "$OUT_DIR/logs/${unit}.log" journalctl -u "$unit" --since "$SINCE" --no-pager
}

redact_stream() {
  sed -E \
    -e 's/(AEGIS_ADMIN_BOOTSTRAP_TOKEN=).*/\1[REDACTED]/' \
    -e 's/^([[:space:]]*bind_password:[[:space:]]*).*/\1[REDACTED]/' \
    -e 's/^([[:space:]]*password:[[:space:]]*).*/\1[REDACTED]/' \
    -e 's/^([[:space:]]*shared_secret:[[:space:]]*).*/\1[REDACTED]/' \
    -e 's/^([[:space:]]*secret:[[:space:]]*).*/\1[REDACTED]/' \
    -e 's/^([[:space:]]*token:[[:space:]]*).*/\1[REDACTED]/'
}

capture_redacted_file() {
  local src="$1"
  local dst="$2"
  if [[ -r "$src" ]]; then
    redact_stream <"$src" >"$dst"
  else
    printf 'unavailable: %s\n' "$src" >"$dst"
  fi
}

capture_health() {
  local port="$1"
  local outfile="$OUT_DIR/summary/health-${port}.txt"
  if curl -sS -m 5 -w '\nhttp_status=%{http_code}\n' "http://127.0.0.1:${port}/health" >"$outfile" 2>&1; then
    :
  else
    printf 'health probe failed for port %s\n' "$port" >>"$outfile"
  fi
}

cat >"$OUT_DIR/summary/metadata.txt" <<EOF
captured_at_utc=${TIMESTAMP}
scenario=${SCENARIO}
since=${SINCE}
hostname=${HOSTNAME_SHORT}
collector=$(whoami)
repo_hint=aegisnas-pi4
EOF

run_capture "$OUT_DIR/summary/systemctl-status.txt" \
  systemctl --no-pager --full status \
  aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy \
  aegis-admin-api dnsmasq freeradius nftables hostapd

run_capture "$OUT_DIR/summary/failed-units.txt" systemctl --failed --no-pager

for port in 8080 8081 8082 8083 8085 8087; do
  capture_health "$port"
done

run_capture "$OUT_DIR/network/ip-br-addr.txt" ip -br addr
run_capture "$OUT_DIR/network/ip-route.txt" ip route
run_capture "$OUT_DIR/network/ip-rule.txt" ip rule
run_capture "$OUT_DIR/network/ss-ltnup.txt" ss -ltnup
run_capture "$OUT_DIR/network/nft-list-ruleset.txt" nft list ruleset
run_capture "$OUT_DIR/network/resolvectl-status.txt" resolvectl status

capture_redacted_file "/etc/aegisnas/config.yaml" "$OUT_DIR/state/config.yaml.redacted"
capture_redacted_file "/etc/default/aegisnas" "$OUT_DIR/state/aegisnas.env.redacted"

run_capture "$OUT_DIR/state/dnsmasq.leases.txt" cat /var/lib/misc/dnsmasq.leases
run_capture "$OUT_DIR/state/systemd-unit-files.txt" systemctl list-unit-files --type=service

for unit in \
  aegis-admin-api \
  aegis-gateway \
  aegis-portal \
  aegis-policy \
  aegis-radius \
  aegis-session \
  dnsmasq \
  freeradius \
  nftables \
  hostapd
do
  capture_service_log "$unit"
done

printf 'Log bundle written to %s\n' "$OUT_DIR"
