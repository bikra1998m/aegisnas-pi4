#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_ROOT="/var/tmp/aegisnas-upgrade-smoke"
WITH_PACKAGES=0
WITH_NETPLAN=0
PROFILE=""
WAN_IFACE=""
LAN_IFACE=""

usage() {
  cat <<EOF
Usage:
  sudo bash scripts/ubuntu-vm-upgrade-smoke-test.sh --wan IFACE --lan IFACE [options]

Options:
  --profile NAME        Optional deployment profile to pass to bootstrap.
  --with-packages       Allow bootstrap to run package installation.
  --with-netplan        Allow bootstrap to rewrite netplan.
  --help                Show this help text.

This script is intended for in-place Ubuntu VM upgrades from an existing
AegisNAS clone. It preserves the current appliance config because it does not
pass --force-config to the bootstrap script.
EOF
}

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fail "run this script with sudo or as root"
  fi
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --wan)
        WAN_IFACE="${2:-}"
        shift 2
        ;;
      --lan)
        LAN_IFACE="${2:-}"
        shift 2
        ;;
      --profile)
        PROFILE="${2:-}"
        shift 2
        ;;
      --with-packages)
        WITH_PACKAGES=1
        shift
        ;;
      --with-netplan)
        WITH_NETPLAN=1
        shift
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        fail "unknown option: $1"
        ;;
    esac
  done

  [[ -n "${WAN_IFACE}" ]] || fail "--wan is required"
  [[ -n "${LAN_IFACE}" ]] || fail "--lan is required"
}

expected_schema_version() {
  sed -nE 's/^[[:space:]]*\{([0-9]+), schemaV[0-9]+\},/\1/p' "${REPO_ROOT}/internal/db/migrate.go" | tail -n 1
}

current_schema_version() {
  sqlite3 /var/lib/aegisnas/data.db 'SELECT COALESCE(MAX(version), 0) FROM schema_version;'
}

read_bootstrap_token() {
  awk -F= '/^AEGIS_ADMIN_BOOTSTRAP_TOKEN=/{print $2}' /etc/default/aegisnas | tail -n 1
}

backup_file() {
  local source="$1"
  local target_dir="$2"
  if [[ -f "${source}" ]]; then
    cp "${source}" "${target_dir}/$(basename "${source}")"
  fi
}

health_probe() {
  local port="$1"
  local target_file="$2"
  curl -fsS "http://127.0.0.1:${port}/health" >"${target_file}"
}

main() {
  require_root
  parse_args "$@"
  require_cmd bash
  require_cmd curl
  require_cmd git
  require_cmd jq
  require_cmd sqlite3
  require_cmd systemctl

  local timestamp output_dir backup_dir expected_schema current_schema admin_token
  timestamp="$(date '+%Y%m%d-%H%M%S')"
  output_dir="${OUTPUT_ROOT}/${timestamp}"
  backup_dir="${output_dir}/backups"
  mkdir -p "${backup_dir}" "${output_dir}/health" "${output_dir}/api"

  log "Capturing pre-upgrade backups into ${backup_dir}"
  backup_file /etc/aegisnas/config.yaml "${backup_dir}"
  backup_file /etc/default/aegisnas "${backup_dir}"
  backup_file /var/lib/aegisnas/data.db "${backup_dir}"

  log "Recording repo and system context"
  git -C "${REPO_ROOT}" rev-parse HEAD >"${output_dir}/git-head.txt"
  git -C "${REPO_ROOT}" status --short >"${output_dir}/git-status.txt" || true
  ip -br addr >"${output_dir}/ip-addr.txt"
  systemctl --no-pager --full status \
    aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api \
    dnsmasq freeradius nftables >"${output_dir}/service-status-before.txt" || true

  log "Running in-place bootstrap"
  bootstrap_args=(--wan "${WAN_IFACE}" --lan "${LAN_IFACE}")
  if [[ -n "${PROFILE}" ]]; then
    bootstrap_args+=(--profile "${PROFILE}")
  fi
  if [[ "${WITH_PACKAGES}" -eq 0 ]]; then
    bootstrap_args+=(--skip-packages)
  fi
  if [[ "${WITH_NETPLAN}" -eq 0 ]]; then
    bootstrap_args+=(--skip-netplan)
  fi
  bash "${REPO_ROOT}/scripts/ubuntu-vm-bootstrap.sh" "${bootstrap_args[@]}"

  log "Collecting post-upgrade service status"
  systemctl --no-pager --full status \
    aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api \
    dnsmasq freeradius nftables >"${output_dir}/service-status-after.txt"

  log "Checking schema version"
  expected_schema="$(expected_schema_version)"
  current_schema="$(current_schema_version)"
  printf 'expected_schema=%s\ncurrent_schema=%s\n' "${expected_schema}" "${current_schema}" >"${output_dir}/schema-version.txt"
  if [[ -z "${expected_schema}" || -z "${current_schema}" ]]; then
    fail "could not determine schema version"
  fi
  if (( current_schema < expected_schema )); then
    fail "database schema version ${current_schema} is behind expected version ${expected_schema}"
  fi

  log "Running health probes"
  health_probe 8080 "${output_dir}/health/gateway-health.json"
  health_probe 8081 "${output_dir}/health/portal-health.json"
  health_probe 8082 "${output_dir}/health/policy-health.json"
  health_probe 8083 "${output_dir}/health/admin-api-health.json"
  health_probe 8085 "${output_dir}/health/radius-health.json"
  health_probe 8087 "${output_dir}/health/session-health.json"

  admin_token="$(read_bootstrap_token)"
  [[ -n "${admin_token}" ]] || fail "could not read AEGIS_ADMIN_BOOTSTRAP_TOKEN from /etc/default/aegisnas"

  log "Calling authenticated admin APIs"
  curl -fsS -H "Authorization: Bearer ${admin_token}" \
    http://127.0.0.1:8083/api/v1/system/network-preview \
    >"${output_dir}/api/network-preview.json"
  curl -fsS -H "Authorization: Bearer ${admin_token}" \
    http://127.0.0.1:8083/api/v1/system/network-backups \
    >"${output_dir}/api/network-backups.json"
  curl -fsS -H "Authorization: Bearer ${admin_token}" \
    http://127.0.0.1:8083/api/v1/system/network-apply-history \
    >"${output_dir}/api/network-apply-history.json"
  curl -fsS -H "Authorization: Bearer ${admin_token}" \
    http://127.0.0.1:8083/api/v1/system/dhcp-lease-history \
    >"${output_dir}/api/dhcp-lease-history.json"

  jq '{requires_confirmation: .risk.requires_confirmation, summary: .risk.summary, items: .risk.items}' \
    "${output_dir}/api/network-preview.json" >"${output_dir}/api/network-preview-risk-summary.json"
  jq '{count: .count}' "${output_dir}/api/network-backups.json" >"${output_dir}/api/network-backups-summary.json"
  jq '{count: .count}' "${output_dir}/api/network-apply-history.json" >"${output_dir}/api/network-apply-history-summary.json"
  jq '{count: .count}' "${output_dir}/api/dhcp-lease-history.json" >"${output_dir}/api/dhcp-lease-history-summary.json"

  cat >"${output_dir}/next-steps.txt" <<EOF
Upgrade and smoke test completed.

Output directory:
  ${output_dir}

Next recommended manual checks:
  1. Sign in to the admin UI.
  2. Open Access Settings.
  3. Run Preview Edge Network.
  4. Confirm the risk panel, rollback list, lease history, and apply history load.
  5. Run the lab drills in docs/edge-network-operations.md.
EOF

  log "Upgrade smoke test completed. Review ${output_dir}/next-steps.txt"
}

main "$@"
