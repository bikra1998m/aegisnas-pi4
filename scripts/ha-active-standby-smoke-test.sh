#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_ROOT="/var/tmp/aegisnas-ha-smoke"
ROLE=""
ADMIN_URL="http://127.0.0.1:8083"
STAGE_SHARED=0
ACTIVATE_LATEST=0

usage() {
  cat <<EOF
Usage:
  sudo bash scripts/ha-active-standby-smoke-test.sh --role active|standby [options]

Options:
  --admin-url URL      Admin API base URL. Default: http://127.0.0.1:8083
  --stage-shared       On standby nodes, stage the latest shared HA package.
  --activate-latest    On standby nodes, activate the latest staged HA package after staging checks.
  --help               Show this help text.

This helper captures a local HA smoke-test bundle for active or standby nodes.
It validates health endpoints, saves HA-related admin API responses, and records
service/network state under ${OUTPUT_ROOT}/<timestamp>-<role>/.
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
      --role)
        ROLE="${2:-}"
        shift 2
        ;;
      --admin-url)
        ADMIN_URL="${2:-}"
        shift 2
        ;;
      --stage-shared)
        STAGE_SHARED=1
        shift
        ;;
      --activate-latest)
        ACTIVATE_LATEST=1
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

  case "${ROLE}" in
    active|standby) ;;
    *)
      fail "--role must be active or standby"
      ;;
  esac
}

read_bootstrap_token() {
  awk -F= '/^AEGIS_ADMIN_BOOTSTRAP_TOKEN=/{print $2}' /etc/default/aegisnas | tail -n 1
}

health_probe() {
  local port="$1"
  local target_file="$2"
  curl -fsS "http://127.0.0.1:${port}/health" >"${target_file}"
}

api_get() {
  local path="$1"
  local target_file="$2"
  curl -fsS -H "Authorization: Bearer ${ADMIN_TOKEN}" "${ADMIN_URL}/api/v1${path}" >"${target_file}"
}

api_post_json() {
  local path="$1"
  local body="$2"
  local target_file="$3"
  curl -fsS -X POST \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "${body}" \
    "${ADMIN_URL}/api/v1${path}" >"${target_file}"
}

latest_stage_id() {
  local source_file="$1"
  jq -r '.packages[0].id // ""' "${source_file}"
}

main() {
  require_root
  parse_args "$@"
  require_cmd curl
  require_cmd jq
  require_cmd ip
  require_cmd sqlite3
  require_cmd systemctl

  local timestamp output_dir
  timestamp="$(date '+%Y%m%d-%H%M%S')"
  output_dir="${OUTPUT_ROOT}/${timestamp}-${ROLE}"
  mkdir -p "${output_dir}/health" "${output_dir}/api" "${output_dir}/system"

  ADMIN_TOKEN="$(read_bootstrap_token)"
  [[ -n "${ADMIN_TOKEN}" ]] || fail "could not read AEGIS_ADMIN_BOOTSTRAP_TOKEN from /etc/default/aegisnas"

  log "Capturing local system state into ${output_dir}"
  ip -br addr >"${output_dir}/system/ip-addr.txt"
  ip route >"${output_dir}/system/ip-route.txt"
  systemctl --no-pager --full status \
    aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api \
    dnsmasq freeradius nftables >"${output_dir}/system/service-status.txt" || true
  journalctl -u aegis-gateway -u aegis-admin-api -n 120 --no-pager >"${output_dir}/system/ha-service-journal.txt" || true
  sqlite3 /var/lib/aegisnas/data.db 'SELECT COALESCE(MAX(version), 0) FROM schema_version;' >"${output_dir}/system/schema-version.txt"

  log "Running local health probes"
  health_probe 8080 "${output_dir}/health/gateway-health.json"
  health_probe 8081 "${output_dir}/health/portal-health.json"
  health_probe 8082 "${output_dir}/health/policy-health.json"
  health_probe 8083 "${output_dir}/health/admin-api-health.json"
  health_probe 8085 "${output_dir}/health/radius-health.json"
  health_probe 8087 "${output_dir}/health/session-health.json"

  log "Capturing HA-related admin API data"
  api_get "/system/status" "${output_dir}/api/system-status.json"
  api_get "/system/ha/replication-shared" "${output_dir}/api/ha-replication-shared.json"
  api_get "/system/ha/replication-staged" "${output_dir}/api/ha-replication-staged.json"
  api_get "/system/ha/history" "${output_dir}/api/ha-history.json"
  api_get "/system/network-observability" "${output_dir}/api/network-observability.json"

  if [[ "${STAGE_SHARED}" -eq 1 ]]; then
    if [[ "${ROLE}" != "standby" ]]; then
      fail "--stage-shared is only valid with --role standby"
    fi
    log "Staging latest shared HA replication package on standby"
    api_post_json "/system/ha/replication-stage-shared" '{}' "${output_dir}/api/ha-stage-shared.json"
    api_get "/system/ha/replication-staged" "${output_dir}/api/ha-replication-staged-after-stage.json"
  fi

  if [[ "${ACTIVATE_LATEST}" -eq 1 ]]; then
    if [[ "${ROLE}" != "standby" ]]; then
      fail "--activate-latest is only valid with --role standby"
    fi
    local staged_source stage_id
    staged_source="${output_dir}/api/ha-replication-staged-after-stage.json"
    if [[ ! -f "${staged_source}" ]]; then
      staged_source="${output_dir}/api/ha-replication-staged.json"
    fi
    stage_id="$(latest_stage_id "${staged_source}")"
    [[ -n "${stage_id}" ]] || fail "could not find a staged HA package to activate"
    log "Activating latest staged HA replication package ${stage_id}"
    api_post_json "/system/ha/replication-activate" "{\"id\":\"${stage_id}\"}" "${output_dir}/api/ha-activate-latest.json"
    sleep 2
    api_get "/system/ha/replication-staged" "${output_dir}/api/ha-replication-staged-after-activate.json"
    api_get "/system/status" "${output_dir}/api/system-status-after-activate.json"
  fi

  log "Writing summary"
  jq '{
    generated_at,
    local_role: .high_availability.role,
    effective_role: .high_availability.runtime.details.effective_role,
    vip_assigned: .high_availability.runtime.details.vip_assigned,
    vip_interface: .high_availability.runtime.details.vip_interface,
    virtual_ip: .high_availability.virtual_ip,
    auto_stage_enabled: .high_availability.auto_stage_shared_package,
    auto_stage_status: .high_availability.replication_runtime.details.auto_stage_status,
    auto_stage_stage_id: .high_availability.replication_runtime.details.auto_stage_stage_id,
    auto_activate_enabled: .high_availability.auto_activate_on_failover,
    auto_activate_status: .high_availability.runtime.details.auto_activate_status,
    auto_activate_stage_id: .high_availability.runtime.details.auto_activate_stage_id,
    replication_status: .high_availability.replication_runtime.status,
    replication_message: .high_availability.replication_runtime.message,
    latest_source_node: .high_availability.replication_runtime.details.latest_source_node,
    latest_age_seconds: .high_availability.replication_runtime.details.latest_age_seconds,
    replication_stale: .high_availability.replication_runtime.details.stale,
    history_stats: .high_availability.history_stats
  }' "${output_dir}/api/system-status.json" >"${output_dir}/summary.json"

  cat >"${output_dir}/next-steps.txt" <<EOF
HA smoke test captured for ${ROLE}.

Output directory:
  ${output_dir}

Recommended manual follow-up:
  1. Review summary.json and confirm the effective role is expected.
  2. If this is the active node, confirm ha-replication-shared.json shows a present package.
  3. If this is the standby node, confirm the shared package is fresh.
  4. If auto-stage is enabled, confirm summary.json shows the expected auto_stage_status.
  5. If you staged a shared package, review ha-replication-staged-after-stage.json.
  6. If you activated the latest package, review ha-activate-latest.json and system-status-after-activate.json.
  7. Follow docs/ha-active-standby-runbook.md for failover drills and auto-activation expectations.
EOF

  log "HA smoke test completed. Review ${output_dir}/summary.json"
}

main "$@"
