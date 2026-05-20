#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ADMIN_BIN="${AEGIS_ADMIN_BIN:-/opt/aegisnas/bin/aegis-admin}"
CONFIG_PATH="/etc/aegisnas/config.yaml"
PACKAGE_PATH=""
OUTPUT_DIR=""
APPLY_RESTORE=0
FORCE_OFFLINE=0
CONFIRMATION_TEXT=""
EXPECTED_CONFIRMATION="APPLY OFFLINE ROLLBACK"

usage() {
  cat <<EOF
Usage:
  sudo bash scripts/ubuntu-upgrade-rollback-restore.sh --package PACKAGE.zip [options]

Options:
  --output-dir DIR     Workspace for inspection, extraction, and live backups.
  --apply              Apply the extracted rollback package onto this node.
  --force-offline      Allow offline restore even when online restore is supported.
  --confirm TEXT       Required with --apply. Must equal: ${EXPECTED_CONFIRMATION}
  --config PATH        Appliance config path. Default: ${CONFIG_PATH}
  --admin-bin PATH     aegis-admin binary path. Default: ${ADMIN_BIN}
  --help               Show this help text.

Without --apply, the script only inspects and extracts the rollback package and
prints the next steps. With --apply, it stops the local AegisNAS services,
backs up the current config/database, installs the extracted payload, and
restarts services.
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
      --package)
        PACKAGE_PATH="${2:-}"
        shift 2
        ;;
      --output-dir)
        OUTPUT_DIR="${2:-}"
        shift 2
        ;;
      --apply)
        APPLY_RESTORE=1
        shift
        ;;
      --force-offline)
        FORCE_OFFLINE=1
        shift
        ;;
      --confirm)
        CONFIRMATION_TEXT="${2:-}"
        shift 2
        ;;
      --config)
        CONFIG_PATH="${2:-}"
        shift 2
        ;;
      --admin-bin)
        ADMIN_BIN="${2:-}"
        shift 2
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

  [[ -n "${PACKAGE_PATH}" ]] || fail "--package is required"
  [[ -f "${PACKAGE_PATH}" ]] || fail "rollback package not found: ${PACKAGE_PATH}"

  if [[ -z "${OUTPUT_DIR}" ]]; then
    OUTPUT_DIR="/var/tmp/aegisnas-upgrade-rollback/$(date '+%Y%m%d-%H%M%S')"
  fi
  mkdir -p "${OUTPUT_DIR}"

  if [[ "${APPLY_RESTORE}" -eq 1 && "${CONFIRMATION_TEXT}" != "${EXPECTED_CONFIRMATION}" ]]; then
    fail "--confirm must exactly equal: ${EXPECTED_CONFIRMATION}"
  fi
}

capture_current_state() {
  "${ADMIN_BIN}" upgrade-readiness --config "${CONFIG_PATH}" --json >"${OUTPUT_DIR}/current-readiness.json"
}

inspect_package() {
  "${ADMIN_BIN}" inspect-upgrade-rollback-package --config "${CONFIG_PATH}" --input "${PACKAGE_PATH}" >"${OUTPUT_DIR}/inspection.json"
}

extract_package() {
  "${ADMIN_BIN}" extract-upgrade-rollback-package --input "${PACKAGE_PATH}" --output-dir "${OUTPUT_DIR}/extracted" >"${OUTPUT_DIR}/extraction.json"
}

backup_if_exists() {
  local source="$1"
  local destination_dir="$2"
  if [[ -f "${source}" ]]; then
    mkdir -p "${destination_dir}"
    cp "${source}" "${destination_dir}/$(basename "${source}")"
  fi
}

service_health_check() {
  local port="$1"
  local name="$2"
  local attempts=15

  for ((i=1; i<=attempts; i++)); do
    if curl -fsS "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
      log "Health check passed for ${name} on port ${port}"
      return 0
    fi
    sleep 2
  done

  fail "health check failed for ${name} on port ${port}"
}

stop_services() {
  systemctl stop aegis-admin-api aegis-portal aegis-session aegis-policy aegis-radius aegis-gateway aegis-telemetry dnsmasq freeradius nftables || true
}

start_services() {
  systemctl start nftables dnsmasq freeradius aegis-radius aegis-gateway aegis-policy aegis-portal aegis-session aegis-admin-api aegis-telemetry
}

write_plan() {
  cat >"${OUTPUT_DIR}/next-steps.txt" <<EOF
Rollback package inspection complete.

Workspace:
  ${OUTPUT_DIR}

Files:
  inspection.json
  current-readiness.json
  extraction.json
  extracted/

Next steps:
  1. Review inspection.json for warnings and compatibility status.
  2. Review extracted/config/system-settings.json and extracted/config/config.yaml.
  3. If offline restore is appropriate, rerun this script with:
       --apply --confirm "${EXPECTED_CONFIRMATION}"
EOF
}

apply_restore() {
  local online_supported current_db_path restored_db_path backup_dir
  online_supported="$(jq -r '.online_restore_supported' "${OUTPUT_DIR}/inspection.json")"
  if [[ "${online_supported}" == "true" && "${FORCE_OFFLINE}" -ne 1 ]]; then
    fail "inspection says online restore is supported; use the guided online restore path unless you also pass --force-offline"
  fi

  current_db_path="$(jq -r '.database_path // empty' "${OUTPUT_DIR}/current-readiness.json")"
  restored_db_path="$(jq -r '.database.path // empty' "${OUTPUT_DIR}/extracted/config/system-settings.json")"
  [[ -n "${restored_db_path}" ]] || fail "could not determine restored database path from extracted settings snapshot"

  log "Validating extracted config"
  "${ADMIN_BIN}" validate-config --config "${OUTPUT_DIR}/extracted/config/config.yaml" >/dev/null

  backup_dir="${OUTPUT_DIR}/live-backups"
  mkdir -p "${backup_dir}"

  log "Capturing live backups in ${backup_dir}"
  backup_if_exists "${CONFIG_PATH}" "${backup_dir}"
  if [[ -n "${current_db_path}" ]]; then
    backup_if_exists "${current_db_path}" "${backup_dir}"
  fi
  if [[ "${restored_db_path}" != "${current_db_path}" ]]; then
    backup_if_exists "${restored_db_path}" "${backup_dir}"
  fi

  log "Stopping local AegisNAS services"
  stop_services

  log "Installing restored config and database"
  install -m 600 "${OUTPUT_DIR}/extracted/config/config.yaml" "${CONFIG_PATH}"
  mkdir -p "$(dirname "${restored_db_path}")"
  install -m 600 "${OUTPUT_DIR}/extracted/database/data.db" "${restored_db_path}"

  log "Starting services again"
  start_services

  log "Running post-restore health checks"
  service_health_check 8080 "gateway"
  service_health_check 8083 "admin-api"
  service_health_check 8085 "radius"

  cat >"${OUTPUT_DIR}/restore-summary.txt" <<EOF
Offline rollback restore applied successfully.

Restored config path:
  ${CONFIG_PATH}

Restored database path:
  ${restored_db_path}

Live backups:
  ${backup_dir}
EOF
}

main() {
  require_root
  parse_args "$@"
  require_cmd "${ADMIN_BIN}"
  require_cmd jq
  require_cmd curl
  require_cmd systemctl

  log "Capturing current readiness"
  capture_current_state
  log "Inspecting rollback package"
  inspect_package
  log "Extracting rollback package"
  extract_package
  write_plan

  if [[ "${APPLY_RESTORE}" -eq 1 ]]; then
    apply_restore
    log "Offline rollback restore completed. Review ${OUTPUT_DIR}/restore-summary.txt"
  else
    log "Offline rollback workspace prepared. Review ${OUTPUT_DIR}/next-steps.txt"
  fi
}

main "$@"
