#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ADMIN_BIN="${AEGIS_ADMIN_BIN:-/opt/aegisnas/bin/aegis-admin}"
CONFIG_PATH="/etc/aegisnas/config.yaml"
OUTPUT_ROOT="/var/tmp/aegisnas-upgrade-rollback-rehearsal"
OUTPUT_DIR=""
PACKAGE_PATH=""
HELPER_SCRIPT="${REPO_ROOT}/scripts/ubuntu-upgrade-rollback-restore.sh"

usage() {
  cat <<EOF
Usage:
  sudo bash scripts/ubuntu-upgrade-rollback-rehearsal.sh [options]

Options:
  --output-dir DIR     Output directory for rehearsal artifacts.
  --package PATH       Optional existing rollback package to rehearse.
  --config PATH        Appliance config path. Default: ${CONFIG_PATH}
  --admin-bin PATH     aegis-admin binary path. Default: ${ADMIN_BIN}
  --helper-script PATH Offline helper script path. Default: ${HELPER_SCRIPT}
  --help               Show this help text.

This helper rehearses the version-aware rollback path without applying a restore.
It creates or reuses a rollback package, inspects it, extracts it, validates the
extracted config, checks the extracted SQLite integrity, and runs the offline
rollback helper in dry-run mode to prepare a restore workspace.
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
      --output-dir)
        OUTPUT_DIR="${2:-}"
        shift 2
        ;;
      --package)
        PACKAGE_PATH="${2:-}"
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
      --helper-script)
        HELPER_SCRIPT="${2:-}"
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

  if [[ -z "${OUTPUT_DIR}" ]]; then
    OUTPUT_DIR="${OUTPUT_ROOT}/$(date '+%Y%m%d-%H%M%S')"
  fi
  mkdir -p "${OUTPUT_DIR}"
}

record_context() {
  if [[ -d "${REPO_ROOT}/.git" ]]; then
    git -C "${REPO_ROOT}" rev-parse HEAD >"${OUTPUT_DIR}/git-head.txt" || true
    git -C "${REPO_ROOT}" status --short >"${OUTPUT_DIR}/git-status.txt" || true
  fi
  systemctl --no-pager --full status \
    aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api \
    dnsmasq freeradius nftables >"${OUTPUT_DIR}/service-status.txt" || true
}

ensure_package() {
  if [[ -n "${PACKAGE_PATH}" ]]; then
    [[ -f "${PACKAGE_PATH}" ]] || fail "rollback package not found: ${PACKAGE_PATH}"
    cp "${PACKAGE_PATH}" "${OUTPUT_DIR}/$(basename "${PACKAGE_PATH}")"
    PACKAGE_PATH="${OUTPUT_DIR}/$(basename "${PACKAGE_PATH}")"
    return 0
  fi

  PACKAGE_PATH="${OUTPUT_DIR}/aegisnas-upgrade-rollback-package.zip"
  log "Creating rollback package"
  "${ADMIN_BIN}" create-upgrade-rollback-package --config "${CONFIG_PATH}" --output "${PACKAGE_PATH}" >/dev/null
}

inspect_package() {
  log "Inspecting rollback package"
  "${ADMIN_BIN}" inspect-upgrade-rollback-package --config "${CONFIG_PATH}" --input "${PACKAGE_PATH}" >"${OUTPUT_DIR}/inspection.json"
}

extract_package() {
  log "Extracting rollback package directly"
  "${ADMIN_BIN}" extract-upgrade-rollback-package --input "${PACKAGE_PATH}" --output-dir "${OUTPUT_DIR}/extracted" >"${OUTPUT_DIR}/extraction.json"
}

validate_extracted_state() {
  log "Validating extracted config"
  "${ADMIN_BIN}" validate-config --config "${OUTPUT_DIR}/extracted/config/config.yaml" >"${OUTPUT_DIR}/extracted-config-validation.txt"

  log "Checking extracted SQLite integrity"
  sqlite3 "${OUTPUT_DIR}/extracted/database/data.db" 'PRAGMA integrity_check;' >"${OUTPUT_DIR}/extracted-database-integrity.txt"
}

prepare_offline_helper_workspace() {
  log "Preparing offline restore helper workspace"
  bash "${HELPER_SCRIPT}" --package "${PACKAGE_PATH}" --output-dir "${OUTPUT_DIR}/offline-helper" >"${OUTPUT_DIR}/offline-helper.log"
}

write_summary() {
  local compatibility online_restore current_schema target_schema
  compatibility="$(jq -r '.compatibility_status' "${OUTPUT_DIR}/inspection.json")"
  online_restore="$(jq -r '.online_restore_supported' "${OUTPUT_DIR}/inspection.json")"
  current_schema="$(jq -r '.current_schema_version' "${OUTPUT_DIR}/current-readiness.json")"
  target_schema="$(jq -r '.target_schema_version' "${OUTPUT_DIR}/current-readiness.json")"

  cat >"${OUTPUT_DIR}/summary.txt" <<EOF
Upgrade rollback rehearsal completed.

Rollback package:
  ${PACKAGE_PATH}

Schema:
  current=${current_schema}
  target=${target_schema}

Inspection:
  compatibility_status=${compatibility}
  online_restore_supported=${online_restore}

Artifacts:
  current-readiness.json
  inspection.json
  extraction.json
  extracted/
  offline-helper/

Next steps:
  1. Review inspection.json and summary.txt.
  2. If online_restore_supported is true, the admin UI and CLI online restore path are available on this runtime.
  3. If you need an offline drill, inspect offline-helper/next-steps.txt and rerun scripts/ubuntu-upgrade-rollback-restore.sh with --apply only on a lab node.
EOF
}

main() {
  require_root
  parse_args "$@"
  require_cmd "${ADMIN_BIN}"
  require_cmd jq
  require_cmd sqlite3
  [[ -x "${HELPER_SCRIPT}" || -f "${HELPER_SCRIPT}" ]] || fail "offline helper script not found: ${HELPER_SCRIPT}"

  log "Recording current readiness"
  "${ADMIN_BIN}" upgrade-readiness --config "${CONFIG_PATH}" --json >"${OUTPUT_DIR}/current-readiness.json"
  record_context
  ensure_package
  inspect_package
  extract_package
  validate_extracted_state
  prepare_offline_helper_workspace
  write_summary
  log "Rollback rehearsal completed. Review ${OUTPUT_DIR}/summary.txt"
}

main "$@"
