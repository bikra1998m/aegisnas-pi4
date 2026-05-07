#!/usr/bin/env bash
set -euo pipefail

OUTPUT_ROOT="/var/tmp/aegisnas-ha-failover"
LOCAL_ADMIN_URL="http://127.0.0.1:8083"
PEER_ADMIN_URL=""
LOCAL_TOKEN=""
PEER_TOKEN=""
POLL_INTERVAL=3
TIMEOUT_SECONDS=0
SKIP_RECOVERY=0

usage() {
  cat <<EOF
Usage:
  sudo bash scripts/ha-failover-drill.sh [options]

Options:
  --local-admin-url URL   Local admin API base URL. Default: http://127.0.0.1:8083
  --peer-admin-url URL    Peer admin API base URL. Defaults to peer_api_url from local status.
  --local-token TOKEN     Local admin bearer token. Defaults to AEGIS_ADMIN_BOOTSTRAP_TOKEN.
  --peer-token TOKEN      Peer admin bearer token. Defaults to local token.
  --timeout-seconds N     Override failover wait timeout. Default: failover_timeout + 30.
  --poll-interval N       Poll interval in seconds. Default: 3.
  --skip-recovery         Leave local aegis-gateway stopped after the promotion check.
  --help                  Show this help text.

This helper is intended for controlled HA failover drills on the active node.
It captures local and peer HA status before, during, and after temporarily
stopping the local aegis-gateway service.
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

read_bootstrap_token() {
  awk -F= '/^AEGIS_ADMIN_BOOTSTRAP_TOKEN=/{print $2}' /etc/default/aegisnas | tail -n 1
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --local-admin-url)
        LOCAL_ADMIN_URL="${2:-}"
        shift 2
        ;;
      --peer-admin-url)
        PEER_ADMIN_URL="${2:-}"
        shift 2
        ;;
      --local-token)
        LOCAL_TOKEN="${2:-}"
        shift 2
        ;;
      --peer-token)
        PEER_TOKEN="${2:-}"
        shift 2
        ;;
      --timeout-seconds)
        TIMEOUT_SECONDS="${2:-0}"
        shift 2
        ;;
      --poll-interval)
        POLL_INTERVAL="${2:-3}"
        shift 2
        ;;
      --skip-recovery)
        SKIP_RECOVERY=1
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
}

api_get() {
  local base_url="$1"
  local token="$2"
  local path="$3"
  local target_file="$4"
  curl -fsS -H "Authorization: Bearer ${token}" "${base_url}/api/v1${path}" >"${target_file}"
}

capture_snapshot() {
  local name="$1"
  local dir="$2"
  mkdir -p "${dir}"
  api_get "${LOCAL_ADMIN_URL}" "${LOCAL_TOKEN}" "/system/status" "${dir}/${name}-local-status.json"
  api_get "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/status" "${dir}/${name}-peer-status.json"
  systemctl --no-pager --full status aegis-gateway >"${dir}/${name}-local-gateway.txt" || true
}

wait_for_peer_promotion() {
  local status_file="$1"
  local timeout_seconds="$2"
  local start now elapsed effective_role vip_assigned auto_activate_status
  start="$(date +%s)"

  while true; do
    now="$(date +%s)"
    elapsed=$(( now - start ))
    api_get "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/status" "${status_file}"
    effective_role="$(jq -r '.high_availability.runtime.details.effective_role // ""' "${status_file}")"
    vip_assigned="$(jq -r '.high_availability.runtime.details.vip_assigned // false' "${status_file}")"
    auto_activate_status="$(jq -r '.high_availability.runtime.details.auto_activate_status // ""' "${status_file}")"
    if [[ "${effective_role}" == "active" && "${vip_assigned}" == "true" ]]; then
      return 0
    fi
    if [[ "${auto_activate_status}" == "restart_scheduled" || "${auto_activate_status}" == "failed" ]]; then
      return 0
    fi
    if (( elapsed >= timeout_seconds )); then
      return 1
    fi
    sleep "${POLL_INTERVAL}"
  done
}

main() {
  require_root
  parse_args "$@"
  require_cmd curl
  require_cmd jq
  require_cmd systemctl

  LOCAL_TOKEN="${LOCAL_TOKEN:-$(read_bootstrap_token)}"
  [[ -n "${LOCAL_TOKEN}" ]] || fail "could not read local admin bootstrap token"
  PEER_TOKEN="${PEER_TOKEN:-${LOCAL_TOKEN}}"

  local timestamp output_dir local_status peer_status local_role local_effective_role local_vip_assigned
  local peer_url failover_timeout expected_timeout preempt peer_effective_role peer_vip_assigned
  local auto_activate_enabled
  local promotion_result recovery_note
  timestamp="$(date '+%Y%m%d-%H%M%S')"
  output_dir="${OUTPUT_ROOT}/${timestamp}"
  mkdir -p "${output_dir}/snapshots" "${output_dir}/polls"

  log "Capturing baseline local status"
  api_get "${LOCAL_ADMIN_URL}" "${LOCAL_TOKEN}" "/system/status" "${output_dir}/baseline-local-status.json"

  local_role="$(jq -r '.high_availability.role // ""' "${output_dir}/baseline-local-status.json")"
  [[ "${local_role}" == "active" ]] || fail "this drill is intended to start on the active node; current configured role is '${local_role}'"
  local_effective_role="$(jq -r '.high_availability.runtime.details.effective_role // ""' "${output_dir}/baseline-local-status.json")"
  [[ "${local_effective_role}" == "active" ]] || fail "local node is not currently effective active; got '${local_effective_role}'"
  local_vip_assigned="$(jq -r '.high_availability.runtime.details.vip_assigned // false' "${output_dir}/baseline-local-status.json")"
  [[ "${local_vip_assigned}" == "true" ]] || fail "local node does not currently hold the VIP"

  peer_url="$(jq -r '.high_availability.peer_api_url // ""' "${output_dir}/baseline-local-status.json")"
  PEER_ADMIN_URL="${PEER_ADMIN_URL:-${peer_url}}"
  [[ -n "${PEER_ADMIN_URL}" ]] || fail "peer admin URL is not configured or provided"

  failover_timeout="$(jq -r '.high_availability.failover_timeout_seconds // 20' "${output_dir}/baseline-local-status.json")"
  preempt="$(jq -r '.high_availability.preempt // false' "${output_dir}/baseline-local-status.json")"
  auto_activate_enabled="$(jq -r '.high_availability.auto_activate_on_failover // false' "${output_dir}/baseline-local-status.json")"
  expected_timeout=$(( failover_timeout + 30 ))
  if (( TIMEOUT_SECONDS > 0 )); then
    expected_timeout="${TIMEOUT_SECONDS}"
  fi

  log "Capturing baseline peer status"
  api_get "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/status" "${output_dir}/baseline-peer-status.json"
  peer_effective_role="$(jq -r '.high_availability.runtime.details.effective_role // ""' "${output_dir}/baseline-peer-status.json")"
  [[ "${peer_effective_role}" == "standby" ]] || fail "peer is not currently effective standby; got '${peer_effective_role}'"
  peer_vip_assigned="$(jq -r '.high_availability.runtime.details.vip_assigned // false' "${output_dir}/baseline-peer-status.json")"
  [[ "${peer_vip_assigned}" == "false" ]] || fail "peer already reports VIP ownership before the drill"
  capture_snapshot "pre-stop" "${output_dir}/snapshots"

  log "Stopping local aegis-gateway to trigger failover"
  systemctl stop aegis-gateway
  trap 'if [[ "${SKIP_RECOVERY}" -eq 0 ]]; then systemctl start aegis-gateway >/dev/null 2>&1 || true; fi' EXIT

  if wait_for_peer_promotion "${output_dir}/polls/peer-promoted.json" "${expected_timeout}"; then
    log "Peer promotion observed"
    promotion_result="success"
  else
    log "Peer promotion not observed within timeout"
    promotion_result="timeout"
  fi

  capture_snapshot "post-stop" "${output_dir}/snapshots"

  if [[ "${SKIP_RECOVERY}" -eq 0 ]]; then
    log "Starting local aegis-gateway for recovery observation"
    systemctl start aegis-gateway
    sleep $(( POLL_INTERVAL + 2 ))
    capture_snapshot "post-recovery" "${output_dir}/snapshots"
    recovery_note="recovery was attempted and post-recovery snapshots were captured"
  else
    recovery_note="recovery was skipped; local aegis-gateway remains stopped until the operator restores it"
  fi

  cat >"${output_dir}/summary.json" <<EOF
{
  "generated_at": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "local_admin_url": "${LOCAL_ADMIN_URL}",
  "peer_admin_url": "${PEER_ADMIN_URL}",
  "failover_timeout_seconds": ${failover_timeout},
  "drill_timeout_seconds": ${expected_timeout},
  "auto_activate_on_failover": ${auto_activate_enabled},
  "preempt": ${preempt},
  "promotion_result": "${promotion_result}",
  "recovery_skipped": $( [[ "${SKIP_RECOVERY}" -eq 1 ]] && echo true || echo false ),
  "recovery_note": "${recovery_note}"
}
EOF

  cat >"${output_dir}/next-steps.txt" <<EOF
HA failover drill completed.

Output directory:
  ${output_dir}

Review:
  - baseline-local-status.json
  - baseline-peer-status.json
  - polls/peer-promoted.json
  - snapshots/post-stop-peer-status.json
$( [[ "${SKIP_RECOVERY}" -eq 0 ]] && printf '  - snapshots/post-recovery-peer-status.json\n' )

Expected outcomes:
  - peer should show effective_role active and vip_assigned true after local gateway stop
  - ${recovery_note}
  - recovery behavior should match the configured preempt policy
EOF

  log "HA failover drill artifacts saved to ${output_dir}"
}

main "$@"
