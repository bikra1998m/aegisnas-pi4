#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_ROOT="/var/tmp/aegisnas-ha-soak"
FAILOVER_OUTPUT_ROOT="/var/tmp/aegisnas-ha-failover"
LOCAL_ADMIN_URL="http://127.0.0.1:8083"
PEER_ADMIN_URL=""
LOCAL_TOKEN=""
PEER_TOKEN=""
CYCLES=1
POLL_INTERVAL=3
TIMEOUT_SECONDS=0
STAGE_SHARED_BEFORE_START=0
ACTIVATE_LATEST_BEFORE_START=0

usage() {
  cat <<EOF
Usage:
  sudo bash scripts/ha-soak-test.sh [options]

Options:
  --local-admin-url URL            Local admin API base URL. Default: http://127.0.0.1:8083
  --peer-admin-url URL             Peer admin API base URL. Defaults to peer_api_url from local status.
  --local-token TOKEN              Local admin bearer token. Defaults to AEGIS_ADMIN_BOOTSTRAP_TOKEN.
  --peer-token TOKEN               Peer admin bearer token. Defaults to local token.
  --cycles N                       Number of failover/recovery cycles to run. Default: 1.
  --poll-interval N                Poll interval in seconds. Default: 3.
  --timeout-seconds N              Override failover wait timeout. Default: failover_timeout + 30.
  --stage-shared-before-start      Stage the latest shared package on the standby before cycle 1.
  --activate-latest-before-start   Activate the latest staged package on the standby before cycle 1.
  --help                           Show this help text.

This helper runs repeated HA failover drills from the currently active node,
captures local and peer HA artifacts for each cycle, and writes a top-level
summary under ${OUTPUT_ROOT}/<timestamp>/.

Important boundary:
  - multi-cycle soak from one node requires high_availability.preempt: true
    so the original active node can reclaim the VIP between cycles.
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
      --cycles)
        CYCLES="${2:-1}"
        shift 2
        ;;
      --poll-interval)
        POLL_INTERVAL="${2:-3}"
        shift 2
        ;;
      --timeout-seconds)
        TIMEOUT_SECONDS="${2:-0}"
        shift 2
        ;;
      --stage-shared-before-start)
        STAGE_SHARED_BEFORE_START=1
        shift
        ;;
      --activate-latest-before-start)
        ACTIVATE_LATEST_BEFORE_START=1
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

  [[ "${CYCLES}" =~ ^[0-9]+$ ]] || fail "--cycles must be a positive integer"
  (( CYCLES > 0 )) || fail "--cycles must be at least 1"
  [[ "${POLL_INTERVAL}" =~ ^[0-9]+$ ]] || fail "--poll-interval must be a positive integer"
  (( POLL_INTERVAL > 0 )) || fail "--poll-interval must be at least 1"
  [[ "${TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]] || fail "--timeout-seconds must be a positive integer"
}

api_get() {
  local base_url="$1"
  local token="$2"
  local path="$3"
  local target_file="$4"
  curl -fsS -H "Authorization: Bearer ${token}" "${base_url}/api/v1${path}" >"${target_file}"
}

api_get_maybe() {
  local base_url="$1"
  local token="$2"
  local path="$3"
  local target_file="$4"
  if curl -fsS -H "Authorization: Bearer ${token}" "${base_url}/api/v1${path}" >"${target_file}" 2>"${target_file}.stderr"; then
    rm -f "${target_file}.stderr"
    return 0
  fi
  return 1
}

api_post_json() {
  local base_url="$1"
  local token="$2"
  local path="$3"
  local body="$4"
  local target_file="$5"
  curl -fsS -X POST \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    -d "${body}" \
    "${base_url}/api/v1${path}" >"${target_file}"
}

latest_stage_id() {
  local source_file="$1"
  jq -r '.packages[0].id // ""' "${source_file}"
}

latest_failover_artifact_dir() {
  if [[ ! -d "${FAILOVER_OUTPUT_ROOT}" ]]; then
    return 0
  fi
  find "${FAILOVER_OUTPUT_ROOT}" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1
}

capture_status_bundle() {
  local prefix="$1"
  local dir="$2"
  api_get "${LOCAL_ADMIN_URL}" "${LOCAL_TOKEN}" "/system/status" "${dir}/${prefix}-local-status.json"
  api_get "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/status" "${dir}/${prefix}-peer-status.json"
  api_get "${LOCAL_ADMIN_URL}" "${LOCAL_TOKEN}" "/system/ha/history" "${dir}/${prefix}-local-ha-history.json"
  api_get "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/ha/history" "${dir}/${prefix}-peer-ha-history.json"
  api_get "${LOCAL_ADMIN_URL}" "${LOCAL_TOKEN}" "/system/ha/replication-shared" "${dir}/${prefix}-local-ha-replication-shared.json"
  api_get "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/ha/replication-shared" "${dir}/${prefix}-peer-ha-replication-shared.json"
}

capture_status_bundle_relaxed() {
  local prefix="$1"
  local dir="$2"
  api_get_maybe "${LOCAL_ADMIN_URL}" "${LOCAL_TOKEN}" "/system/status" "${dir}/${prefix}-local-status.json" || true
  api_get_maybe "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/status" "${dir}/${prefix}-peer-status.json" || true
  api_get_maybe "${LOCAL_ADMIN_URL}" "${LOCAL_TOKEN}" "/system/ha/history" "${dir}/${prefix}-local-ha-history.json" || true
  api_get_maybe "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/ha/history" "${dir}/${prefix}-peer-ha-history.json" || true
  api_get_maybe "${LOCAL_ADMIN_URL}" "${LOCAL_TOKEN}" "/system/ha/replication-shared" "${dir}/${prefix}-local-ha-replication-shared.json" || true
  api_get_maybe "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/ha/replication-shared" "${dir}/${prefix}-peer-ha-replication-shared.json" || true
}

wait_for_local_reclaim() {
  local status_file="$1"
  local timeout_seconds="$2"
  local start now elapsed effective_role vip_assigned
  start="$(date +%s)"

  while true; do
    now="$(date +%s)"
    elapsed=$(( now - start ))
    api_get "${LOCAL_ADMIN_URL}" "${LOCAL_TOKEN}" "/system/status" "${status_file}"
    effective_role="$(jq -r '.high_availability.runtime.details.effective_role // ""' "${status_file}")"
    vip_assigned="$(jq -r '.high_availability.runtime.details.vip_assigned // false' "${status_file}")"
    if [[ "${effective_role}" == "active" && "${vip_assigned}" == "true" ]]; then
      return 0
    fi
    if (( elapsed >= timeout_seconds )); then
      return 1
    fi
    sleep "${POLL_INTERVAL}"
  done
}

prepare_standby() {
  local output_dir="$1"
  local staged_file stage_id
  mkdir -p "${output_dir}"

  if [[ "${STAGE_SHARED_BEFORE_START}" -eq 1 ]]; then
    log "Staging the latest shared package on the standby before the soak run"
    api_post_json "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/ha/replication-stage-shared" '{}' "${output_dir}/stage-shared.json"
  fi

  staged_file="${output_dir}/peer-staged-packages.json"
  api_get "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/ha/replication-staged" "${staged_file}"

  if [[ "${ACTIVATE_LATEST_BEFORE_START}" -eq 1 ]]; then
    stage_id="$(latest_stage_id "${staged_file}")"
    [[ -n "${stage_id}" ]] || fail "could not find a staged HA package to activate on the standby"
    log "Activating staged HA package ${stage_id} on the standby before the soak run"
    api_post_json "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/ha/replication-activate" "{\"id\":\"${stage_id}\"}" "${output_dir}/activate-latest.json"
    sleep $(( POLL_INTERVAL + 1 ))
    api_get "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/status" "${output_dir}/peer-status-after-activate.json"
  fi

  api_get "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/ha/replication-staged" "${output_dir}/peer-staged-packages-after-prep.json"
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

  local timestamp output_dir baseline_file failover_timeout expected_timeout peer_url local_role local_effective_role local_vip_assigned
  local preempt auto_activate_enabled
  local failures cycle

  timestamp="$(date '+%Y%m%d-%H%M%S')"
  output_dir="${OUTPUT_ROOT}/${timestamp}"
  mkdir -p "${output_dir}/cycles" "${output_dir}/prep"

  log "Capturing baseline HA status"
  baseline_file="${output_dir}/baseline-local-status.json"
  api_get "${LOCAL_ADMIN_URL}" "${LOCAL_TOKEN}" "/system/status" "${baseline_file}"

  local_role="$(jq -r '.high_availability.role // ""' "${baseline_file}")"
  [[ "${local_role}" == "active" ]] || fail "this soak helper must start on the configured active node; current configured role is '${local_role}'"
  local_effective_role="$(jq -r '.high_availability.runtime.details.effective_role // ""' "${baseline_file}")"
  [[ "${local_effective_role}" == "active" ]] || fail "local node is not currently effective active; got '${local_effective_role}'"
  local_vip_assigned="$(jq -r '.high_availability.runtime.details.vip_assigned // false' "${baseline_file}")"
  [[ "${local_vip_assigned}" == "true" ]] || fail "local node does not currently hold the VIP"

  peer_url="$(jq -r '.high_availability.peer_api_url // ""' "${baseline_file}")"
  PEER_ADMIN_URL="${PEER_ADMIN_URL:-${peer_url}}"
  [[ -n "${PEER_ADMIN_URL}" ]] || fail "peer admin URL is not configured or provided"

  failover_timeout="$(jq -r '.high_availability.failover_timeout_seconds // 20' "${baseline_file}")"
  preempt="$(jq -r '.high_availability.preempt // false' "${baseline_file}")"
  auto_activate_enabled="$(jq -r '.high_availability.auto_activate_on_failover // false' "${baseline_file}")"
  expected_timeout=$(( failover_timeout + 30 ))
  if (( TIMEOUT_SECONDS > 0 )); then
    expected_timeout="${TIMEOUT_SECONDS}"
  fi

  if (( CYCLES > 1 )) && [[ "${preempt}" != "true" ]]; then
    fail "multi-cycle soak requires high_availability.preempt: true so the original active node can reclaim the VIP between cycles"
  fi

  if [[ "${ACTIVATE_LATEST_BEFORE_START}" -eq 1 ]]; then
    STAGE_SHARED_BEFORE_START=1
  fi
  if (( STAGE_SHARED_BEFORE_START == 1 || ACTIVATE_LATEST_BEFORE_START == 1 )); then
    prepare_standby "${output_dir}/prep"
  fi

  failures=0
  for (( cycle=1; cycle<=CYCLES; cycle++ )); do
    local cycle_dir cycle_id before_drill_dir after_drill_dir drill_status promotion_result reclaim_status success error_message
    cycle_id="$(printf 'cycle-%02d' "${cycle}")"
    cycle_dir="${output_dir}/cycles/${cycle_id}"
    mkdir -p "${cycle_dir}"

    log "Starting ${cycle_id} of ${CYCLES}"
    capture_status_bundle "pre" "${cycle_dir}"

    before_drill_dir="$(latest_failover_artifact_dir)"
    if bash "${SCRIPT_DIR}/ha-failover-drill.sh" \
      --local-admin-url "${LOCAL_ADMIN_URL}" \
      --peer-admin-url "${PEER_ADMIN_URL}" \
      --local-token "${LOCAL_TOKEN}" \
      --peer-token "${PEER_TOKEN}" \
      --poll-interval "${POLL_INTERVAL}" \
      --timeout-seconds "${expected_timeout}"; then
      drill_status=0
    else
      drill_status=$?
    fi

    after_drill_dir="$(latest_failover_artifact_dir)"
    if [[ -z "${after_drill_dir}" || "${after_drill_dir}" == "${before_drill_dir}" ]]; then
      after_drill_dir=""
    fi

    if [[ -n "${after_drill_dir}" ]]; then
      printf '%s\n' "${after_drill_dir}" >"${cycle_dir}/failover-artifact-dir.txt"
      ln -sfn "${after_drill_dir}" "${cycle_dir}/failover-artifacts" 2>/dev/null || true
    fi

    capture_status_bundle_relaxed "post" "${cycle_dir}"

    promotion_result="unknown"
    if [[ -n "${after_drill_dir}" && -f "${after_drill_dir}/summary.json" ]]; then
      promotion_result="$(jq -r '.promotion_result // "unknown"' "${after_drill_dir}/summary.json")"
    fi

    reclaim_status="not_required"
    if [[ "${preempt}" == "true" ]]; then
      if wait_for_local_reclaim "${cycle_dir}/reclaim-local-status.json" "${expected_timeout}"; then
        reclaim_status="reclaimed"
        api_get_maybe "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/status" "${cycle_dir}/reclaim-peer-status.json" || true
      else
        reclaim_status="timeout"
      fi
    fi

    success=true
    error_message=""
    if (( drill_status != 0 )); then
      success=false
      error_message="ha-failover-drill.sh exited with status ${drill_status}"
    elif [[ "${promotion_result}" != "success" ]]; then
      success=false
      error_message="promotion result was '${promotion_result}'"
    elif [[ "${preempt}" == "true" && "${reclaim_status}" != "reclaimed" ]]; then
      success=false
      error_message="local active node did not reclaim the VIP after recovery"
    fi

    if [[ "${success}" != "true" ]]; then
      failures=$(( failures + 1 ))
    fi

    jq -n \
      --arg cycle_id "${cycle_id}" \
      --arg drill_dir "${after_drill_dir}" \
      --arg promotion_result "${promotion_result}" \
      --arg reclaim_status "${reclaim_status}" \
      --arg error_message "${error_message}" \
      --argjson success "${success}" \
      --argjson auto_activate_on_failover "${auto_activate_enabled}" \
      --arg local_effective_role_before "$(jq -r '.high_availability.runtime.details.effective_role // ""' "${cycle_dir}/pre-local-status.json")" \
      --arg peer_effective_role_before "$(jq -r '.high_availability.runtime.details.effective_role // ""' "${cycle_dir}/pre-peer-status.json")" \
      --arg local_effective_role_after "$(jq -r '.high_availability.runtime.details.effective_role // ""' "${cycle_dir}/post-local-status.json" 2>/dev/null || printf '')" \
      --arg peer_effective_role_after "$(jq -r '.high_availability.runtime.details.effective_role // ""' "${cycle_dir}/post-peer-status.json" 2>/dev/null || printf '')" \
      --arg local_vip_after "$(jq -r '.high_availability.runtime.details.vip_assigned // false' "${cycle_dir}/post-local-status.json" 2>/dev/null || printf false)" \
      --arg peer_vip_after "$(jq -r '.high_availability.runtime.details.vip_assigned // false' "${cycle_dir}/post-peer-status.json" 2>/dev/null || printf false)" \
      '{
        cycle_id: $cycle_id,
        success: $success,
        failover_artifact_dir: $drill_dir,
        promotion_result: $promotion_result,
        reclaim_status: $reclaim_status,
        auto_activate_on_failover: $auto_activate_on_failover,
        local_effective_role_before: $local_effective_role_before,
        peer_effective_role_before: $peer_effective_role_before,
        local_effective_role_after: $local_effective_role_after,
        peer_effective_role_after: $peer_effective_role_after,
        local_vip_after: $local_vip_after,
        peer_vip_after: $peer_vip_after,
        error_message: $error_message
      }' >"${cycle_dir}/summary.json"
  done

  jq -s '.' "${output_dir}"/cycles/*/summary.json >"${output_dir}/cycle-summaries.json"
  jq -n \
    --arg generated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg local_admin_url "${LOCAL_ADMIN_URL}" \
    --arg peer_admin_url "${PEER_ADMIN_URL}" \
    --argjson cycles "${CYCLES}" \
    --argjson failover_timeout_seconds "${failover_timeout}" \
    --argjson drill_timeout_seconds "${expected_timeout}" \
    --argjson preempt "${preempt}" \
    --argjson auto_activate_on_failover "${auto_activate_enabled}" \
    --argjson stage_shared_before_start "$( [[ "${STAGE_SHARED_BEFORE_START}" -eq 1 ]] && echo true || echo false )" \
    --argjson activate_latest_before_start "$( [[ "${ACTIVATE_LATEST_BEFORE_START}" -eq 1 ]] && echo true || echo false )" \
    --argjson failure_count "${failures}" \
    --slurpfile cycle_data "${output_dir}/cycle-summaries.json" \
    '{
      generated_at: $generated_at,
      local_admin_url: $local_admin_url,
      peer_admin_url: $peer_admin_url,
      cycles_requested: $cycles,
      failover_timeout_seconds: $failover_timeout_seconds,
      drill_timeout_seconds: $drill_timeout_seconds,
      preempt: $preempt,
      auto_activate_on_failover: $auto_activate_on_failover,
      stage_shared_before_start: $stage_shared_before_start,
      activate_latest_before_start: $activate_latest_before_start,
      failure_count: $failure_count,
      passed_cycles: ([ $cycle_data[0][] | select(.success == true) ] | length),
      cycles: $cycle_data[0]
    }' >"${output_dir}/summary.json"

  cat >"${output_dir}/next-steps.txt" <<EOF
HA soak run completed.

Output directory:
  ${output_dir}

Recommended review:
  - summary.json
  - cycle-summaries.json
  - cycles/cycle-*/summary.json
  - cycles/cycle-*/failover-artifacts/

What to confirm:
  - every cycle shows promotion_result: success
  - when preempt is true, every cycle shows reclaim_status: reclaimed
  - post-cycle local and peer effective roles match the expected HA policy
  - HA history on both nodes reflects the promotion, restart, and recovery flow cleanly
EOF

  if (( failures > 0 )); then
    fail "HA soak recorded ${failures} failed cycle(s); review ${output_dir}/summary.json"
  fi

  log "HA soak completed successfully. Review ${output_dir}/summary.json"
}

main "$@"
