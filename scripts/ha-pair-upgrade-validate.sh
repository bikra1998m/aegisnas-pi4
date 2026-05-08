#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_ROOT="/var/tmp/aegisnas-ha-upgrade-validate"
LOCAL_ADMIN_URL="http://127.0.0.1:8083"
PEER_ADMIN_URL=""
LOCAL_TOKEN=""
PEER_TOKEN=""
PEER_SSH=""
EXPECTED_SCHEMA=""
POLL_INTERVAL=3
TIMEOUT_SECONDS=0
STAGE_SHARED_PEER=0
ACTIVATE_LATEST_PEER=0
RUN_FAILOVER_DRILL=0
RUN_SOAK_CYCLES=0

usage() {
  cat <<EOF
Usage:
  sudo bash scripts/ha-pair-upgrade-validate.sh [options]

Options:
  --local-admin-url URL       Local admin API base URL. Default: http://127.0.0.1:8083
  --peer-admin-url URL        Peer admin API base URL. Defaults to peer_api_url from local status.
  --local-token TOKEN         Local admin bearer token. Defaults to AEGIS_ADMIN_BOOTSTRAP_TOKEN.
  --peer-token TOKEN          Peer admin bearer token. Defaults to local token.
  --peer-ssh USER@HOST        Optional SSH target for peer schema and service checks.
  --expected-schema N         Optional schema version override. Default: latest repo migration version.
  --poll-interval N           Poll interval in seconds for optional drills. Default: 3.
  --timeout-seconds N         Timeout override for optional drills. Default: failover_timeout + 30.
  --stage-shared-peer         Stage the latest shared HA package on the standby peer.
  --activate-latest-peer      Activate the latest staged HA package on the standby peer.
  --run-failover-drill        Run a controlled failover drill after upgrade validation.
  --run-soak-cycles N         Run the HA soak helper after validation.
  --help                      Show this help text.

This helper validates an HA pair after both nodes have been upgraded.
It always validates the local node deeply, validates the peer over the admin API,
and optionally uses SSH for peer schema and service checks.

Important boundaries:
  - this does not upgrade the peer remotely
  - it validates the pair after the local and peer nodes have already been upgraded
  - multi-cycle soak requires high_availability.preempt: true
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
      --peer-ssh)
        PEER_SSH="${2:-}"
        shift 2
        ;;
      --expected-schema)
        EXPECTED_SCHEMA="${2:-}"
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
      --stage-shared-peer)
        STAGE_SHARED_PEER=1
        shift
        ;;
      --activate-latest-peer)
        ACTIVATE_LATEST_PEER=1
        shift
        ;;
      --run-failover-drill)
        RUN_FAILOVER_DRILL=1
        shift
        ;;
      --run-soak-cycles)
        RUN_SOAK_CYCLES="${2:-0}"
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

  [[ "${POLL_INTERVAL}" =~ ^[0-9]+$ ]] || fail "--poll-interval must be a positive integer"
  (( POLL_INTERVAL > 0 )) || fail "--poll-interval must be at least 1"
  [[ "${TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]] || fail "--timeout-seconds must be a positive integer"
  [[ "${RUN_SOAK_CYCLES}" =~ ^[0-9]+$ ]] || fail "--run-soak-cycles must be a positive integer"
  if [[ -n "${EXPECTED_SCHEMA}" ]]; then
    [[ "${EXPECTED_SCHEMA}" =~ ^[0-9]+$ ]] || fail "--expected-schema must be a positive integer"
  fi
  if (( RUN_FAILOVER_DRILL == 1 && RUN_SOAK_CYCLES > 0 )); then
    fail "--run-failover-drill and --run-soak-cycles cannot be used together"
  fi
  if [[ "${ACTIVATE_LATEST_PEER}" -eq 1 ]]; then
    STAGE_SHARED_PEER=1
  fi
}

read_bootstrap_token() {
  awk -F= '/^AEGIS_ADMIN_BOOTSTRAP_TOKEN=/{print $2}' /etc/default/aegisnas | tail -n 1
}

expected_schema_version() {
  if [[ -n "${EXPECTED_SCHEMA}" ]]; then
    printf '%s\n' "${EXPECTED_SCHEMA}"
  else
    sed -nE 's/^[[:space:]]*\{([0-9]+), schemaV[0-9]+\},/\1/p' "${REPO_ROOT}/internal/db/migrate.go" | tail -n 1
  fi
}

current_schema_version() {
  sqlite3 /var/lib/aegisnas/data.db 'SELECT COALESCE(MAX(version), 0) FROM schema_version;'
}

peer_schema_version() {
  local ssh_target="$1"
  ssh -o BatchMode=yes -o ConnectTimeout=10 "${ssh_target}" \
    "sudo sqlite3 /var/lib/aegisnas/data.db 'SELECT COALESCE(MAX(version), 0) FROM schema_version;'"
}

api_get() {
  local base_url="$1"
  local token="$2"
  local path="$3"
  local target_file="$4"
  curl -fsS -H "Authorization: Bearer ${token}" "${base_url}/api/v1${path}" >"${target_file}"
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

health_probe() {
  local port="$1"
  local target_file="$2"
  curl -fsS "http://127.0.0.1:${port}/health" >"${target_file}"
}

latest_stage_id() {
  local source_file="$1"
  jq -r '.packages[0].id // ""' "${source_file}"
}

latest_helper_artifact_dir() {
  local root_dir="$1"
  if [[ ! -d "${root_dir}" ]]; then
    return 0
  fi
  find "${root_dir}" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1
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
  if [[ -n "${PEER_SSH}" ]]; then
    require_cmd ssh
  fi

  LOCAL_TOKEN="${LOCAL_TOKEN:-$(read_bootstrap_token)}"
  [[ -n "${LOCAL_TOKEN}" ]] || fail "could not read local admin bootstrap token"
  PEER_TOKEN="${PEER_TOKEN:-${LOCAL_TOKEN}}"

  local timestamp output_dir expected_schema local_schema peer_url local_role local_effective_role local_vip_assigned
  local peer_effective_role peer_vip_assigned failover_timeout preempt auto_stage_enabled auto_activate_enabled
  local peer_schema="unknown" stage_id helper_artifact_before helper_artifact_after helper_artifact_dir

  timestamp="$(date '+%Y%m%d-%H%M%S')"
  output_dir="${OUTPUT_ROOT}/${timestamp}"
  mkdir -p "${output_dir}/health" "${output_dir}/api" "${output_dir}/peer"

  expected_schema="$(expected_schema_version)"
  [[ -n "${expected_schema}" ]] || fail "could not determine expected schema version"

  log "Capturing local system context"
  git -C "${REPO_ROOT}" rev-parse HEAD >"${output_dir}/git-head.txt"
  git -C "${REPO_ROOT}" status --short >"${output_dir}/git-status.txt" || true
  ip -br addr >"${output_dir}/ip-addr.txt"
  ip route >"${output_dir}/ip-route.txt"
  systemctl --no-pager --full status \
    aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api \
    dnsmasq freeradius nftables >"${output_dir}/service-status-local.txt" || true

  log "Collecting local and peer HA status"
  api_get "${LOCAL_ADMIN_URL}" "${LOCAL_TOKEN}" "/system/status" "${output_dir}/api/local-system-status.json"
  local_role="$(jq -r '.high_availability.role // ""' "${output_dir}/api/local-system-status.json")"
  local_effective_role="$(jq -r '.high_availability.runtime.details.effective_role // ""' "${output_dir}/api/local-system-status.json")"
  local_vip_assigned="$(jq -r '.high_availability.runtime.details.vip_assigned // false' "${output_dir}/api/local-system-status.json")"
  [[ "${local_role}" == "active" ]] || fail "run this helper from the active node after the pair upgrade; current configured role is '${local_role}'"
  [[ "${local_effective_role}" == "active" ]] || fail "local node is not currently effective active; got '${local_effective_role}'"
  [[ "${local_vip_assigned}" == "true" ]] || fail "local node does not currently hold the VIP"

  peer_url="$(jq -r '.high_availability.peer_api_url // ""' "${output_dir}/api/local-system-status.json")"
  PEER_ADMIN_URL="${PEER_ADMIN_URL:-${peer_url}}"
  [[ -n "${PEER_ADMIN_URL}" ]] || fail "peer admin URL is not configured or provided"

  api_get "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/status" "${output_dir}/api/peer-system-status.json"
  api_get "${LOCAL_ADMIN_URL}" "${LOCAL_TOKEN}" "/system/ha/history" "${output_dir}/api/local-ha-history.json"
  api_get "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/ha/history" "${output_dir}/api/peer-ha-history.json"
  api_get "${LOCAL_ADMIN_URL}" "${LOCAL_TOKEN}" "/system/ha/replication-shared" "${output_dir}/api/local-ha-replication-shared.json"
  api_get "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/ha/replication-shared" "${output_dir}/api/peer-ha-replication-shared.json"
  api_get "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/ha/replication-staged" "${output_dir}/api/peer-ha-replication-staged.json"

  peer_effective_role="$(jq -r '.high_availability.runtime.details.effective_role // ""' "${output_dir}/api/peer-system-status.json")"
  peer_vip_assigned="$(jq -r '.high_availability.runtime.details.vip_assigned // false' "${output_dir}/api/peer-system-status.json")"
  [[ "${peer_effective_role}" == "standby" ]] || fail "peer is not currently effective standby; got '${peer_effective_role}'"
  [[ "${peer_vip_assigned}" == "false" ]] || fail "peer already reports VIP ownership"

  failover_timeout="$(jq -r '.high_availability.failover_timeout_seconds // 20' "${output_dir}/api/local-system-status.json")"
  preempt="$(jq -r '.high_availability.preempt // false' "${output_dir}/api/local-system-status.json")"
  auto_stage_enabled="$(jq -r '.high_availability.auto_stage_shared_package // false' "${output_dir}/api/local-system-status.json")"
  auto_activate_enabled="$(jq -r '.high_availability.auto_activate_on_failover // false' "${output_dir}/api/local-system-status.json")"
  if (( TIMEOUT_SECONDS == 0 )); then
    TIMEOUT_SECONDS=$(( failover_timeout + 30 ))
  fi

  log "Checking schema versions"
  local_schema="$(current_schema_version)"
  [[ -n "${local_schema}" ]] || fail "could not determine local schema version"
  if (( local_schema < expected_schema )); then
    fail "local schema version ${local_schema} is behind expected version ${expected_schema}"
  fi
  printf 'expected_schema=%s\nlocal_schema=%s\n' "${expected_schema}" "${local_schema}" >"${output_dir}/schema-local.txt"

  if [[ -n "${PEER_SSH}" ]]; then
    log "Collecting peer service and schema data over SSH"
    peer_schema="$(peer_schema_version "${PEER_SSH}")"
    [[ -n "${peer_schema}" ]] || fail "could not determine peer schema version over SSH"
    if (( peer_schema < expected_schema )); then
      fail "peer schema version ${peer_schema} is behind expected version ${expected_schema}"
    fi
    printf 'expected_schema=%s\npeer_schema=%s\n' "${expected_schema}" "${peer_schema}" >"${output_dir}/schema-peer.txt"
    ssh -o BatchMode=yes -o ConnectTimeout=10 "${PEER_SSH}" \
      "sudo systemctl --no-pager --full status aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api dnsmasq freeradius nftables" \
      >"${output_dir}/peer/service-status-peer.txt" || true
    ssh -o BatchMode=yes -o ConnectTimeout=10 "${PEER_SSH}" "ip -br addr" >"${output_dir}/peer/ip-addr-peer.txt" || true
  fi

  log "Running local health probes"
  health_probe 8080 "${output_dir}/health/gateway-health.json"
  health_probe 8081 "${output_dir}/health/portal-health.json"
  health_probe 8082 "${output_dir}/health/policy-health.json"
  health_probe 8083 "${output_dir}/health/admin-api-health.json"
  health_probe 8085 "${output_dir}/health/radius-health.json"
  health_probe 8087 "${output_dir}/health/session-health.json"

  if [[ "${STAGE_SHARED_PEER}" -eq 1 ]]; then
    log "Staging the latest shared package on the standby peer"
    api_post_json "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/ha/replication-stage-shared" '{}' "${output_dir}/api/peer-stage-shared.json"
    api_get "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/ha/replication-staged" "${output_dir}/api/peer-ha-replication-staged-after-stage.json"
  fi

  if [[ "${ACTIVATE_LATEST_PEER}" -eq 1 ]]; then
    stage_id="$(latest_stage_id "${output_dir}/api/peer-ha-replication-staged-after-stage.json")"
    [[ -n "${stage_id}" ]] || fail "could not find a staged HA package to activate on the peer"
    log "Activating staged HA package ${stage_id} on the standby peer"
    api_post_json "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/ha/replication-activate" "{\"id\":\"${stage_id}\"}" "${output_dir}/api/peer-activate-latest.json"
    sleep $(( POLL_INTERVAL + 1 ))
    api_get "${PEER_ADMIN_URL}" "${PEER_TOKEN}" "/system/status" "${output_dir}/api/peer-system-status-after-activate.json"
  fi

  helper_artifact_dir=""
  if (( RUN_FAILOVER_DRILL == 1 )); then
    helper_artifact_before="$(latest_helper_artifact_dir '/var/tmp/aegisnas-ha-failover')"
    log "Running HA failover drill after upgrade validation"
    bash "${SCRIPT_DIR}/ha-failover-drill.sh" \
      --local-admin-url "${LOCAL_ADMIN_URL}" \
      --peer-admin-url "${PEER_ADMIN_URL}" \
      --local-token "${LOCAL_TOKEN}" \
      --peer-token "${PEER_TOKEN}" \
      --poll-interval "${POLL_INTERVAL}" \
      --timeout-seconds "${TIMEOUT_SECONDS}"
    helper_artifact_after="$(latest_helper_artifact_dir '/var/tmp/aegisnas-ha-failover')"
    if [[ -n "${helper_artifact_after}" && "${helper_artifact_after}" != "${helper_artifact_before}" ]]; then
      helper_artifact_dir="${helper_artifact_after}"
    fi
    printf '%s\n' "${helper_artifact_dir}" >"${output_dir}/post-upgrade-failover-artifact-dir.txt"
  elif (( RUN_SOAK_CYCLES > 0 )); then
    helper_artifact_before="$(latest_helper_artifact_dir '/var/tmp/aegisnas-ha-soak')"
    log "Running HA soak helper after upgrade validation"
    bash "${SCRIPT_DIR}/ha-soak-test.sh" \
      --local-admin-url "${LOCAL_ADMIN_URL}" \
      --peer-admin-url "${PEER_ADMIN_URL}" \
      --local-token "${LOCAL_TOKEN}" \
      --peer-token "${PEER_TOKEN}" \
      --poll-interval "${POLL_INTERVAL}" \
      --timeout-seconds "${TIMEOUT_SECONDS}" \
      --cycles "${RUN_SOAK_CYCLES}"
    helper_artifact_after="$(latest_helper_artifact_dir '/var/tmp/aegisnas-ha-soak')"
    if [[ -n "${helper_artifact_after}" && "${helper_artifact_after}" != "${helper_artifact_before}" ]]; then
      helper_artifact_dir="${helper_artifact_after}"
    fi
    printf '%s\n' "${helper_artifact_dir}" >"${output_dir}/post-upgrade-soak-artifact-dir.txt"
  fi

  jq -n \
    --arg generated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg local_admin_url "${LOCAL_ADMIN_URL}" \
    --arg peer_admin_url "${PEER_ADMIN_URL}" \
    --arg peer_ssh "${PEER_SSH}" \
    --arg expected_schema "${expected_schema}" \
    --arg local_schema "${local_schema}" \
    --arg peer_schema "${peer_schema}" \
    --arg local_effective_role "${local_effective_role}" \
    --arg peer_effective_role "${peer_effective_role}" \
    --argjson auto_stage_enabled "${auto_stage_enabled}" \
    --argjson auto_activate_enabled "${auto_activate_enabled}" \
    --argjson preempt "${preempt}" \
    --argjson run_failover_drill "$( [[ "${RUN_FAILOVER_DRILL}" -eq 1 ]] && echo true || echo false )" \
    --argjson run_soak_cycles "${RUN_SOAK_CYCLES}" \
    --argjson stage_shared_peer "$( [[ "${STAGE_SHARED_PEER}" -eq 1 ]] && echo true || echo false )" \
    --argjson activate_latest_peer "$( [[ "${ACTIVATE_LATEST_PEER}" -eq 1 ]] && echo true || echo false )" \
    --arg helper_artifact_dir "${helper_artifact_dir}" \
    '{
      generated_at: $generated_at,
      local_admin_url: $local_admin_url,
      peer_admin_url: $peer_admin_url,
      peer_ssh: $peer_ssh,
      expected_schema: $expected_schema,
      local_schema: $local_schema,
      peer_schema: $peer_schema,
      local_effective_role: $local_effective_role,
      peer_effective_role: $peer_effective_role,
      auto_stage_enabled: $auto_stage_enabled,
      auto_activate_enabled: $auto_activate_enabled,
      preempt: $preempt,
      stage_shared_peer: $stage_shared_peer,
      activate_latest_peer: $activate_latest_peer,
      run_failover_drill: $run_failover_drill,
      run_soak_cycles: $run_soak_cycles,
      helper_artifact_dir: $helper_artifact_dir
    }' >"${output_dir}/summary.json"

  cat >"${output_dir}/next-steps.txt" <<EOF
HA pair upgrade validation completed.

Output directory:
  ${output_dir}

Recommended review:
  1. summary.json
  2. schema-local.txt
$( [[ -n "${PEER_SSH}" ]] && printf '  3. schema-peer.txt\n  4. peer/service-status-peer.txt\n' || printf '  3. peer schema was not checked over SSH; use --peer-ssh for a stronger validation pass\n' )
  5. api/local-system-status.json
  6. api/peer-system-status.json
  7. api/local-ha-replication-shared.json
  8. api/peer-ha-replication-staged.json
$( [[ -n "${helper_artifact_dir}" ]] && printf '  9. helper artifacts under %s\n' "${helper_artifact_dir}" )

Acceptance expectations:
  - local and peer schema are at or above the repo migration version
  - local node is effective active and holds the VIP
  - peer node is effective standby and does not hold the VIP
  - shared replication is fresh
  - optional post-upgrade failover or soak helper completed without errors
EOF

  log "HA pair upgrade validation completed. Review ${output_dir}/summary.json"
}

main "$@"
