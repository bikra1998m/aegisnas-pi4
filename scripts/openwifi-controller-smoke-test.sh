#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ADMIN_URL="http://127.0.0.1:8083"
ADMIN_TOKEN_ENV="AEGIS_ADMIN_TOKEN"
GATEWAY_URL=""
GATEWAY_API_KEY_ENV="AEGIS_OPENWIFI_API_KEY"
SELECTOR=""
OUTPUT_ROOT="/var/tmp/aegisnas-openwifi-certification"
OUTPUT_DIR=""
RUN_PUSH=0
TIMEOUT_SECONDS=180
POLL_SECONDS=5
SELF_TEST=0
STEPS_FILE=""
FAILURES=0
PREFLIGHT_READY=0
PUSH_READY=0

usage() {
  cat <<EOF
Usage:
  bash scripts/openwifi-controller-smoke-test.sh --gateway-url URL --selector VALUE [options]

Required:
  --gateway-url URL          OWGW API v1 base, for example https://host:16002/api/v1.
  --selector VALUE           AP serial number without separators or venue UUID.

Options:
  --admin-url URL            AegisNAS Admin API base. Default: ${ADMIN_URL}
  --admin-token-env NAME     Admin token environment variable. Default: ${ADMIN_TOKEN_ENV}
  --gateway-api-key-env NAME OWGW X-API-KEY environment variable. Default: ${GATEWAY_API_KEY_ENV}
  --output-root DIR          Evidence root. Default: ${OUTPUT_ROOT}
  --push                     Queue a confirmed configuration push and verify completion.
                             Also requires AEGIS_CERTIFY_OPENWIFI_PUSH=YES.
  --timeout-seconds N        Command and convergence timeout. Default: ${TIMEOUT_SECONDS}
  --poll-seconds N           Poll interval. Default: ${POLL_SECONDS}
  --self-test                Validate redaction and command-state helpers without network access.
  --help                     Show this help text.

The default run is read-only. Evidence never stores the admin token, OWGW API key,
RADIUS shared secrets, personal keys, or unredacted uCentral configuration.
EOF
}

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

sanitize_field() {
  printf '%s' "$1" | tr '\t\r\n' '   '
}

record_step() {
  local key="$1" status="$2" detail="$3" artifact="${4:-}"
  printf '%s\t%s\t%s\t%s\n' \
    "$(sanitize_field "${key}")" \
    "$(sanitize_field "${status}")" \
    "$(sanitize_field "${detail}")" \
    "$(sanitize_field "${artifact}")" >>"${STEPS_FILE}"
  if [[ "${status}" == "fail" ]]; then
    FAILURES=$((FAILURES + 1))
  fi
  log "${status^^}: ${key} - ${detail}"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --gateway-url) GATEWAY_URL="${2:-}"; shift 2 ;;
      --selector) SELECTOR="${2:-}"; shift 2 ;;
      --admin-url) ADMIN_URL="${2:-}"; shift 2 ;;
      --admin-token-env) ADMIN_TOKEN_ENV="${2:-}"; shift 2 ;;
      --gateway-api-key-env) GATEWAY_API_KEY_ENV="${2:-}"; shift 2 ;;
      --output-root) OUTPUT_ROOT="${2:-}"; shift 2 ;;
      --push) RUN_PUSH=1; shift ;;
      --timeout-seconds) TIMEOUT_SECONDS="${2:-}"; shift 2 ;;
      --poll-seconds) POLL_SECONDS="${2:-}"; shift 2 ;;
      --self-test) SELF_TEST=1; shift ;;
      --help|-h) usage; exit 0 ;;
      *) fail "unknown option: $1" ;;
    esac
  done

  if [[ "${SELF_TEST}" -eq 1 ]]; then
    return
  fi
  [[ -n "${GATEWAY_URL}" ]] || fail "--gateway-url is required"
  [[ "${GATEWAY_URL}" =~ ^https://[^[:space:]]+$ ]] || fail "--gateway-url must use https"
  GATEWAY_URL="${GATEWAY_URL%/}"
  [[ -n "${SELECTOR}" ]] || fail "--selector is required"
  [[ "${SELECTOR}" =~ ^[a-zA-Z0-9_-]+$ ]] || fail "--selector contains unsupported characters"
  [[ "${TIMEOUT_SECONDS}" =~ ^[1-9][0-9]*$ ]] || fail "--timeout-seconds must be a positive integer"
  [[ "${POLL_SECONDS}" =~ ^[1-9][0-9]*$ ]] || fail "--poll-seconds must be a positive integer"
  if [[ "${RUN_PUSH}" -eq 1 && "${AEGIS_CERTIFY_OPENWIFI_PUSH:-}" != "YES" ]]; then
    fail "--push requires AEGIS_CERTIFY_OPENWIFI_PUSH=YES"
  fi
}

read_admin_token() {
  local token="${!ADMIN_TOKEN_ENV:-}"
  if [[ -z "${token}" && -r /etc/default/aegisnas ]]; then
    token="$(awk -F= '/^AEGIS_ADMIN_BOOTSTRAP_TOKEN=/{print $2}' /etc/default/aegisnas | tail -n 1)"
  fi
  printf '%s' "${token}"
}

redact_json() {
  jq '
    def sensitive_key:
      ascii_downcase | test("^(secret|password|private-key|key|token|api[-_]?key)$");
    def scrub:
      walk(if type == "object" then
        with_entries(if (.key | sensitive_key) then .value = "<redacted>" else . end)
      else . end);
    if ((.configuration? | type) == "string") then
      .configuration = (try (.configuration | fromjson | scrub | tojson) catch "<invalid-configuration>")
    else . end | scrub
  '
}

admin_get() {
  local path="$1"
  curl -fsS -H "Authorization: Bearer ${ADMIN_TOKEN}" "${ADMIN_URL}/api/v1${path}"
}

admin_post() {
  local path="$1" body="$2"
  curl -fsS -X POST \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "${body}" \
    "${ADMIN_URL}/api/v1${path}"
}

gateway_get() {
  local path="$1"
  curl -fsS -H "X-API-KEY: ${GATEWAY_API_KEY}" -H "Accept: application/json" "${GATEWAY_URL}${path}"
}

command_failed() {
  jq -e '
    ((.errorCode? // 0) | tonumber? // 0) > 0 or
    ((.status? // "") | ascii_downcase | test("fail|error|reject|cancel"))
  ' >/dev/null
}

command_complete() {
  jq -e '
    ((.completed? // 0) | tonumber? // 0) > 0 or
    ((.status? // "") | ascii_downcase | test("^(complete|completed|done|success|succeeded)$"))
  ' >/dev/null
}

run_self_test() {
  if ! command -v jq >/dev/null 2>&1; then
    printf 'OpenWiFi controller smoke harness syntax passed; jq-dependent self-tests skipped (jq unavailable)\n'
    return
  fi
  local redacted
  redacted="$(printf '%s' '{"token":"admin-token-value","configuration":"{\"uuid\":1,\"radius\":{\"secret\":\"radius-secret-value\"},\"encryption\":{\"key\":\"psk-value\"}}"}' | redact_json)"
  [[ "${redacted}" != *'admin-token-value'* ]] || fail "top-level token redaction self-test failed"
  [[ "${redacted}" != *'radius-secret-value'* ]] || fail "configuration secret redaction self-test failed"
  [[ "${redacted}" != *'psk-value'* ]] || fail "configuration key redaction self-test failed"
  printf '%s' '{"status":"completed","errorCode":0}' | command_complete || fail "completed command self-test failed"
  if printf '%s' '{"status":"failed","errorCode":4}' | command_complete; then
    fail "failed command was classified as complete"
  fi
  printf '%s' '{"status":"failed","errorCode":4}' | command_failed || fail "failed command self-test failed"
  printf 'OpenWiFi controller smoke harness self-test passed\n'
}

collect_inventory() {
  local offset=1 page items count inventory='[]'
  while (( offset < 100000 )); do
    page="$(gateway_get "/devices?deviceWithStatus=true&limit=100&offset=${offset}&platform=ap")" || return 1
    items="$(jq -c '(.devicesWithStatus // .devices // [])' <<<"${page}")" || return 1
    count="$(jq -r 'length' <<<"${items}")"
    inventory="$(jq -cn --argjson current "${inventory}" --argjson page "${items}" '$current + $page')"
    if (( count < 100 )); then
      printf '%s' "${inventory}"
      return 0
    fi
    offset=$((offset + 100))
  done
  return 1
}

select_serials() {
  local inventory="$1"
  jq -r --arg selector "${SELECTOR,,}" '
    map(select(((.serialNumber // "") | ascii_downcase) == $selector)) as $serial_matches |
    if ($serial_matches | length) > 0 then $serial_matches
    else map(select(((.venue // "") | ascii_downcase) == $selector)) end |
    .[].serialNumber
  ' <<<"${inventory}"
}

collect_device_snapshot() {
  local serial="$1" phase="$2" response output
  output="${OUTPUT_DIR}/device-${phase}-${serial}.json"
  if ! response="$(gateway_get "/device/${serial}")"; then
    record_step "device_${phase}_${serial}" "fail" "Could not read AP ${serial}." "$(basename "${output}")"
    return 1
  fi
  printf '%s' "${response}" | redact_json >"${output}"
  if jq -e '(.configuration | type == "string") and ((.configuration | fromjson) | has("uuid"))' <<<"${response}" >/dev/null; then
    record_step "device_${phase}_${serial}" "pass" "AP ${serial} returned a valid uCentral document." "$(basename "${output}")"
    return 0
  fi
  record_step "device_${phase}_${serial}" "fail" "AP ${serial} did not return a valid uCentral document with uuid." "$(basename "${output}")"
  return 1
}

run_preflight() {
  local adapters inventory selected safe_selected="" failures_before="${FAILURES}" serial
  if adapters="$(admin_get "/system/controller-adapters")" &&
    jq -e '.configured.normalized_platform == "openwifi" and .configured.ready == true' <<<"${adapters}" >/dev/null; then
    printf '%s' "${adapters}" | redact_json >"${OUTPUT_DIR}/controller-adapters.json"
    record_step "aegisnas_readiness" "pass" "AegisNAS reports the OpenWiFi adapter ready." "controller-adapters.json"
  else
    printf '%s' "${adapters:-{}}" | redact_json >"${OUTPUT_DIR}/controller-adapters.json" 2>/dev/null || true
    record_step "aegisnas_readiness" "fail" "AegisNAS OpenWiFi adapter is not ready." "controller-adapters.json"
  fi

  if ! inventory="$(collect_inventory)"; then
    record_step "owgw_inventory" "fail" "Could not page OWGW AP inventory." "owgw-inventory.json"
    return
  fi
  jq -n --argjson devices "${inventory}" '{devicesWithStatus:$devices}' | redact_json >"${OUTPUT_DIR}/owgw-inventory.json"
  selected="$(select_serials "${inventory}")"
  if [[ -z "${selected}" ]]; then
    record_step "owgw_inventory" "fail" "Selector ${SELECTOR} matched no OWGW AP." "owgw-inventory.json"
    return
  fi
  while IFS= read -r serial; do
    [[ -n "${serial}" ]] || continue
    if [[ ! "${serial}" =~ ^[a-zA-Z0-9_-]+$ ]]; then
      record_step "owgw_inventory" "fail" "OWGW returned an unsafe AP serial number." "owgw-inventory.json"
      continue
    fi
    safe_selected+="${serial}"$'\n'
  done <<<"${selected}"
  if [[ -z "${safe_selected}" ]]; then
    record_step "owgw_inventory" "fail" "Selector ${SELECTOR} matched no safe OWGW AP serial number." "owgw-inventory.json"
    return
  fi
  printf '%s' "${safe_selected}" >"${OUTPUT_DIR}/selected-devices.txt"
  record_step "owgw_inventory" "pass" "Selector ${SELECTOR} matched $(wc -l <"${OUTPUT_DIR}/selected-devices.txt") AP(s)." "owgw-inventory.json"
  while IFS= read -r serial; do
    [[ -n "${serial}" ]] && collect_device_snapshot "${serial}" "before" || true
  done <"${OUTPUT_DIR}/selected-devices.txt"
  if [[ "${FAILURES}" -eq "${failures_before}" ]]; then
    PREFLIGHT_READY=1
  fi
}

run_pull() {
  local preview result drift failed
  if ! preview="$(admin_get "/system/controller-sync/preview?operation=pull")" ||
    ! jq -e '.preview.adapter == "tip-openwifi-owgw"' <<<"${preview}" >/dev/null; then
    record_step "controller_pull_preview" "fail" "OpenWiFi pull preview failed or selected the wrong adapter." "controller-pull-preview.json"
    return
  fi
  printf '%s' "${preview}" | redact_json >"${OUTPUT_DIR}/controller-pull-preview.json"
  record_step "controller_pull_preview" "pass" "OpenWiFi read-only pull preview is valid." "controller-pull-preview.json"

  if ! result="$(admin_post "/system/controller-sync" '{"operation":"pull"}')"; then
    record_step "controller_pull" "fail" "OpenWiFi pull request failed." "controller-pull.json"
    return
  fi
  printf '%s' "${result}" | redact_json >"${OUTPUT_DIR}/controller-pull.json"
  drift="$(jq -r '.result.drift_detected // false' <<<"${result}")"
  failed="$(jq -r '.result.failed_count // 0' <<<"${result}")"
  if [[ "${failed}" != "0" ]]; then
    record_step "controller_pull" "fail" "OpenWiFi pull reported ${failed} failed item(s)." "controller-pull.json"
  elif [[ "${drift}" == "true" && "${RUN_PUSH}" -eq 0 ]]; then
    record_step "controller_pull" "fail" "OpenWiFi pull reported drift; rerun with a reviewed push only when intentional." "controller-pull.json"
  elif [[ "${drift}" == "true" ]]; then
    record_step "controller_pull" "pass" "OpenWiFi pull found intentional drift for the guarded push drill." "controller-pull.json"
    PUSH_READY=1
  elif [[ "${RUN_PUSH}" -eq 1 ]]; then
    record_step "controller_pull" "fail" "Push drill requires a reviewed, intentional drift item; pull was already clean." "controller-pull.json"
  else
    record_step "controller_pull" "pass" "OpenWiFi pull is clean." "controller-pull.json"
  fi
}

poll_command() {
  local serial="$1" command_uuid="$2" deadline response artifact
  if [[ ! "${serial}" =~ ^[a-zA-Z0-9_-]+$ || ! "${command_uuid}" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    record_step "command_receipt" "fail" "OWGW returned an unsafe serial number or command UUID." "controller-push.json"
    return 1
  fi
  deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
  artifact="command-${command_uuid}.json"
  while (( $(date +%s) <= deadline )); do
    if response="$(gateway_get "/command/${command_uuid}")"; then
      printf '%s' "${response}" | redact_json >"${OUTPUT_DIR}/${artifact}"
      if command_failed <<<"${response}"; then
        record_step "command_${command_uuid}" "fail" "OWGW command for ${serial} failed." "${artifact}"
        return 1
      fi
      if command_complete <<<"${response}"; then
        record_step "command_${command_uuid}" "pass" "OWGW command for ${serial} completed." "${artifact}"
        return 0
      fi
    fi
    sleep "${POLL_SECONDS}"
  done
  record_step "command_${command_uuid}" "fail" "OWGW command for ${serial} did not complete within ${TIMEOUT_SECONDS}s." "${artifact}"
  return 1
}

wait_for_convergence() {
  local deadline result artifact="controller-post-push-pull.json"
  deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
  while (( $(date +%s) <= deadline )); do
    if result="$(admin_post "/system/controller-sync" '{"operation":"pull"}')"; then
      printf '%s' "${result}" | redact_json >"${OUTPUT_DIR}/${artifact}"
      if jq -e '(.result.failed_count // 0) == 0 and (.result.drift_detected // false) == false' <<<"${result}" >/dev/null; then
        record_step "post_push_convergence" "pass" "AegisNAS pull reports no OpenWiFi drift after command completion." "${artifact}"
        return 0
      fi
    fi
    sleep "${POLL_SECONDS}"
  done
  record_step "post_push_convergence" "fail" "OpenWiFi policy did not converge within ${TIMEOUT_SECONDS}s." "${artifact}"
  return 1
}

run_push() {
  if [[ "${RUN_PUSH}" -eq 0 ]]; then
    record_step "controller_push" "skip" "Push was not requested." ""
    return
  fi
  if [[ "${PREFLIGHT_READY}" -ne 1 || "${PUSH_READY}" -ne 1 || ! -s "${OUTPUT_DIR}/selected-devices.txt" ]]; then
    record_step "controller_push" "fail" "Push blocked because OWGW preflight or intentional-drift pull gate did not pass." "controller-pull.json"
    return
  fi
  local preview result receipts applied receipt_count serial command_uuid
  if ! preview="$(admin_get "/system/controller-sync/preview?operation=push")" ||
    ! jq -e '.preview.adapter == "tip-openwifi-owgw"' <<<"${preview}" >/dev/null; then
    record_step "controller_push_preview" "fail" "OpenWiFi push preview failed or selected the wrong adapter." "controller-push-preview.json"
    return
  fi
  printf '%s' "${preview}" | redact_json >"${OUTPUT_DIR}/controller-push-preview.json"
  record_step "controller_push_preview" "pass" "OpenWiFi push preview is valid and redacted." "controller-push-preview.json"

  if ! result="$(admin_post "/system/controller-sync" '{"operation":"push","confirmation":"PUSH CONTROLLER POLICY"}')"; then
    record_step "controller_push" "fail" "Confirmed OpenWiFi push request failed." "controller-push.json"
    return
  fi
  printf '%s' "${result}" | redact_json >"${OUTPUT_DIR}/controller-push.json"
  applied="$(jq -r '.result.applied_count // 0' <<<"${result}")"
  receipts="$(jq -c '.result.details.queued_commands // []' <<<"${result}")"
  receipt_count="$(jq -r 'length' <<<"${receipts}")"
  if ! jq -e '.status == "ok" and (.result.failed_count // 0) == 0' <<<"${result}" >/dev/null ||
    [[ "${applied}" -lt 1 || "${receipt_count}" != "${applied}" ]]; then
    record_step "controller_push" "fail" "Push did not return one OWGW command receipt per applied AP." "controller-push.json"
    return
  fi
  record_step "controller_push" "pass" "AegisNAS queued ${applied} OWGW AP configuration command(s)." "controller-push.json"

  while IFS=$'\t' read -r serial command_uuid; do
    [[ -n "${serial}" && -n "${command_uuid}" ]] || continue
    poll_command "${serial}" "${command_uuid}" || true
  done < <(jq -r '.[] | [.serial_number,.command_uuid] | @tsv' <<<"${receipts}")
  wait_for_convergence || true
  while IFS= read -r serial; do
    [[ -n "${serial}" ]] && collect_device_snapshot "${serial}" "after" || true
  done <"${OUTPUT_DIR}/selected-devices.txt"
}

write_summary() {
  local status="passed" git_head="unknown"
  [[ "${FAILURES}" -eq 0 ]] || status="failed"
  if [[ -d "${REPO_ROOT}/.git" ]]; then
    git_head="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"
  fi
  jq -Rn \
    --arg generated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg status "${status}" \
    --arg selector "${SELECTOR}" \
    --arg gateway_url "${GATEWAY_URL}" \
    --arg git_head "${git_head}" \
    '[inputs | select(length > 0) | split("\t") | {
      key:.[0], status:.[1], detail:.[2], artifact:(if (.[3] | length) > 0 then .[3] else null end)
    }] as $steps | {
      generated_at:$generated_at, status:$status, selector:$selector,
      gateway_url:$gateway_url, git_head:$git_head,
      summary:{total:($steps|length),passed:($steps|map(select(.status=="pass"))|length),failed:($steps|map(select(.status=="fail"))|length),skipped:($steps|map(select(.status=="skip"))|length)},
      steps:$steps
    }' "${STEPS_FILE}" >"${OUTPUT_DIR}/summary.json"
  log "OpenWiFi certification ${status}. Evidence: ${OUTPUT_DIR}/summary.json"
}

main() {
  parse_args "$@"
  if [[ "${SELF_TEST}" -eq 1 ]]; then
    run_self_test
    return
  fi
  require_cmd curl
  require_cmd jq
  ADMIN_TOKEN="$(read_admin_token)"
  GATEWAY_API_KEY="${!GATEWAY_API_KEY_ENV:-}"
  [[ -n "${ADMIN_TOKEN}" ]] || fail "admin token environment variable ${ADMIN_TOKEN_ENV} is empty"
  [[ -n "${GATEWAY_API_KEY}" ]] || fail "OWGW API key environment variable ${GATEWAY_API_KEY_ENV} is empty"

  OUTPUT_DIR="${OUTPUT_ROOT}/$(date '+%Y%m%d-%H%M%S')-${SELECTOR}"
  mkdir -p "${OUTPUT_DIR}"
  STEPS_FILE="${OUTPUT_DIR}/steps.tsv"
  : >"${STEPS_FILE}"

  run_preflight
  run_pull
  run_push
  write_summary
  [[ "${FAILURES}" -eq 0 ]]
}

main "$@"
