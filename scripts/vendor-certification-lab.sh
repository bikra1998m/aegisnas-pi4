#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_ROOT="/var/tmp/aegisnas-vendor-certification"
ADMIN_URL="http://127.0.0.1:8083"
ADMIN_TOKEN_ENV="AEGIS_ADMIN_TOKEN"
PACK=""
NAS_TYPE=""
EXPECTED_ATTRIBUTE=""
RADIUS_HOST="127.0.0.1"
RADIUS_USER=""
RADIUS_PASSWORD_ENV="AEGIS_CERT_RADIUS_PASSWORD"
RADIUS_SECRET_ENV="AEGIS_RADIUS_SECRET"
CAPTURE_INTERFACE=""
CAPTURE_SECONDS=0
DEVICE_IP=""
RUN_CONTROLLER_PULL=0
RUN_CONTROLLER_PUSH=0
ALLOW_DRIFT=0
RUN_FREERADIUS_CHECK=0
RUN_UPGRADE_SMOKE=0
RUN_ROLLBACK_REHEARSAL=0
WAN_IFACE=""
LAN_IFACE=""
SELF_TEST=0
ALLOW_PLACEHOLDER_PEN=0
OUTPUT_DIR=""
STEPS_FILE=""
CAPTURE_PID=""
REQUIRED_FAILURES=0

usage() {
  cat <<EOF
Usage:
  bash scripts/vendor-certification-lab.sh --pack PACK [options]

Required:
  --pack PACK                 Vendor compatibility pack, such as cisco, aruba, fortinet, ruckus, ubnt, or mist.

Core options:
  --nas-type TYPE             NAS profile used for reply preview. Defaults to PACK.
  --expected-attribute NAME   Vendor reply attribute that must be present.
  --admin-url URL             Admin API base URL. Default: ${ADMIN_URL}
  --admin-token-env NAME      Environment variable containing an admin token. Default: ${ADMIN_TOKEN_ENV}
  --output-root DIR           Evidence output root. Default: ${OUTPUT_ROOT}

Live RADIUS and packet options:
  --radius-user USER          Run radtest and accounting checks for this user.
  --radius-host HOST          RADIUS host. Default: ${RADIUS_HOST}
  --radius-password-env NAME  Environment variable containing the test password.
  --radius-secret-env NAME    Environment variable containing the RADIUS shared secret.
  --capture-interface IFACE   Capture RADIUS, CoA, DHCP, and DNS packets with tcpdump. Requires root.
  --capture-seconds N         Keep packet capture open N seconds for a real-device association attempt.
  --device-ip ADDRESS         Require a successful ping to a real AP, switch, or controller.
  --freeradius-check          Require a successful freeradius -XC configuration check.

Controller options:
  --controller-pull           Run read-only controller pull and drift comparison.
  --allow-drift               Record controller drift as a warning instead of a failure.
  --controller-push           Run a confirmed controller policy push. Also requires AEGIS_CERTIFY_CONTROLLER_PUSH=YES.

Upgrade options:
  --upgrade-smoke             Run the existing Ubuntu VM upgrade smoke script. Requires root, --wan, and --lan.
  --rollback-rehearsal        Run the existing non-applying rollback rehearsal. Requires root.
  --wan IFACE                 WAN interface passed to the upgrade smoke script.
  --lan IFACE                 LAN interface passed to the upgrade smoke script.

Other:
  --self-test                 Validate harness mappings and argument-independent helpers.
  --allow-placeholder-pen     Lab only: do not fail while AegisNAS still uses its placeholder PEN.
  --help                      Show this help text.

The default run is non-mutating. Controller push and upgrade actions are explicit opt-ins.
Every run writes summary.json and evidence artifacts under OUTPUT_ROOT/<timestamp>-<pack>/.
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

require_root() {
  [[ "${EUID}" -eq 0 ]] || fail "$1 requires sudo or root"
}

expected_attribute_for_pack() {
  case "${1,,}" in
    aegisnas) printf '%s' 'AegisNAS-Role' ;;
    cisco) printf '%s' 'Cisco-AVPair' ;;
    aruba) printf '%s' 'Aruba-User-Role' ;;
    mikrotik) printf '%s' 'Mikrotik-Rate-Limit' ;;
    ruckus) printf '%s' 'Ruckus-User-Groups' ;;
    fortinet) printf '%s' 'Fortinet-Group-Name' ;;
    ubnt) printf '%s' 'UBNT-Data-Rate-DL' ;;
    cambium) printf '%s' 'Cambium-ePMP-Data-VLAN-Id' ;;
    extreme) printf '%s' 'Extreme-Security-Profile' ;;
    juniper) printf '%s' 'Juniper-Local-User-Name' ;;
    huawei) printf '%s' 'Huawei-User-Class' ;;
    h3c) printf '%s' 'H3C-User-Role' ;;
    paloalto) printf '%s' 'PaloAlto-Admin-Role' ;;
    tplink) printf '%s' 'TPLink-Xmit-limit' ;;
    hp) printf '%s' 'User-Role' ;;
    dlink) printf '%s' 'VLAN-ID' ;;
    arista) printf '%s' 'User-Role' ;;
    pica8) printf '%s' 'IP-Downloadable-ACL-Name' ;;
    zte) printf '%s' 'Rate-Ctrl-SCR-Down' ;;
    nokia) printf '%s' 'User-Profile' ;;
    mist) printf '%s' '' ;;
    standard|wispr|meraki|aerohive|airespace|nomadix|chillispot|sonicwall|meru|colubris|openwifi) printf '%s' '' ;;
    *) printf '%s' '' ;;
  esac
}

run_self_test() {
  [[ "$(expected_attribute_for_pack cisco)" == "Cisco-AVPair" ]] || fail "Cisco mapping self-test failed"
  [[ "$(expected_attribute_for_pack aruba)" == "Aruba-User-Role" ]] || fail "Aruba mapping self-test failed"
  [[ "$(expected_attribute_for_pack fortinet)" == "Fortinet-Group-Name" ]] || fail "Fortinet mapping self-test failed"
  [[ -z "$(expected_attribute_for_pack standard)" ]] || fail "standard mapping self-test failed"
  printf 'vendor certification harness self-test passed\n'
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pack) PACK="${2:-}"; shift 2 ;;
      --nas-type) NAS_TYPE="${2:-}"; shift 2 ;;
      --expected-attribute) EXPECTED_ATTRIBUTE="${2:-}"; shift 2 ;;
      --admin-url) ADMIN_URL="${2:-}"; shift 2 ;;
      --admin-token-env) ADMIN_TOKEN_ENV="${2:-}"; shift 2 ;;
      --output-root) OUTPUT_ROOT="${2:-}"; shift 2 ;;
      --radius-user) RADIUS_USER="${2:-}"; shift 2 ;;
      --radius-host) RADIUS_HOST="${2:-}"; shift 2 ;;
      --radius-password-env) RADIUS_PASSWORD_ENV="${2:-}"; shift 2 ;;
      --radius-secret-env) RADIUS_SECRET_ENV="${2:-}"; shift 2 ;;
      --capture-interface) CAPTURE_INTERFACE="${2:-}"; shift 2 ;;
      --capture-seconds) CAPTURE_SECONDS="${2:-}"; shift 2 ;;
      --device-ip) DEVICE_IP="${2:-}"; shift 2 ;;
      --freeradius-check) RUN_FREERADIUS_CHECK=1; shift ;;
      --controller-pull) RUN_CONTROLLER_PULL=1; shift ;;
      --allow-drift) ALLOW_DRIFT=1; shift ;;
      --controller-push) RUN_CONTROLLER_PUSH=1; shift ;;
      --upgrade-smoke) RUN_UPGRADE_SMOKE=1; shift ;;
      --rollback-rehearsal) RUN_ROLLBACK_REHEARSAL=1; shift ;;
      --wan) WAN_IFACE="${2:-}"; shift 2 ;;
      --lan) LAN_IFACE="${2:-}"; shift 2 ;;
      --self-test) SELF_TEST=1; shift ;;
      --allow-placeholder-pen) ALLOW_PLACEHOLDER_PEN=1; shift ;;
      --help|-h) usage; exit 0 ;;
      *) fail "unknown option: $1" ;;
    esac
  done

  if [[ "${SELF_TEST}" -eq 1 ]]; then
    return
  fi
  PACK="${PACK,,}"
  [[ -n "${PACK}" ]] || fail "--pack is required"
  [[ "${PACK}" =~ ^[a-z0-9_-]+$ ]] || fail "--pack contains unsupported characters"
  NAS_TYPE="${NAS_TYPE:-${PACK}}"
  EXPECTED_ATTRIBUTE="${EXPECTED_ATTRIBUTE:-$(expected_attribute_for_pack "${PACK}")}"
  [[ "${CAPTURE_SECONDS}" =~ ^[0-9]+$ ]] || fail "--capture-seconds must be a non-negative integer"
  if [[ "${CAPTURE_SECONDS}" -gt 0 && -z "${CAPTURE_INTERFACE}" ]]; then
    fail "--capture-seconds requires --capture-interface"
  fi
  for endpoint in "${RADIUS_HOST}" "${DEVICE_IP}"; do
    [[ -z "${endpoint}" || "${endpoint}" =~ ^[a-zA-Z0-9._:-]+$ ]] || fail "network address contains unsupported characters: ${endpoint}"
  done
  for interface_name in "${CAPTURE_INTERFACE}" "${WAN_IFACE}" "${LAN_IFACE}"; do
    [[ -z "${interface_name}" || "${interface_name}" =~ ^[a-zA-Z0-9._:-]+$ ]] || fail "interface name contains unsupported characters: ${interface_name}"
  done
  if [[ "${RUN_UPGRADE_SMOKE}" -eq 1 ]]; then
    [[ -n "${WAN_IFACE}" && -n "${LAN_IFACE}" ]] || fail "--upgrade-smoke requires --wan and --lan"
  fi
  if [[ "${RUN_CONTROLLER_PUSH}" -eq 1 && "${AEGIS_CERTIFY_CONTROLLER_PUSH:-}" != "YES" ]]; then
    fail "--controller-push requires AEGIS_CERTIFY_CONTROLLER_PUSH=YES"
  fi
}

sanitize_field() {
  printf '%s' "$1" | tr '\t\r\n' '   '
}

record_step() {
  local key="$1" status="$2" required="$3" detail="$4" artifact="${5:-}"
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "$(sanitize_field "${key}")" \
    "$(sanitize_field "${status}")" \
    "${required}" \
    "$(sanitize_field "${detail}")" \
    "$(sanitize_field "${artifact}")" >>"${STEPS_FILE}"
  if [[ "${status}" == "fail" && "${required}" == "true" ]]; then
    REQUIRED_FAILURES=$((REQUIRED_FAILURES + 1))
  fi
  log "${status^^}: ${key} - ${detail}"
}

read_admin_token() {
  local token="${!ADMIN_TOKEN_ENV:-}"
  if [[ -z "${token}" && -r /etc/default/aegisnas ]]; then
    token="$(awk -F= '/^AEGIS_ADMIN_BOOTSTRAP_TOKEN=/{print $2}' /etc/default/aegisnas | tail -n 1)"
  fi
  printf '%s' "${token}"
}

api_get() {
  local path="$1" output="$2"
  curl -fsS -H "Authorization: Bearer ${ADMIN_TOKEN}" "${ADMIN_URL}/api/v1${path}" >"${output}"
}

api_post() {
  local path="$1" body="$2" output="$3"
  curl -fsS -X POST \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "${body}" \
    "${ADMIN_URL}/api/v1${path}" >"${output}"
}

start_capture() {
  if [[ -z "${CAPTURE_INTERFACE}" ]]; then
    record_step "packet_capture" "skip" "false" "No capture interface requested." ""
    return
  fi
  require_root "packet capture"
  require_cmd tcpdump
  local capture_file="${OUTPUT_DIR}/packets.pcap"
  tcpdump -i "${CAPTURE_INTERFACE}" -U -n -w "${capture_file}" \
    '(udp port 1812 or udp port 1813 or udp port 3799 or udp port 67 or udp port 68 or udp port 53)' \
    >"${OUTPUT_DIR}/tcpdump.log" 2>&1 &
  CAPTURE_PID=$!
  sleep 1
  if kill -0 "${CAPTURE_PID}" 2>/dev/null; then
    log "Packet capture started on ${CAPTURE_INTERFACE} with PID ${CAPTURE_PID}."
  else
    CAPTURE_PID=""
    record_step "packet_capture" "fail" "true" "tcpdump did not remain running." "tcpdump.log"
  fi
}

stop_capture() {
  if [[ -z "${CAPTURE_PID}" ]]; then
    return
  fi
  kill -INT "${CAPTURE_PID}" 2>/dev/null || true
  wait "${CAPTURE_PID}" 2>/dev/null || true
  CAPTURE_PID=""
  local capture_file="${OUTPUT_DIR}/packets.pcap"
  if [[ -s "${capture_file}" ]]; then
    tcpdump -nn -r "${capture_file}" >"${OUTPUT_DIR}/packets.txt" 2>&1 || true
    if [[ -s "${OUTPUT_DIR}/packets.txt" ]]; then
      record_step "packet_capture" "pass" "true" "Captured and decoded certification traffic." "packets.pcap"
    else
      record_step "packet_capture" "fail" "true" "Capture file did not contain decodable packets." "packets.pcap"
    fi
  else
    record_step "packet_capture" "fail" "true" "No certification packets were captured." "packets.pcap"
  fi
}

run_catalog_check() {
  local output="${OUTPUT_DIR}/vendor-compatibility.json"
  if api_get "/system/vendor-compatibility" "${output}"; then
    if jq -e --arg pack "${PACK}" '.packs | any(.key == $pack)' "${output}" >/dev/null; then
      record_step "vendor_catalog" "pass" "true" "Compatibility pack ${PACK} is present in the runtime catalog." "vendor-compatibility.json"
    else
      record_step "vendor_catalog" "fail" "true" "Compatibility pack ${PACK} is absent from the runtime catalog." "vendor-compatibility.json"
    fi
    local placeholder
    placeholder="$(jq -r '.summary.product_vendor_id_placeholder // true' "${output}")"
    if [[ "${placeholder}" == "true" && "${ALLOW_PLACEHOLDER_PEN}" -eq 0 ]]; then
      record_step "vendor_identity" "fail" "true" "AegisNAS still uses the placeholder Private Enterprise Number." "vendor-compatibility.json"
    elif [[ "${placeholder}" == "true" ]]; then
      record_step "vendor_identity" "pass" "true" "Placeholder PEN accepted for this lab-only run." "vendor-compatibility.json"
    else
      record_step "vendor_identity" "pass" "true" "AegisNAS reports a non-placeholder Private Enterprise Number." "vendor-compatibility.json"
    fi
  else
    record_step "vendor_catalog" "fail" "true" "Could not read vendor compatibility catalog." "vendor-compatibility.json"
    record_step "vendor_identity" "fail" "true" "Could not verify AegisNAS vendor identity." "vendor-compatibility.json"
  fi
}

run_reply_preview_check() {
  local output="${OUTPUT_DIR}/vendor-reply-preview.json" body
  body="$(jq -cn \
    --arg nas_type "${NAS_TYPE}" \
    --arg pack "${PACK}" \
    '{nas_type:$nas_type,compatibility_packs:["standard",$pack],role:"certification-user",vlan:4094,download_kbps:10000,upload_kbps:5000,acl_policy_name:"certification-acl",acl_rules:[{action:"permit",direction:"in",protocol:"tcp",source:"any",destination:"any",destination_port:"443"}]}')"
  if ! api_post "/system/vendor-reply-preview" "${body}" "${output}"; then
    record_step "vendor_reply_preview" "fail" "true" "Vendor reply preview request failed." "vendor-reply-preview.json"
    return
  fi
  if ! jq -e --arg pack "${PACK}" '.effective_packs | index($pack) != null' "${output}" >/dev/null; then
    record_step "vendor_reply_preview" "fail" "true" "Effective reply packs do not include ${PACK}." "vendor-reply-preview.json"
    return
  fi
  if [[ -n "${EXPECTED_ATTRIBUTE}" ]] && ! jq -e --arg attribute "${EXPECTED_ATTRIBUTE}" '.attributes | any(.name == $attribute)' "${output}" >/dev/null; then
    record_step "vendor_reply_preview" "fail" "true" "Expected attribute ${EXPECTED_ATTRIBUTE} was not rendered." "vendor-reply-preview.json"
    return
  fi
  if ! jq -e '.attributes | length > 0' "${output}" >/dev/null; then
    record_step "vendor_reply_preview" "fail" "true" "Reply preview rendered no attributes." "vendor-reply-preview.json"
    return
  fi
  record_step "vendor_reply_preview" "pass" "true" "Vendor reply and ACL intent rendered for ${NAS_TYPE}." "vendor-reply-preview.json"
}

run_freeradius_check() {
  if [[ "${RUN_FREERADIUS_CHECK}" -eq 0 ]]; then
    record_step "freeradius_config" "skip" "false" "FreeRADIUS validation was not requested." ""
    return
  fi
  require_cmd freeradius
  if freeradius -XC >"${OUTPUT_DIR}/freeradius-check.txt" 2>&1; then
    record_step "freeradius_config" "pass" "true" "FreeRADIUS configuration validation passed." "freeradius-check.txt"
  else
    record_step "freeradius_config" "fail" "true" "FreeRADIUS configuration validation failed." "freeradius-check.txt"
  fi
}

run_radius_checks() {
  if [[ -z "${RADIUS_USER}" ]]; then
    record_step "radius_authentication" "skip" "false" "No RADIUS test user was requested." ""
    record_step "radius_accounting" "skip" "false" "No RADIUS test user was requested." ""
    return
  fi
  require_cmd radtest
  require_cmd radclient
  local password="${!RADIUS_PASSWORD_ENV:-}" secret="${!RADIUS_SECRET_ENV:-}"
  [[ -n "${password}" ]] || fail "RADIUS password environment variable ${RADIUS_PASSWORD_ENV} is empty"
  [[ -n "${secret}" ]] || fail "RADIUS secret environment variable ${RADIUS_SECRET_ENV} is empty"

  local auth_raw="${OUTPUT_DIR}/radius-auth.raw" auth_ok=0
  if radtest "${RADIUS_USER}" "${password}" "${RADIUS_HOST}" 0 "${secret}" >"${auth_raw}" 2>&1 && \
    grep -q 'Access-Accept' "${auth_raw}"; then
    auth_ok=1
  fi
  sed -E 's/^([[:space:]]*(User-Password|Cleartext-Password|PAP-Password)[[:space:]]*=).*/\1 "<redacted>"/I' \
    "${auth_raw}" >"${OUTPUT_DIR}/radius-auth.txt"
  rm -f "${auth_raw}"
  if [[ "${auth_ok}" -eq 1 ]]; then
    record_step "radius_authentication" "pass" "true" "RADIUS Access-Accept received for ${RADIUS_USER}." "radius-auth.txt"
  else
    record_step "radius_authentication" "fail" "true" "RADIUS authentication did not return Access-Accept." "radius-auth.txt"
  fi

  local session_id="aegis-cert-$(date +%s)"
  if printf 'User-Name = "%s"\nAcct-Status-Type = Start\nAcct-Session-Id = "%s"\nNAS-IP-Address = 127.0.0.1\n' "${RADIUS_USER}" "${session_id}" | \
    radclient -x "${RADIUS_HOST}:1813" acct "${secret}" >"${OUTPUT_DIR}/radius-accounting.txt" 2>&1 && \
    grep -q 'Accounting-Response' "${OUTPUT_DIR}/radius-accounting.txt"; then
    record_step "radius_accounting" "pass" "true" "RADIUS accounting start received Accounting-Response." "radius-accounting.txt"
  else
    record_step "radius_accounting" "fail" "true" "RADIUS accounting did not return Accounting-Response." "radius-accounting.txt"
  fi
}

run_device_check() {
  if [[ -z "${DEVICE_IP}" ]]; then
    record_step "real_device_reachability" "skip" "false" "No real device address was requested." ""
    return
  fi
  require_cmd ping
  if ping -c 3 -W 2 "${DEVICE_IP}" >"${OUTPUT_DIR}/device-ping.txt" 2>&1; then
    record_step "real_device_reachability" "pass" "true" "Real AP, switch, or controller ${DEVICE_IP} is reachable." "device-ping.txt"
  else
    record_step "real_device_reachability" "fail" "true" "Real device ${DEVICE_IP} did not answer ping." "device-ping.txt"
  fi
}

run_controller_checks() {
  if [[ "${RUN_CONTROLLER_PULL}" -eq 0 ]]; then
    record_step "controller_pull" "skip" "false" "Controller pull was not requested." ""
  else
    local preview="${OUTPUT_DIR}/controller-pull-preview.json" result="${OUTPUT_DIR}/controller-pull.json"
    if api_get "/system/controller-sync/preview?operation=pull" "${preview}" && \
      api_post "/system/controller-sync" '{"operation":"pull"}' "${result}"; then
      local drift
      drift="$(jq -r '.result.drift_detected // false' "${result}")"
      if [[ "${drift}" == "true" && "${ALLOW_DRIFT}" -eq 0 ]]; then
        record_step "controller_pull" "fail" "true" "Controller pull reported policy drift." "controller-pull.json"
      else
        record_step "controller_pull" "pass" "true" "Controller pull completed; drift=${drift}." "controller-pull.json"
      fi
    else
      record_step "controller_pull" "fail" "true" "Controller pull or preview failed." "controller-pull.json"
    fi
  fi

  if [[ "${RUN_CONTROLLER_PUSH}" -eq 0 ]]; then
    record_step "controller_push" "skip" "false" "Controller push was not requested." ""
    return
  fi
  local preview="${OUTPUT_DIR}/controller-push-preview.json" result="${OUTPUT_DIR}/controller-push.json"
  if api_get "/system/controller-sync/preview?operation=push" "${preview}" && \
    api_post "/system/controller-sync" '{"operation":"push","confirmation":"PUSH CONTROLLER POLICY"}' "${result}" && \
    jq -e '.status == "ok" and ((.result.failed_count // 0) == 0)' "${result}" >/dev/null && \
    { [[ "${PACK}" != "openwifi" ]] || jq -e '
        (.result.applied_count // 0) > 0 and
        ((.result.details.queued_commands // []) | length) == (.result.applied_count // 0) and
        ((.result.details.queued_commands // []) | all((.serial_number // "") != "" and (.command_uuid // "") != ""))
      ' "${result}" >/dev/null; }; then
    record_step "controller_push" "pass" "true" "Confirmed controller policy push completed." "controller-push.json"
  else
    record_step "controller_push" "fail" "true" "Controller policy push failed or reported failed items." "controller-push.json"
  fi
}

run_upgrade_checks() {
  if [[ "${RUN_UPGRADE_SMOKE}" -eq 0 ]]; then
    record_step "upgrade_smoke" "skip" "false" "Ubuntu upgrade smoke test was not requested." ""
  else
    require_root "upgrade smoke test"
    if bash "${REPO_ROOT}/scripts/ubuntu-vm-upgrade-smoke-test.sh" --wan "${WAN_IFACE}" --lan "${LAN_IFACE}" >"${OUTPUT_DIR}/upgrade-smoke.txt" 2>&1; then
      record_step "upgrade_smoke" "pass" "true" "Ubuntu in-place upgrade smoke test passed." "upgrade-smoke.txt"
    else
      record_step "upgrade_smoke" "fail" "true" "Ubuntu in-place upgrade smoke test failed." "upgrade-smoke.txt"
    fi
  fi

  if [[ "${RUN_ROLLBACK_REHEARSAL}" -eq 0 ]]; then
    record_step "rollback_rehearsal" "skip" "false" "Rollback rehearsal was not requested." ""
  else
    require_root "rollback rehearsal"
    if bash "${REPO_ROOT}/scripts/ubuntu-upgrade-rollback-rehearsal.sh" --output-dir "${OUTPUT_DIR}/rollback" >"${OUTPUT_DIR}/rollback-rehearsal.txt" 2>&1; then
      record_step "rollback_rehearsal" "pass" "true" "Version-aware rollback rehearsal passed." "rollback-rehearsal.txt"
    else
      record_step "rollback_rehearsal" "fail" "true" "Version-aware rollback rehearsal failed." "rollback-rehearsal.txt"
    fi
  fi
}

write_summary() {
  local git_head="unknown" overall="passed"
  if [[ -d "${REPO_ROOT}/.git" ]]; then
    git_head="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"
  fi
  if [[ "${REQUIRED_FAILURES}" -gt 0 ]]; then
    overall="failed"
  fi
  jq -Rn \
    --arg generated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg status "${overall}" \
    --arg pack "${PACK}" \
    --arg nas_type "${NAS_TYPE}" \
    --arg expected_attribute "${EXPECTED_ATTRIBUTE}" \
    --arg admin_url "${ADMIN_URL}" \
    --arg git_head "${git_head}" \
    '[inputs | select(length > 0) | split("\t") | {
      key: .[0], status: .[1], required: (.[2] == "true"), detail: .[3], artifact: (if (.[4] | length) > 0 then .[4] else null end)
    }] as $steps |
    {
      generated_at: $generated_at,
      status: $status,
      pack: $pack,
      nas_type: $nas_type,
      expected_attribute: $expected_attribute,
      admin_url: $admin_url,
      git_head: $git_head,
      summary: {
        total: ($steps | length),
        passed: ($steps | map(select(.status == "pass")) | length),
        failed: ($steps | map(select(.status == "fail")) | length),
        skipped: ($steps | map(select(.status == "skip")) | length),
        required_failures: ($steps | map(select(.status == "fail" and .required)) | length)
      },
      steps: $steps
    }' "${STEPS_FILE}" >"${OUTPUT_DIR}/summary.json"
  log "Certification ${overall}. Evidence: ${OUTPUT_DIR}/summary.json"
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
  [[ -n "${ADMIN_TOKEN}" ]] || fail "admin token environment variable ${ADMIN_TOKEN_ENV} is empty and no bootstrap token was found"

  OUTPUT_DIR="${OUTPUT_ROOT}/$(date '+%Y%m%d-%H%M%S')-${PACK}"
  mkdir -p "${OUTPUT_DIR}"
  STEPS_FILE="${OUTPUT_DIR}/steps.tsv"
  : >"${STEPS_FILE}"
  trap stop_capture EXIT INT TERM

  start_capture
  run_catalog_check
  run_reply_preview_check
  run_freeradius_check
  run_radius_checks
  run_device_check
  run_controller_checks
  run_upgrade_checks
  if [[ -n "${CAPTURE_PID}" && "${CAPTURE_SECONDS}" -gt 0 ]]; then
    log "Keeping packet capture open for ${CAPTURE_SECONDS} seconds. Trigger the real AP or switch authentication now."
    sleep "${CAPTURE_SECONDS}"
  fi
  stop_capture
  trap - EXIT INT TERM
  write_summary

  if [[ "${REQUIRED_FAILURES}" -gt 0 ]]; then
    exit 1
  fi
}

main "$@"
