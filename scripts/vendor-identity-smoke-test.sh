#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/vendor-identity-smoke-test.sh --api URL --pen PEN --organization NAME [--raddb DIR]

Requires AEGIS_ADMIN_TOKEN. Verifies the active API assignment, generated
dictionary, and local FreeRADIUS configuration. Run on the target appliance
after applying a production vendor identity migration.
USAGE
}

API_URL=""
EXPECTED_PEN=""
EXPECTED_ORGANIZATION=""
RADDB="/etc/freeradius/3.0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api) API_URL="${2:-}"; shift 2 ;;
    --pen) EXPECTED_PEN="${2:-}"; shift 2 ;;
    --organization) EXPECTED_ORGANIZATION="${2:-}"; shift 2 ;;
    --raddb) RADDB="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "${API_URL}" && -n "${EXPECTED_PEN}" && -n "${EXPECTED_ORGANIZATION}" ]] || { usage >&2; exit 2; }
[[ -n "${AEGIS_ADMIN_TOKEN:-}" ]] || { echo "AEGIS_ADMIN_TOKEN is required" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
command -v freeradius >/dev/null || { echo "freeradius is required" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemctl is required" >&2; exit 1; }

STATUS_FILE="$(mktemp)"
trap 'rm -f "${STATUS_FILE}"' EXIT
curl --fail --silent --show-error --max-time 15 \
  -H "Authorization: Bearer ${AEGIS_ADMIN_TOKEN}" \
  "${API_URL%/}/api/v1/system/vendor-identity?limit=5" > "${STATUS_FILE}"

jq -e --argjson pen "${EXPECTED_PEN}" --arg org "${EXPECTED_ORGANIZATION}" '
  .ready == true and
  .status == "production_verified" and
  .current.pen == $pen and
  .current.assigned_organization == $org and
  .config_evidence_valid == true and
  .assignment.pen == $pen and
  .assignment.organization == $org
' "${STATUS_FILE}" >/dev/null

DICTIONARY="${RADDB%/}/dictionary.aegisnas"
ROOT_DICTIONARY="${RADDB%/}/dictionary"
[[ -f "${DICTIONARY}" ]] || { echo "missing ${DICTIONARY}" >&2; exit 1; }
grep -Fxq "VENDOR AegisNAS ${EXPECTED_PEN}" "${DICTIONARY}" || { echo "dictionary PEN mismatch" >&2; exit 1; }
grep -Fxq '$INCLUDE dictionary.aegisnas' "${ROOT_DICTIONARY}" || { echo "dictionary include is missing" >&2; exit 1; }

freeradius -XC -d "${RADDB}"
systemctl is-active --quiet freeradius
systemctl is-active --quiet aegis-radius
echo "vendor identity smoke test passed for PEN ${EXPECTED_PEN} (${EXPECTED_ORGANIZATION})"
