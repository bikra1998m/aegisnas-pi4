#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/install-aegisnas-freeradius-dictionary.sh [--raddb DIR] [--vendor-id ID] [--organization NAME] [--registry-file FILE] [--allow-placeholder]

Installs the AegisNAS FreeRADIUS product dictionary as dictionary.aegisnas and
adds "$INCLUDE dictionary.aegisnas" to the local FreeRADIUS dictionary.

Set --vendor-id or AEGISNAS_VENDOR_ID to your IANA Private Enterprise Number
and set --organization or AEGISNAS_IANA_ORGANIZATION to the exact organization
in IANA's registry. The lab placeholder 55555 is refused unless
--allow-placeholder is supplied. --registry-file permits an operator-pinned
registry snapshot; otherwise the authoritative HTTPS text registry is fetched.
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RADDB="/etc/freeradius/3.0"
VENDOR_ID="${AEGISNAS_VENDOR_ID:-}"
ORGANIZATION="${AEGISNAS_IANA_ORGANIZATION:-}"
REGISTRY_FILE=""
ALLOW_PLACEHOLDER=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --raddb)
      RADDB="${2:-}"
      shift 2
      ;;
    --vendor-id)
      VENDOR_ID="${2:-}"
      shift 2
      ;;
    --organization)
      ORGANIZATION="${2:-}"
      shift 2
      ;;
    --registry-file)
      REGISTRY_FILE="${2:-}"
      shift 2
      ;;
    --allow-placeholder)
      ALLOW_PLACEHOLDER=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${VENDOR_ID}" ]]; then
  VENDOR_ID="55555"
fi

if ! [[ "${VENDOR_ID}" =~ ^(0|[1-9][0-9]*)$ ]]; then
  echo "vendor ID must be numeric" >&2
  exit 2
fi

if [[ "${VENDOR_ID}" == "0" || "${VENDOR_ID}" == "4294967295" ]]; then
  echo "vendor ID ${VENDOR_ID} is reserved and cannot be used" >&2
  exit 2
fi

if (( VENDOR_ID > 4294967294 )); then
  echo "vendor ID ${VENDOR_ID} exceeds the assignable uint32 range" >&2
  exit 2
fi

if [[ "${VENDOR_ID}" == "32473" ]]; then
  echo "vendor ID 32473 is reserved for documentation by RFC 5612" >&2
  exit 2
fi

if [[ "${VENDOR_ID}" == "55555" && "${ALLOW_PLACEHOLDER}" != "1" ]]; then
  echo "refusing to install lab placeholder vendor ID 55555 without --allow-placeholder" >&2
  echo "request an IANA PEN, then rerun with --vendor-id <PEN> and --organization <exact-IANA-name>" >&2
  exit 2
fi

REGISTRY_URL="https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers.txt"
REGISTRY_TMP=""
REGISTRY_SHA256=""
REGISTRY_UPDATED=""
if [[ "${VENDOR_ID}" != "55555" ]]; then
  if [[ -z "${ORGANIZATION// }" ]]; then
    echo "--organization or AEGISNAS_IANA_ORGANIZATION is required for a production PEN" >&2
    exit 2
  fi
  if [[ -z "${REGISTRY_FILE}" ]]; then
    command -v curl >/dev/null 2>&1 || { echo "curl is required to verify the IANA assignment" >&2; exit 1; }
    REGISTRY_TMP="$(mktemp)"
    trap 'rm -f "${REGISTRY_TMP}" "${TARGET:-}.tmp"' EXIT
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
      --max-time 30 --max-filesize 8388608 "${REGISTRY_URL}" --output "${REGISTRY_TMP}"
    REGISTRY_FILE="${REGISTRY_TMP}"
  elif [[ ! -f "${REGISTRY_FILE}" ]]; then
    echo "registry snapshot does not exist: ${REGISTRY_FILE}" >&2
    exit 2
  fi
  ASSIGNED_ORGANIZATION="$(awk -v pen="${VENDOR_ID}" '
    $0 == pen { found=1; next }
    found && /^  [^ ]/ { sub(/^  /, ""); print; exit }
    found && NF { exit }
  ' "${REGISTRY_FILE}")"
  if [[ -z "${ASSIGNED_ORGANIZATION}" ]]; then
    echo "PEN ${VENDOR_ID} is not present in the supplied IANA registry" >&2
    exit 2
  fi
  if [[ "${ASSIGNED_ORGANIZATION}" != "${ORGANIZATION}" ]]; then
    echo "PEN ${VENDOR_ID} is assigned to '${ASSIGNED_ORGANIZATION}', not '${ORGANIZATION}'" >&2
    exit 2
  fi
  REGISTRY_SHA256="$(sha256sum "${REGISTRY_FILE}" | awk '{print $1}')"
  REGISTRY_UPDATED="$(sed -n 's/^(last updated \([0-9][0-9-]*\))$/\1/p' "${REGISTRY_FILE}" | head -n 1)"
  if [[ -z "${REGISTRY_UPDATED}" ]]; then
    echo "IANA registry snapshot has no valid last-updated date" >&2
    exit 2
  fi
fi

SOURCE="${ROOT_DIR}/configs/dictionary.aegisnas"
TARGET="${RADDB%/}/dictionary.aegisnas"
ROOT_DICTIONARY="${RADDB%/}/dictionary"
INCLUDE_LINE='$INCLUDE dictionary.aegisnas'

if [[ ! -f "${SOURCE}" ]]; then
  echo "missing source dictionary: ${SOURCE}" >&2
  exit 1
fi

install -d -m 0755 "${RADDB}"
sed "s/^VENDOR AegisNAS .*/VENDOR AegisNAS ${VENDOR_ID}/" "${SOURCE}" > "${TARGET}.tmp"
if [[ "${VENDOR_ID}" != "55555" ]]; then
  {
    printf '# IANA organization: %s\n' "${ORGANIZATION}"
    printf '# IANA registry: %s\n' "${REGISTRY_URL}"
    printf '# IANA registry last updated: %s\n' "${REGISTRY_UPDATED}"
    printf '# IANA registry SHA-256: %s\n' "${REGISTRY_SHA256}"
    cat "${TARGET}.tmp"
  } > "${TARGET}.verified.tmp"
  mv "${TARGET}.verified.tmp" "${TARGET}.tmp"
fi
install -m 0644 "${TARGET}.tmp" "${TARGET}"
rm -f "${TARGET}.tmp"

touch "${ROOT_DICTIONARY}"
if ! grep -Fxq "${INCLUDE_LINE}" "${ROOT_DICTIONARY}"; then
  printf '\n%s\n' "${INCLUDE_LINE}" >> "${ROOT_DICTIONARY}"
fi

echo "installed ${TARGET}"
echo "ensured include in ${ROOT_DICTIONARY}: ${INCLUDE_LINE}"
