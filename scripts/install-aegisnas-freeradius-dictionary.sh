#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/install-aegisnas-freeradius-dictionary.sh [--raddb DIR] [--vendor-id ID] [--allow-placeholder]

Installs the AegisNAS FreeRADIUS product dictionary as dictionary.aegisnas and
adds "$INCLUDE dictionary.aegisnas" to the local FreeRADIUS dictionary.

Set --vendor-id or AEGISNAS_VENDOR_ID to your IANA Private Enterprise Number
before production use. The lab placeholder 55555 is refused unless
--allow-placeholder is supplied.
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RADDB="/etc/freeradius/3.0"
VENDOR_ID="${AEGISNAS_VENDOR_ID:-}"
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

if ! [[ "${VENDOR_ID}" =~ ^[0-9]+$ ]]; then
  echo "vendor ID must be numeric" >&2
  exit 2
fi

if [[ "${VENDOR_ID}" == "0" || "${VENDOR_ID}" == "4294967295" ]]; then
  echo "vendor ID ${VENDOR_ID} is reserved and cannot be used" >&2
  exit 2
fi

if [[ "${VENDOR_ID}" == "55555" && "${ALLOW_PLACEHOLDER}" != "1" ]]; then
  echo "refusing to install lab placeholder vendor ID 55555 without --allow-placeholder" >&2
  echo "request an IANA PEN, then rerun with --vendor-id <PEN> or AEGISNAS_VENDOR_ID=<PEN>" >&2
  exit 2
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
install -m 0644 "${TARGET}.tmp" "${TARGET}"
rm -f "${TARGET}.tmp"

touch "${ROOT_DICTIONARY}"
if ! grep -Fxq "${INCLUDE_LINE}" "${ROOT_DICTIONARY}"; then
  printf '\n%s\n' "${INCLUDE_LINE}" >> "${ROOT_DICTIONARY}"
fi

echo "installed ${TARGET}"
echo "ensured include in ${ROOT_DICTIONARY}: ${INCLUDE_LINE}"
