#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROFILE="branch"
FORM="virtual"
WAN_IFACE=""
LAN_IFACE=""
LAN_ADDRESS="192.168.50.1/24"
LAN_DHCP_RANGE="192.168.50.100,192.168.50.200,12h"
ADMIN_PORT="8083"
PORTAL_PORT="8081"
HEALTH_PORT="8080"
TELEMETRY_PORT="9090"
PORTAL_BRANDING="AegisNAS VM Lab"
SUCCESS_URL="https://example.com/success"
LOGOUT_URL="https://example.com/logout"
SKIP_PACKAGES=0
SKIP_TESTS=0
SKIP_BUILD=0
SKIP_NETPLAN=0
FORCE_CONFIG=0
GO_VERSION="1.25.0"
NODE_MAJOR="20"

INSTALL_PREFIX="/opt/aegisnas"
BIN_DIR="${INSTALL_PREFIX}/bin"
UI_DIR="${INSTALL_PREFIX}/admin-ui"
CONFIG_DIR="/etc/aegisnas"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
ENV_FILE="/etc/default/aegisnas"
NETPLAN_FILE="/etc/netplan/90-aegisnas.yaml"

TELEMETRY_ENABLED="true"
AILITE_ENABLED="true"
RUNTIME_SHAPING_ENABLED="true"

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Bootstrap AegisNAS inside an Ubuntu VM from a Git clone.

Usage:
  ./scripts/ubuntu-vm-bootstrap.sh [options]

Options:
  --wan <iface>              Upstream interface name. Default: auto-detect from default route.
  --lan <iface>              Downstream interface name. Default: first non-loopback interface not used as WAN.
  --lan-address <cidr>       LAN gateway CIDR. Default: 192.168.50.1/24
  --lan-dhcp-range <range>   dnsmasq DHCP range. Default: 192.168.50.100,192.168.50.200,12h
  --profile <name>           Deployment profile: lite, branch, enterprise, custom. Default: branch
  --portal-branding <text>   Portal branding text. Default: AegisNAS VM Lab
  --skip-packages            Skip apt and toolchain installation.
  --skip-tests               Skip go test verification before build.
  --skip-build               Skip local rebuild and reuse existing release artifacts.
  --skip-netplan             Do not write / apply netplan configuration.
  --force-config             Overwrite /etc/aegisnas/config.yaml and /etc/default/aegisnas.
  -h, --help                 Show this help.

Examples:
  ./scripts/ubuntu-vm-bootstrap.sh
  ./scripts/ubuntu-vm-bootstrap.sh --wan ens160 --lan ens192
  ./scripts/ubuntu-vm-bootstrap.sh --profile lite --skip-tests

Notes:
  - Run this from the cloned repository inside the Ubuntu VM.
  - The script needs sudo privileges for package install, netplan, systemd, and /opt|/etc writes.
  - If you are connected over SSH, netplan apply may briefly interrupt your session.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --wan)
      WAN_IFACE="${2:-}"
      shift 2
      ;;
    --lan)
      LAN_IFACE="${2:-}"
      shift 2
      ;;
    --lan-address)
      LAN_ADDRESS="${2:-}"
      shift 2
      ;;
    --lan-dhcp-range)
      LAN_DHCP_RANGE="${2:-}"
      shift 2
      ;;
    --profile)
      PROFILE="${2:-}"
      shift 2
      ;;
    --portal-branding)
      PORTAL_BRANDING="${2:-}"
      shift 2
      ;;
    --skip-packages)
      SKIP_PACKAGES=1
      shift
      ;;
    --skip-tests)
      SKIP_TESTS=1
      shift
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --skip-netplan)
      SKIP_NETPLAN=1
      shift
      ;;
    --force-config)
      FORCE_CONFIG=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown option: $1"
      ;;
  esac
done

[[ -f "${REPO_ROOT}/go.mod" ]] || die "Run this script from inside the AegisNAS repository."

require_sudo() {
  sudo -v
}

current_go_version() {
  if command -v go >/dev/null 2>&1; then
    go version | awk '{print $3}' | sed 's/^go//'
  fi
}

ensure_go() {
  local current
  current="$(current_go_version || true)"
  if [[ "${current}" == "${GO_VERSION}"* ]]; then
    log "Go ${current} already available."
  else
    log "Installing Go ${GO_VERSION}."
    local tarball
    tarball="$(mktemp)"
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o "${tarball}"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "${tarball}"
    rm -f "${tarball}"
  fi

  export PATH="/usr/local/go/bin:${PATH}"
  if ! grep -qs '/usr/local/go/bin' "${HOME}/.profile"; then
    printf '\nexport PATH=/usr/local/go/bin:$PATH\n' >> "${HOME}/.profile"
  fi
}

ensure_node() {
  local node_major=""
  if command -v node >/dev/null 2>&1; then
    node_major="$(node -p 'process.versions.node.split(`.`)[0]')"
  fi

  if [[ "${node_major}" == "${NODE_MAJOR}" ]]; then
    log "Node.js ${node_major} already available."
    return
  fi

  log "Installing Node.js ${NODE_MAJOR}."
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | sudo -E bash -
  sudo apt-get install -y nodejs
}

install_packages() {
  if [[ "${SKIP_PACKAGES}" -eq 1 ]]; then
    log "Skipping package and toolchain installation."
    ensure_go
    ensure_node
    return
  fi

  log "Installing Ubuntu runtime packages."
  sudo apt-get update
  sudo apt-get install -y \
    ca-certificates \
    curl \
    git \
    dnsmasq \
    freeradius \
    freeradius-ldap \
    freeradius-utils \
    hostapd \
    iproute2 \
    jq \
    kmod \
    nftables \
    qemu-guest-agent \
    sqlite3 \
    build-essential \
    openssl

  ensure_go
  ensure_node

  sudo systemctl enable --now qemu-guest-agent >/dev/null 2>&1 || true
}

apply_profile_defaults() {
  case "${PROFILE}" in
    lite)
      TELEMETRY_ENABLED="false"
      AILITE_ENABLED="false"
      RUNTIME_SHAPING_ENABLED="false"
      ;;
    branch|enterprise)
      TELEMETRY_ENABLED="true"
      AILITE_ENABLED="true"
      RUNTIME_SHAPING_ENABLED="true"
      ;;
    custom)
      ;;
    *)
      die "Unsupported profile: ${PROFILE}"
      ;;
  esac
}

detect_interfaces() {
  if [[ -z "${WAN_IFACE}" ]]; then
    WAN_IFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
  fi

  if [[ -z "${LAN_IFACE}" ]]; then
    LAN_IFACE="$(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -v '^lo$' | grep -v "^${WAN_IFACE}$" | head -n1 || true)"
  fi

  [[ -n "${WAN_IFACE}" ]] || die "Could not detect WAN interface. Pass --wan <iface>."
  [[ -n "${LAN_IFACE}" ]] || die "Could not detect LAN interface. Pass --lan <iface>."
  [[ "${WAN_IFACE}" != "${LAN_IFACE}" ]] || die "WAN and LAN interfaces must be different."

  log "Using WAN interface: ${WAN_IFACE}"
  log "Using LAN interface: ${LAN_IFACE}"
}

write_netplan() {
  if [[ "${SKIP_NETPLAN}" -eq 1 ]]; then
    log "Skipping netplan configuration."
    return
  fi

  log "Writing netplan config to ${NETPLAN_FILE}."
  sudo tee "${NETPLAN_FILE}" >/dev/null <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${WAN_IFACE}:
      dhcp4: true
    ${LAN_IFACE}:
      dhcp4: false
      addresses:
        - ${LAN_ADDRESS}
EOF

  sudo chmod 0644 "${NETPLAN_FILE}"
  sudo netplan generate
  sudo netplan apply
}

existing_env_value() {
  local key="$1"
  if sudo test -f "${ENV_FILE}"; then
    sudo awk -F= -v key="${key}" '$1 == key { sub($1 "=", "", $0); print $0 }' "${ENV_FILE}" | tail -n1
  fi
}

write_env_file() {
  local bootstrap_token revision_key allowed_origins

  bootstrap_token="${AEGIS_ADMIN_BOOTSTRAP_TOKEN:-$(existing_env_value "AEGIS_ADMIN_BOOTSTRAP_TOKEN")}"
  revision_key="${AEGIS_REVISION_SIGNING_KEY:-$(existing_env_value "AEGIS_REVISION_SIGNING_KEY")}"
  allowed_origins="${AEGIS_ADMIN_ALLOWED_ORIGINS:-$(existing_env_value "AEGIS_ADMIN_ALLOWED_ORIGINS")}"

  if [[ -z "${bootstrap_token}" ]]; then
    bootstrap_token="$(openssl rand -hex 32)"
  fi
  if [[ -z "${revision_key}" ]]; then
    revision_key="$(openssl rand -hex 32)"
  fi
  if [[ -z "${allowed_origins}" ]]; then
    allowed_origins="http://${LAN_IP}:${ADMIN_PORT}"
  fi

  export AEGIS_ADMIN_BOOTSTRAP_TOKEN="${bootstrap_token}"
  export AEGIS_REVISION_SIGNING_KEY="${revision_key}"
  export AEGIS_ADMIN_ALLOWED_ORIGINS="${allowed_origins}"

  if sudo test -f "${ENV_FILE}" && [[ "${FORCE_CONFIG}" -ne 1 ]]; then
    log "Preserving existing ${ENV_FILE}."
    return
  fi

  log "Writing environment file ${ENV_FILE}."
  sudo tee "${ENV_FILE}" >/dev/null <<EOF
AEGIS_ADMIN_UI_DIR=${UI_DIR}
AEGIS_ADMIN_ALLOWED_ORIGINS=${AEGIS_ADMIN_ALLOWED_ORIGINS}
AEGIS_ADMIN_BOOTSTRAP_TOKEN=${AEGIS_ADMIN_BOOTSTRAP_TOKEN}
AEGIS_REVISION_SIGNING_KEY=${AEGIS_REVISION_SIGNING_KEY}
EOF
  sudo chmod 0640 "${ENV_FILE}"
}

write_config() {
  local cpu_cores memory_mb hostname_short

  if sudo test -f "${CONFIG_FILE}" && [[ "${FORCE_CONFIG}" -ne 1 ]]; then
    log "Preserving existing ${CONFIG_FILE}."
    return
  fi

  if sudo test -f "${CONFIG_FILE}"; then
    sudo cp "${CONFIG_FILE}" "${CONFIG_FILE}.bak.$(date +%s)"
  fi

  cpu_cores="$(nproc)"
  memory_mb="$(awk '/MemTotal/ { printf "%d", $2 / 1024 }' /proc/meminfo)"
  hostname_short="$(hostname -s)"

  log "Writing VM config to ${CONFIG_FILE}."
  sudo tee "${CONFIG_FILE}" >/dev/null <<EOF
mode: two-nic

deployment:
  profile: ${PROFILE}
  form: ${FORM}
  hardware:
    memory_mb: ${memory_mb}
    cpu_cores: ${cpu_cores}
    prefer_external_ap: true

wan:
  name: ${WAN_IFACE}
  dhcp: true

lan:
  name: ${LAN_IFACE}
  dhcp: false
  address: ${LAN_ADDRESS}
  gateway: ${LAN_IP}
  dhcp_range: "${LAN_DHCP_RANGE}"

database:
  path: /var/lib/aegisnas/data.db

logging:
  level: info
  output: stdout

health:
  port: ${HEALTH_PORT}

admin_port: ${ADMIN_PORT}

radius:
  secret: "${RADIUS_SECRET}"
  auth_port: 1812
  acct_port: 1813
  max_sessions: 1024
  cert_dir: /etc/freeradius/3.0/certs
  nas_identifier: "aegisnas-${hostname_short}"
  request_timeout_seconds: 5
  interim_update_seconds: 300
  eap:
    default_type: peap
    peap_inner: mschapv2
    ttls_inner: mschapv2
    tls_min_version: "1.2"
    tls_max_version: "1.3"
  dynamic_auth:
    enabled: true
    port: 3799
  clients:
    - ip: 127.0.0.1
      secret: "${RADIUS_SECRET}"
      shortname: "localhost"
  upstream:
    enabled: false
    realm: "aegis-upstream"
    pool_strategy: "fail-over"
    status_check: "status-server"
    response_window: 20
    zombie_period: 40
    revive_interval: 120
    check_interval: 30
    num_answers_to_alive: 3
    strip_realm: false
    servers: []

portal:
  enabled: true
  port: ${PORTAL_PORT}
  listen_ip: "${LAN_IP}"
  branding: "${PORTAL_BRANDING}"
  success_url: "${SUCCESS_URL}"
  logout_url: "${LOGOUT_URL}"
  radius_auth: false
  local_fallback: true

ldap:
  enabled: false
  url: "ldaps://ldap.example.com"
  base_dn: "dc=example,dc=com"
  bind_dn: "cn=svc-aegisnas,dc=example,dc=com"
  bind_password: "replace-this-password"
  user_filter: "(uid=%s)"
  group_filter: "(memberUid=%s)"

policy:
  default_role: guest-basic
  runtime_shaping_enabled: ${RUNTIME_SHAPING_ENABLED}

telemetry:
  enabled: ${TELEMETRY_ENABLED}
  prometheus_port: ${TELEMETRY_PORT}

ailite:
  enabled: ${AILITE_ENABLED}
  recommendation_limit: 100
  remote_webhook: ""

dhcp:
  enabled: true
  lease_time: 12h
  authoritative: true

wireless:
  enabled: false
  country_code: US
  interface: wlan0
  driver: nl80211
  hw_mode: g
  channel: 6
  beacon_interval: 100
  wmm_enabled: true
  ht_enabled: true
  ctrl_interface: /var/run/hostapd
  hostapd_config_path: /etc/hostapd/hostapd.conf
  ssids: []
EOF
  sudo chmod 0640 "${CONFIG_FILE}"
}

run_tests() {
  if [[ "${SKIP_TESTS}" -eq 1 ]]; then
    log "Skipping go test verification."
    return
  fi

  log "Running Go test suite."
  export CGO_ENABLED=0
  go test -count=1 -p=1 ./...
}

build_release() {
  if [[ "${SKIP_BUILD}" -eq 1 ]]; then
    [[ -x "${REPO_ROOT}/release/bin/aegis-admin" ]] || die "release/bin is missing. Drop --skip-build or build first."
    [[ -f "${REPO_ROOT}/release/admin-ui/index.html" ]] || die "release/admin-ui is missing. Drop --skip-build or build first."
    log "Skipping rebuild and reusing existing release artifacts."
    return
  fi

  log "Building Go services."
  rm -rf "${REPO_ROOT}/release/bin" "${REPO_ROOT}/release/admin-ui"
  mkdir -p "${REPO_ROOT}/release/bin" "${REPO_ROOT}/release/admin-ui"

  local app
  for app in \
    aegis-admin \
    aegis-admin-api \
    aegis-ai-lite \
    aegis-gateway \
    aegis-policy \
    aegis-portal \
    aegis-radius \
    aegis-session \
    aegis-telemetry; do
    go build -o "${REPO_ROOT}/release/bin/${app}" "./cmd/${app}"
  done

  log "Building admin UI."
  pushd "${REPO_ROOT}/web/admin-ui" >/dev/null
  npm ci
  npm run build
  popd >/dev/null

  cp -a "${REPO_ROOT}/web/admin-ui/dist/." "${REPO_ROOT}/release/admin-ui/"
}

install_payload() {
  log "Installing AegisNAS payload to ${INSTALL_PREFIX}."
  sudo install -d -m 0755 "${BIN_DIR}" "${UI_DIR}" "${CONFIG_DIR}" /var/lib/aegisnas
  sudo cp -a "${REPO_ROOT}/release/bin/." "${BIN_DIR}/"
  sudo rm -rf "${UI_DIR:?}/"*
  sudo cp -a "${REPO_ROOT}/release/admin-ui/." "${UI_DIR}/"
  sudo chmod 0755 "${BIN_DIR}/"*
}

write_unit() {
  local name="$1"
  local description="$2"
  local after="$3"
  local exec_start="$4"

  sudo tee "/etc/systemd/system/${name}.service" >/dev/null <<EOF
[Unit]
Description=${description}
After=${after}
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-${ENV_FILE}
ExecStart=${exec_start}
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
}

write_systemd_units() {
  log "Writing systemd unit files."
  write_unit "aegis-gateway" "AegisNAS Gateway" "network-online.target dnsmasq.service" "${BIN_DIR}/aegis-gateway run --config ${CONFIG_FILE}"
  write_unit "aegis-radius" "AegisNAS RADIUS Broker" "network-online.target freeradius.service" "${BIN_DIR}/aegis-radius run --config ${CONFIG_FILE}"
  write_unit "aegis-portal" "AegisNAS Portal" "network-online.target" "${BIN_DIR}/aegis-portal run --config ${CONFIG_FILE}"
  write_unit "aegis-session" "AegisNAS Session Service" "network-online.target" "${BIN_DIR}/aegis-session run --config ${CONFIG_FILE}"
  write_unit "aegis-policy" "AegisNAS Policy Service" "network-online.target" "${BIN_DIR}/aegis-policy run --config ${CONFIG_FILE}"
  write_unit "aegis-admin-api" "AegisNAS Admin API" "network-online.target" "${BIN_DIR}/aegis-admin-api run --config ${CONFIG_FILE}"
  write_unit "aegis-ai-lite" "AegisNAS AI Lite" "network-online.target" "${BIN_DIR}/aegis-ai-lite run --config ${CONFIG_FILE}"
  write_unit "aegis-telemetry" "AegisNAS Telemetry" "network-online.target" "${BIN_DIR}/aegis-telemetry run --config ${CONFIG_FILE}"
}

validate_and_seed() {
  log "Validating config and initializing database."
  sudo "${BIN_DIR}/aegis-admin" validate-config --config "${CONFIG_FILE}"
  sudo "${BIN_DIR}/aegis-admin" migrate --config "${CONFIG_FILE}"
  sudo --preserve-env=AEGIS_ADMIN_BOOTSTRAP_TOKEN "${BIN_DIR}/aegis-admin" seed --config "${CONFIG_FILE}"
}

start_services() {
  local units=(
    aegis-gateway
    aegis-radius
    aegis-portal
    aegis-session
    aegis-policy
    aegis-admin-api
    aegis-ai-lite
    aegis-telemetry
  )

  log "Enabling and restarting services."
  sudo systemctl daemon-reload
  sudo systemctl enable dnsmasq freeradius nftables >/dev/null
  sudo systemctl enable "${units[@]}" >/dev/null
  sudo systemctl restart dnsmasq freeradius nftables
  sudo systemctl restart "${units[@]}"
}

show_summary() {
  cat <<EOF

AegisNAS bootstrap completed.

Admin UI:  http://${LAN_IP}:${ADMIN_PORT}
Portal:    http://${LAN_IP}:${PORTAL_PORT}
Health:    http://127.0.0.1:${HEALTH_PORT}/health

Bootstrap admin token:
${AEGIS_ADMIN_BOOTSTRAP_TOKEN}

Next commands:
  systemctl --no-pager --full status aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api
  curl -fsS http://127.0.0.1:${HEALTH_PORT}/health
  curl -fsS http://127.0.0.1:${PORTAL_PORT}/health
  curl -fsS http://127.0.0.1:${ADMIN_PORT}/health

Full flow test guide:
  ${REPO_ROOT}/docs/ubuntu-vm-runbook.md
EOF
}

main() {
  require_sudo
  apply_profile_defaults
  detect_interfaces

  LAN_IP="${LAN_ADDRESS%%/*}"
  RADIUS_SECRET="${RADIUS_SECRET:-$(openssl rand -hex 16)}"

  install_packages
  write_netplan
  run_tests
  build_release
  install_payload
  write_env_file
  write_config
  write_systemd_units
  validate_and_seed
  start_services
  show_summary
}

main "$@"
