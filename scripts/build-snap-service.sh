#!/usr/bin/env bash
# Compile one lab snap payload. This is not signed release admission.
set -euo pipefail

[[ $# -eq 2 ]] || { echo 'Usage: build-snap-service.sh SERVICE INSTALL-DIR' >&2; exit 2; }
service="$1"
case "$service" in
  aegis-gateway|aegis-radius|aegis-portal|aegis-session|aegis-policy|aegis-admin-api|aegis-telemetry|aegis-ai-lite) ;;
  *) echo 'Unknown snap service' >&2; exit 2 ;;
esac
source_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -d "$2" ]] || { echo 'Snap install directory must already exist' >&2; exit 2; }
install_root="$(cd -- "$2" && pwd)"
cd "$source_root"

# Match the repository exactly, including its patched Go toolchain. A moving
# build-snap channel must not silently select a different compiler.
version="$(awk '$1 == "go" { print $2 }' go.mod)"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid Go toolchain requirement' >&2; exit 1; }
export GOTOOLCHAIN="go${version}" CGO_ENABLED=0 GOOS=linux GOWORK="$source_root/go.work"
export GOARCH="${CRAFT_ARCH_BUILD_FOR:-$(go env GOARCH)}"
case "$GOARCH" in
  amd64|arm64) ;;
  *) echo 'Snap payload builds support amd64 and arm64 only' >&2; exit 1 ;;
esac
[[ "$(go env GOVERSION)" == "$GOTOOLCHAIN" ]] || { echo 'Go compiler does not match go.mod' >&2; exit 1; }
mkdir -p "$install_root/bin"
go build -mod=readonly -trimpath -o "$install_root/bin/$service" "./cmd/$service"
[[ -s "$install_root/bin/$service" ]] || { echo 'Compiler produced no service binary' >&2; exit 1; }
