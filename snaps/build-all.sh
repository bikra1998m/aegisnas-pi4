#!/usr/bin/env bash
# Lab packaging only; no upload, install, signing, or production admission.
set -euo pipefail
[[ $# -eq 1 ]] || { echo 'Usage: build-all.sh NEW-OUTPUT-DIRECTORY' >&2; exit 2; }
snap_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ ! -e "$1" && ! -L "$1" ]] || { echo 'Output already exists; preserve previous artifacts' >&2; exit 1; }
command -v snapcraft >/dev/null || { echo 'snapcraft is required' >&2; exit 1; }
mkdir -- "$1"
output_root="$(cd -- "$1" && pwd)"
services=(aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api aegis-telemetry aegis-ai-lite)
for service in "${services[@]}"; do
    echo "Building lab snap for $service..."
    # Absolute paths work from any caller directory, including paths with spaces.
    # Do not delete existing snapcraft workspaces or earlier build evidence.
    (cd "$snap_root/$service" && snapcraft pack --output "$output_root/$service.snap")
    [[ -s "$output_root/$service.snap" ]] || { echo "Missing artifact for $service" >&2; exit 1; }
done
(cd "$output_root" && sha256sum -- *.snap > SHA256SUMS)
echo "Lab snaps built in $output_root. Production admission and image certification remain required."
