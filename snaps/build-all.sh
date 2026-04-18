#!/bin/bash
set -e

SERVICES="aegis-gateway aegis-radius aegis-portal aegis-session aegis-policy aegis-admin-api aegis-telemetry aegis-ai-lite"

for service in $SERVICES; do
    echo "Building snap for $service..."
    cd "$(dirname "$0")/$service"
    snapcraft clean
    snapcraft
    echo "Snap built: $(ls *.snap)"
    cd ../..
done

echo "All snaps built successfully."