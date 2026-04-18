#!/bin/bash
set -e

# Sign the model assertion with your developer key.
# Requires snapcraft login and a registered developer key.

if [ ! -f model.json ]; then
    echo "model.json not found in current directory."
    exit 1
fi

echo "Signing model assertion..."
cat model.json | snap sign -k default > model.signed

echo "Model signed: model.signed"