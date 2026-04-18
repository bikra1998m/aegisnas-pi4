#!/bin/bash
set -e

# Build the Ubuntu Core image for Raspberry Pi 4 using ubuntu-image.
# Requires ubuntu-image snap installed: sudo snap install ubuntu-image --classic

MODEL_FILE="model.signed"
if [ ! -f "$MODEL_FILE" ]; then
    echo "Signed model file $MODEL_FILE not found. Please run sign-model.sh first."
    exit 1
fi

OUTPUT_DIR="./output"
mkdir -p "$OUTPUT_DIR"

echo "Building Ubuntu Core image for AegisNAS Pi4..."
ubuntu-image snap "$MODEL_FILE" --output-dir "$OUTPUT_DIR"

echo "Image built successfully. Output: $OUTPUT_DIR/aegisnas-pi4.img"