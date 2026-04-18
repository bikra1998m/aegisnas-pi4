#!/bin/bash
set -e

cd "$(dirname "$0")"
echo "Running AegisNAS acceptance tests..."

# Ensure dependencies are available
go mod tidy

# Run tests with verbose output
go test -v -timeout 5m ./...

echo "Acceptance tests completed."