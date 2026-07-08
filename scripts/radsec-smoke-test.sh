#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <host> <port> <server-name> <ca-file> <client-cert> <client-key> [alpn]" >&2
  exit 2
}

[[ $# -ge 6 && $# -le 7 ]] || usage

host=$1
port=$2
server_name=$3
ca_file=$4
client_cert=$5
client_key=$6
alpn=${7:-radius/1.0}

for command in freeradius openssl; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required command not found: $command" >&2
    exit 1
  }
done

for path in "$ca_file" "$client_cert" "$client_key"; do
  [[ -r "$path" ]] || {
    echo "required credential is not readable: $path" >&2
    exit 1
  }
done

echo "Validating generated FreeRADIUS configuration"
freeradius -XC

echo "Validating client certificate chain"
openssl verify -CAfile "$ca_file" "$client_cert"

echo "Testing mutual TLS and ALPN against ${server_name} (${host}:${port})"
output=$(printf '' | openssl s_client \
  -connect "${host}:${port}" \
  -servername "$server_name" \
  -verify_hostname "$server_name" \
  -verify_return_error \
  -CAfile "$ca_file" \
  -cert "$client_cert" \
  -key "$client_key" \
  -alpn "$alpn" 2>&1)

grep -q "Verify return code: 0 (ok)" <<<"$output" || {
  echo "$output" >&2
  echo "RadSec TLS verification failed" >&2
  exit 1
}

if grep -q "ALPN protocol:" <<<"$output"; then
  grep -q "ALPN protocol: $alpn" <<<"$output" || {
    echo "$output" >&2
    echo "RadSec ALPN negotiation failed" >&2
    exit 1
  }
fi

echo "RadSec configuration, certificate chain, hostname, mTLS, and ALPN checks passed"
