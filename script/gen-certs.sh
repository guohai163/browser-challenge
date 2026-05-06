#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-/out}"
mkdir -p "${OUT_DIR}"

openssl req -x509 -newkey rsa:2048 -sha256 -days 365 \
  -nodes \
  -keyout "${OUT_DIR}/privkey1.pem" \
  -out "${OUT_DIR}/fullchain1.pem" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "Generated certs in ${OUT_DIR}"
