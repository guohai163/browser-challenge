#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

docker build -f script/Dockerfile.envoy.patched -t ghcr.io/guohai163/browser-challenge-envoy:ja3raw .

echo "Built image: ghcr.io/guohai163/browser-challenge-envoy:ja3raw"
