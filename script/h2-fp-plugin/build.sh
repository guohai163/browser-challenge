#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${ROOT_DIR}/../plugins"
TARGET="wasm32-unknown-unknown"
CRATE="h2_fp_plugin"
WASM_IN="${ROOT_DIR}/target/${TARGET}/release/${CRATE}.wasm"
WASM_OUT="${OUT_DIR}/h2_fp.wasm"

if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup is required" >&2
  exit 1
fi

rustup target add "${TARGET}" >/dev/null
cargo build --manifest-path "${ROOT_DIR}/Cargo.toml" --target "${TARGET}" --release

mkdir -p "${OUT_DIR}"
cp "${WASM_IN}" "${WASM_OUT}"

echo "Generated ${WASM_OUT}"
