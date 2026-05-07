# Envoy JA3 Raw + GREASE Normalization Patch

This directory documents the required listener-level Envoy patch for JA3 raw extraction.

## Why patch is needed

Current upstream Envoy formatter `%TLS_JA3_FINGERPRINT%` exposes only JA3 hash value.
It does not expose the pre-hash JA3 raw string, so GREASE normalization cannot be done at app layer with full fidelity.

## Patch contract

At listener TLS inspection stage (ClientHello parse), add three exported values:

1. `ja3_raw`
- Standard JA3 source string before hashing:
  - `tls_version,ciphers,extensions,elliptic_curves,ec_point_formats`
- Lists use `-` separators and sections use `,` separators.

2. `ja3_raw_normalized`
- Same JA3 string but all GREASE values removed from all numeric lists.
- Keep remaining values in original order.

3. `ja3_md5_normalized`
- `md5(ja3_raw_normalized)` in lowercase hex.

## Expected Envoy exposure

The patch should make these values available for:

- request header injection:
  - `X-JA3-RAW`
  - `X-JA3-NORMALIZED`
  - `X-JA3-NORMALIZED-MD5`
- access log formatters/metadata for diagnostics.

## GREASE detection rule

A value is GREASE when `(value & 0x0f0f) == 0x0a0a` and high/low bytes are equal pattern per RFC 8701.
Typical set includes: 0x0a0a, 0x1a1a, ..., 0xfafa.

## Validation checklist

1. Same browser repeated requests:
- `ja3_raw` may change.
- `ja3_raw_normalized` and `ja3_md5_normalized` should remain stable.

2. Different browser/version:
- `ja3_md5_normalized` should differ.

3. Header/log/app consistency:
- `X-JA3-NORMALIZED-MD5` equals access-log value equals backend received value.

## This repo implementation status

Implemented in local Envoy source tree:

- `source/extensions/filters/listener/tls_inspector/tls_inspector.cc`
  - build `ja3_raw` (without GREASE filtering)
  - build `ja3_normalized` (GREASE filtered)
  - MD5 of normalized string as `ja3_md5_normalized`
  - write metadata under namespace `envoy.filters.listener.tls_inspector`

- `source/common/formatter/stream_info_formatter.cc`
  - new formatters:
    - `%TLS_JA3_RAW%`
    - `%TLS_JA3_NORMALIZED%`
    - `%TLS_JA3_NORMALIZED_MD5%`

Envoy config is wired to inject:

- `X-JA3-RAW: %TLS_JA3_RAW%`
- `X-JA3-NORMALIZED: %TLS_JA3_NORMALIZED%`
- `X-JA3-NORMALIZED-MD5: %TLS_JA3_NORMALIZED_MD5%`

Build helper:

- `script/Dockerfile.envoy.patched`
- `script/build-envoy-patched.sh`
