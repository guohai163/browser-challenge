# Changelog

## v0.1.36 - 2026-05-07

### Added
- Added DB-backed fingerprint whitelist storage with schema initialization (`risk_fingerprint_whitelist`) and repository/service integration.
- Added whitelist testing endpoints:
  - `POST /api/gydev/whitelist/capture` to capture current real browser fingerprint into DB whitelist.
  - `GET /api/gydev/whitelist/test` to validate current request against strong-signal gate.
  - `GET /api/gydev/whitelist/list` to list enabled whitelist records.
- Added PostgreSQL runtime dependency and JDBC starter for whitelist persistence.

### Changed
- Refactored risk decision from score-based allow to strong-signal gate enforcement with explicit `gatePassed/gateFailures/circuitLevel` outputs.
- Switched runtime datasource defaults from local H2 file mode to PostgreSQL environment-driven configuration.
- Updated Docker Compose to include `pgsql` service and wired Spring app datasource environment to the compose PostgreSQL network.
- Updated application metadata in `application.yml` for the new release version and publish timestamp.
- Updated Maven project version in `pom.xml` to `0.1.36`.

## v0.1.35 - 2026-05-07

### Changed
- Kept Chinese status prompts on demo page and adapted status rendering to minimal backend response fields (`blocked`, `riskLevel`), preserving clear `通过/拦截` user messaging without exposing internal block reasons.
- Switched displayed publish time on demo page to browser local time formatting.
- Updated `application.yml` app metadata before release (`app.version` and `app.published-at`).
- Updated Maven project version in `pom.xml` to `0.1.35`.

## v0.1.34 - 2026-05-07

### Changed
- Simplified `/api/gydev/submit-get` and `/api/gydev/submit-post` client response payload to minimal fields: `blocked` and `riskLevel`.
- Moved detailed decision context (`reason`, module details, token verification internals) to server-side logs via `GydevGuardService` audit logging.
- Updated controller tests to validate minimal payload exposure and ensure sensitive diagnostic fields are not returned to clients.
- Updated Maven project version in `pom.xml` to `0.1.34`.

## v0.1.33 - 2026-05-07

### Fixed
- Relaxed Safari-family H2 browser detection in `TlsClassifierService` to support iOS Safari variants that differ in `h2_window` and may omit `unknown=1`.
- Added iOS Safari regression test in `TlsClassifierServiceTest` to ensure Safari H2 core settings (`enable_push=0;max_concurrent_streams=100;initial_window_size=2097152`) are classified as `browser/high` with non-fixed positive window values.

### Changed
- Updated Maven project version in `pom.xml` to `0.1.33`.

## v0.1.32 - 2026-05-07

### Fixed
- Expanded browser H2 fingerprint classification in `TlsClassifierService` to recognize Safari-like H2 settings/window pattern (`enable_push=0;max_concurrent_streams=100;initial_window_size=2097152;unknown=1` with window `10420225`).
- Added Safari regression coverage in `TlsClassifierServiceTest` to ensure Safari browser traffic is classified as `browser/high`.

### Changed
- Updated Maven project version in `pom.xml` to `0.1.32`.

## v0.1.31 - 2026-05-06

### Fixed
- Improved browser TLS/H2 classification in `TlsClassifierService` by adding structured browser-like H2 settings/window detection for real browser traffic forwarded by gateway fingerprints.
- Added regression test coverage in `TlsClassifierServiceTest` for browser requests that provide hashed H2 fingerprint plus canonical browser H2 settings/window values.
- Updated Envoy access log format in `script/envoy.yml` to output `h2_fp/h2_settings/h2_window/h2_priority` from request headers (`X-H2-*`) and keep metadata mirrors (`*_meta`) for debugging.

### Changed
- Updated Maven project version in `pom.xml` to `0.1.31`.

## v0.1.23 - 2026-05-06

### Changed
- Release-only version bump to `v0.1.23`.
- Updated application metadata in `application.yml` for the new release version and publish timestamp.

## v0.1.22 - 2026-05-06

### Added
- Added Envoy HCM JSON access logs for fingerprint diagnostics, including `ja3`, `ja4`, `h2_fp`, `h2_settings`, `h2_window`, and `h2_priority`.
- Added backend TLS classification diagnostic logs in `TlsClassifierService` for quick verification of received `X-H2-*` headers.
- Added risk submission TLS summary logs in `RiskChallengeService` to clearly show missing/available JA3/JA4/H2 signals.

### Fixed
- Updated Envoy dynamic metadata formatter usage to path-array form (e.g. `%DYNAMIC_METADATA([\"gydev.h2\",\"fp\"])%`) for newer Envoy versions.

### Changed
- Updated application metadata in `application.yml` for the new release version and publish timestamp.

## v0.1.21 - 2026-05-06

### Fixed
- Kept strict TLS policy requiring JA3/JA4/H2 fingerprints and restored reject reason to `Missing required JA3/JA4/H2 fingerprints`.
- Updated H2 Wasm extractor finalize timing in `script/h2-fp-plugin/src/lib.rs` to emit fingerprint metadata earlier (no longer waits for PRIORITY frame), improving `X-H2-*` availability in request processing.

### Changed
- Updated h2-fp-plugin documentation to describe early metadata emission behavior.
- Updated application metadata in `application.yml` for the new release version and publish timestamp.

## v0.1.20 - 2026-05-06

### Fixed
- Fixed Envoy header formatter expressions in `script/envoy.yml` by removing unsupported `:Z` suffix from `%DYNAMIC_METADATA(...)%` commands to satisfy newer Envoy parser validation.

### Changed
- Updated application metadata in `application.yml` for the new release version and publish timestamp.

## v0.1.16 - 2026-05-06

### Changed
- Updated TLS certificate file paths in `script/envoy.yml` from `fullchain1.pem`/`privkey1.pem` to `fullchain.pem`/`privkey.pem`.
- Updated application metadata in `application.yml` for the new release version and publish timestamp.

## v0.1.15 - 2026-05-06

### Changed
- Release-only version bump to `v0.1.15`.
- Updated application metadata in `application.yml` for the new release version and publish timestamp.

## v0.1.14 - 2026-05-06

### Fixed
- Fixed Envoy Wasm filter config structure in `script/envoy.yml` by removing invalid nested `config.config` and using valid `envoy.extensions.wasm.v3.PluginConfig` fields for Envoy `v1.35`.

### Changed
- Updated application metadata in `application.yml` for the new release version and publish timestamp.

## v0.1.13 - 2026-05-06

### Changed
- Updated Envoy base image in `script/Dockerfile.envoy` from `envoyproxy/envoy-contrib:v1.31.4` to `envoyproxy/envoy-contrib:v1.35-latest`.
- Updated application metadata in `application.yml` for the new release version and publish timestamp.

## v0.1.12 - 2026-05-06

### Added
- Added gydev challenge assets and utility scripts for local experimentation.

### Changed
- Updated docker compose deployment flow to use prebuilt GHCR images on target servers instead of local compose builds.
- Updated GitHub release workflow to build and push both Spring app and Envoy images.
- Enhanced guard service, controllers, and SDK logic for gydev verification and TLS/fingerprint handling.
- Updated frontend SDK static assets (`gydev-guard-sdk.js` and `gydev-guard-sdk.ts`) with new guard flow support.
- Updated application metadata in `application.yml` for the new release version and publish timestamp.

### Fixed
- Improved guard-related configuration and request payload handling consistency across backend services.
