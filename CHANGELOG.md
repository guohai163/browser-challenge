# Changelog

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
