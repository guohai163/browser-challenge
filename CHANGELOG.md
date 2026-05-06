# Changelog

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
