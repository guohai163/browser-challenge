# h2-fp-plugin

Envoy network wasm filter plugin for extracting H2 fingerprint fields.

## Output contract

The plugin writes dynamic metadata under namespace `gydev.h2`:

- `fp`: sha256 hex of `settings|window|priority`
- `settings`: canonicalized H2 SETTINGS pairs
- `window`: first WINDOW_UPDATE increment
- `priority`: first PRIORITY tuple (or empty)

`script/envoy.yml` forwards these values to headers:

- `X-H2-FP`
- `X-H2-SETTINGS`
- `X-H2-WINDOW`
- `X-H2-PRIORITY`

## Build

```bash
cd script/h2-fp-plugin
./build.sh
```

Generated artifact:

- `script/plugins/h2_fp.wasm`

## Test

```bash
cd script/h2-fp-plugin
cargo test
```

## Build Envoy image

```bash
docker build -f script/Dockerfile.envoy -t browser-challenge-envoy .
```

## Validate Envoy config

```bash
docker run --rm browser-challenge-envoy \
  envoy --mode validate -c /etc/envoy/envoy.yml
```
