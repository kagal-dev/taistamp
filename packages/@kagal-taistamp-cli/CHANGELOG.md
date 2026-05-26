# Changelog

All notable changes to `@kagal/taistamp-cli` will be
documented in this file.

## [Unreleased]

## [0.1.0] - 2026-05-26

First release of the `taistamp` CLI companion — Ed25519
seed minting and `/.well-known/taistamp` endpoint probing
for `@kagal/taistamp` operators.

### Added

- `taistamp seed new [selector]` — mints a fresh
  `selector:base64` Ed25519 secret and prints it with the
  `<selector>._taistamp` DNS TXT record publishing its
  public half. The selector positional defaults to the
  literal string `default`.
- Global `--env-file <path>` argument and `./.env`
  auto-loading — file values never override variables
  already set in the environment.
- `taistamp probe <url>` — probes a remote
  `/.well-known/taistamp` endpoint. With one or more
  `--secret` / `--secret-env` supplied, gates on HTTP
  reachability, nonce echo, a verifier resolved for the
  advertised selector, body shape, leap-seconds and
  signature header parsing, and Ed25519 signature
  verification under the resolved key. Without secrets
  it gates only on reachability and nonce echo, then
  reports the advertised selector and signature as
  informational.
- API doc model in the published package —
  `@kagal/build-tsdoc` extracts the TSDoc surface at
  build time into `dist/bin.api.json`.
