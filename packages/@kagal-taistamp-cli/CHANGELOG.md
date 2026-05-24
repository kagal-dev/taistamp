# Changelog

All notable changes to `@kagal/taistamp-cli` will be
documented in this file.

## [Unreleased]

### Added

- `taistamp seed new [--selector <id>]` — mints a fresh
  `selector:base64` Ed25519 secret. `--selector` defaults
  to the literal string `default`.
- `taistamp probe <url>` — probes a remote
  `/.well-known/taistamp` endpoint. With one or more
  `--secret` / `--secret-env` supplied, gates on HTTP
  reachability, nonce echo, selector membership in the
  supplied bag, body shape, leap-seconds and signature
  header parsing, and Ed25519 signature verification.
  Without secrets it gates only on reachability and
  nonce echo, then reports the advertised selector and
  signature as informational.
