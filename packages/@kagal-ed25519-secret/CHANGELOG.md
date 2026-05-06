# Changelog

All notable changes to `@kagal/ed25519-secret` will be
documented in this file.

## [Unreleased]

## [0.0.1] - 2026-05-06

### Added

- Initial scaffolding lifted from `@kagal/taistamp` so
  the signer and selector validation are reusable
  outside taistamp:
  - `Signer` interface and `newSigner(key)` —
    pluggable sign abstraction plus a built-in
    WebCrypto Ed25519 signer producing 64-byte
    RFC 8032 signatures.
  - Selector helpers — `SELECTOR_PATTERN`,
    `isValidSelector(value)`, and
    `assertValidSelector(value, context?)` enforcing
    the DKIM single-label grammar (RFC 6376 §3.1,
    narrowed so the value is also a valid sf-token
    under RFC 9651).
