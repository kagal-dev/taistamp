# Changelog

All notable changes to `@kagal/ed25519-secret` will be
documented in this file.

## [Unreleased]

### Added

- Ed25519 key-pair construction — `newKeyPair(input,
  context?)` produces a `KeyPair` from a 32-byte
  Ed25519 seed (RFC 8032), accepting either raw bytes
  or their base64 encoding. The returned `KeyPair`
  carries the branded seed (`privateKey`), an
  extractable `publicKey` (for distribution), and a
  non-extractable `signKey` (for in-process signing).
  `context` (default `'newKeyPair'`) prefixes any
  thrown error.
- Seed validator — `asEd25519Seed(input, context?)`
  validates length and defensive-copies seed bytes,
  returning the branded `Ed25519Seed`. String input is
  decoded as base64 first.
- Base64 helpers:
  - `encodeBase64(bytes)` — standard, padded.
  - `decodeBase64(b64, context?)` — standard or
    URL-safe, padding optional; throws `TypeError`
    on `atob` rejection, optional `context` prefix.

### Changed

- `newSigner(key, context?)`:
  - Validates `key.algorithm.name` and `key.usages`
    at construction; both throws use the
    `expected X, got Y` form.
  - Optional `context?` prefixes the error with
    `<context>:`, joining `assertValidSelector` and
    `decodeBase64`.
- `assertValidSelector` error quotes the offending
  value alongside the pattern, matching the same
  `expected X, got Y` shape.

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
