# Changelog

All notable changes to `@kagal/ed25519-secret` will be
documented in this file.

## [Unreleased]

### Added

- `encodeKey(key, context?)` — export an extractable
  Ed25519 public `CryptoKey` as standard base64 of its
  32-byte raw form, for out-of-band distribution.
  Throws `TypeError` on non-Ed25519 or non-public
  input, or when WebCrypto refuses to export the raw
  bytes (non-extractable) — the underlying rejection
  is preserved as `cause` on the rewrap.
- `Bytes` — type alias for `Uint8Array<ArrayBuffer>`
  (TS lib 5.7+; plain `Uint8Array` on older), the
  shape `BufferSource` accepts. The byte helpers
  (`decodeBase64`, `getRandom`, `asBytes`) now return
  `Bytes`, so callers can pass results into
  `crypto.subtle.*` without casting.

### Changed

- README reworked for shopfront and SEO — H1
  tagline, jsDocs.io / npm / Licence badges,
  runtime-compat line, and `npm install` /
  `yarn add` blocks alongside `pnpm add`.
  Usage H3s rewritten to name the operation
  ("Generating a fresh Ed25519 key pair",
  "Verifying an Ed25519 signature in
  WebCrypto", "Validating a DKIM-style
  selector"). `## API` sub-categorised into
  `Keys and seeds`, `Secrets`, `Signer`,
  `Selector validation`, and `Byte helpers`.
  Hero replaces the cross-package "no
  dependency on `@kagal/taistamp`" note with
  "Zero runtime dependencies — only the host
  runtime's WebCrypto", and adds verification
  to the surface enumeration.
- `keywords` expanded — `base64url`,
  `cryptography`, `dkim`, `eddsa`, `rfc8032`,
  `webcrypto`.

### Fixed

- `dist/index.d.ts` companion — restored
  alongside `.d.mts`. obuild emits only the
  modern extension; legacy declaration
  extractors (notably jsDocs.io) probe for
  `.d.ts` and treat the package as untyped
  when only `.d.mts` is present. Byte-identical
  to the `.d.mts`, matching the pre-obuild
  tarball shape.

## [0.1.2] - 2026-05-15

Maintenance release.

### Changed

- DevDependency pins normalised to `^` outside
  `~0.0.x`, so routine minor bumps no longer require
  a manual range edit.
- DevDependencies refreshed — `@types/node`,
  `@vitest/coverage-istanbul`, `publint`, `vitest`.
- TypeScript devDependency bumped to `^6.0.3` (major).
- Build toolchain migrated from `unbuild` to `obuild`;
  dist layout (`index.mjs` + `index.d.mts` + sourcemaps)
  is unchanged.

### Removed

- TSDoc extraction is no longer wired into the build.
  The `_docs/api*.json` artefacts previously emitted by
  `@kagal/build-tsdoc`'s `newDocumentsHook` are no
  longer produced; a placeholder build hook prints
  `TSDoc extraction not run`.

## [0.1.1] - 2026-05-13

Maintenance release.

### Added

- `test:compat` — framework-free smoke probe at
  `src/__tests__/compat.mjs` confirming the built
  dist loads on the current Node version and that
  public exports resolve to the expected shapes.

## [0.1.0] - 2026-05-11

### Added

- Ed25519 key-pair construction — `newKeyPair(input?,
  context?)` produces a `KeyPair` from a 32-byte
  Ed25519 seed (RFC 8032), accepting raw bytes, their
  base64 encoding, or no input at all (fresh seed
  generated via `crypto.getRandomValues`). The
  returned `KeyPair` carries the branded seed
  (`privateKey`), an extractable `publicKey` (for
  distribution), and a
  non-extractable `signKey` (for in-process signing).
  `context` (default `'newKeyPair'`) prefixes any
  thrown error.
- Seed validator — `asEd25519Seed(input, context?)`
  validates length and defensive-copies seed bytes,
  returning the branded `Ed25519Seed`. String input is
  decoded as base64 first.
- Secret parsing:
  - `parseSecretToKey(secretString, context?)` — parse
    a `selector:base64` secret into a `KeyConfig`;
    `context` (default `'parseSecretToKey'`) prefixes
    any thrown error.
  - `KeyConfig` — `{ selector, privateKey, publicKey,
    signKey, signer }`. Selector is validated against
    `SELECTOR_PATTERN`; `privateKey` is the raw seed
    (branded `Ed25519Seed`); `signKey` is
    non-extractable / sign-only; `signer` wraps
    `signKey`.
- Byte helpers:
  - `encodeBase64(bytes)` — standard, padded.
  - `decodeBase64(b64, context?)` — standard or
    URL-safe, padding optional; throws `TypeError`
    on `atob` rejection, optional `context` prefix.
  - `asBytes(input, context?)` — normalise bytes or
    base64 to a fresh `Uint8Array`.
  - `getRandom(length, context?)` — fresh random
    bytes via `crypto.getRandomValues`; throws
    `TypeError` on non-integer or negative `length`,
    optional `context` prefix.

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
