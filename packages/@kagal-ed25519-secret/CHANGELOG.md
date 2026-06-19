# Changelog

All notable changes to `@kagal/ed25519-secret` will be
documented in this file.

## [Unreleased]

## [0.3.2] - 2026-06-19

Mint-side `selector:base64` secret generation, plus the
`atLeast` and `isInRange` numeric helpers.

### Added

- `newSecret(selector, context?)` — mint a fresh
  `selector:base64` secret: validates the selector
  against `SELECTOR_PATTERN`, then encodes a freshly
  generated 32-byte Ed25519 seed from
  `crypto.getRandomValues`. The mint counterpart to
  `parseSecretToKey`, completing the
  `newSecret` → `parseSecretToKey` → `makeKeyRecords`
  provisioning journey in one package.
- `atLeast(min, value?)` — the larger of `min` and
  `value`, rounding a fractional `value` to the
  nearest integer first and falling back to `min`
  when `value` is absent or non-finite. With an
  integer `min` the result is always an integer
  ≥ `min`.
- `isInRange(value, min, max?)` — whether `value` is an
  integer within the inclusive range `[min, max]`. `max`
  defaults to `Number.MAX_SAFE_INTEGER`, so the
  two-argument form tests for an integer ≥ `min`.
  `getRandom`'s non-negative-integer guard now delegates
  to it.

## [0.3.1] - 2026-06-07

API doc model publication and a devDependency refresh.

### Added

- API doc model in the published package —
  `@kagal/build-tsdoc` extracts the TSDoc surface at
  build time into `dist/index.api.json`.

### Changed

- DevDependencies refreshed — `@poupe/eslint-config`,
  `@vitest/coverage-istanbul`, `vitest`.

## [0.3.0] - 2026-06-02

DKIM-style key-record publication and parsing, plus the
Ed25519 verifier side — in-process verification, raw-key
import, and record-to-key/verifier parsing.

### Added

- `makeKeyRecords(input, template?, context?)` — build
  `KeyRecord`s ready for publication as
  `<selector>._keys.<domain>` DNS TXT values.
  Accepts a single `KeyRecordInput`, an array
  (including empty), or `undefined`; returns a frozen
  `{ [selector]: record }` object keyed by selector
  (insertion order matches input order; duplicate
  selectors last-write-wins). `k=` is the public key's
  algorithm (lowercase WebCrypto name, `'ed25519'`);
  `p=` is the base64-encoded raw public key via
  `encodeKey`. An input that omits `publicKey` is a
  revocation record (empty `p=`, `k=` omitted, RFC 6376
  §3.6.1). `v=` and additional tags
  flow from `template` (via its index signature);
  `context` (default `'makeKeyRecords'`) prefixes any
  thrown error, with array inputs decorated as
  `<context>: input N` to disambiguate failures.
- `parseKeyRecord(input, context?)` — parse a DNS TXT
  record value into a `KeyRecord<Uint8Array>` per
  RFC 6376 §3.2 (tag-list grammar) and §3.6.1 (`p=`
  semantics). Accepts a raw tag-list string, a
  DoH-JSON-style string of one or more whitespace-
  separated quoted character-strings (RFC 1035 §3.3
  and RFC 6376 §3.6.2.2), or an array of pre-extracted
  character-strings (Node `dns.resolveTxt`, DoH-wire
  parsers); multi-piece forms are concatenated with no
  intervening whitespace. Strict on grammar (rejects
  empty tag-specs, malformed quoting, duplicate tag
  names, missing `p=`, undecodable base64); lenient on
  semantics (unknown tags preserved, unknown `v`/`k`
  values passed through). Empty `p=` yields
  `p: undefined` per RFC 6376 §3.6.1's revoked-key
  convention. `context` (optional) prefixes any thrown
  error.
- `KeyRecord<P>` — DKIM-style tag-list key record
  (RFC 6376 §3.2 syntax, §3.6.1 `p=` semantics) with
  declared `k?`, `p`, `v?` and an index signature for
  additional tags. `P` tracks `p`'s value type:
  `Uint8Array` (default; parse direction), `string`
  (publish direction), `CryptoKey` (verify-only,
  post-import), or `Verifier` (post-wrap). Consumers
  needing typed access to a specific tag set extend the
  interface.
- `KeyRecordInput` — `{ publicKey?, selector }`; a
  public `CryptoKey` of a supported algorithm paired
  with the DKIM selector under which it will be
  published. Omit
  `publicKey` to publish a revocation record (empty
  `p=`, RFC 6376 §3.6.1). `KeyConfig` (and any config
  carrying a `selector`) satisfies this structurally.
- `Verifier` — verify-side counterpart to `Signer`;
  `{ verify: (sig, msg) => Promise<boolean> }` where
  `sig` is `BufferSource` and `msg` is
  `BufferSource | string` (strings encoded as UTF-8).
- `newVerifier(key, context?)` — WebCrypto Ed25519
  verifier factory. Accepts an Ed25519 public
  `CryptoKey` with `'verify'` in `usages`; delegates
  each call to `crypto.subtle.verify`, which is
  specified to apply RFC 8032 §5.1.7 strict
  verification on conformant runtimes. Throws
  `TypeError` on a non-Ed25519 key or missing usage;
  `context` (optional) prefixes the message.
- `asMessageBytes(message)` — normalise a
  `BufferSource | string` input to `BufferSource`,
  encoding strings as UTF-8. Used internally by
  `Signer.sign` and `Verifier.verify`; exported for
  callers that need the same coercion.
- `KeyConfig.verifier` — `Verifier` backed by
  `KeyContext.publicKey`, mirroring the existing
  `KeyConfig.signer`. Pre-built by
  `parseSecretToKey` / `parseSecretsToKeys` so
  callers can verify in-process without an extra
  `newVerifier` step.
- `importVerifyKey(algorithm, keyData, context?)` —
  import a raw-encoded public verifying key (e.g. the
  `p=` bytes from `parseKeyRecord`) into an extractable
  verify-only `CryptoKey` ready for `newVerifier` or a
  direct `crypto.subtle.verify` call. `algorithm`
  matches case-insensitively so DKIM `k=` values
  (lowercase `'ed25519'` per RFC 6376 §3.6.1) work
  without pre-normalisation; the canonical form
  (`'Ed25519'`) is fed to `crypto.subtle.importKey`.
  `keyData` accepts raw bytes or their base64 encoding
  (standard or URL-safe). Throws `TypeError` for an
  unsupported algorithm, wrong byte length, or
  undecodable base64 (the last via `asBytes`).
- `parseRecordToKey(input, context?)` — parse a DNS TXT
  record value into a `KeyRecord<CryptoKey>`, importing
  the `p=` key bytes into a verify-only `CryptoKey`. The
  algorithm comes from the record's `k=`, defaulting to
  `rsa` only when `k=` is absent (RFC 6376 §3.6.1); an
  unsupported algorithm — the `rsa` default, an empty
  `k=`, or any non-Ed25519 value — is rejected rather
  than silently substituted. A revoked record (empty
  `p=`) carries through as `p: undefined` with no import;
  `v`, `k`, and unknown tags pass through unchanged.
  `context` (default `'parseRecordToKey'`) prefixes any
  thrown error.
- `parseRecordToVerifier(input, context?)` — parse a DNS
  TXT record value into a `KeyRecord<Verifier>`, the
  record's published key wrapped as a ready-to-use
  `Verifier`. Same revocation and tag pass-through
  behaviour as `parseRecordToKey`; `context` (default
  `'parseRecordToVerifier'`) prefixes any thrown error.

### Changed

- `newSigner` and `encodeKey` — algorithm-rejection
  error wording changed from `expected Ed25519 key,
  got <X>` to `unsupported algorithm: <X>`.
- `Signer.sign` — `message` parameter widened from
  `BufferSource` to `BufferSource | string`; string
  inputs are encoded as UTF-8 before signing.
- README — the "Fetching a published public key"
  walkthrough now uses `parseKeyRecord` instead of
  ad-hoc quote-stripping and a direct `decodeBase64`;
  covers multi-string concatenation (RFC 1035 §3.3)
  and revoked-key handling (RFC 6376 §3.6.1).
- README — the "Verifying an Ed25519 signature in
  WebCrypto" walkthrough now uses `newVerifier` in
  place of bare `crypto.subtle.verify`.
- README — the "Fetching a published public key"
  walkthrough now uses `importVerifyKey` in place of
  a bare `crypto.subtle.importKey('raw', ...)`.

## [0.2.1] - 2026-05-29

ASCII byte decoding and an empty-context error-prefix fix.

### Added

- `decodeASCII(bytes, context?)` — decode bytes as 7-bit
  ASCII, one code point per byte. Rejects any byte ≥
  `0x80` with `TypeError` (`expected 7-bit ASCII, got
  0x<hh>`, optional `context` prefix) rather than mapping
  it into the Latin-1 range.

### Fixed

- An empty `context` argument no longer prepends a bare
  `:` to thrown error messages. `decodeBase64`,
  `encodeKey`, `getRandom`, `asEd25519Seed`,
  `assertValidSelector`, and `newSigner` now treat `''`
  the same as an omitted context.

## [0.2.0] - 2026-05-20

JWKS publication and multi-secret parsing.

### Added

- `newKeys(input?, kid?, context?)` — supersedes
  `newKeyPair`. Accepts an optional `kid` (RFC 7517
  §4.5; free-form, threaded verbatim; falsy values
  omit the field) and returns a `KeyContext` that
  also carries a publication-ready `publicJWK`
  (`Object.freeze`d at construction). `context`
  defaults to `'newKeys'`.
- `KeyContext` — `{ privateKey, publicKey, signKey,
  publicJWK }`. New canonical return type for
  `newKeys`.
- `Ed25519PublicJWK` — typed public JWK for Ed25519
  (RFC 8037 §3.1) with literal `kty: 'OKP'`,
  `crv: 'Ed25519'`, plus `x` (base64url-encoded raw
  public key), `use: 'sig'`, `alg: 'EdDSA'`, and the
  optional `kid`.
- `encodeKey(key, context?)` — export an extractable
  Ed25519 public `CryptoKey` as standard base64 of its
  32-byte raw form, for out-of-band distribution.
  Throws `TypeError` on non-Ed25519 or non-public
  input, or when WebCrypto refuses to export the raw
  bytes (non-extractable) — the underlying rejection
  is preserved as `cause`.
- `Bytes` — type alias for `Uint8Array<ArrayBuffer>`
  (TS lib 5.7+; plain `Uint8Array` on older), the
  shape `BufferSource` accepts. The byte helpers
  (`decodeBase64`, `getRandom`, `asBytes`) now return
  `Bytes`, so callers can pass results into
  `crypto.subtle.*` without casting.
- `parseSecretsToKeys(secrets, strict?, context?)` —
  parse multiple `selector:base64` secrets from a
  single string. Splits on any character outside the
  `selector:base64` alphabet — whitespace, commas,
  semicolons, pipes, etc. — and drops empty fragments.
  `strict: true` (default) rejects on a malformed
  entry with `<context>: secret N: ...`;
  `strict: false` silently skips failures. Input
  order preserved.
- `splitFirst(items)` — generic list helper. Takes a
  list, a single value, or `undefined`; returns
  `{ first?, rest }`. `undefined` or an empty array
  yields `{ rest: [] }`; a single value or a
  one-element array yields `{ first, rest: [] }`.
- `splitLast(items)` — generic list helper. Takes a
  list, a single value, or `undefined`; returns
  `{ last?, rest }`. `undefined` or an empty array
  yields `{ rest: [] }`; a single value or a
  one-element array yields `{ last, rest: [] }`.
- `makeJWKS(keys)` — collect every entry's `publicJWK`
  into an `Ed25519JWKSet` (RFC 7517 §5). Accepts a
  single `KeyContext` (or any `{ publicJWK }`
  container), an array (including empty), or
  `undefined`; empty inputs yield `{ keys: [] }`.
  Input order is preserved. The returned set and its
  `keys` array are `Object.freeze`d.
- `Ed25519JWKSet` — typed JWK Set (RFC 7517 §5)
  containing Ed25519 public JWKs only;
  `{ keys: Ed25519PublicJWK[] }`.

### Changed

- Hero gains `JWKS-ready and DNS-TXT-ready public key
  publication`.
- JWKS-endpoint walkthrough added under Usage.
- `KeyConfig` now extends `KeyContext`; the returned
  shape inherits `publicJWK`, with `kid` set to the
  parsed selector. Existing fields (`privateKey`,
  `publicKey`, `signKey`, `selector`, `signer`) are
  unchanged.
- `parseSecretToKey` now surfaces the inherited
  `publicJWK` on the returned `KeyConfig`, with `kid`
  pinned to the parsed selector — making a
  selector-scoped secret directly usable as a JWKS
  entry.
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
  `cryptography`, `dkim`, `eddsa`, `jwk`,
  `jwks`, `rfc7517`, `rfc8032`, `rfc8037`,
  `webcrypto`.
- `obuild` devDependency bumped to `^0.4.35`.

### Deprecated

- `newKeyPair(input?, context?)` — kept as a thin
  wrapper over `newKeys` for source-compatibility with
  0.1.x callers. New code should call `newKeys`
  directly.
- `KeyPair` — type alias for `KeyContext`; the surface
  is now the wider `KeyContext` shape (with
  `publicJWK`).

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
