# Changelog

<!-- cspell:words Datatracker -->

All notable changes to `@kagal/taistamp` will be
documented in this file.

## [Unreleased]

## [0.1.0] - 2026-05-20

Signed-nonce framing fixed to match spec §6.1 — 0.0.x signatures were never spec-conformant.

### Changed

- README reworked for shopfront and SEO — H1
  tagline, jsDocs.io / npm / Licence badges,
  runtime-compat line, and `npm install` /
  `yarn add` blocks alongside `pnpm add`.
  `## Handler` → `## Usage`, `## Signing` →
  `## Signing the response`, `## Verifying` →
  `## Verifying a signature`. New `## API`
  umbrella documents the verifier-side helpers
  (`composeSignaturePayload`, `asLeapSeconds`,
  `extractLeapSeconds`, `asNonce`) and branded
  types previously left implicit.
- `keywords` expanded — `cryptography`,
  `ed25519`, `eddsa`, `handler`, `http`,
  `nonce`, `rfc8032`, `signing`, `timestamp`,
  `webcrypto`.
- README now names the IETF Internet-Draft the
  implementation tracks (`draft-mery-nagy-taistamp`
  / `karasz/rfc-taistamp`) via a `## Specification`
  section linking Datatracker and the GitHub
  working tree. Inline `spec §N` citations across
  the README, `cors.ts`, `handler.ts`,
  `leap-seconds.ts`, and `nonce.ts` are refreshed
  against draft `-00` (notably §5.2 → §5.4, §5.1
  → §5.3, §7 → §9).
- `obuild` devDependency bumped to `^0.4.35`.
- `@kagal/ed25519-secret` workspace dependency
  re-resolves to `^0.2.0` at publish time.

### Fixed

- `dist/index.d.ts` companion — restored
  alongside `.d.mts`. obuild emits only the
  modern extension; legacy declaration
  extractors (notably jsDocs.io) probe for
  `.d.ts` and treat the package as untyped
  when only `.d.mts` is present. Byte-identical
  to the `.d.mts`, matching the pre-obuild
  tarball shape.
- Selector-regex prose in the README — quoted
  as `[A-Za-z][A-Za-z0-9_-]{0,62}`, missing the
  trailing-letter-or-digit constraint that
  `SELECTOR_PATTERN` enforces. Now quotes the
  pattern verbatim; surrounding prose notes
  "ends with a letter or digit".
- `composeSignaturePayload` now signs the decoded
  sf-binary octets of the nonce per spec §6.1, not
  the wire `:base64:` framing. Signatures emitted
  by previous releases will not verify against a
  spec-conformant verifier reconstructing the
  payload from spec text.
- README and `nonce.ts` doc comments now
  distinguish the wire-form length range
  (14..174 octets — a pre-decode optimisation)
  from spec §5.4's normative decoded-length bound
  (7..129 octets).

## [0.0.5] - 2026-05-15

Maintenance release.

### Added

- `TAISTAMP_PATH` constant — canonical export for the
  `/.well-known/taistamp` endpoint path.

### Changed

- DevDependency pins normalised to `^` outside
  `~0.0.x`, so routine minor bumps no longer require
  a manual range edit.
- DevDependencies refreshed — `@cloudflare/workers-types`,
  `@types/node`, `@vitest/coverage-istanbul`, `publint`,
  `vitest`.
- TypeScript devDependency bumped to `^6.0.3` (major).
- Build toolchain migrated from `unbuild` to `obuild`;
  dist layout (`index.mjs` + `index.d.mts` + sourcemaps)
  is unchanged.
- `@kagal/ed25519-secret` workspace dependency
  re-resolves to `^0.1.2` at publish time.

### Deprecated

- `TAI64N_PATH` — renamed to `TAISTAMP_PATH`. Kept as
  an alias so existing imports continue to work.

### Removed

- TSDoc extraction is no longer wired into the build.
  The `_docs/api*.json` artefacts previously emitted by
  `@kagal/build-tsdoc`'s `newDocumentsHook` are no
  longer produced; a placeholder build hook prints
  `TSDoc extraction not run`.

### Fixed

- Publish workflow no longer fails on `node:process`
  resolution. The unbuild → obuild bundler swap
  removes jiti's TypeScript loader from the prepack
  path, which the `@cloudflare/vitest-pool-workers`
  pool was incompatible with under the publish
  environment.
- `TAI64N_PATH` was a misnomer for the
  `/.well-known/taistamp` endpoint; the canonical
  export is now `TAISTAMP_PATH`. The old name stays
  as a deprecated alias for back-compat.

## [0.0.4] - 2026-05-13

Maintenance release.

### Added

- `test:compat` — framework-free smoke probe at
  `src/__tests__/compat.mjs` confirming the built
  dist loads on the current Node version and that
  public exports (HTTP wire constants, encoding
  constants, function-typed entries) resolve to the
  expected shapes.

## [0.0.3] - 2026-05-13

### Added

- `Access-Control-Max-Age: 600` on the pre-flight
  `OPTIONS` response, satisfying the spec §4.2
  SHOULD. Cuts pre-flight churn on high-traffic
  cross-origin clients (browsers' built-in defaults
  range from Chromium ~5s to Firefox 24h).

### Fixed

- `HEAD` responses no longer echo `TAI-Nonce` when
  the client sent one. The handler's nonce-echo
  branch was unconditional on method; spec §4.1
  forbids `HEAD` responses from carrying
  `TAI-Nonce` (alongside the already-omitted
  `TAI-Key-Selector` and `TAI-Signature`).

### Changed

- README's Verifying section now cites spec §7's
  MUST that verifiers apply the RFC 8032 §5.1.7
  strict verification procedure (cofactor handling,
  signature-malleability resistance), with a
  fallback note for runtimes whose WebCrypto
  `Ed25519 verify` is not guaranteed strict.
- `Signer` and `newEd25519Signer` move out into the
  new `@kagal/ed25519-secret` workspace package
  (`newEd25519Signer` is renamed to `newSigner` there
  — the algorithm lives in the package name now).
  `@kagal/taistamp` keeps both symbols available under
  the old names by re-exporting `Signer` and
  `newSigner as newEd25519Signer` from
  `@kagal/ed25519-secret`, so existing imports keep
  working. Selector validation, previously inlined in
  `handler.ts`, is now delegated to
  `assertValidSelector` from the same package.
  `@kagal/taistamp` depends on it via `workspace:^`.

## [0.0.2] - 2026-05-06

### Added

- `Nonce` branded type plus `asNonce(value)` —
  brands a string when it satisfies sf-binary syntax
  (RFC 9651 §3.3.5) and the 14..174 octet range, or
  returns `undefined` for every spec §5.2 "treat as
  absent" case. Verifiers wrap their recorded client
  nonce with `asNonce` before passing it to
  `composeSignaturePayload`.
- `TAI_LEAP_SECONDS_MAX` constant (= `0xFFFFFFFF`) —
  the upper bound for `leapSeconds` in the signed
  payload (u32be encoding).
- `LeapSeconds` branded type, plus
  `extractLeapSeconds(headers)` (reads `TAI-Leap-Seconds`
  from response headers) and `asLeapSeconds(number)`
  (coerces a raw number). Both return the value branded
  when in range, or `undefined` for missing / empty /
  non-numeric / non-integer / negative / out-of-range
  input — every spec §5.1 "treat as unsigned" case
  collapsed into one verdict. Mirrors the shape of
  `asNonce` / `Nonce`; the brand prevents arbitrary
  numbers from reaching the signing path.
- `composeSignaturePayload` now requires branded values
  for both its `leapSeconds` (`LeapSeconds`) and
  `nonce` (`Nonce`) arguments, so the framing helper
  cannot be called with unvalidated input.
- `OPTIONS` requests are now answered with `200 OK`
  and `Allow: GET, HEAD, OPTIONS`, advertising the
  supported method set per RFC 9110 §9.3.7. `OPTIONS`
  responses are never signed.
- `cors` config field on `newTaistampHandler()` —
  defaults to `'*'`; pass a specific origin to scope,
  or `false` to disable. When enabled: pre-flight
  `OPTIONS` carries `Access-Control-Allow-Origin`,
  `-Allow-Methods`, `-Allow-Headers`, and
  `-Expose-Headers`; `GET` / `HEAD` carry
  `Access-Control-Allow-Origin` and
  `-Expose-Headers`; `405` carries
  `Access-Control-Allow-Origin`; a non-`'*'` value
  adds `Vary: Origin` to every response.

### Changed

- `TAI-Nonce` handling now follows spec §5.2's
  "treat as absent" rule uniformly. A field that is
  missing, empty, duplicated, structurally malformed
  (sf-binary per RFC 9651 §3.3.5), or outside the
  14..174 octet range is dropped — no echo, no
  signature. The previous 400-on-duplicate branch is
  gone; out-of-range nonces are no longer echoed.
- `TAI_OFFSET` renamed to `TAI_LEAP_SECONDS` — same
  value (37), more accurate name (it's the leap-second
  count, not a generic offset), and pairs with the new
  `TAI_LEAP_SECONDS_MAX`. Now exported as
  `LeapSeconds` rather than `number` so it can be
  passed to `composeSignaturePayload` without coercion.
  Breaking for any caller that imported the old name;
  expected to be rare at 0.0.x.
- `taistampSignedPayload` renamed to
  `composeSignaturePayload` — "compose" matches the
  helper's existing JSDoc verb, "Signature" (modifier)
  is more accurate than "Signed" (past participle) for
  bytes that *will be* signed, and dropping the
  `taistamp` prefix avoids redundancy with the package
  namespace. Breaking for any caller that imported the
  old name; expected to be rare at 0.0.x.
- `Allow` header on `405` responses is now
  `GET, HEAD, OPTIONS` (was `GET, HEAD`).
- `sf-binary` citation refreshed RFC 8941 → RFC 9651.

## [0.0.1] - 2026-05-03

Initial release of `@kagal/taistamp` — platform-neutral
handler for `/.well-known/taistamp` serving signed
TAI64N timestamps over HTTP, against
[`draft-nagy-taistamp-00`][taistamp-draft-00].

### Added

- `newTaistampHandler({ selector?, signer? })` — Web
  Fetch handler. `GET`/`HEAD` return a 25-byte TAI64N
  label with `Content-Type: application/tai64n`,
  `Cache-Control: no-store`, and `TAI-Leap-Seconds`.
  Other methods return `405` with `Allow: GET, HEAD`.
  Signs the response when a 14–174 octet `TAI-Nonce`
  is present and `signer`+`selector` are configured;
  adds `TAI-Key-Selector` and `TAI-Signature`
  (sf-binary) headers.
- `taistampSignedPayload(label, leap, selector, nonce)`
  — exported framing helper for verifiers, producing
  the byte sequence `taistamp-v1\0 || labelBytes ||
  leapU32BE || selectorLen(u8) || selectorBytes ||
  nonceBytes`.
- `newEd25519Signer(key)` — built-in WebCrypto Ed25519
  signer producing 64-byte RFC 8032 signatures.
- `Signer` interface — pluggable for HSM/KMS backends.
- TAI64N helpers: `now()`, `fromUTC()`, `tai64nLabel()`,
  `tai64nLabelFromUTC()`.
- Constants: `TAI64N_PATH`, `TAI64N_CONTENT_TYPE`,
  `TAI64N_CONTENT_LENGTH`,
  `TAI64N_HEADER_KEY_SELECTOR`,
  `TAI64N_HEADER_LEAP_SECONDS`, `TAI64N_HEADER_NONCE`,
  `TAI64N_HEADER_SIGNATURE`, `TAI_OFFSET` (= 37),
  `TAI64_EPOCH_HI`, `VERSION`.

### Notes

- A duplicated `TAI-Nonce` field returns
  `400 Bad Request` — stricter than the draft's
  "treat as absent" rule for singletons; a duplicated
  singleton is treated as malformed input.

<!-- references -->
[taistamp-draft-00]: TBD
