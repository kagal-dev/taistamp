# Changelog

All notable changes to `@kagal/taistamp` will be
documented in this file.

## [Unreleased]

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
