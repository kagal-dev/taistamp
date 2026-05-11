# @kagal/ed25519-secret

WebCrypto Ed25519 — key-pair construction, signing,
DKIM-style selector validation, and base64 helpers.
Self-contained — no dependency on `@kagal/taistamp`.

## Install

```sh
pnpm add @kagal/ed25519-secret
```

## API

- `KeyPair` — the returned triple: `privateKey` (the
  branded `Ed25519Seed`, for persistence), `publicKey`
  (extractable, for distribution), and `signKey`
  (non-extractable, for in-process signing).
- `Ed25519Seed` — branded 32-byte seed (RFC 8032);
  values are length-validated and defensive-copied at
  construction.
- `asEd25519Seed(input, context?)` — validate length
  and brand a seed; accepts a 32-byte `Uint8Array` or
  its base64 encoding.
- `newKeyPair(input?, context?)` — build a `KeyPair`
  from a 32-byte raw seed (or its base64 encoding);
  omit / pass `undefined` to generate a fresh seed via
  `crypto.getRandomValues`. `context` prefixes any
  thrown error and defaults to `'newKeyPair'`.
- `KeyConfig` — the returned config: selector, the
  Ed25519 key triple, and a `Signer`:
  - `selector: string` — validated against
    `SELECTOR_PATTERN`.
  - `privateKey: Ed25519Seed` — raw seed for
    persistence.
  - `publicKey: CryptoKey` — extractable, verify-only.
  - `signKey: CryptoKey` — non-extractable, sign-only.
  - `signer: Signer` — pre-built, backed by `signKey`.
- `parseSecretToKey(secretString, context?)` — parse
  a `selector:base64` secret into a `KeyConfig`. The
  base64 portion is a 32-byte Ed25519 seed (standard
  or URL-safe). `context` prefixes any thrown error
  and defaults to `'parseSecretToKey'`.
- `Signer` — `{ sign(message: BufferSource): Promise<ArrayBuffer> }`
- `newSigner(key, context?)` — WebCrypto Ed25519
  signer factory. Pass an Ed25519 private `CryptoKey`
  with `'sign'` in `usages`; returns 64-byte raw
  RFC 8032 signatures. Throws `TypeError` if the key
  fails either check; `context` prefixes the message.
- `SELECTOR_PATTERN` —
  `/^[A-Za-z](?:[\dA-Za-z_-]{0,61}[\dA-Za-z])?$/`, the
  DKIM selector grammar (RFC 6376 §3.1, narrowed to a
  single label so the value is also a valid sf-token
  under RFC 9651). Selectors must start with a letter
  and end with a letter or digit.
- `isValidSelector(value)` — boolean predicate.
- `assertValidSelector(value, context?)` — throws
  `TypeError` on a non-matching value, naming the
  pattern and quoting the input; `context` prefixes
  the message.

### Byte helpers

- `encodeBase64(bytes)` — encode bytes as standard
  base64 with `=` padding.
- `decodeBase64(b64, context?)` — decode standard or
  URL-safe base64, padding optional. Throws `TypeError`
  on `atob`-rejected input (original rejection as
  `cause`); pass `context` to prefix the error message.
- `asBytes(input, context?)` — normalise a
  bytes-or-base64 input to a fresh `Uint8Array`. Bytes
  are defensive-copied; strings go through
  `decodeBase64`.
- `getRandom(length, context?)` — fresh `Uint8Array`
  of the requested length filled via
  `crypto.getRandomValues`. Throws `TypeError` on
  non-integer or negative `length`; pass `context` to
  prefix the error message.

## Licence

MIT — see [LICENCE.txt](./LICENCE.txt).
