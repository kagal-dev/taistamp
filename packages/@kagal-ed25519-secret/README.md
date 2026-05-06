# @kagal/ed25519-secret

WebCrypto Ed25519 signer, DKIM-style selector
validation, and base64 helpers. Self-contained — no
dependency on `@kagal/taistamp`.

## Install

```sh
pnpm add @kagal/ed25519-secret
```

## API

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

### Base64 helpers

- `encodeBase64(bytes)` — encode bytes as standard
  base64 with `=` padding.
- `decodeBase64(b64, context?)` — decode standard or
  URL-safe base64, padding optional. Throws `TypeError`
  on `atob`-rejected input (original rejection as
  `cause`); pass `context` to prefix the error message.

## Licence

MIT — see [LICENCE.txt](./LICENCE.txt).
