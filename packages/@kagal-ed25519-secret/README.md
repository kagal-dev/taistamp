# @kagal/ed25519-secret

WebCrypto Ed25519 signer plus DKIM-style selector
validation. Self-contained — no dependency on
`@kagal/taistamp`.

## Install

```sh
pnpm add @kagal/ed25519-secret
```

## API

- `Signer` — `{ sign(message: BufferSource): Promise<ArrayBuffer> }`
- `newSigner(key)` — WebCrypto Ed25519 signer factory.
  Pass an Ed25519 private `CryptoKey` with `'sign'`
  usage; returns 64-byte raw RFC 8032 signatures.
- `SELECTOR_PATTERN` —
  `/^[A-Za-z](?:[\dA-Za-z_-]{0,61}[\dA-Za-z])?$/`, the
  DKIM selector grammar (RFC 6376 §3.1, narrowed to a
  single label so the value is also a valid sf-token
  under RFC 9651). Selectors must start with a letter
  and end with a letter or digit.
- `isValidSelector(value)` — boolean predicate.
- `assertValidSelector(value, context?)` — throws
  `TypeError` on a non-matching value; pass `context`
  to prefix the error message.

## Licence

MIT — see [LICENCE.txt](./LICENCE.txt).
