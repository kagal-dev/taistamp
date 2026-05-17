# @kagal/ed25519-secret — Ed25519 keys, signing, and verification for WebCrypto

[![jsDocs.io][jsdocs-badge]][jsdocs-url]
[![npm version][npm-badge]][npm-url]
[![Licence: MIT][license-badge]][license-url]

WebCrypto Ed25519 — key-pair construction, signing and
verification, JWKS-ready and DNS-TXT-ready public key
publication, DKIM-style selector validation, and
base64 helpers.
Zero runtime dependencies — only the host runtime's
WebCrypto.

Runs anywhere with `crypto.subtle` — modern browsers,
Node ≥ 20, Cloudflare Workers, Deno, and Bun.

## Install

```sh
npm install @kagal/ed25519-secret
```

```sh
yarn add @kagal/ed25519-secret
```

```sh
pnpm add @kagal/ed25519-secret
```

## Usage

### Generating a fresh Ed25519 key pair

`newKeys()` mints the private seed (to store), the
public key (to publish), and a JWKS-ready `publicJWK`
in one call:

```ts
import { encodeBase64, encodeKey, newKeys } from '@kagal/ed25519-secret';

const selector = 's1';
// `undefined` ⇒ generate a fresh seed; the selector
// becomes `publicJWK.kid`.
const { privateKey, publicKey, publicJWK } =
  await newKeys(undefined, selector);

// Private — store somewhere safe (env var, secret manager, etc.)
const secret = `${selector}:${encodeBase64(privateKey)}`;

// Public — base64 of the raw public key for DNS-style
// distribution; `publicJWK` (carrying `kid: selector`)
// for a JWKS endpoint
const distributable = await encodeKey(publicKey);
```

### Building an Ed25519 key pair from your own seed

When you already hold a 32-byte seed (raw bytes or its
base64 encoding — e.g. derived from a KDF):

```ts
import { newKeys } from '@kagal/ed25519-secret';

// `seed`: a 32-byte Uint8Array or its base64 encoding
const { privateKey, publicKey } = await newKeys(seed);
```

### Publishing a JWKS endpoint

`newKeys` returns a `publicJWK` ready to drop into a
JWKS `keys` array (RFC 7517 §5); the optional `kid`
argument is threaded through verbatim:

```ts
import { newKeys } from '@kagal/ed25519-secret';

// `seed` from your secret store (or `undefined` for a fresh seed)
const { publicJWK } = await newKeys(seed, 's1');
// {
//   kty: 'OKP', crv: 'Ed25519', x: '<base64url>',
//   use: 'sig', alg: 'EdDSA', kid: 's1',
// }

const jwks = { keys: [publicJWK] };

// Serve as application/jwk-set+json (RFC 7517 §8.5.1):
return new Response(JSON.stringify(jwks), {
  headers: { 'content-type': 'application/jwk-set+json' },
});
```

For rotation, collect `publicJWK`s from multiple
`newKeys` calls — each pinned to its own `kid` — and
publish them together: `{ keys: [current, previous] }`.

### Parsing a secret and signing a message

```ts
import { encodeBase64, parseSecretToKey } from '@kagal/ed25519-secret';

// `secret` may use standard or URL-safe base64 — both round-trip
const config = await parseSecretToKey(secret);
const signature = await config.signer.sign(
  new TextEncoder().encode('payload'),
);
const wire = encodeBase64(new Uint8Array(signature)); // for transport
```

### Plugging in a custom Signer

Drop in any `Signer` implementation — it's just
`{ sign: (message: BufferSource) => Promise<ArrayBuffer> }`:

```ts
import type { Signer } from '@kagal/ed25519-secret';

const remoteSigner: Signer = {
  sign: async (message) => {
    const response = await fetch('https://signer.example.com/sign', {
      method: 'POST',
      body: message,
    });
    return response.arrayBuffer();
  },
};

const signature = await remoteSigner.sign(
  new TextEncoder().encode('payload'),
);
```

### Publishing the public key from a stored secret

If you already have the `selector:base64` secret and need to
(re-)publish the public key — e.g. rolling out to new DNS infra
without rotating the seed:

```ts
import { encodeKey, parseSecretToKey } from '@kagal/ed25519-secret';

const { publicKey } = await parseSecretToKey(secret);
const distributable = await encodeKey(publicKey);
// publish under a selector-scoped channel (e.g. a DNS TXT record)
```

The same config also carries `publicJWK` — drop that
into a JWKS `keys` array if you publish over HTTP
rather than DNS.

### Fetching a published public key

DNS-over-HTTPS JSON via `fetch` works in any runtime with
global `fetch`:

```ts
import { decodeBase64 } from '@kagal/ed25519-secret';

const response = await fetch(
  `https://1.1.1.1/dns-query?name=${selector}._keys.example.com&type=TXT`,
  { headers: { accept: 'application/dns-json' } },
);
if (!response.ok) throw new Error(`DoH ${response.status}`);
const { Answer } = await response.json();
const data = Answer?.[0]?.data;
if (!data) throw new Error('public key not found');

// DNS-over-HTTPS wraps each TXT character-string in
// quotes; this strips a single-string record only —
// multi-string records (RFC 1035 §3.3) need further
// handling.
const publicKey = await crypto.subtle.importKey(
  'raw',
  decodeBase64(data.replaceAll(/^"|"$/g, '')),
  { name: 'Ed25519' },
  true,
  ['verify'],
);
```

### Verifying an Ed25519 signature in WebCrypto

WebCrypto's `Ed25519 verify` is specified to apply RFC 8032 §5.1.7
strict verification (cofactor handling, signature-malleability
resistance); confirm your runtime conforms, or fall back to a
strict-verify library such as `@noble/ed25519`.

```ts
// `publicKey` from the previous snippet; `signature` is the bytes
// you received over the wire (BufferSource)
const ok = await crypto.subtle.verify(
  'Ed25519',
  publicKey,
  signature,
  new TextEncoder().encode('payload'),
);
```

### Validating a DKIM-style selector

```ts
import { assertValidSelector, isValidSelector } from '@kagal/ed25519-secret';

// Predicate: branch on the result
if (isValidSelector(value)) {
  // matches the pattern
}

// Assertion: fail fast on misconfigured input
assertValidSelector(value, 'config');
```

## API

- `VERSION` — package version string, mirrors
  `package.json#version`.

### Keys and seeds

- `KeyContext` — the returned value: `privateKey` (the
  branded `Ed25519Seed`, for persistence), `publicKey`
  (extractable, for distribution), `signKey`
  (non-extractable, for in-process signing), and
  `publicJWK` (publication-ready JWK).
- `KeyPair` — deprecated alias for `KeyContext`.
- `Ed25519PublicJWK` — typed public JWK for Ed25519
  (RFC 8037 §3.1): literal `kty: 'OKP'`,
  `crv: 'Ed25519'`, `x` (base64url public key),
  `use: 'sig'`, `alg: 'EdDSA'`, and the optional
  `kid` (RFC 7517 §4.5). Values returned by `newKeys`
  are `Object.freeze`d.
- `Ed25519Seed` — branded 32-byte seed (RFC 8032);
  values are length-validated and defensive-copied at
  construction.
- `asEd25519Seed(input, context?)` — validate length
  and brand a seed; accepts a 32-byte `Uint8Array` or
  its base64 encoding.
- `encodeKey(key, context?)` — export an extractable
  Ed25519 public `CryptoKey` as standard base64 of its
  32-byte raw form, ready for out-of-band distribution
  (e.g. a DNS TXT record). The output round-trips
  through `decodeBase64` +
  `crypto.subtle.importKey('raw', ...)`. Throws
  `TypeError` if the key's algorithm isn't Ed25519, or
  if it isn't a public key, or if WebCrypto refuses to
  export the raw bytes (non-extractable); pass
  `context` to prefix the error message.
- `newKeys(input?, kid?, context?)` — build a
  `KeyContext` from a 32-byte raw seed (or its base64
  encoding); omit / pass `undefined` to generate a
  fresh seed via `crypto.getRandomValues`. `kid`
  (optional, free-form string) is threaded into
  `publicJWK.kid`; falsy values (`undefined`, empty
  string) omit the field. `context` prefixes any
  thrown error and defaults to `'newKeys'`.
- `newKeyPair(input?, context?)` — deprecated wrapper
  over `newKeys` preserving the original 2-arg
  signature. `context` defaults to `'newKeyPair'`;
  the returned `publicJWK` carries no `kid`.

### Secrets

- `KeyConfig` — extends `KeyContext` with two fields,
  inheriting `privateKey`, `publicKey`, `signKey`,
  `publicJWK` from it:
  - `selector: string` — validated against
    `SELECTOR_PATTERN`; also set as
    `publicJWK.kid`.
  - `signer: Signer` — pre-built, backed by `signKey`.
- `parseSecretToKey(secretString, context?)` — parse
  a `selector:base64` secret into a `KeyConfig`. The
  base64 portion is a 32-byte Ed25519 seed (standard
  or URL-safe). `context` prefixes any thrown error
  and defaults to `'parseSecretToKey'`.

### Signer

- `Signer` — `{ sign: (message: BufferSource) => Promise<ArrayBuffer> }`
- `newSigner(key, context?)` — WebCrypto Ed25519
  signer factory. Pass an Ed25519 private `CryptoKey`
  with `'sign'` in `usages`; returns 64-byte raw
  RFC 8032 signatures. Throws `TypeError` if the key
  fails either check; `context` prefixes the message.

### Selector validation

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

- `Bytes` — `Uint8Array<ArrayBuffer>`-shaped type (TS
  lib 5.7+; plain `Uint8Array` on older), matching
  what `BufferSource` (and therefore every
  `crypto.subtle.*` byte parameter) accepts. The
  return type of `decodeBase64`, `getRandom`, and
  `asBytes`.
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

<!-- Badge references -->
[jsdocs-badge]: https://img.shields.io/badge/jsDocs.io-reference-blue
[jsdocs-url]: https://www.jsdocs.io/package/@kagal/ed25519-secret
[license-badge]: https://img.shields.io/badge/Licence-MIT-blue.svg
[license-url]: ./LICENCE.txt
[npm-badge]: https://img.shields.io/npm/v/@kagal/ed25519-secret.svg
[npm-url]: https://www.npmjs.com/package/@kagal/ed25519-secret
