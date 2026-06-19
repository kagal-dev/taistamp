# @kagal/ed25519-secret — Ed25519 keys, signing, and verification for WebCrypto

[![jsDocs.io][jsdocs-badge]][jsdocs-url]
[![npm version][npm-badge]][npm-url]
[![Licence: MIT][license-badge]][license-url]

WebCrypto Ed25519 — key-pair construction, signing and
verification, JWKS-ready and DNS-TXT-ready public key
publication, DKIM-style key-record parsing and
selector validation, and base64 helpers.
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

`makeJWKS` wraps one or many keys into the JWK Set
body (RFC 7517 §5) served by a `jwks.json` endpoint;
each `publicJWK` carries the `kid` supplied to
`newKeys` verbatim (RFC 7517 §4.5):

```ts
import { makeJWKS, newKeys } from '@kagal/ed25519-secret';

// `seed` from your secret store (or `undefined` for a fresh seed)
const key = await newKeys(seed, 's1');
const jwks = makeJWKS(key);
// jwks:
// {
//   keys: [{
//     kty: 'OKP', crv: 'Ed25519', x: '<base64url>',
//     use: 'sig', alg: 'EdDSA', kid: 's1',
//   }],
// }
//
// Pass an array of keys to publish many at once —
// each entry's `kid` rides on its own `publicJWK`.

// Serve as application/jwk-set+json (RFC 7517 §8.5.1):
return new Response(JSON.stringify(jwks), {
  headers: { 'content-type': 'application/jwk-set+json' },
});
```

For the env-var rotation pattern, see
[Parsing multiple secrets at once](#parsing-multiple-secrets-at-once).

### Publishing keys as DKIM-style DNS TXT records

`makeKeyRecords` builds the publishable record body
for each key (RFC 6376 §3.2 syntax, §3.6.1 `p=`
semantics) and returns them keyed by selector — ready
to serialise as DKIM tag-list TXT values:

```ts
import { makeKeyRecords, newKeys } from '@kagal/ed25519-secret';

// `seed` from your secret store (or `undefined` for a fresh seed)
const { publicKey } = await newKeys(seed);
const records = await makeKeyRecords(
  { publicKey, selector: 's1' },
  { v: 'DKIM1' },
);
// records:
// {
//   's1': { v: 'DKIM1', k: 'ed25519', p: '<base64>' },
// }
//
// Pass an array of `{ publicKey, selector }` inputs to
// publish many at once — each input's selector becomes
// the dict key. `KeyConfig` (from `parseSecretToKey` /
// `parseSecretsToKeys`) satisfies the input shape
// structurally.

// Serialise each entry as a DKIM tag-list TXT value
// (`v=DKIM1; k=ed25519; p=<base64>`) and publish under
// `<selector>._domainkey.<domain>`.
```

### Parsing a secret and signing a message

```ts
import { encodeBase64, parseSecretToKey } from '@kagal/ed25519-secret';

// `secret` may use standard or URL-safe base64 — both round-trip
const config = await parseSecretToKey(secret);
const signature = await config.signer.sign('payload');
const wire = encodeBase64(new Uint8Array(signature)); // for transport
```

### Parsing multiple secrets at once

One rotation pattern: append new secrets to the end
of the env var so existing entries keep their
position. Which entry signs new tokens is a
signing-side choice — the example uses the last
entry.

The JWKS publishes every entry's `publicJWK` and
verifiers match by `kid` (RFC 7517 §4.5), so
signatures issued before the rotation continue to
verify:

```ts
import { Hono } from 'hono';
import {
  makeJWKS,
  parseSecretsToKeys,
  splitLast,
} from '@kagal/ed25519-secret';
// hypothetical — your token-issuing handler factory
import { mountTokensHandler } from './tokens';

type Bindings = { SIGNING_SECRETS: string };

async function loadKeys(env: Bindings) {
  const keys = await parseSecretsToKeys(env.SIGNING_SECRETS);
  const { last: current } = splitLast(keys);
  if (!current) {
    throw new Error('SIGNING_SECRETS contained no usable secrets');
  }
  return { keys, current };
}

const app = new Hono<{ Bindings: Bindings }>();

// Publish every public key — verifiers match by `kid`
app.get('/.well-known/jwks.json', async (c) => {
  const { keys } = await loadKeys(c.env);
  return c.json(makeJWKS(keys));
});

// Issue tokens with the most recent secret
mountTokensHandler(app, async (c) => {
  const { current } = await loadKeys(c.env);
  return current.signer;
});

export default app;
```

### Plugging in a custom Signer

Drop in any `Signer` implementation — it's just
`{ sign: (message: BufferSource | string) => Promise<ArrayBuffer> }`.
Implementations that forward the message to another
byte-oriented API (a fetch body, an HSM SDK, …) can
use `asMessageBytes` to coerce string inputs to UTF-8
bytes:

```ts
import { asMessageBytes, type Signer } from '@kagal/ed25519-secret';

const remoteSigner: Signer = {
  sign: async (message) => {
    const response = await fetch('https://signer.example.com/sign', {
      method: 'POST',
      body: asMessageBytes(message),
    });
    return response.arrayBuffer();
  },
};

const signature = await remoteSigner.sign('payload');
```

### Publishing the public key from a stored secret

If you already have the `selector:base64` secret and need to
(re-)publish the public key — e.g. rolling out to new DNS infra
without rotating the seed:

```ts
import { encodeKey, parseSecretToKey } from '@kagal/ed25519-secret';

const config = await parseSecretToKey(secret);
const distributable = await encodeKey(config.publicKey);
// publish under a selector-scoped channel (e.g. a DNS TXT record)
```

For HTTP publication, pass the same config to
`makeJWKS` — the carried `publicJWK` lands in the
JWK Set's `keys` array.

### Fetching a published public key

`parseKeyRecord` handles the DKIM-style tag-list parsing,
DoH-JSON quote stripping, and multi-piece concatenation
(RFC 1035 §3.3 and RFC 6376 §3.6.2.2); feed the returned
record's `p` to `importVerifyKey`.
DNS-over-HTTPS JSON via `fetch` works in any runtime with
global `fetch`:

```ts
import { importVerifyKey, parseKeyRecord } from '@kagal/ed25519-secret';

const response = await fetch(
  `https://1.1.1.1/dns-query?name=${selector}._keys.example.com&type=TXT`,
  { headers: { accept: 'application/dns-json' } },
);
if (!response.ok) throw new Error(`DoH ${response.status}`);
const { Answer } = await response.json();
const data = Answer?.[0]?.data;
if (!data) throw new Error('record not found');

const record = parseKeyRecord(data);
if (record.p === undefined) throw new Error('key has been revoked');

// RFC 6376 §3.6.1: absent k= defaults to rsa.
const publicKey = await importVerifyKey(record.k ?? 'rsa', record.p);
```

`record.p` is `undefined` when the record uses RFC 6376
§3.6.1's revoked-on-empty convention; branch on it before
importing. `record.k` is `undefined` when the record omits
`k=`, which RFC 6376 §3.6.1 defaults to `rsa`; the
`?? 'rsa'` fallback makes that default explicit, and
`importVerifyKey` then rejects it as
`unsupported algorithm: rsa`. `importVerifyKey` matches
its `algorithm` argument case-insensitively, so DKIM's
`'ed25519'` lands without pre-normalisation. The
`v=` tag and any additional tags pass through unchecked —
the package is protocol-agnostic across DKIM-style record
formats; protocol-specific version validation (matching
`record.v` against an expected label) belongs with the
caller.

### Verifying an Ed25519 signature in WebCrypto

`newVerifier` wraps an Ed25519 public `CryptoKey` in a
`Verifier` — the verify-side counterpart to `Signer`. It
gate-checks `algorithm.name` and `usages` at construction
and delegates each `verify` call to `crypto.subtle.verify`,
which is specified to apply RFC 8032 §5.1.7 strict
verification (cofactor handling and signature-malleability
resistance); confirm your runtime conforms, or fall back to
a strict-verify library such as `@noble/ed25519`.

```ts
import { newVerifier } from '@kagal/ed25519-secret';

// `publicKey` from the previous snippet; `signature` is the bytes
// you received over the wire (BufferSource)
const verifier = newVerifier(publicKey);
const ok = await verifier.verify(signature, 'payload');
```

`verify` accepts the message as bytes (`BufferSource`) or
as a string; strings are encoded as UTF-8. Callers needing
another encoding can pass bytes directly.

The two walkthroughs above take a record apart step by
step. Two helpers bundle those steps for production use:

- `parseRecordToKey` — the fetch section's
  `parseKeyRecord` + `importVerifyKey`, returning the
  verify-only `CryptoKey`.
- `parseRecordToVerifier` — the above plus the
  `newVerifier` wrap, returning a ready `Verifier`.

Both carry the surviving tags alongside the key in the
returned record, so the revoked-key, `k=`-default, and tag
pass-through rules described above are unchanged:

```ts
import { parseRecordToVerifier } from '@kagal/ed25519-secret';

// `data` from the DoH fetch above; `signature` from the wire
const { p: verifier } = await parseRecordToVerifier(data);
if (verifier === undefined) throw new Error('key has been revoked');
const ok = await verifier.verify(signature, 'payload');
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
  public `CryptoKey` for a supported algorithm as
  standard base64 of its raw form, ready for out-of-band
  distribution (e.g. a DNS TXT record). The output
  round-trips through `decodeBase64` +
  `crypto.subtle.importKey('raw', ...)`. Throws
  `TypeError` if the key's algorithm isn't supported, or
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

### JWKS

- `Ed25519JWKSet` — JWK Set (RFC 7517 §5) containing
  Ed25519 public JWKs only — the shape served by a
  `jwks.json` endpoint when every key is Ed25519:
  `{ keys: Ed25519PublicJWK[] }`. Values returned by
  `makeJWKS` are `Object.freeze`d (the set and its
  `keys` array).
- `makeJWKS(keys)` — collect every entry's `publicJWK`
  into an `Ed25519JWKSet`. Accepts a single
  `KeyContext` (or any `{ publicJWK }` container), an
  array (including empty), or `undefined`; empty
  inputs yield `{ keys: [] }`. Input order is
  preserved.

### Key records

- `KeyRecord<P>` — DKIM-style tag-list record
  (RFC 6376 §3.2 syntax, §3.6.1 `p=` semantics) with
  declared `k?`, `p`, `v?` and an index signature for
  additional tags. `P` tracks `p`'s value type:
  `Uint8Array` (default; parse direction),
  `string` (publish direction), `CryptoKey`
  (verify-only, post-import), or `Verifier`
  (post-wrap). Consumers needing typed access to a
  specific tag set extend the interface.
- `KeyRecordInput` — `{ publicKey?, selector }`; a
  public `CryptoKey` of a supported algorithm paired
  with the DKIM selector under which it will be
  published. Omit `publicKey` to publish a revocation
  record (empty `p=`, RFC 6376 §3.6.1). `KeyConfig`
  (and any config carrying a `selector`) satisfies
  this structurally.
- `makeKeyRecords(input, template?, context?)` —
  build `KeyRecord`s ready for publication as
  `<selector>._keys.<domain>` DNS TXT values.
  Accepts a single `KeyRecordInput`, an array
  (including empty), or `undefined`; returns a frozen
  `{ [selector]: record }` keyed by selector. Input
  order is preserved; duplicate selectors
  last-write-wins. `template` supplies `v=` and any
  additional tags (via its index signature); `k=` (the
  key's algorithm — lowercase WebCrypto name,
  `'ed25519'`) and `p` (the base64-encoded public key)
  are synthesised by the function and override any
  same-named entries in `template`. An input that omits
  `publicKey` yields a revocation record (empty `p=`,
  `k=` omitted, RFC 6376 §3.6.1). `context`
  (default `'makeKeyRecords'`) prefixes any thrown
  error; array inputs decorate as
  `<context>: input N` to disambiguate failures.
- `parseKeyRecord(input, context?)` — parse a TXT
  record value (raw string, DoH-JSON-quoted string,
  or a pre-extracted character-string array) into a
  `KeyRecord<Uint8Array>`. Strict on tag-list syntax,
  lenient on semantics (unknown `v=`/`k=` values and
  extra tags pass through). Empty `p=` yields
  `p: undefined` per RFC 6376 §3.6.1's revoked-key
  convention. `context` prefixes any thrown error.
- `parseRecordToKey(input, context?)` — parse a TXT
  record value into a `KeyRecord<CryptoKey>`, importing
  the `p=` bytes into a verify-only `CryptoKey`. The
  algorithm comes from `k=`, defaulting to `rsa` only
  when `k=` is absent (RFC 6376 §3.6.1); an unsupported
  algorithm — the `rsa` default, an empty `k=`, or any
  non-Ed25519 value — is rejected rather than silently
  substituted. A revoked record (empty `p=`) carries
  through as `p: undefined`; other tags pass through.
  `context` (default `'parseRecordToKey'`) prefixes any
  thrown error.
- `parseRecordToVerifier(input, context?)` — like
  `parseRecordToKey`, but wraps the imported key as a
  `Verifier`, yielding a `KeyRecord<Verifier>`. Same
  revocation and tag pass-through behaviour; `context`
  defaults to `'parseRecordToVerifier'`.

### Secrets

- `KeyConfig` — extends `KeyContext` with three
  fields, inheriting `privateKey`, `publicKey`,
  `signKey`, `publicJWK` from it:
  - `selector: string` — validated against
    `SELECTOR_PATTERN`; also set as
    `publicJWK.kid`.
  - `signer: Signer` — pre-built, backed by `signKey`.
  - `verifier: Verifier` — pre-built, backed by `publicKey`.
- `newSecret(selector, context?)` — mint a fresh
  `selector:base64` secret. Validates `selector`
  against `SELECTOR_PATTERN`, then encodes a freshly
  generated 32-byte Ed25519 seed
  (`crypto.getRandomValues`) as standard base64. No
  selector default — the caller supplies it. `context`
  prefixes any thrown error and defaults to
  `'newSecret'`.
- `parseSecretToKey(secretString, context?)` — parse
  a `selector:base64` secret into a `KeyConfig`. The
  base64 portion is a 32-byte Ed25519 seed (standard
  or URL-safe). `context` prefixes any thrown error
  and defaults to `'parseSecretToKey'`.
- `parseSecretsToKeys(secrets, strict?, context?)` —
  parse multiple `selector:base64` secrets from a
  single string with whitespace- or
  punctuation-separated entries; empty fragments are
  dropped.
  - `strict: true` (default) rejects on a malformed
    entry with `<context>: secret N: ...`.
  - `strict: false` silently skips failures and
    returns only the entries that parsed (input
    order preserved).
  - `context` defaults to `'parseSecretsToKeys'`.

### Signer

- `Signer` — `{ sign: (message) => Promise<ArrayBuffer> }`
  where `message: BufferSource | string`
- `newSigner(key, context?)` — WebCrypto Ed25519
  signer factory. Pass an Ed25519 private `CryptoKey`
  with `'sign'` in `usages`; returns 64-byte raw
  RFC 8032 signatures. Throws `TypeError` on a
  non-Ed25519 key or missing usage; `context`
  prefixes the message.

### Verifier

- `Verifier` — `{ verify: (sig, msg) => Promise<boolean> }`
  where `sig: BufferSource` and
  `msg: BufferSource | string`
- `newVerifier(key, context?)` — WebCrypto Ed25519
  verifier factory. Pass an Ed25519 public `CryptoKey`
  with `'verify'` in `usages`; delegates each call to
  `crypto.subtle.verify`, which is specified to apply
  RFC 8032 §5.1.7 strict verification on conformant
  runtimes. Throws `TypeError` on a non-Ed25519 key or
  missing usage; `context` prefixes the message.
- `importVerifyKey(algorithm, keyData, context?)` —
  import a raw-encoded public verifying key (e.g. the
  `p=` bytes from `parseKeyRecord`) into an extractable
  verify-only `CryptoKey`. `algorithm` matches
  case-insensitively, so DKIM `k=` values
  (`'ed25519'` per RFC 6376 §3.6.1) work without
  pre-normalisation. `keyData` accepts raw bytes or
  their base64 encoding (standard or URL-safe). Throws
  `TypeError` for an unsupported algorithm, wrong byte
  length, or undecodable base64; `context` prefixes the
  message.

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
- `decodeASCII(bytes, context?)` — decode bytes as 7-bit
  ASCII, one code point per byte. Throws `TypeError` on
  any byte ≥ `0x80` rather than mapping it into the
  Latin-1 range; pass `context` to prefix the error
  message.
- `asBytes(input, context?)` — normalise a
  bytes-or-base64 input to a fresh `Uint8Array`. Bytes
  are defensive-copied; strings go through
  `decodeBase64`.
- `asMessageBytes(message)` — normalise a
  `BufferSource | string` input to `BufferSource`.
  Bytes pass through; strings are encoded as UTF-8.
  Used internally by `Signer.sign` / `Verifier.verify`
  to accept either shape; differs from `asBytes`,
  whose string input is base64-decoded.
- `getRandom(length, context?)` — fresh `Uint8Array`
  of the requested length filled via
  `crypto.getRandomValues`. Throws `TypeError` on
  non-integer or negative `length`; pass `context` to
  prefix the error message.

### Numeric helpers

- `atLeast(min, value?)` — a minimum floor for an
  optional numeric value: always returns a whole number
  no smaller than `min`, never a fractional or `NaN`
  result. A missing, non-finite, or below-`min` value
  collapses to `min`; anything larger is rounded to the
  nearest integer.
- `isInRange(value, min, max?)` — whether `value` is an
  integer within the inclusive range `[min, max]`. `max`
  defaults to `Number.MAX_SAFE_INTEGER`, so a
  two-argument call tests whether `value` is an integer
  ≥ `min`. Fractional, `NaN`, infinite, and out-of-range
  values are `false`.

### List helpers

- `splitFirst(items)` / `splitLast(items)` — split
  `items` into `first`/`last` + `rest`. Accepts a
  list, a single value, or `undefined`. `undefined`
  or an empty array yields `{ rest: [] }`; a single
  value or a one-element array yields
  `{ first/last, rest: [] }`.

## Licence

MIT — see [LICENCE.txt](./LICENCE.txt).

<!-- Badge references -->
[jsdocs-badge]: https://img.shields.io/badge/jsDocs.io-reference-blue
[jsdocs-url]: https://www.jsdocs.io/package/@kagal/ed25519-secret
[license-badge]: https://img.shields.io/badge/Licence-MIT-blue.svg
[license-url]: ./LICENCE.txt
[npm-badge]: https://img.shields.io/npm/v/@kagal/ed25519-secret.svg
[npm-url]: https://www.npmjs.com/package/@kagal/ed25519-secret
