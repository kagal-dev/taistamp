# @kagal/taistamp — HTTP handler for Ed25519-signed TAI64N timestamps

[![jsDocs.io][jsdocs-badge]][jsdocs-url]
[![npm version][npm-badge]][npm-url]
[![Licence: MIT][mit-badge]][mit]

Platform-neutral handler for `/.well-known/taistamp` —
serves signed [TAI64N][tai64n] timestamps over HTTP for
clients that need authenticated wall-clock time without
running an NTP stack or trusting an unauthenticated TLS
handshake clock.

Runs anywhere with `crypto.subtle` — modern browsers,
Node ≥ 20, Cloudflare Workers, Deno, and Bun.

## Specification

Implements [`draft-mery-nagy-taistamp`][draft], the
IETF Internet-Draft for signed TAI64N timestamps over
HTTP. Working version: [`karasz/rfc-taistamp`][rfc-repo].
Inline `spec §N` citations in this README resolve
against that document.

## Install

```sh
npm install @kagal/taistamp
```

```sh
yarn add @kagal/taistamp
```

```sh
pnpm add @kagal/taistamp
```

## Usage

```typescript
import { newTaistampHandler, TAISTAMP_PATH } from '@kagal/taistamp';

const taistamp = newTaistampHandler();

// Worker fetch handler
export default {
  async fetch(request: Request): Promise<Response> {
    if (new URL(request.url).pathname === TAISTAMP_PATH) {
      return taistamp(request);
    }
    // ...
  },
};

// Hono route
app.get(TAISTAMP_PATH, (c) => taistamp(c.req.raw));
```

`newTaistampHandler()` returns an
`async (request) => Response`. `GET` and `HEAD` succeed
with a fresh 25-byte TAI64N label
(`@<sec-hi><sec-lo><nano>`); `OPTIONS` returns `200`
with `Allow: GET, HEAD, OPTIONS`; other methods return
`405` with the same `Allow`. A `TAI-Nonce` that is
missing, empty, duplicated, not a valid sf-binary
value, or outside the 14–174 octet range is treated as
absent (no echo, no signature) per [spec §5.4][spec-nonce].

Response headers on success:

| Header | Value |
|--------|-------|
| `Content-Type` | `application/tai64n` |
| `Content-Length` | `25` |
| `Cache-Control` | `no-store` |
| `TAI-Leap-Seconds` | decimal count (e.g. `37`), always present |

A request `TAI-Nonce` on `GET` is echoed verbatim in
the response. `HEAD` responses carry the same headers
as the corresponding `GET` but never include
`TAI-Nonce`, `TAI-Key-Selector`, or `TAI-Signature` —
the signed payload covers the response body, so a
`HEAD` cannot be verified, and the spec forbids the
nonce echo on `HEAD` for the same reason.

## CORS

The handler is cross-origin permissive by default.
Pass a specific origin to scope the policy, or
`false` to disable the CORS-specific headers
entirely.

```typescript
newTaistampHandler();                                // cors: '*' (default)
newTaistampHandler({ cors: 'https://example.com' }); // scoped origin
newTaistampHandler({ cors: false });                 // CORS-specific headers off
```

When CORS is enabled, responses carry:

| Response | CORS headers added | `Vary: Origin` (scoped origin only) |
|----------|--------------------|------|
| `OPTIONS` 200 | `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods: GET, HEAD`, `Access-Control-Allow-Headers: TAI-Nonce`, `Access-Control-Expose-Headers: TAI-Leap-Seconds, TAI-Nonce, TAI-Key-Selector, TAI-Signature`, `Access-Control-Max-Age: 600` | yes |
| `GET` / `HEAD` 200 | `Access-Control-Allow-Origin`, `Access-Control-Expose-Headers` (so browser JS can read the `TAI-*` headers) | yes |
| `405` | `Access-Control-Allow-Origin` | yes |

`Vary: Origin` lands on every response when the
configured origin is anything other than `'*'`, so
caches can keep per-origin variants distinct. The
`Allow: GET, HEAD, OPTIONS` and `Access-Control-Allow-Methods:
GET, HEAD` lists are intentionally different — the
former is RFC 9110 §9.3.7 method discovery (includes
`OPTIONS` itself), the latter is the Fetch CORS list
of methods JS would ever preflight (so `OPTIONS` is
omitted).

With `cors: false` none of the `Access-Control-*` or
`Vary` headers are emitted, but `OPTIONS` is still
answered with `200` and
`Allow: GET, HEAD, OPTIONS` — method discovery
(RFC 9110 §9.3.7) is independent of cross-origin
policy.

## Signing the response

```typescript
import {
  newEd25519Signer,
  newTaistampHandler,
} from '@kagal/taistamp';

const taistamp = newTaistampHandler({
  selector: 'sel2026q2',
  signer: newEd25519Signer(privateKey),
});
```

The `Signer` interface and the `newEd25519Signer`
factory are re-exported from
[`@kagal/ed25519-secret`](../@kagal-ed25519-secret/README.md)
— callers of `@kagal/taistamp` get them through this
package and don't need to depend on the underlying
package directly.

`signer` and `selector` are co-required: pass both to
sign, neither for an unsigned handler. Construction
throws if only one is supplied, or if `selector` does
not match `/^[A-Za-z](?:[\dA-Za-z_-]{0,61}[\dA-Za-z])?$/`
(a single DNS-safe label that starts with a letter,
ends with a letter or digit, and is also a valid
Structured Field token).

When the request is a `GET` carrying a valid
`TAI-Nonce` (see Usage section for the
"treat as absent" rules) *and* a signer is configured,
the response gains:

- `TAI-Key-Selector: <selector>`
- `TAI-Signature: :<base64>:` (sf-binary, RFC 9651)
  over the framed payload.

`HEAD`, `405`, and nonce-less responses are never
signed.

The framed payload is:

```text
'taistamp-v1\0' || labelBytes || leapU32BE
              || selectorLen(u8) || selectorBytes
              || nonceBytes
```

- `taistamp-v1\0` — domain-separation tag with
  trailing NUL, so the same key cannot be tricked
  into signing for any other protocol.
- `labelBytes` — the 25 ASCII bytes of the TAI64N
  label.
- `leapU32BE` — leap-seconds count as a 4-byte
  big-endian unsigned integer.
- `selectorLen` / `selectorBytes` — the selector
  length-prefixed by a single byte, so a downgrade
  attacker cannot rewrite `TAI-Key-Selector` without
  invalidating the signature.
- `nonceBytes` — the octet sequence obtained by
  decoding the `TAI-Nonce` field value as an
  sf-binary item per RFC 9651. The textual
  `:base64:` framing is not part of the signed
  input (spec §6.1).

`newEd25519Signer(key: CryptoKey)` is the built-in
signer — pass an Ed25519 private `CryptoKey` with
`'sign'` usage and the response carries a 64-byte
RFC 8032 signature. The `Signer` interface is
HSM/KMS-friendly:

```typescript
interface Signer {
  sign: (message: BufferSource) => Promise<ArrayBuffer>;
}
```

## DNS publication

Publish the public key as a DNS `TXT` record at
`<selector>._taistamp.<host>` (DKIM-style). The same
host that serves `/.well-known/taistamp`. Verifiers
read the selector from the `TAI-Key-Selector` response
header and look up the matching record.

TXT record format (single string, ≤ 255 bytes,
DKIM/DMARC-style tag-value list):

```text
v=tai1; k=ed25519; p=<base64-of-32-raw-pubkey-bytes>
```

| Tag | Value |
|-----|-------|
| `v` | Protocol version. `tai1` for the framing in this README. |
| `k` | Key algorithm. `ed25519` for the only algorithm currently defined. |
| `p` | Public key, standard base64. For Ed25519: 32 raw bytes → 43-44 chars. |

Rotate by publishing a new selector alongside the old
one, switching the handler over to the new selector,
then removing the old TXT once cached responses have
expired. Verifiers cache by selector, so old
signatures stay verifiable until their TXT is removed.

## Verifying a signature

[Spec §9][spec-verify] requires verifiers to use the
RFC 8032 §5.1.7 strict verification procedure (cofactor
handling, signature-malleability resistance).
WebCrypto's `Ed25519 verify` is specified to apply
strict verification; confirm your runtime conforms,
or fall back to a strict-verify library such as
`@noble/ed25519`.

```typescript
import {
  asNonce,
  extractLeapSeconds,
  composeSignaturePayload,
} from '@kagal/taistamp';

const response = await fetch(taistampURL, {
  headers: { 'TAI-Nonce': clientNonce },
});
const label = await response.text();
const selector = response.headers.get('TAI-Key-Selector')!;
const sigSf = response.headers.get('TAI-Signature')!;

// Spec §5.3: a `TAI-Leap-Seconds` value outside the
// signed-payload u32 range MUST be treated as unsigned.
// `extractLeapSeconds` returns `undefined` whenever
// the field is missing, empty, non-numeric, non-integer,
// negative, or out-of-range; the branded `LeapSeconds`
// it yields is the only type `composeSignaturePayload`
// accepts.
const leap = extractLeapSeconds(response.headers);
if (leap === undefined) {
  throw new Error('TAI-Leap-Seconds out of range; treat as unsigned');
}

// Brand the recorded nonce so it can flow into the
// signing path. `asNonce` returns `undefined` for any
// value that fails sf-binary syntax or the wire
// length range — the same "treat as absent" verdict
// the server applied per spec §5.4.
const nonce = asNonce(clientNonce);
if (nonce === undefined) {
  throw new Error('client nonce is not a valid sf-binary item');
}

// Look up the public key in DNS at
// `${selector}._taistamp.${host}` and parse the
// `p=` tag from the TXT record.
const publicKey = await loadPublicKey(host, selector);

const payload = composeSignaturePayload(
  label,
  leap,
  selector,
  nonce,
);
const valid = await crypto.subtle.verify(
  'Ed25519',
  publicKey,
  sfBinaryDecode(sigSf), // strip leading/trailing ':' then base64-decode
  payload,
);
```

`composeSignaturePayload(label, leapSeconds, selector,
nonce)` reconstructs the exact byte sequence the
server signed; the verifier supplies only the public
key and an sf-binary decoder. `leapSeconds` must be a
branded `LeapSeconds` — obtain one from
`extractLeapSeconds(headers)` (the verifier path) or
`asLeapSeconds(number)` (when you already have the
value). Both return `undefined` for out-of-range
input, collapsing every "treat as unsigned" case in
[spec §5.3][spec-leap] into one verdict. `nonce` must be a branded
`Nonce` — wrap the recorded client nonce with
`asNonce(value)`, which returns `undefined` for any
value that would have been treated as absent on the
server (missing, empty, malformed sf-binary, or out
of length range — see [spec §5.4][spec-nonce]).
Comparing the verifier's recorded nonce against the
response's `TAI-Nonce` defends against replay.

## API

- `VERSION` — package version string, mirrors
  `package.json#version`.

### Handler

- `newTaistampHandler(config?)` — async fetch
  handler for `/.well-known/taistamp`. See
  [Usage](#usage) above for behaviour,
  [Signing the response](#signing-the-response) for
  signed responses, and
  [CORS](#cors) for cross-origin policy.
- `TaistampHandlerConfig` — `{ cors?, selector?,
  signer? }`. `cors` accepts `'*'` (default), a
  specific origin string, or `false`; `signer` and
  `selector` are co-required.

### Signer

Re-exported from `@kagal/ed25519-secret`:

- `Signer` — `{ sign: (message: BufferSource) =>
  Promise<ArrayBuffer> }`.
- `newEd25519Signer(key)` — WebCrypto Ed25519
  signer factory. Pass an Ed25519 private
  `CryptoKey` with `'sign'` in `usages`.

### Verification helpers

For verifier-side validation of a signed response
(see [Verifying a signature](#verifying-a-signature)):

- `composeSignaturePayload(label, leapSeconds,
  selector, nonce)` — reconstructs the exact byte
  sequence the server signed.
- `asLeapSeconds(number)` — brand a numeric
  leap-second count; returns `undefined` for
  out-of-range input.
- `extractLeapSeconds(headers)` — parse
  `TAI-Leap-Seconds` from response headers; returns
  `undefined` if missing, non-numeric, non-integer,
  negative, or out of range.
- `LeapSeconds` — branded leap-second count
  accepted by `composeSignaturePayload`.
- `asNonce(value)` — brand a recorded nonce;
  returns `undefined` for any value that fails
  sf-binary syntax or the length range checked
  per [spec §5.4][spec-nonce].
- `Nonce` — branded sf-binary nonce accepted by
  `composeSignaturePayload`.

### TAI64N helpers

The handler uses these primitives internally; they
are re-exported for callers that need raw TAI64N
construction:

| Export | Description |
|--------|-------------|
| `now()` | Current TAI as `{ sec, nano, offset }` |
| `fromUTC(utc)` | `Date.now()`-shaped milliseconds → TAI timestamp |
| `tai64nLabel(t?)` | 25-byte label string for a timestamp (or `now()`) |
| `tai64nLabelFromUTC(utc)` | Shortcut for `tai64nLabel(fromUTC(utc))` |

`fromUTC` applies the constant `TAI_LEAP_SECONDS`
(currently 37 seconds). Historic UTC timestamps
spanning a leap-second boundary need caller-side
adjustment — the constant tracks the present, not
history.

### Constants

| Name | Value |
|------|-------|
| `TAISTAMP_PATH` | `/.well-known/taistamp` |
| `TAI64N_CONTENT_TYPE` | `application/tai64n` |
| `TAI64N_CONTENT_LENGTH` | `25` |
| `TAI64N_HEADER_KEY_SELECTOR` | `TAI-Key-Selector` |
| `TAI64N_HEADER_LEAP_SECONDS` | `TAI-Leap-Seconds` |
| `TAI64N_HEADER_NONCE` | `TAI-Nonce` |
| `TAI64N_HEADER_SIGNATURE` | `TAI-Signature` |
| `TAI_LEAP_SECONDS` | `37` (current TAI − UTC offset) |
| `TAI_LEAP_SECONDS_MAX` | `0xFFFFFFFF` (signed-payload u32 cap) |
| `TAI64_EPOCH_HI` | `0x40000000` |

## Licence

[MIT][mit]

<!-- references -->
[draft]: https://datatracker.ietf.org/doc/draft-mery-nagy-taistamp/
[jsdocs-badge]: https://img.shields.io/badge/jsDocs.io-reference-blue
[jsdocs-url]: https://www.jsdocs.io/package/@kagal/taistamp
[mit]: ../../LICENCE.txt
[mit-badge]: https://img.shields.io/badge/Licence-MIT-blue.svg
[npm-badge]: https://img.shields.io/npm/v/@kagal/taistamp.svg
[npm-url]: https://www.npmjs.com/package/@kagal/taistamp
[rfc-repo]: https://github.com/karasz/rfc-taistamp
[spec-leap]: https://datatracker.ietf.org/doc/html/draft-mery-nagy-taistamp-00#section-5.3
[spec-nonce]: https://datatracker.ietf.org/doc/html/draft-mery-nagy-taistamp-00#section-5.4
[spec-verify]: https://datatracker.ietf.org/doc/html/draft-mery-nagy-taistamp-00#section-9
[tai64n]: https://cr.yp.to/libtai/tai64.html
