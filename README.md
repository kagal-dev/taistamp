# taistamp — signed TAI64N timestamps over HTTP

Authenticated wall-clock time over HTTP, without
running an NTP stack or trusting an unauthenticated
TLS handshake clock. A TypeScript toolkit
implementing [`draft-mery-nagy-taistamp`][draft]:
issue and verify Ed25519-signed timestamps, publish
keys via JWKS endpoints or DNS TXT records with
DKIM-style selectors, mint seeds and probe endpoints
from a companion CLI.

Runs anywhere with `crypto.subtle` — modern browsers,
Node ≥ 20, Cloudflare Workers, Deno, and Bun.

[![Licence: MIT](https://img.shields.io/badge/Licence-MIT-blue.svg)](./LICENCE.txt)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](package.json)
[![pnpm](https://img.shields.io/badge/pnpm-%3E%3D10.33.2-orange)](package.json)

## Use cases

- Issuing authenticated wall-clock time over HTTP, for
  receipts, audit trails, and anti-replay.
- Workers, serverless, and edge runtimes where an NTP
  stack or unauthenticated TLS handshake clock isn't
  enough.
- Independent verification of timestamps after the fact
  — clients keep the signed payload, fetch the verifying
  key from a JWKS endpoint or DNS TXT record, and
  re-check without re-trusting the server.

## Packages

### [`@kagal/taistamp`](packages/@kagal-taistamp/)

Platform-neutral HTTP handler for `/.well-known/taistamp` —
Ed25519-signed timestamps.

### [`@kagal/taistamp-cli`](packages/@kagal-taistamp-cli/)

Companion CLI (`taistamp`) — Ed25519 seed minting
and `/.well-known/taistamp` endpoint probing.

### [`@kagal/ed25519-secret`](packages/@kagal-ed25519-secret/)

Ed25519 keys, signing, verification, JWKS-ready and
DNS-TXT-ready public key publication, and DKIM-style
selector validation for WebCrypto. Zero runtime
dependencies.

## Specification

Implements [`draft-mery-nagy-taistamp`][draft], the
IETF Internet-Draft for signed TAI64N timestamps over
HTTP. Working version: [`karasz/rfc-taistamp`][rfc-repo].

[draft]: https://datatracker.ietf.org/doc/draft-mery-nagy-taistamp/
[rfc-repo]: https://github.com/karasz/rfc-taistamp

## Development

```sh
pnpm install
pnpm precommit   # dev:prepare → lint → type-check → build → test
```

## Licence

[MIT](LICENCE.txt)
