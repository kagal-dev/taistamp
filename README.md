# taistamp — signed TAI64N timestamps over HTTP

Two TypeScript packages: an HTTP handler that issues
Ed25519-signed TAI64N timestamps, and the WebCrypto
signing toolkit it builds on, with JWKS-ready and
DNS-TXT-ready public key publication.

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
