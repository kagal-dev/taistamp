# taistamp — signed TAI64N timestamps over HTTP

Two TypeScript packages: an HTTP handler that issues
Ed25519-signed TAI64N timestamps, and the WebCrypto
signing toolkit it builds on.

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
  — clients keep the signed payload and re-check without
  re-trusting the server.

## Packages

### [`@kagal/taistamp`](packages/@kagal-taistamp/)

Platform-neutral HTTP handler for `/.well-known/taistamp` —
Ed25519-signed timestamps.

### [`@kagal/ed25519-secret`](packages/@kagal-ed25519-secret/)

Ed25519 keys, signing, and verification for WebCrypto,
plus DKIM-style selector validation. Zero runtime
dependencies.

## Development

```sh
pnpm install
pnpm precommit   # dev:prepare → lint → type-check → build → test
```

## Licence

[MIT](LICENCE.txt)
