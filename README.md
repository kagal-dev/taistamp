# taistamp

Monorepo for Taistamp — signed TAI64N timestamps over
HTTP.

## Packages

### [`@kagal/taistamp`](packages/@kagal-taistamp/)

Platform-neutral handler for `/.well-known/taistamp`.

### [`@kagal/ed25519-secret`](packages/@kagal-ed25519-secret/)

WebCrypto Ed25519 signer plus DKIM-style selector
validation. Self-contained.

## Development

```sh
pnpm install
pnpm precommit   # dev:prepare → lint → type-check → build → test
```

## Licence

[MIT](LICENCE.txt)
