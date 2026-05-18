# AGENTS.md

This file provides guidance to AI coding assistants
working on `@kagal/ed25519-secret` — the WebCrypto
Ed25519 signer plus DKIM-style selector validation
package in the `kagal-dev/taistamp` monorepo. The
package sits at `packages/@kagal-ed25519-secret/`.

Shared guidelines for the monorepo live in the
[root AGENTS.md](../../AGENTS.md). This file covers
the package-local layout and conventions.

## Source layout

```text
.
└── src/
    ├── index.ts            # public API surface
    ├── secret.ts           # selector:base64 secret parsing
    ├── key.ts              # Ed25519 key construction and public JWK shape
    ├── signer.ts           # Ed25519 signer interface and factory
    ├── selector.ts         # DKIM selector pattern and validators
    ├── utils.ts            # byte helpers — base64, random, normalisation
    └── __tests__/
```

## Throwing helpers

Helpers that throw accept a trailing context parameter
— prepended as `${context}:` to the error message — in
one of two shapes:

- `context?: string` — absent means no prefix. Used by
  `asBytes`, `asEd25519Seed`, `assertValidSelector`,
  `decodeBase64`, `encodeKey`, `getRandom`, and
  `newSigner`.
- `context: string = '<factory name>'` — used by
  composing factories that thread the context through
  to their delegates (`newKeys`, `parseSecretToKey`,
  `parseSecretsToKeys`, and the deprecated `newKeyPair`);
  absence falls back to the factory name so the error
  always carries attribution.
