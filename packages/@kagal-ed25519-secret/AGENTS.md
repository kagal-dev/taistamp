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
    ├── algo.ts             # supported-algorithm metadata
    ├── key.ts              # Ed25519 key construction and public JWK shape
    ├── jwks.ts             # Ed25519 JWK Set assembly
    ├── key-record.ts       # DKIM-style key-record assembly and parsing
    ├── signer.ts           # Ed25519 signer interface and factory
    ├── verifier.ts         # Ed25519 verifier interface and factories
    ├── selector.ts         # DKIM selector pattern and validators
    ├── utils.ts            # byte helpers and list splitters
    └── __tests__/
```

## Throwing helpers

Helpers that throw accept a trailing context parameter
— prepended as `${context}:` to the error message — in
one of two shapes:

- `context?: string` — absent means no prefix. Used by
  `asBytes`, `asEd25519Seed`, `assertValidSelector`,
  `decodeASCII`, `decodeBase64`, `encodeKey`,
  `getRandom`, `importVerifyKey`, `newSigner`,
  `newVerifier`, and `parseKeyRecord`.
- `context: string = '<factory name>'` — used by
  composing factories that thread the context through
  to their delegates (`makeKeyRecords`, `newKeys`,
  `parseSecretToKey`, `parseSecretsToKeys`, and the
  deprecated `newKeyPair`); absence falls back to the
  factory name so the error always carries attribution.
