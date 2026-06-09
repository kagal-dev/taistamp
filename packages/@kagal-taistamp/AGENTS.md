# AGENTS.md

This file provides guidance to AI coding assistants
working on `@kagal/taistamp` — the platform-neutral
handler for signed TAI64N timestamps at
`/.well-known/taistamp` in the `kagal-dev/taistamp`
monorepo. The package sits at `packages/@kagal-taistamp/`.

Shared guidelines for the monorepo live in the
[root AGENTS.md](../../AGENTS.md). This file covers
the package-local layout and conventions.

## Source layout

```text
.
├── src/
│   ├── index.ts            # main export — protocol surface
│   ├── utils.ts            # /utils subpath — additional related exports
│   ├── handler.ts          # request handler and signature payload assembly
│   ├── body.ts             # verifier-side response-body decoding
│   ├── cors.ts             # CORS headers keyed by response kind
│   ├── nonce.ts            # nonce branded type and header parsing
│   ├── leap-seconds.ts     # leap-seconds branded type and header parsing
│   ├── sf-binary.ts        # RFC 9651 sf-binary framing helpers
│   ├── signature.ts        # TAI-Signature verify-side decoding
│   ├── const.ts            # protocol and label-format constants
│   ├── time.ts             # TAI64N time helpers
│   └── __tests__/          # Vitest suites split across pools (see below)
└── wrangler.jsonc          # workerd test pool stub
```

## Test pool layout

Vitest defines two projects in `vitest.config.ts`; a
file-naming convention splits one of them into three
suites:

- `*.workerd.test.ts` → workerd project, using
  `@cloudflare/vitest-pool-workers`. Configured by
  `wrangler.jsonc` — a test-only stub, not a
  deployment target.
- `*.noble.test.ts` → node project, using
  `@noble/ed25519` as an independent reference
  verifier. Catches framing mismatches between
  WebCrypto and pure-JS Ed25519 implementations.
- all other `*.test.ts` → node project, default Node
  pool.
