# AGENTS.md

This file provides guidance to AI coding assistants
working on `@kagal/taistamp-cli` — the companion CLI
for [`@kagal/taistamp`][taistamp] in the
`kagal-dev/taistamp` monorepo. The package sits at
`packages/@kagal-taistamp-cli/`.

Shared guidelines for the monorepo live in the
[root AGENTS.md](../../AGENTS.md). This file covers
the package-local layout and conventions.

## Source layout

```text
.
└── src/
    ├── bin.ts                 # executable entry point
    ├── index.ts               # root command and subcommand wiring
    ├── commands/
    │   ├── seed.ts            # seed minting subcommand
    │   ├── probe.ts           # endpoint probe subcommand
    │   └── command-utils.ts   # error-reporting helper
    └── __tests__/
        ├── cli.test.ts            # vitest shape probe
        ├── command-utils.test.ts  # error-reporting unit tests
        ├── probe.test.ts          # probe behaviour and CLI wiring
        ├── seed.test.ts           # seed minting and CLI wiring
        └── compat.mjs             # standalone bin smoke probe
```

Unlike the platform-neutral library siblings, `src/`
uses Node APIs directly (`process.exitCode`,
`node:child_process`); `tsconfig.json` declares
`"types": ["node"]` to match.

## Subcommands

`seed new` mints a fresh `selector:base64` Ed25519
secret via `mintSecret` and prints it on stdout.
Selector defaults to the literal string `default`.

`probe <url>` runs in one of two modes. With one or
more `--secret` / `--secret-env` supplied it performs
strict-trust verification: HTTP reachability, nonce
echo, selector membership in the supplied bag, body
shape, leap-seconds and signature header parsing, and
the Ed25519 `crypto.subtle.verify` step. Without any
secrets it falls back to a reachability check —
reachability and nonce echo gate, then the advertised
selector and signature headers are reported as
informational.

Internal helpers (`mintSecret`, `seedNew`,
`resolveProbeURL`, `collectSecretSources`, `buildKeyMap`,
`probeEndpoint`, `reportCommandError`) are not re-exported
from `src/index.ts`; tests deep-import them via
`../commands/<name>` per the CLI convention against
speculative exports.

## bin shim

`build` runs `obuild` then `chmod +x dist/bin.mjs`
— obuild preserves the source shebang
(`#!/usr/bin/env node`) but does not preserve the
exec bit. `prepare` (`cross-test -s dist/bin.mjs ||
obuild --stub`) ensures `pnpm install` produces a
working bin path immediately, so `pnpm exec
taistamp` resolves without a preceding build.

<!-- references -->
[taistamp]: ../@kagal-taistamp/AGENTS.md
