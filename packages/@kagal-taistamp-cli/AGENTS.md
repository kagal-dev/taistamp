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
    ├── utils.ts               # default selector, DNS TXT record rendering
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
`process.loadEnvFile`, `console.log`); `tsconfig.json`
declares `"types": ["node"]` to match.

## Subcommands

`seed new` mints a fresh `selector:base64` Ed25519
secret via `newSecret` and prints it on stdout together
with its `<selector>._taistamp` DNS TXT record. The
selector is an optional positional, defaulting to the
literal string `default`.

`probe <url>` gates on HTTP reachability and nonce
echo, then resolves a verifier for the advertised
selector. With one or more `--secret` / `--secret-env`
supplied the resolver is the parsed key bag, and the
probe continues through body shape, leap-seconds and
signature header parsing, and Ed25519 signature
verification under the resolved verifier. Without any
secrets no resolver is installed: the probe stops
after the nonce echo, reporting the advertised
selector and signature headers as informational. The
probe itself is a trampoline — each state function
reports its outcome, then returns the next state
function bound to the state it produced.

Environment loading is global: the root command's setup
hook loads the `--env-file` argument first (a missing
file throws), then `./.env` when present;
`process.loadEnvFile` never overrides already-set
variables. The shared `ENV_FILE_ARG` spec is also
declared on each leaf command so the flag's value token
parses as a flag value rather than a positional.

Internal helpers (`DEFAULT_SELECTOR`,
`makeKeyRecordTXT`, `seedNew`, `resolveProbeURL`,
`collectSecretSources`, `buildKeyMap`, `probeEndpoint`,
`loadEnvFiles`, `reportCommandError`) and the
`STEP_LABELS` step-label map and `ENV_FILE_ARG` spec
are not re-exported from `src/index.ts`; tests
deep-import them from their defining module (`../utils`
or `../commands/<name>`) per the CLI convention against
speculative exports.

## bin shim

`build` runs `obuild` then `chmod +x dist/bin.mjs`
— obuild preserves the source shebang
(`#!/usr/bin/env node`) but does not preserve the
exec bit. `prepare` (`cross-test -s dist/bin.mjs ||
pnpm dev:prepare`) ensures `pnpm install` produces a
working bin path immediately, so `pnpm exec
taistamp` resolves without a preceding build.

<!-- references -->
[taistamp]: ../@kagal-taistamp/AGENTS.md
