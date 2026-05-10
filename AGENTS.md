# AGENTS.md

This file provides guidance to AI coding assistants
(Claude Code, GitHub Copilot, Cody, etc.) when working
with code in the kagal-dev/taistamp monorepo.

## Project Overview

This monorepo holds MIT-licensed TypeScript packages
implementing Taistamp — signed TAI64N timestamps over
HTTP at `/.well-known/taistamp`.

- **`@kagal/taistamp`** — platform-neutral handler
- **`@kagal/ed25519-secret`** — WebCrypto Ed25519 signer
  plus DKIM-style selector validation

## Monorepo Structure

```text
taistamp/
├── packages/
│   ├── @kagal-taistamp/              # @kagal/taistamp
│   │   ├── src/
│   │   │   ├── index.ts              # public API surface
│   │   │   ├── handler.ts            # newTaistampHandler, composeSignaturePayload
│   │   │   ├── cors.ts               # buildCORSHeaders
│   │   │   ├── nonce.ts              # Nonce brand + extract
│   │   │   ├── leap-seconds.ts       # LeapSeconds brand + extract
│   │   │   ├── const.ts, utils.ts    # protocol constants, TAI64N helpers
│   │   │   └── __tests__/            # default + .workerd + .noble pools
│   │   └── wrangler.jsonc            # workerd test pool stub
│   └── @kagal-ed25519-secret/        # @kagal/ed25519-secret
│       └── src/
│           ├── index.ts              # public API surface
│           ├── signer.ts             # Ed25519 signer interface and factory
│           ├── selector.ts           # DKIM selector pattern and validators
│           └── __tests__/
├── docs/                             # design notes (untracked)
├── internal/build/cspell.json        # shared cspell config
└── .github/workflows/                # build, publish, renovate
```

Each package also carries the usual TS workspace boilerplate
(`package.json`, `tsconfig.{json,tests.json,tools.json}`,
`build.config.ts`, `vitest.config.ts`, `eslint.config.mjs`,
`README.md`, `CHANGELOG.md`, `LICENCE.txt`); the same set
exists at the root for shared/ignore configuration plus
`pnpm-workspace.yaml` and `renovate.json`.

## Common Commands

```bash
pnpm install
pnpm build              # Build all packages
pnpm test               # Test all packages
pnpm lint               # Lint all (root + packages)
pnpm type-check         # Type-check all packages
pnpm precommit          # dev:prepare → lint → type-check → build → test
pnpm prepack            # lint:root:check → per-package prepack
pnpm test:coverage      # test with istanbul coverage report
```

Per-package commands via `--filter`:

```bash
pnpm --filter @kagal/taistamp build
pnpm --filter @kagal/taistamp test
```

## Code Style Guidelines

Enforced by .editorconfig and @poupe/eslint-config:

- **Indentation**: 2 spaces
- **Line Endings**: Unix (LF)
- **Charset**: UTF-8
- **Quotes**: Single quotes
- **Semicolons**: Always
- **Module System**: ES modules (`type: "module"`)
- **Line Length**: Max 78 characters preferred
- **Comments**: TSDoc format
- **Naming**: camelCase for variables/functions,
  PascalCase for types/interfaces
- **Spelling**: British English (serialisable,
  behaviour, colour)
- **Final Newline**: Always insert
- **Trailing Whitespace**: Always trim

### Factory functions

Prefer `new` or `make` prefix, not `create`
(e.g. `newFoo()`, `makeFoo()`).

### Throwing helpers

In `@kagal-ed25519-secret`, validation helpers that
throw take a trailing optional `context?: string`
parameter — prepended as `${context}:` to the error
message so callers can label errors with their own
identity.

### Handling cspell findings

`pnpm lint` runs `cspell` against the tree using
`internal/build/cspell.json`. When cspell flags a
word, prefer fixing over whitelisting:

- US spelling → British equivalent.
- Concatenated compound → hyphenate so cspell sees
  the dictionary parts.
- Inconsistent identifier → harmonise to the
  canonical form already used elsewhere in the
  codebase.

If the word is genuinely correct (RFC term, brand,
acronym, our own type name, or real English missing
from cspell's dictionary), whitelist it at the right
scope:

- **Single file** — `cspell:words` for *named terms*
  you want recognised across the file, placed near
  the section heading or docstring it applies to;
  `cspell:disable-next-line` for *opaque literals*
  (test-vector strings, fixture filenames) where
  naming the substring would just be noise.
- **Multi-file** — promote to `words` in
  `internal/build/cspell.json`.
- **JSON file** (no comments allowed) — extend the
  `overrides` block in `internal/build/cspell.json`.

Don't put `cspell:disable-next-line` directly above
a TSDoc/JSDoc comment — use `cspell:words` for the
specific term. Don't break tables or bullet lists
with inline annotations; place directives at the
preceding section heading.

Don't add base64 fragments or random test-vector
substrings to the dictionary. The `ignoreRegExpList`
patterns in `internal/build/cspell.json` already
match quoted base64 blobs (16+ chars, plus the
`'eyJ…'` JWT prefix); extend those patterns rather
than adding literal fragments to `words`.

## Development Practices

### Pre-commit (MANDATORY)

Before committing any changes, ALWAYS run:

1. `pnpm precommit`
2. Fix any issues found

### DO

- Use workspace protocol (`workspace:^`) for internal
  dependencies
- Write tests for all new functionality
- Check existing code patterns before creating new ones
- Follow strict TypeScript practices
- Run `pnpm dev:prepare` before `lint` or `type-check`
  (stubs gate cross-package resolution)

### DON'T

- Create files unless necessary — prefer editing
  existing ones
- Add external dependencies without careful
  consideration
- Ignore TypeScript errors or ESLint warnings
- Use relative imports between packages (use workspace
  deps)
- **NEVER use `git add .` or `git add -A`**
- **NEVER commit without explicitly listing files**
- **NEVER use `cd`** — use `pnpm --filter`, `git -C`,
  or relative paths

## Git Workflow

### Commits

- Always use `-s` flag for sign-off
- Write clear messages describing actual changes
- No AI advertising in commit messages
- Focus on the final result, not the iterations

### Direct Commits (MANDATORY)

ALWAYS list files explicitly in the commit command.
Use `git add` only for new/untracked files, then pass
all files (new and modified) to `git commit`.

```bash
git add src/new-file.ts
git commit -sF .tmp/commit-<slug>.txt -- src/new-file.ts src/changed.ts
```

Temporary files use `.tmp/` with a shared prefix:

- Commit messages: `.tmp/commit-<slug>.txt`
- PR descriptions: `.tmp/pr-<slug>.md`

### Commit Message Guidelines

- First line: type(scope): brief description (50 chars)
- Blank line
- Body: what and why, not how (wrap at 72 chars)
- Use bullet points for multiple changes
- Reference issues/PRs when relevant

## TypeScript Configuration

Each package has multiple tsconfig files:

- `tsconfig.json` — source code (no Node types)
- `tsconfig.tools.json` — adds Node types for
  build.config.ts, vitest.config.ts
- `tsconfig.tests.json` — test files and compile-time
  type assertions

The root `tsconfig.json` provides shared compiler
options (ESNext, bundler resolution, strict mode).

## Testing

- All packages use Vitest
- Test files: `*.test.ts` under `src/__tests__/`
- Cross-runtime split via `vitest.config.ts` projects:
  - `*.workerd.test.ts` → workerd pool
    (`@cloudflare/vitest-pool-workers`, configured
    via `wrangler.jsonc` — a test-only stub, not a
    deployment target)
  - `*.noble.test.ts` → Node pool with `@noble/ed25519`
    as an independent reference verifier — catches
    framing mismatches between WebCrypto and pure-JS
    Ed25519 implementations
  - all other `*.test.ts` → Node pool
- `@kagal/cross-test` (external dep) provides the
  conditional stub helper for `prepare` scripts

## Build

- **unbuild** for all packages (ESM + DTS, sourcemaps)
- `build.config.ts` defines entry points
- `@kagal/build-tsdoc` provides `newDocumentsHook()` —
  an unbuild `build:done` hook that extracts TSDoc
  symbols and writes per-export JSON to `_docs/` at the
  package root (not inside `dist/`, does not ship to npm)
- `prepare` script: `cross-test -s dist/index.mjs ||
  unbuild --stub` (conditional stubbing)
- `dev:prepare`: `unbuild --stub` (unconditional)

## Publishing

npm packages are published via GitHub Actions using
npm's OIDC trusted publishing with `--provenance`.
No tokens stored as secrets.

1. Push a version tag (`v*`) to trigger `publish.yml`
2. GitHub Actions authenticates to npm via OIDC
3. `pnpm -r publish:maybe` checks each package —
   publishes only if `$name@$version` is not yet on npm
4. `pkg-pr-new` provides preview publishes on non-tag
   pushes

<!-- cspell:words npmjs -->
### Setup (per package on npmjs.com)

Each `@kagal/*` package must be configured as a
trusted publisher on npmjs.com:

- **Repository**: `kagal-dev/taistamp`
- **Workflow**: `publish.yml`
- **Environment**: (none)

## Sibling Repositories

This repo has siblings under the same org:

- **kagal** — fleet management framework (Cloudflare
  edge).
- **pki** — ACME library and private CA.
- **tsdoc** — TSDoc extraction hook (`@kagal/build-tsdoc`).
- **cross-test** — shared test utilities.

Conventions (commit style, tooling, CI patterns) should
stay consistent across the family.
