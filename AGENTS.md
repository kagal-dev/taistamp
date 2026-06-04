# AGENTS.md

This file provides guidance to AI coding assistants
(Claude Code, GitHub Copilot, Cody, etc.) when working
with code in the kagal-dev/taistamp monorepo. It
collects the shared guidelines that apply across the
repo; per-package source layout and local conventions
live in each package's AGENTS.md (linked from the
Project Overview below).

## Project Overview

This monorepo holds MIT-licensed TypeScript packages
implementing Taistamp — signed TAI64N timestamps over
HTTP at `/.well-known/taistamp`.

- [`@kagal/taistamp`](packages/@kagal-taistamp/AGENTS.md)
  — platform-neutral handler.
- [`@kagal/taistamp-cli`](packages/@kagal-taistamp-cli/AGENTS.md)
  — companion CLI for seed generation and endpoint
  probing (bin `taistamp`).
- [`@kagal/ed25519-secret`](packages/@kagal-ed25519-secret/AGENTS.md)
  — WebCrypto Ed25519 signer plus DKIM-style selector
  validation.

## Monorepo Structure

```text
taistamp/
├── packages/
│   ├── @kagal-taistamp/        # @kagal/taistamp
│   ├── @kagal-taistamp-cli/    # @kagal/taistamp-cli (bin: taistamp)
│   └── @kagal-ed25519-secret/  # @kagal/ed25519-secret
├── docs/                       # design notes (untracked)
├── internal/build/cspell.json  # shared cspell config
└── .github/workflows/          # build, publish, renovate
```

Each package also carries the usual TS workspace boilerplate
(`package.json`, `tsconfig.{json,tests.json,tools.json}`,
`build.config.ts`, `vitest.config.ts`, `eslint.config.mjs`,
`README.md`, `CHANGELOG.md`, `LICENCE.txt`). The repo
root mirrors these for the monorepo as a whole, plus
`pnpm-workspace.yaml` and `renovate.json`.

## Common Commands

```bash
pnpm install
pnpm build              # Build all packages
pnpm test               # Test all packages
pnpm lint               # Lint all (root + packages)
pnpm type-check         # Type-check all packages
pnpm precommit          # Full pre-commit verification gate
pnpm prepack            # Pre-publication checks
pnpm test:coverage      # Test with istanbul coverage report
```

Per-package commands via `--filter`:

```bash
pnpm --filter @kagal/taistamp build
pnpm --filter @kagal/ed25519-secret test
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

## Handling cspell findings

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

### Pre-commit

Before committing any changes, run:

1. `pnpm precommit`.
2. Fix any issues found.

### DO

- Use workspace protocol (`workspace:^`) for internal
  dependencies.
- Write tests for all new functionality.
- Run `pnpm dev:prepare` before `lint` or `type-check`
  (stubs gate cross-package resolution).

### DON'T

- Create files unless necessary — prefer editing
  existing ones.
- Add external dependencies without careful
  consideration.
- Ignore TypeScript errors or ESLint warnings.
- Use relative imports between packages (use
  workspace deps).
- Use `cd` — prefer `pnpm --filter`, `git -C`, or
  relative paths.

## Git Workflow

### Commits

- Always use `-s` flag for sign-off.
- Write clear messages describing actual changes.
- No AI advertising in commit messages.
- Focus on the final result, not the iterations.

### Direct Commits

List files explicitly in the commit command. Use
`git add` only for new/untracked files, then pass all
files (new and modified) to `git commit`.

```bash
git add src/new-file.ts
git commit -sF .tmp/commit-<slug>.txt -- src/new-file.ts src/changed.ts
```

Temporary files use `.tmp/` with a shared prefix:

- Commit messages: `.tmp/commit-<slug>.txt`
- PR descriptions: `.tmp/pr-<slug>.md`

### Commit Message Guidelines

- First line: type(scope): brief description (50 chars).
- Blank line.
- Body: what and why, not how (wrap at 72 chars).
- Use bullet points for multiple changes.
- Reference issues/PRs when relevant.

## TypeScript Configuration

Each package has multiple tsconfig files:

- `tsconfig.json` — source code (no Node types).
- `tsconfig.tools.json` — adds Node types for
  build.config.ts, vitest.config.ts.
- `tsconfig.tests.json` — test files and compile-time
  type assertions.

The root `tsconfig.json` provides shared compiler
options (ESNext, bundler resolution, strict mode).

## Testing

- All packages use Vitest.
- Test files: `*.test.ts` under `src/__tests__/`.
- Per-package pool/runtime details (cross-runtime
  splits, workerd stubs, reference verifiers): see the
  package's AGENTS.md.
- `@kagal/cross-test` (from a
  [sibling repo](#sibling-repositories)) provides the
  conditional stub helper for `prepare` scripts.

## Build

- **obuild** for all packages (ESM + DTS, except
  `@kagal/taistamp-cli` which emits only `dist/bin.mjs`).
- `build.config.ts` defines `bundle` entries with
  sourcemaps enabled.
- Library packages print `TSDoc extraction not run` —
  placeholder hook, no extraction performed.
  `@kagal/taistamp-cli` omits the hook (no library
  surface to extract).
- `prepare` script: `cross-test -s dist/index.mjs ||
  obuild --stub` for library packages;
  `@kagal/taistamp-cli` checks `dist/bin.mjs`.
- `dev:prepare`: `obuild --stub` (unconditional).

## Publishing

npm packages are published via GitHub Actions using
npm's OIDC trusted publishing with `--provenance`.
No tokens stored as secrets.

1. Push a per-package tag (`@<scope>/<name>@<version>`,
   e.g. `@kagal/taistamp@0.0.5`) to trigger
   `publish.yml`.
2. GitHub Actions authenticates to npm via OIDC.
3. The workflow filters to the tagged package and runs
   `publish:maybe`, which publishes only if
   `$name@$version` is not yet on npm.
4. `pkg-pr-new` provides preview publishes on non-tag
   pushes.

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

Commit style, tooling, and CI patterns stay consistent
across these repos.
