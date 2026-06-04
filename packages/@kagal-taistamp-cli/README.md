# @kagal/taistamp-cli — companion CLI for @kagal/taistamp

[![Licence: MIT][mit-badge]][mit]

CLI for working with [`@kagal/taistamp`][taistamp]
deployments — Ed25519 seed generation and remote
endpoint probing for `/.well-known/taistamp`.

Requires Node ≥ 20.20.1.

## Install

```sh
npm install -g @kagal/taistamp-cli
```

```sh
yarn global add @kagal/taistamp-cli
```

```sh
pnpm add -g @kagal/taistamp-cli
```

One-shot, no install:

```sh
pnpm dlx @kagal/taistamp-cli --help
```

## Usage

```sh
taistamp --help
taistamp seed new
taistamp probe <url>
```

See [Subcommands](#subcommands) below for flags.

## Monorepo development

Within this repository, the `cli` script runs the
locally-built `dist/bin.mjs` directly:

```sh
pnpm --filter @kagal/taistamp-cli cli --help
```

`pnpm install` produces a `dist/bin.mjs` stub via the
`prepare` script; `pnpm build` produces the bundled
bin.

## Subcommands

- `taistamp seed new [--selector <id>]` — mints a fresh
  `selector:base64` Ed25519 secret consumable by
  `parseSecretToKey` from [`@kagal/ed25519-secret`][secret].
  `--selector` defaults to `default`; rotate by passing
  a real selector name.
- `taistamp probe <url>` — fetches `<url>/.well-known/taistamp`
  (smart-appended when `<url>` is a bare origin) with a
  fresh nonce, then either:
  - **verify mode** (one or more `--secret` /
    `--secret-env` supplied): gates on transport
    reachability, nonce echo, selector membership in
    the supplied bag, body shape, leap-seconds and
    signature header parsing, and Ed25519 signature
    verification under the matched key.
  - **reachability mode** (no secrets supplied): gates
    on transport reachability and nonce echo, then
    reports the advertised selector and signature
    headers as informational.

  `--secret <selector:base64>` may be repeated; the
  same shape as `taistamp seed new` output.
  `--secret-env <name>` may be repeated; reads the
  named environment variable, whose value may carry
  one or many secrets separated by whitespace or
  punctuation.

Both subcommands exit `1` on failure and `0` on success.

<!-- references -->
[taistamp]: ../@kagal-taistamp#readme
[secret]: ../@kagal-ed25519-secret#readme
[mit]: ./LICENCE.txt
[mit-badge]: https://img.shields.io/badge/Licence-MIT-blue.svg
