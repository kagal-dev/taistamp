import {
  assertValidSelector,
  encodeBase64,
  getRandom,
} from '@kagal/ed25519-secret';
import { defineCommand } from 'citty';

import { reportCommandError } from './command-utils';

/**
 * Default `--selector` value for {@link seedNew}. Picked
 * to look obviously placeholder-y so operators don't ship
 * it as their production selector; RFC 6376 leaves
 * selectors entirely to operator choice, so the dummy
 * default is purely a usability cue.
 */
const DEFAULT_SELECTOR = 'default';

/**
 * Mint a fresh `selector:base64` Ed25519 secret, the wire
 * shape consumed by `parseSecretToKey` from
 * `@kagal/ed25519-secret`. The base64 payload is a
 * 32-byte RFC 8032 seed drawn from
 * `crypto.getRandomValues`.
 *
 * @param selector - DKIM-style selector pinned onto the
 *   resulting key's `kid`. Defaults to `'default'`.
 * @param context - label for thrown error messages;
 *   defaults to `'mintSecret'`
 * @returns a `selector:base64` string
 * @throws TypeError when `selector` fails
 *   `assertValidSelector`
 */
export const mintSecret = (
  selector: string = DEFAULT_SELECTOR,
  context: string = 'mintSecret',
): string => {
  assertValidSelector(selector, context);
  return `${selector}:${encodeBase64(getRandom(32))}`;
};

/**
 * `taistamp seed new` — mint and print a fresh
 * `selector:base64` Ed25519 secret on stdout. The
 * `--selector` flag defaults to `'default'`; invalid
 * selectors are reported and the process exits non-zero.
 */
export const seedNew = defineCommand({
  meta: {
    name: 'new',
    description: 'Mint a fresh selector:base64 Ed25519 secret',
  },
  args: {
    selector: {
      type: 'string',
      description: 'DKIM-style key selector (single DNS label, ' +
        'letter-prefixed, ≤63 chars)',
      default: DEFAULT_SELECTOR,
    },
  },
  run({ args }) {
    try {
      console.log(mintSecret(args.selector, 'taistamp seed new'));
    } catch (error) {
      reportCommandError(error);
      process.exitCode = 1;
    }
  },
});

/**
 * Root command for `taistamp seed`. Hosts subcommands
 * for Ed25519 secret material — currently {@link seedNew}.
 */
export const seed = defineCommand({
  meta: {
    name: 'seed',
    description: 'Manage Ed25519 seeds',
  },
  subCommands: {
    new: seedNew,
  },
});
