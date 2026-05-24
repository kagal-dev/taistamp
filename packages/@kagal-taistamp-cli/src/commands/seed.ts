import { newSecret, parseSecretToKey } from '@kagal/ed25519-secret';
import { defineCommand } from 'citty';

import { DEFAULT_SELECTOR, makeKeyRecordTXT } from '../utils';

import { ENV_FILE_ARG, reportCommandError } from './command-utils';

/**
 * `taistamp seed new` — mint a fresh `selector:base64`
 * Ed25519 secret and print it on stdout together with
 * the `<selector>._taistamp` DNS TXT record publishing
 * its public half. The optional selector positional
 * defaults to {@link DEFAULT_SELECTOR}; invalid
 * selectors are reported and the process exits non-zero.
 */
export const seedNew = defineCommand({
  meta: {
    name: 'new',
    description: 'Mint a fresh selector:base64 Ed25519 secret',
  },
  args: {
    ...ENV_FILE_ARG,
    selector: {
      type: 'positional',
      description: 'DKIM-style key selector (single DNS label, ' +
        'letter-prefixed, ≤63 chars)',
      required: false,
      default: DEFAULT_SELECTOR,
    },
  },
  async run({ args }) {
    try {
      const context = 'taistamp seed new';
      const secret = newSecret(args.selector, context);
      const key = await parseSecretToKey(secret, context);
      const record = await makeKeyRecordTXT(key, context);
      console.log(secret);
      console.log(`${key.selector}._taistamp TXT ${record}`);
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
