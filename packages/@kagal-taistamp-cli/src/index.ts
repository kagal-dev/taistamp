import { defineCommand } from 'citty';

import pkg from '../package.json' with { type: 'json' };
import { probe } from './commands/probe';
import { seed } from './commands/seed';

/**
 * Root command for the `taistamp` CLI. Exposes
 * subcommands for seed generation
 * ({@link seed}) and endpoint probing
 * ({@link probe}).
 */
export const main = defineCommand({
  meta: {
    name: 'taistamp',
    version: pkg.version,
    description: pkg.description,
  },
  subCommands: {
    probe,
    seed,
  },
});
