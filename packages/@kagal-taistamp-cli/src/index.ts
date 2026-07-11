import { defineCommand } from 'citty';

import pkg from '../package.json';
import { ENV_FILE_ARG, loadEnvFiles } from './commands/command-utils';
import { probe } from './commands/probe';
import { seed } from './commands/seed';

/**
 * Root command for the `taistamp` CLI. Exposes
 * subcommands for seed generation
 * ({@link seed}) and endpoint probing
 * ({@link probe}). The setup hook loads the global
 * `--env-file` argument and then `./.env` before any
 * subcommand runs; variables already set in the real
 * environment always win.
 */
export const main = defineCommand({
  meta: {
    name: 'taistamp',
    version: pkg.version,
    description: pkg.description,
  },
  args: {
    ...ENV_FILE_ARG,
  },
  setup({ args }) {
    loadEnvFiles(args.envFile);
  },
  subCommands: {
    probe,
    seed,
  },
});
