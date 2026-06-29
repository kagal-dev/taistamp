import type { ArgsDef } from 'citty';
import { consola } from 'consola';

/**
 * Shared `--env-file` argument: declared on the root
 * command, whose setup hook consumes it, and on each
 * leaf command so the flag's value token parses as a
 * flag value rather than a positional.
 */
export const ENV_FILE_ARG = {
  envFile: {
    type: 'string',
    description: 'load environment variables from this file',
  },
} as const satisfies ArgsDef;

/**
 * Load environment files into `process.env`: the
 * explicit `--env-file` path first — a missing or
 * unreadable file is a loud `TypeError` — then `./.env`
 * when present, silently skipped otherwise.
 * `process.loadEnvFile` never overrides variables
 * already set, so precedence is the real environment,
 * then the explicit file, then `./.env`.
 */
export const loadEnvFiles = (envFile?: string): void => {
  if (envFile !== undefined) {
    try {
      process.loadEnvFile(envFile);
    } catch (error) {
      throw new TypeError(
        `cannot load env file: ${envFile}`,
        { cause: error },
      );
    }
  }
  try {
    process.loadEnvFile();
  } catch {
    // no ./.env in the CWD — nothing to auto-load
  }
};

/**
 * Print a thrown command error via `consola.error`: just
 * the message for operator-correctable `TypeError`s, the
 * full `Error` instance (or stringified value) for other
 * throws.
 */
export const reportCommandError = (error: unknown): void => {
  if (error instanceof TypeError) {
    consola.error(error.message);
  } else if (error instanceof Error) {
    consola.error(error);
  } else {
    consola.error(String(error));
  }
};
