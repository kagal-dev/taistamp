import { consola } from 'consola';

/**
 * Print a thrown command error via consola: terse `fail`
 * for operator-correctable `TypeError`s, full `error`
 * with stack or string content for other throws.
 */
export const reportCommandError = (error: unknown): void => {
  if (error instanceof TypeError) {
    consola.fail(error.message);
  } else if (error instanceof Error) {
    consola.error(error);
  } else {
    consola.error(String(error));
  }
};
