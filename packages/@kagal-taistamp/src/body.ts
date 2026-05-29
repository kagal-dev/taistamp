import { decodeASCII } from '@kagal/ed25519-secret';

import { TAI64N_CONTENT_LENGTH } from './const';

/**
 * Read a response body as a 7-bit ASCII string.
 *
 * `application/tai64n` is an octet-typed media type, not
 * text: the TAI64N label is a fixed sequence of ASCII
 * bytes. Reading it with `Response.text()` would route
 * the body through UTF-8 decoding and silently mangle any
 * non-ASCII octet, so this reads the raw bytes and decodes
 * them one code point per byte instead.
 *
 * Throws `TypeError` on any byte ≥ `0x80`, surfacing a
 * malformed body rather than masking it; pass `context` to
 * prefix that error message. Consumes the response body,
 * which can only be read once.
 *
 * Use {@link readLabel} when the body is meant to be a
 * TAI64N label and its length should be validated too.
 */
export const readASCII = async (
  response: Response,
  context?: string,
): Promise<string> =>
  decodeASCII(new Uint8Array(await response.arrayBuffer()), context);

/**
 * Read and return the TAI64N label from a response body.
 *
 * Builds on {@link readASCII}, adding the structural
 * invariant every label satisfies: the body is exactly
 * `TAI64N_CONTENT_LENGTH` octets. Throws `TypeError` if the
 * length differs or the body carries a non-ASCII octet;
 * pass `context` to prefix that error message. Consumes the
 * response body.
 */
export const readLabel = async (
  response: Response,
  context?: string,
): Promise<string> => {
  const label = await readASCII(response, context);
  // readASCII admitted only 7-bit bytes, so the string has
  // one code unit per octet — its length is the octet count.
  if (label.length !== TAI64N_CONTENT_LENGTH) {
    const prefix = context ? `${context}: ` : '';
    throw new TypeError(
      `${prefix}expected ${TAI64N_CONTENT_LENGTH}-octet ` +
      `TAI64N label, got ${label.length}`,
    );
  }
  return label;
};
