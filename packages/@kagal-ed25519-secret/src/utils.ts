/**
 * `Uint8Array<ArrayBuffer>`-shaped on TS lib 5.7+
 * (`Uint8Array` on older) — the backing buffer
 * narrowed to plain `ArrayBuffer`, not
 * `SharedArrayBuffer`. Matches what `BufferSource`
 * requires, and therefore what every `crypto.subtle.*`
 * byte parameter accepts.
 */
export type Bytes = ReturnType<typeof Uint8Array.from>;

/**
 * Encode bytes as standard base64 (RFC 4648 §4) with
 * padding. The output round-trips through
 * {@link decodeBase64}.
 */
export const encodeBase64 = (bytes: Readonly<Uint8Array>): string => {
  let binary = '';
  for (const byte of bytes) binary += String.fromCodePoint(byte);
  return btoa(binary);
};

/**
 * Decode standard or URL-safe base64 (RFC 4648 §4 and
 * §5) into bytes. URL-safe `-`/`_` map to `+`/`/`;
 * padding (`=`) optional. Throws `TypeError` on
 * `atob`-rejected input, with the original rejection
 * preserved as `cause`. The thrown message is
 * `invalid base64`, optionally prefixed `<context>: `.
 */
export const decodeBase64 = (
  b64: string,
  context?: string,
): Bytes => {
  const standard = b64.replaceAll('-', '+').replaceAll('_', '/');
  let binary: string;
  try {
    binary = atob(standard);
  } catch (error) {
    const prefix = context === undefined ? '' : `${context}: `;
    throw new TypeError(`${prefix}invalid base64`, { cause: error });
  }
  // atob returns a binary string: each char's code unit is in
  // [0, 255] and represents one decoded byte, so charCodeAt
  // gives the byte directly. codePointAt would force a `?? 0`
  // for an impossible undefined branch.
  // eslint-disable-next-line unicorn/prefer-code-point
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
};

/**
 * Encode an extractable Ed25519 public `CryptoKey` as
 * standard base64 (RFC 4648 §4) of its 32-byte raw
 * form, ready for out-of-band distribution
 * (e.g. a DNS TXT record). The output round-trips
 * through `decodeBase64` +
 * `crypto.subtle.importKey('raw', ...)`.
 *
 * @param key - extractable Ed25519 public `CryptoKey`
 * @param context - optional prefix prepended to the
 *   thrown error message
 * @returns base64-encoded 32-byte raw public key
 * @throws TypeError if `key`'s algorithm isn't
 *   Ed25519, if it isn't a public key, or if it
 *   cannot be exported as `'raw'` (non-extractable);
 *   in the export-failure case the underlying
 *   rejection is preserved as `cause`.
 */
export const encodeKey = async (
  key: CryptoKey,
  context?: string,
): Promise<string> => {
  const prefix = context === undefined ? '' : `${context}: `;
  if (key.algorithm.name !== 'Ed25519') {
    throw new TypeError(
      `${prefix}expected Ed25519 key, got ${key.algorithm.name}`,
    );
  }
  if (key.type !== 'public') {
    throw new TypeError(
      `${prefix}expected public key, got ${key.type}`,
    );
  }
  let raw: ArrayBuffer;
  try {
    raw = await crypto.subtle.exportKey('raw', key);
  } catch (error) {
    throw new TypeError(
      `${prefix}cannot export key as raw`,
      { cause: error },
    );
  }
  return encodeBase64(new Uint8Array(raw));
};

/**
 * Fill a fresh `Uint8Array` of the requested length
 * with cryptographically secure random bytes via
 * `crypto.getRandomValues`, subject to its length cap
 * (typically 64 KiB).
 *
 * @param length - non-negative integer byte count
 * @param context - optional prefix prepended to the
 *   thrown error message
 * @returns a fresh `Uint8Array` of `length` random
 *   bytes
 * @throws TypeError if `length` is not a non-negative
 *   integer
 * @throws QuotaExceededError forwarded from
 *   `crypto.getRandomValues` when `length` exceeds
 *   the underlying cap (typically 65536 bytes)
 */
export const getRandom = (
  length: number,
  context?: string,
): Bytes => {
  if (!Number.isInteger(length) || length < 0) {
    const prefix = context === undefined ? '' : `${context}: `;
    throw new TypeError(
      `${prefix}expected non-negative integer length, got ${length}`,
    );
  }
  return crypto.getRandomValues(new Uint8Array(length));
};

/**
 * Normalise a bytes-or-base64 input to a fresh
 * `Uint8Array`. Bytes are defensive-copied; strings
 * are decoded via {@link decodeBase64}.
 *
 * @param input - bytes or base64 string
 * @param context - optional prefix prepended to a
 *   decode error
 * @returns a fresh `Uint8Array`
 * @throws TypeError if string input fails to decode
 *   as base64
 */
export const asBytes = (
  input: Readonly<Uint8Array> | string,
  context?: string,
): Bytes =>
  typeof input === 'string' ?
    decodeBase64(input, context) :
    new Uint8Array(input);

/**
 * Split a list (or single value) into `first` + `rest`.
 * `undefined` or an empty array yields `{ rest: [] }`;
 * a single value or a one-element array yields
 * `{ first, rest: [] }`.
 */
export const splitFirst = <T>(
  items: T | T[] | undefined,
): { first?: T; rest: T[] } => {
  if (items === undefined) return { rest: [] };
  if (!Array.isArray(items)) return { first: items, rest: [] };
  if (items.length === 0) return { rest: [] };
  return { first: items.at(0), rest: items.slice(1) };
};

/**
 * Split a list (or single value) into `last` + `rest`.
 * `undefined` or an empty array yields `{ rest: [] }`;
 * a single value or a one-element array yields
 * `{ last, rest: [] }`.
 */
export const splitLast = <T>(
  items: T | T[] | undefined,
): { last?: T; rest: T[] } => {
  if (items === undefined) return { rest: [] };
  if (!Array.isArray(items)) return { last: items, rest: [] };
  if (items.length === 0) return { rest: [] };
  return { last: items.at(-1), rest: items.slice(0, -1) };
};
