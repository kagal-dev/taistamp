import { SUPPORTED_ALGORITHMS } from './algo';

const UTF8_ENCODER = new TextEncoder();

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
    const prefix = context ? `${context}: ` : '';
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
 * Decode bytes as 7-bit ASCII, one code point per byte.
 * A byte ≥ `0x80` is rejected rather than mapped into
 * the Latin-1 range: the input is declared ASCII, so a
 * high byte signals a malformed source. The thrown
 * message is `expected 7-bit ASCII, got 0x<hh>`,
 * optionally prefixed `<context>: `.
 *
 * @param bytes - ASCII octets
 * @param context - optional prefix prepended to the
 *   thrown error message
 * @returns the decoded ASCII string
 * @throws TypeError if any byte is ≥ `0x80`
 */
export const decodeASCII = (
  bytes: Readonly<Uint8Array>,
  context?: string,
): string => {
  let out = '';
  for (const byte of bytes) {
    if (byte > 0x7F) {
      const prefix = context ? `${context}: ` : '';
      const hex = byte.toString(16).padStart(2, '0');
      throw new TypeError(`${prefix}expected 7-bit ASCII, got 0x${hex}`);
    }
    out += String.fromCodePoint(byte);
  }
  return out;
};

/**
 * Encode an extractable public `CryptoKey` whose
 * algorithm this package supports as standard base64
 * (RFC 4648 §4) of its raw form, ready for out-of-band
 * distribution (e.g. a DNS TXT record). The output
 * round-trips through `decodeBase64` +
 * `crypto.subtle.importKey('raw', ...)`.
 *
 * @param key - extractable public `CryptoKey` for a
 *   supported algorithm
 * @param context - optional prefix prepended to the
 *   thrown error message
 * @returns base64-encoded raw public key
 * @throws TypeError if `key`'s algorithm isn't
 *   supported, if it isn't a public key, or if it
 *   cannot be exported as `'raw'` (non-extractable);
 *   in the export-failure case the underlying
 *   rejection is preserved as `cause`.
 */
export const encodeKey = async (
  key: CryptoKey,
  context?: string,
): Promise<string> => {
  const prefix = context ? `${context}: ` : '';
  const algorithm = key.algorithm.name;
  if (SUPPORTED_ALGORITHMS.get(algorithm.toLowerCase()) === undefined) {
    throw new TypeError(
      `${prefix}unsupported algorithm: ${algorithm}`,
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
 * Whether `value` is an integer within the inclusive
 * range `[min, max]`. `max` defaults to
 * `Number.MAX_SAFE_INTEGER`, so the two-argument form
 * tests for an integer ≥ `min`. An `undefined`,
 * fractional, `NaN`, infinite, or out-of-range `value`
 * is `false`.
 */
export const isInRange = (
  value: number | undefined,
  min: number,
  max: number = Number.MAX_SAFE_INTEGER,
): boolean =>
  value !== undefined &&
  Number.isInteger(value) && value >= min && value <= max;

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
  if (!isInRange(length, 0)) {
    const prefix = context ? `${context}: ` : '';
    throw new TypeError(
      `${prefix}expected non-negative integer length, got ${length}`,
    );
  }
  return crypto.getRandomValues(new Uint8Array(length));
};

/**
 * The larger of `min` and `value`, rounding a fractional
 * `value` to the nearest integer first, and falling back
 * to `min` when `value` is absent or not a finite number.
 * With an integer `min` the result is always an integer
 * ≥ `min`.
 */
export const atLeast = (min: number, value?: number): number =>
  typeof value === 'number' && Number.isFinite(value) ?
    Math.max(min, Math.round(value)) :
    min;

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
 * Normalise a message input to `BufferSource`.
 * `BufferSource` values are passed through unchanged;
 * strings are encoded as UTF-8. Use when calling a
 * crypto primitive that requires `BufferSource` from a
 * caller holding a domain-level string. Callers
 * needing a non-UTF-8 encoding should pass bytes
 * directly.
 *
 * Differs from {@link asBytes} above, where a string
 * input is decoded as base64.
 */
export const asMessageBytes = (
  message: BufferSource | string,
): BufferSource =>
  typeof message === 'string' ? UTF8_ENCODER.encode(message) : message;

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
