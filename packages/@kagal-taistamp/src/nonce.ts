import { TAI64N_HEADER_NONCE } from './const';

/**
 * Lower bound on `TAI-Nonce` field-value octets. A
 * field shorter than this is treated as absent (spec
 * §5.4). sf-binary is ASCII-only — the string length
 * equals the octet count.
 */
export const NONCE_MIN_OCTETS = 14;

/**
 * Upper bound on `TAI-Nonce` field-value octets. A
 * field longer than this is treated as absent (spec
 * §5.4).
 */
export const NONCE_MAX_OCTETS = 174;

/**
 * sf-binary item per RFC 9651 §3.3.5: standard base64
 * with `=` padding, wrapped in a leading and trailing
 * colon. The empty payload (`::`) is excluded — a
 * zero-length nonce is treated as absent per spec
 * §5.4. The alphabet contains no `,`, so a duplicated
 * field (joined by the Web `Headers` API with `,`)
 * fails the same check.
 */
const SF_BINARY_PATTERN =
  /^:(?:[\d+/A-Za-z]{4})*(?:[\d+/A-Za-z]{4}|[\d+/A-Za-z]{3}=|[\d+/A-Za-z]{2}==):$/;

declare const NonceBrand: unique symbol;

/**
 * `string` that has been confirmed to satisfy the
 * sf-binary syntax of RFC 9651 §3.3.5 and the
 * `[NONCE_MIN_OCTETS, NONCE_MAX_OCTETS]` length range
 * required by spec §5.4. Construct only via
 * {@link asNonce} or {@link extractNonce}; the brand
 * prevents arbitrary strings from reaching the
 * signing path.
 */
export type Nonce = string & { readonly [NonceBrand]: never };

/**
 * Brand `value` as a {@link Nonce} when it satisfies
 * sf-binary syntax (RFC 9651 §3.3.5) and falls inside
 * `[NONCE_MIN_OCTETS, NONCE_MAX_OCTETS]`. Returns
 * `undefined` for anything else — every "treat as
 * absent" case in spec §5.4 collapsed into one
 * verdict.
 */
export const asNonce = (value: string): Nonce | undefined => {
  if (
    !value ||
    value.length < NONCE_MIN_OCTETS ||
    value.length > NONCE_MAX_OCTETS ||
    !SF_BINARY_PATTERN.test(value)
  ) return undefined;
  return value as Nonce;
};

/**
 * Extract a usable `TAI-Nonce` from request headers.
 * Returns `undefined` when the field is missing or
 * fails {@link asNonce} validation.
 */
export const extractNonce = (headers: Headers): Nonce | undefined => {
  const value = headers.get(TAI64N_HEADER_NONCE);
  return value === null ? undefined : asNonce(value);
};
