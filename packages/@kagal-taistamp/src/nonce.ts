import { getRandom, isInRange } from '@kagal/ed25519-secret';

import { TAISTAMP_HEADER_NONCE } from './const';
import { encodeSFBinary, SF_BINARY_PATTERN } from './sf-binary';

/**
 * Decoded-length lower bound on `TAI-Nonce` — spec
 * §5.4's normative minimum of 7 octets, providing the
 * client-supplied entropy for the replay defence.
 */
export const NONCE_MIN_BYTES = 7;

/**
 * Decoded-length upper bound on `TAI-Nonce` — spec
 * §5.4's normative maximum of 129 octets, capping the
 * nonce's contribution to overall response size.
 */
export const NONCE_MAX_BYTES = 129;

/**
 * Wire-form lower bound on `TAI-Nonce`. Spec §5.4 sets
 * the normative bound on decoded length (≥ 7 octets);
 * 14 is the smallest wire form (`:` + 12 base64 chars
 * + `:`) that can decode to 7 octets, so the wire
 * check rejects undersize input before base64 decoding.
 * This also rejects the empty payload (`::`) — a
 * zero-length nonce is treated as absent per spec §5.4.
 * sf-binary is ASCII-only — the string length equals
 * the octet count.
 */
export const NONCE_MIN_OCTETS = 14;

/**
 * Wire-form upper bound on `TAI-Nonce`. Spec §5.4 sets
 * the normative bound on decoded length (≤ 129 octets);
 * 174 is the longest wire form (`:` + 172 base64 chars
 * + `:`) whose decoded payload stays within 129 octets,
 * so the wire check rejects oversize input before
 * base64 decoding.
 */
export const NONCE_MAX_OCTETS = 174;

declare const NonceBrand: unique symbol;

/**
 * `string` that has been confirmed to satisfy the
 * sf-binary syntax of RFC 9651 §3.3.5 and to fall
 * inside the wire-form length range
 * `[NONCE_MIN_OCTETS, NONCE_MAX_OCTETS]` — the
 * pre-decode form of spec §5.4's normative
 * decoded-length bound of 7..129 octets. Construct
 * only via {@link asNonce}, {@link extractNonce}, or
 * {@link newNonce}; the brand prevents arbitrary
 * strings from reaching the signing path.
 */
export type Nonce = string & { readonly [NonceBrand]: never };

/**
 * Brand `value` as a {@link Nonce} when it satisfies
 * sf-binary syntax (RFC 9651 §3.3.5) and falls inside
 * `[NONCE_MIN_OCTETS, NONCE_MAX_OCTETS]` — the wire
 * range equivalent to spec §5.4's normative
 * decoded-length bound of 7..129 octets. Returns
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
 * Extract a usable `TAI-Nonce` from headers — the
 * request on the serving side, the response's nonce
 * echo on the verifying side. Returns `undefined` when
 * the field is missing or fails {@link asNonce}
 * validation.
 */
export const extractNonce = (headers: Headers): Nonce | undefined => {
  const value = headers.get(TAISTAMP_HEADER_NONCE);
  return value === null ? undefined : asNonce(value);
};

/**
 * Mint a fresh client `TAI-Nonce`: `byteLength` random
 * bytes framed as an sf-binary item, branded directly —
 * the result is conformant by construction.
 * `byteLength` must be an integer within
 * `[NONCE_MIN_BYTES, NONCE_MAX_BYTES]` —
 * spec §5.4's decoded-length bound; anything else
 * throws `TypeError`. `context` (default `'newNonce'`)
 * prefixes the thrown error.
 */
export const newNonce = (
  byteLength: number = 16,
  context: string = 'newNonce',
): Nonce => {
  if (!isInRange(byteLength, NONCE_MIN_BYTES, NONCE_MAX_BYTES)) {
    const prefix = context ? `${context}: ` : '';
    throw new TypeError(
      `${prefix}expected integer byte length within ` +
      `${NONCE_MIN_BYTES}..${NONCE_MAX_BYTES}, got ${byteLength}`,
    );
  }
  return encodeSFBinary(getRandom(byteLength, context)) as Nonce;
};
