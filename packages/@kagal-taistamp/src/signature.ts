import { type Bytes } from '@kagal/ed25519-secret';

import { TAISTAMP_HEADER_SIGNATURE } from './const';
import { decodeSFBinary, SF_BINARY_PATTERN } from './sf-binary';

/**
 * Decoded length of every valid `TAI-Signature`: a raw
 * Ed25519 signature is 64 octets (RFC 8032).
 */
export const SIGNATURE_BYTES = 64;

/**
 * Decode a `TAI-Signature` wire value into the raw
 * Ed25519 signature bytes. Returns `undefined` when
 * `value` fails sf-binary syntax (RFC 9651 §3.3.5) or
 * does not decode to exactly `SIGNATURE_BYTES`
 * octets — a malformed field is equivalent to a
 * missing one. This validates form only; semantics
 * involving other fields (nonce echo, selector,
 * verification) stay with the caller.
 */
export const asSignature = (value: string): Bytes | undefined => {
  if (!SF_BINARY_PATTERN.test(value)) return undefined;
  const bytes = decodeSFBinary(value);
  return bytes.length === SIGNATURE_BYTES ? bytes : undefined;
};

/**
 * Extract the raw Ed25519 signature from response
 * headers. Returns `undefined` when the
 * `TAI-Signature` field is missing or fails
 * {@link asSignature} validation.
 */
export const extractSignature = (
  headers: Headers,
): Bytes | undefined => {
  const value = headers.get(TAISTAMP_HEADER_SIGNATURE);
  return value === null ? undefined : asSignature(value);
};
