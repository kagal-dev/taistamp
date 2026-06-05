import { type Bytes, decodeBase64, encodeBase64 } from '@kagal/ed25519-secret';

/**
 * sf-binary item per RFC 9651 §3.3.5: standard base64
 * with `=` padding, wrapped in a leading and trailing
 * colon. The empty payload (`::`) is valid sf-binary;
 * consumers impose their own length bounds. The
 * alphabet contains no `,`, so a duplicated field
 * (joined by the Web `Headers` API with `,`) fails the
 * same check.
 */
export const SF_BINARY_PATTERN =
  /^:(?:(?:[\d+/A-Za-z]{4})*(?:[\d+/A-Za-z]{4}|[\d+/A-Za-z]{3}=|[\d+/A-Za-z]{2}==))?:$/;

/**
 * Encode bytes as an sf-binary item (RFC 9651 §3.3.5):
 * standard base64 wrapped in colons. The output
 * satisfies {@link SF_BINARY_PATTERN} and round-trips
 * through {@link decodeSFBinary}.
 */
export const encodeSFBinary = (bytes: Readonly<Uint8Array>): string =>
  `:${encodeBase64(bytes)}:`;

/**
 * Decode an sf-binary item back into bytes. Enforces
 * the full RFC 9651 §3.3.5 syntax: throws `TypeError`
 * when `value` does not satisfy
 * {@link SF_BINARY_PATTERN}; the thrown message is
 * optionally prefixed `<context>: `.
 */
export const decodeSFBinary = (
  value: string,
  context?: string,
): Bytes => {
  if (!SF_BINARY_PATTERN.test(value)) {
    const prefix = context ? `${context}: ` : '';
    throw new TypeError(`${prefix}invalid sf-binary`);
  }
  // the pattern guarantees decodable standard base64
  return decodeBase64(value.slice(1, -1), context);
};
