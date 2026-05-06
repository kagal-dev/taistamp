/**
 * Encode bytes as standard base64 (RFC 4648 §4) with
 * padding. The output round-trips through
 * {@link decodeBase64}.
 */
export const encodeBase64 = (bytes: Uint8Array): string => {
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
): Uint8Array => {
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
