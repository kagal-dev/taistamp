/**
 * Pluggable abstraction over a private signing key.
 * Implementations sign caller-provided bytes and
 * return the raw signature bytes; the algorithm and
 * key store are implementation details.
 */
export interface Signer {
  /**
   * Produce a signature over `message`.
   *
   * @param message - bytes to sign; the caller is
   *   responsible for any framing or domain separation
   * @returns the raw signature bytes (algorithm-defined
   *   length and encoding)
   */
  sign: (message: BufferSource) => Promise<ArrayBuffer>
}

/**
 * Build a {@link Signer} backed by a WebCrypto Ed25519
 * private `CryptoKey`.
 *
 * @param key - Ed25519 private `CryptoKey` with `'sign'`
 *   in `key.usages`
 * @param context - optional prefix prepended to error
 *   messages, typically the calling function's name
 * @returns a {@link Signer} producing 64-byte raw
 *   Ed25519 signatures (R ‖ s, RFC 8032)
 * @throws `TypeError` when `key.algorithm.name` is not
 *   `'Ed25519'` or `'sign'` is missing from `key.usages`
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8032}
 */
export const newSigner = (
  key: CryptoKey,
  context?: string,
): Signer => {
  const prefix = context ? `${context}: ` : '';
  if (key.algorithm.name !== 'Ed25519') {
    throw new TypeError(
      `${prefix}expected Ed25519 key, got ${key.algorithm.name}`,
    );
  }
  if (!key.usages.includes('sign')) {
    throw new TypeError(
      `${prefix}expected sign usage, got [${key.usages.join(', ')}]`,
    );
  }
  return {
    sign: async (message) => crypto.subtle.sign('Ed25519', key, message),
  };
};
