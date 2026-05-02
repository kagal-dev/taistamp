/**
 * Generic signer abstraction over a private key.
 *
 * @remarks
 * The handler doesn't care which algorithm or key
 * store produced the signature, only that signing
 * succeeded. Pluggable so consumers can wire in
 * HSM-backed, KMS-backed, or in-process WebCrypto
 * signers without touching the handler. Verifiers
 * must agree on the algorithm and the public key
 * out-of-band — typically by pinning the public key
 * to a DNS TXT record.
 */
export interface Signer {
  /**
   * Produce a signature over `message`.
   *
   * @param message - bytes to sign; the caller is
   *   responsible for any framing or domain separation.
   *   Typed as {@link BufferSource} to match WebCrypto's
   *   own input shape — any `ArrayBuffer` or typed-array
   *   view is accepted.
   * @returns the raw signature bytes (algorithm-defined
   *   length and encoding) as an `ArrayBuffer`, matching
   *   WebCrypto's native output shape
   */
  sign: (message: BufferSource) => Promise<ArrayBuffer>
}

/**
 * Build a {@link Signer} backed by a WebCrypto Ed25519
 * private `CryptoKey`.
 *
 * @param key - Ed25519 private key with `'sign'` in
 *   `key.usages`. The algorithm `name` must be
 *   `'Ed25519'`.
 * @returns a {@link Signer} producing 64-byte raw
 *   Ed25519 signatures (R ‖ s, RFC 8032)
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8032}
 */
export const newEd25519Signer = (key: CryptoKey): Signer => ({
  sign: async (message) => crypto.subtle.sign('Ed25519', key, message),
});
