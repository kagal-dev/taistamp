import { SUPPORTED_ALGORITHMS } from './algo';
import { asMessageBytes } from './utils';

/**
 * Pluggable abstraction over a public verifying key.
 * Implementations check a candidate signature against a
 * message and report the result as a boolean; the
 * algorithm and key store are implementation details.
 */
export interface Verifier {
  /**
   * Check `signature` against `message`.
   *
   * @param signature - bytes claimed as a signature over
   *   `message` (algorithm-defined length and encoding)
   * @param message - message the signature is claimed
   *   to cover, either bytes or a string (encoded as
   *   UTF-8); the caller is responsible for any
   *   framing or domain separation
   * @returns `true` when the signature verifies under
   *   the underlying key, `false` otherwise
   */
  verify: (
    signature: BufferSource,
    message: BufferSource | string,
  ) => Promise<boolean>
}

/**
 * Build a {@link Verifier} backed by a WebCrypto
 * Ed25519 public `CryptoKey`. Each call delegates to
 * `crypto.subtle.verify`, which is specified to apply
 * RFC 8032 §5.1.7 strict verification on conformant
 * runtimes.
 *
 * @param key - Ed25519 public `CryptoKey` with
 *   `'verify'` in `key.usages`
 * @param context - optional prefix prepended to error
 *   messages, typically the calling function's name
 * @returns a {@link Verifier} routing each call through
 *   `crypto.subtle.verify`
 * @throws `TypeError` when `key.algorithm.name` is not a
 *   supported algorithm or `'verify'` is missing from
 *   `key.usages`
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.7 | RFC 8032 §5.1.7}
 */
export const newVerifier = (
  key: CryptoKey,
  context?: string,
): Verifier => {
  const prefix = context ? `${context}: ` : '';
  const algorithm = key.algorithm.name;
  const meta = SUPPORTED_ALGORITHMS.get(algorithm.toLowerCase());
  if (meta === undefined) {
    throw new TypeError(
      `${prefix}unsupported algorithm: ${algorithm}`,
    );
  }
  if (!key.usages.includes('verify')) {
    throw new TypeError(
      `${prefix}expected verify usage, got [${key.usages.join(', ')}]`,
    );
  }
  return {
    verify: async (signature, message) =>
      crypto.subtle.verify(
        meta.name, key, signature, asMessageBytes(message),
      ),
  };
};
