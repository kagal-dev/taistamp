import { SUPPORTED_ALGORITHMS } from './algo';
import { asBytes, asMessageBytes } from './utils';

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

/**
 * Import a raw-encoded public verifying key (e.g. the
 * `p=` bytes from a DKIM-style DNS TXT record, RFC 6376
 * §3.6.1) into an extractable verify-only `CryptoKey`,
 * suitable for {@link newVerifier} or a direct
 * `crypto.subtle.verify` call.
 *
 * `algorithm` matches case-insensitively against
 * {@link SUPPORTED_ALGORITHMS} so DKIM `k=` values
 * (lowercase by RFC 6376 §3.6.1) work without
 * pre-normalisation; the canonical form (`'Ed25519'`)
 * is what `crypto.subtle.importKey` receives.
 *
 * @param algorithm - algorithm name, e.g. `'Ed25519'`
 *   or `'ed25519'` (case-insensitive)
 * @param keyData - raw public-key bytes (32 bytes for
 *   Ed25519) or their base64 encoding (standard or
 *   URL-safe per RFC 4648 §4 / §5)
 * @param context - optional prefix prepended to thrown
 *   error messages
 * @returns an extractable verify-only `CryptoKey`
 * @throws `TypeError` for an unsupported algorithm,
 *   wrong byte length, or undecodable base64 (the last
 *   via {@link asBytes})
 */
export const importVerifyKey = async (
  algorithm: string,
  keyData: Readonly<Uint8Array> | string,
  context?: string,
): Promise<CryptoKey> => {
  const prefix = context ? `${context}: ` : '';
  const meta = SUPPORTED_ALGORITHMS.get(algorithm.toLowerCase());
  if (meta === undefined) {
    throw new TypeError(
      `${prefix}unsupported algorithm: ${algorithm}`,
    );
  }
  const bytes = asBytes(keyData, context);
  if (bytes.length !== meta.rawKeyLength) {
    const want = `${meta.rawKeyLength}-byte ${meta.name} key`;
    throw new TypeError(
      `${prefix}expected ${want}, got ${bytes.length}`,
    );
  }
  return crypto.subtle.importKey(
    'raw', bytes, { name: meta.name }, true, ['verify'],
  );
};
