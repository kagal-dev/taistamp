import { asEd25519Seed, type Ed25519Seed, newKeyPair } from './key';
import { assertValidSelector } from './selector';
import { newSigner, type Signer } from './signer';

/**
 * Parsed `selector:base64` secret: the selector, the
 * Ed25519 key triple (raw seed, public, sign-only),
 * and a {@link Signer} backed by the sign-only key.
 */
export interface KeyConfig {
  /**
   * The 32-byte raw Ed25519 seed (RFC 8032), branded
   * as {@link Ed25519Seed}. Pass to `encodeBase64` to
   * reassemble a `selector:base64` secret. WebCrypto
   * cannot expose this through {@link signKey}, so this
   * field is the only path to persist or republish the
   * key material.
   */
  privateKey: Ed25519Seed

  /**
   * Extractable Ed25519 public `CryptoKey` with
   * `'verify'` usage. Export via
   * `crypto.subtle.exportKey` to publish the verifier
   * out-of-band (e.g. under a selector-scoped DNS
   * record), or pass to `crypto.subtle.verify` for
   * in-process verification.
   */
  publicKey: CryptoKey

  /**
   * Selector portion of the parsed secret, validated
   * against {@link SELECTOR_PATTERN}.
   */
  selector: string

  /**
   * Non-extractable Ed25519 `CryptoKey` with `'sign'`
   * usage. Pass to `crypto.subtle.sign` for raw access,
   * or use {@link signer} for the pre-built convenience
   * wrapper. Non-extractable so the seed cannot be
   * exfiltrated through this handle — use
   * {@link privateKey} for persistence.
   */
  signKey: CryptoKey

  /**
   * {@link Signer} backed by {@link signKey}. Calls
   * `crypto.subtle.sign('Ed25519', signKey, message)`
   * and returns the raw 64-byte RFC 8032 signature.
   */
  signer: Signer
}

/**
 * Parse a `selector:base64` secret into a {@link KeyConfig}.
 * The base64 portion is a raw 32-byte Ed25519 private
 * seed in standard or URL-safe encoding; the selector
 * is validated against {@link SELECTOR_PATTERN}.
 *
 * @param secretString - secret of the form
 *   `selector:base64`
 * @param context - prefix prepended to the thrown
 *   error message; defaults to `'parseSecretToKey'`
 * @returns a {@link KeyConfig} carrying the raw seed,
 *   the extractable public `CryptoKey`, the
 *   non-extractable sign-only `CryptoKey`, and a
 *   ready-to-use {@link Signer} backed by the sign-only
 *   key
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8410}
 */
export const parseSecretToKey = async (
  secretString: string,
  context: string = 'parseSecretToKey',
): Promise<KeyConfig> => {
  const parts = secretString.split(':');
  if (parts.length !== 2) {
    const got = parts.length === 1 ?
      'no separator' :
      `${parts.length} colon-separated parts`;
    throw new TypeError(
      `${context}: expected "selector:base64", got ${got}`,
    );
  }
  const [selector, b64Key] = parts;
  if (!selector) {
    throw new TypeError(
      `${context}: expected "selector:base64", got empty selector`,
    );
  }
  if (!b64Key) {
    throw new TypeError(
      `${context}: expected "selector:base64", got empty base64`,
    );
  }

  assertValidSelector(selector, context);

  const seed = asEd25519Seed(b64Key, context);
  const { privateKey, publicKey, signKey } = await newKeyPair(seed, context);

  return {
    privateKey,
    publicKey,
    selector,
    signKey,
    signer: newSigner(signKey, context),
  };
};
