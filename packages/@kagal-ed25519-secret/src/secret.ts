import { asEd25519Seed, type KeyContext, newKeys } from './key';
import { assertValidSelector } from './selector';
import { newSigner, type Signer } from './signer';
import { newVerifier, type Verifier } from './verifier';

/**
 * Parsed `selector:base64` secret. Extends
 * {@link KeyContext} with the parsed `selector` and
 * pre-built {@link Signer} / {@link Verifier}; the
 * inherited {@link KeyContext.publicJWK} carries the
 * selector as its `kid`.
 */
export interface KeyConfig extends KeyContext {
  /**
   * Selector portion of the parsed secret, validated
   * against {@link SELECTOR_PATTERN}. Pinned onto
   * {@link KeyContext.publicJWK} as its `kid`, so a
   * JWKS endpoint and a DNS-style channel can both
   * index the same key under the same identifier.
   */
  selector: string

  /**
   * {@link Signer} backed by {@link KeyContext.signKey}.
   * Calls `crypto.subtle.sign('Ed25519', signKey, message)`
   * and returns the raw 64-byte RFC 8032 signature.
   */
  signer: Signer

  /**
   * {@link Verifier} backed by {@link KeyContext.publicKey}.
   * Calls `crypto.subtle.verify('Ed25519', publicKey, signature, message)`
   * and returns the boolean result.
   */
  verifier: Verifier
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
 * @returns a {@link KeyConfig} — a {@link KeyContext}
 *   (carrying the raw seed, the public / sign-only
 *   `CryptoKey`s, and a `publicJWK` with `kid` set to
 *   the parsed selector) plus the `selector` itself
 *   and ready-to-use {@link Signer} / {@link Verifier}
 * @throws TypeError if `secretString` is not in
 *   `selector:base64` form, if the selector fails
 *   {@link SELECTOR_PATTERN}, or if the base64 fails
 *   to decode to a 32-byte seed
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
  const keys = await newKeys(seed, selector, context);

  return {
    ...keys,
    selector,
    signer: newSigner(keys.signKey, context),
    verifier: newVerifier(keys.publicKey, context),
  };
};

/**
 * Parse a string containing multiple `selector:base64`
 * secrets into an array of {@link KeyConfig}s. Splits
 * on any character outside the `selector:base64`
 * alphabet (alphanumerics, `:`, `+`, `/`, `=`, `_`,
 * `-`) — so whitespace, commas, semicolons, pipes,
 * and other punctuation all work as delimiters. Empty
 * fragments (from leading, trailing, or consecutive
 * delimiters) are dropped before any decode is
 * attempted.
 *
 * Returned entries preserve input order; in lenient
 * mode that's the order among entries that parsed.
 *
 * @param secrets - one or more `selector:base64`
 *   secrets separated by whitespace or punctuation
 * @param strict - when `true` (default), a malformed
 *   entry rejects the whole call; when
 *   `false`, malformed entries are silently skipped
 *   and the returned array contains only the entries
 *   that parsed
 * @param context - prefix prepended to per-entry
 *   error messages; only visible in strict mode
 *   (lenient mode swallows the errors); defaults to
 *   `'parseSecretsToKeys'`
 * @returns array of {@link KeyConfig}s, one per
 *   successfully-parsed secret; empty when `secrets`
 *   yields no usable tokens
 * @throws TypeError (in strict mode) — the message
 *   identifies the 1-based index of the offending
 *   entry: `<context>: secret N: <inner error>`
 */
export const parseSecretsToKeys = async (
  secrets: string,
  strict: boolean = true,
  context: string = 'parseSecretsToKeys',
): Promise<KeyConfig[]> => {
  const tokens = secrets.split(/[^A-Za-z0-9:+/=_-]+/).filter(Boolean);
  const promises = tokens.map((token, index) =>
    parseSecretToKey(token, `${context}: secret ${index + 1}`),
  );

  if (strict) {
    return Promise.all(promises);
  }

  const results = await Promise.allSettled(promises);
  return results
    .filter(
      (r): r is PromiseFulfilledResult<KeyConfig> => r.status === 'fulfilled',
    )
    .map((r) => r.value);
};
