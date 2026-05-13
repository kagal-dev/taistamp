import { asBytes, getRandom } from './utils';

const PKCS8_ED25519_HEADER = new Uint8Array([
  0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

/**
 * Compose a DER-encoded `PrivateKeyInfo` (RFC 5958)
 * carrying a 32-byte Ed25519 private seed under
 * algorithm OID 1.3.101.112 (RFC 8410). The 16-byte
 * prefix frames a 34-byte OCTET STRING containing the
 * 32-byte `CurvePrivateKey`, for a total of 48 bytes —
 * the input shape `crypto.subtle.importKey('pkcs8', …)`
 * expects.
 */
const composePrivateKeyInfo = (seed: Readonly<Uint8Array>): ArrayBuffer => {
  const out = new Uint8Array(PKCS8_ED25519_HEADER.length + seed.length);
  out.set(PKCS8_ED25519_HEADER, 0);
  out.set(seed, PKCS8_ED25519_HEADER.length);
  return out.buffer as ArrayBuffer;
};

declare const ed25519SeedBrand: unique symbol;

/**
 * A 32-byte Ed25519 private seed (RFC 8032). Construct
 * via {@link asEd25519Seed}; the brand is unforgeable
 * from outside the package, so a value of this type has
 * been length-checked and defensive-copied. Mutating
 * method calls (`.set`, `.fill`, etc.) are flagged by
 * `Readonly<Uint8Array>`, but indexed writes are not
 * blocked at runtime.
 */
export type Ed25519Seed = Readonly<Uint8Array> & {
  readonly [ed25519SeedBrand]: void
};

/**
 * Validate and brand a 32-byte Ed25519 private seed
 * (RFC 8032). String input is decoded as base64 first;
 * standard and URL-safe forms (RFC 4648 §4 and §5) are
 * both accepted, with optional padding.
 *
 * @param input - candidate seed: a 32-byte
 *   `Uint8Array`, or its base64 encoding
 * @param context - optional prefix prepended to any
 *   thrown error message
 * @returns a branded {@link Ed25519Seed} (defensive copy)
 * @throws TypeError if the (decoded) length is not 32,
 *   or if string input fails to decode as base64 (with
 *   the original `atob` rejection as `cause`)
 */
export const asEd25519Seed = (
  input: Readonly<Uint8Array> | string,
  context?: string,
): Ed25519Seed => {
  const bytes = asBytes(input, context);
  if (bytes.length !== 32) {
    const prefix = context === undefined ? '' : `${context}: `;
    throw new TypeError(
      `${prefix}expected 32-byte seed, got ${bytes.length}`,
    );
  }
  return bytes as unknown as Ed25519Seed;
};

/**
 * Three forms of an Ed25519 key drawn from the same
 * 32-byte seed: the raw seed bytes (for persistence),
 * the verify-only public key (for distribution), and
 * the sign-only private key (for in-process signing).
 */
export interface KeyPair {
  /**
   * The 32-byte raw Ed25519 seed (RFC 8032), branded as
   * {@link Ed25519Seed} (defensive copy of the input).
   * Pass to `encodeBase64` to round-trip the seed, or
   * feed back into {@link newKeyPair} to rebuild the
   * key-pair on another host. WebCrypto cannot expose
   * the seed through {@link signKey}.
   */
  privateKey: Ed25519Seed

  /**
   * Extractable Ed25519 `CryptoKey` with `'verify'`
   * usage. Export via `crypto.subtle.exportKey` to
   * publish out-of-band (e.g. under a selector-scoped
   * DNS record), or pass to `crypto.subtle.verify` for
   * in-process verification.
   */
  publicKey: CryptoKey

  /**
   * Non-extractable Ed25519 `CryptoKey` with `'sign'`
   * usage. Pass to `crypto.subtle.sign`, or wrap with
   * `newSigner` for the convenience interface.
   * Use {@link privateKey} for persistence.
   */
  signKey: CryptoKey
}

/**
 * Build an Ed25519 key triple from a 32-byte private
 * seed (RFC 8032). Omit / pass `undefined` to generate
 * a fresh seed via `crypto.getRandomValues`.
 *
 * The seed is routed through {@link asEd25519Seed} so
 * the returned {@link KeyPair.privateKey} is a
 * defensive copy, branded as {@link Ed25519Seed}.
 *
 * @param input - 32-byte raw Ed25519 seed, its base64
 *   encoding, or `undefined` (or omitted) to generate
 *   a fresh seed
 * @param context - prefix prepended to the thrown
 *   error message; defaults to `'newKeyPair'`
 * @returns a {@link KeyPair} ready for sign / verify
 * @throws TypeError if `input` is the wrong length, or
 *   string input fails to decode as base64
 */
export const newKeyPair = async (
  input?: Readonly<Uint8Array> | string,
  context: string = 'newKeyPair',
): Promise<KeyPair> => {
  const privateKey = asEd25519Seed(input ?? getRandom(32), context);

  const pkcs8 = composePrivateKeyInfo(privateKey);

  // WebCrypto has no derivePublicKey for Ed25519, so we
  // recover the public component by importing the seed as an
  // extractable private key, exporting it as JWK, and
  // re-importing the public-only fields. Dropping `d` (the
  // seed) is what tells the second importKey to treat the
  // JWK as a public key and grant `verify`. The signKey is
  // a separate import made non-extractable, so the seed
  // cannot be exfiltrated through it.
  const extractable = await crypto.subtle.importKey(
    'pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign'],
  );
  const jwk = await crypto.subtle.exportKey('jwk', extractable);
  const publicJWK: JsonWebKey = {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
  };

  const publicKey = await crypto.subtle.importKey(
    'jwk', publicJWK, { name: 'Ed25519' }, true, ['verify'],
  );
  const signKey = await crypto.subtle.importKey(
    'pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign'],
  );

  return { privateKey, publicKey, signKey };
};
