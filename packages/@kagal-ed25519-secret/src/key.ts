import { ED25519_KEY_BYTES } from './algo';
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
  if (bytes.length !== ED25519_KEY_BYTES) {
    const prefix = context ? `${context}: ` : '';
    throw new TypeError(
      `${prefix}expected ${ED25519_KEY_BYTES}-byte seed, got ${bytes.length}`,
    );
  }
  return bytes as unknown as Ed25519Seed;
};

/**
 * Public-only JWK for an Ed25519 verifying key
 * (RFC 8037 §3.1). `kty`/`crv` are literal; `x` is the
 * base64url-encoded 32-byte raw public key. `use` and
 * `alg` are always populated for drop-in use under a
 * `keys` array on a JWKS endpoint (RFC 7517 §5).
 * Values returned by {@link newKeys} are
 * `Object.freeze`d — the `readonly` markers reflect
 * that runtime guarantee.
 */
export interface Ed25519PublicJWK {
  /** Algorithm — `'EdDSA'` (RFC 8037 §3.1). */
  readonly alg: 'EdDSA'
  /** Curve — always `'Ed25519'` (RFC 8037 §3.1). */
  readonly crv: 'Ed25519'
  /**
   * Key identifier (RFC 7517 §4.5). Free-form,
   * case-sensitive string. Set by {@link newKeys}
   * when a truthy `kid` is supplied; otherwise
   * omitted.
   */
  readonly kid?: string
  /** Key type — always `'OKP'` (RFC 8037 §2). */
  readonly kty: 'OKP'
  /** Public-key use — `'sig'` (RFC 7517 §4.2). */
  readonly use: 'sig'
  /**
   * Base64url-encoded 32-byte raw public key (no
   * padding), as produced by WebCrypto's JWK export.
   */
  readonly x: string
}

/**
 * Four forms of an Ed25519 key drawn from the same
 * 32-byte seed — raw seed (for persistence),
 * verify-only public key, sign-only private key, and
 * a publication-ready public JWK (RFC 8037 §3.1).
 */
export interface KeyContext {
  /**
   * The 32-byte raw Ed25519 seed (RFC 8032), branded as
   * {@link Ed25519Seed} (defensive copy of the input).
   * Pass to `encodeBase64` to round-trip the seed, or
   * feed back into {@link newKeys} to rebuild the
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

  /**
   * Publication-ready public JWK (RFC 8037 §3.1) with
   * `use: 'sig'` and `alg: 'EdDSA'` populated, ready
   * to drop into a JWKS `keys` array (RFC 7517 §5).
   * Carries `kid` when {@link newKeys} is called with
   * a truthy `kid` argument.
   */
  publicJWK: Ed25519PublicJWK
}

/**
 * @deprecated Renamed to {@link KeyContext}; kept as an
 * alias so older callers continue to compile. The
 * shape now also carries {@link KeyContext.publicJWK}.
 */
export type KeyPair = KeyContext;

/**
 * Build an Ed25519 {@link KeyContext} from a 32-byte
 * private seed (RFC 8032). Omit / pass `undefined` to
 * generate a fresh seed via `crypto.getRandomValues`.
 *
 * The seed is routed through {@link asEd25519Seed} so
 * the returned {@link KeyContext.privateKey} is a
 * defensive copy, branded as {@link Ed25519Seed}.
 *
 * @param input - 32-byte raw Ed25519 seed, its base64
 *   encoding, or `undefined` (or omitted) to generate
 *   a fresh seed
 * @param kid - optional key identifier (RFC 7517 §4.5).
 *   Truthy values land on the returned
 *   {@link KeyContext.publicJWK} verbatim; falsy
 *   values (undefined, empty string) omit the field
 * @param context - prefix prepended to the thrown
 *   error message; defaults to `'newKeys'`
 * @returns a {@link KeyContext} — the raw seed, the
 *   verify-only and sign-only `CryptoKey`s, and a
 *   frozen, publication-ready {@link Ed25519PublicJWK}
 * @throws TypeError if `input` is the wrong length, or
 *   string input fails to decode as base64
 */
export const newKeys = async (
  input?: Readonly<Uint8Array> | string,
  kid?: string,
  context: string = 'newKeys',
): Promise<KeyContext> => {
  const privateKey = asEd25519Seed(
    input ?? getRandom(ED25519_KEY_BYTES),
    context,
  );

  const pkcs8 = composePrivateKeyInfo(privateKey);

  // WebCrypto has no derivePublicKey for Ed25519, so we
  // recover the public component by importing the seed as an
  // extractable private key, exporting it as JWK, and
  // re-importing the public-only fields. Dropping `d` (the
  // seed) is what tells the second importKey to treat the
  // JWK as a public key and grant `verify`. The signKey is
  // a separate import made non-extractable, so the seed
  // cannot be exfiltrated through it — and it shares no
  // dependency on the JWK round-trip, so the two pkcs8
  // imports run in parallel.
  const [extractable, signKey] = await Promise.all([
    crypto.subtle.importKey(
      'pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign'],
    ),
    crypto.subtle.importKey(
      'pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign'],
    ),
  ]);
  const jwk = await crypto.subtle.exportKey('jwk', extractable);

  // Minimal JWK for the verify-side import; published
  // metadata (use, alg, kid) lives only on the returned
  // publicJWK so importKey's consistency checks stay
  // narrow.
  const importJWK: JsonWebKey = {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
  };
  const publicKey = await crypto.subtle.importKey(
    'jwk', importJWK, { name: 'Ed25519' }, true, ['verify'],
  );

  const publicJWK: Ed25519PublicJWK = Object.freeze({
    kty: 'OKP',
    crv: 'Ed25519',
    x: jwk.x!,
    use: 'sig',
    alg: 'EdDSA',
    ...(kid ? { kid } : {}),
  });

  return { privateKey, publicKey, signKey, publicJWK };
};

/**
 * @deprecated Renamed to {@link newKeys}, which also
 * accepts an optional `kid` and surfaces a
 * publication-ready {@link Ed25519PublicJWK} on the
 * returned {@link KeyContext}. This wrapper preserves
 * the original 2-arg signature for source-compatibility
 * with 0.1.x callers.
 */
export const newKeyPair = async (
  input?: Readonly<Uint8Array> | string,
  context: string = 'newKeyPair',
): Promise<KeyPair> => newKeys(input, undefined, context);
