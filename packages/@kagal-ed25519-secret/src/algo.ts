/**
 * Per-algorithm metadata: the canonical name fed to
 * WebCrypto (`crypto.subtle.sign` / `verify` /
 * `importKey`) and the byte length of its
 * `'raw'`-encoded public key.
 */
export interface AlgorithmMeta {
  readonly name: string
  readonly rawKeyLength: number
}

/**
 * Byte length of an Ed25519 key in raw form. RFC 8032
 * fixes both the private seed and the public key at
 * `b / 8 = 32` bytes (`b = 256`), so a single value
 * bounds the seed guard and
 * {@link AlgorithmMeta.rawKeyLength}.
 */
export const ED25519_KEY_BYTES = 32;

/**
 * The algorithms this package supports, keyed by
 * **lowercase** name so DKIM-style `k=` values
 * (`'ed25519'`, RFC 6376 §3.6.1) match without
 * pre-normalisation; {@link AlgorithmMeta.name} carries
 * the canonical form WebCrypto recognises.
 */
export const SUPPORTED_ALGORITHMS: ReadonlyMap<string, AlgorithmMeta> = new Map([
  ['ed25519', { name: 'Ed25519', rawKeyLength: ED25519_KEY_BYTES }],
]);
