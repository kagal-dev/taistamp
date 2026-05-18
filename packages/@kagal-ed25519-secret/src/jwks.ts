import type { Ed25519PublicJWK } from './key';

/**
 * JWK Set (RFC 7517 §5) containing Ed25519 public
 * JWKs only — the shape served by a `jwks.json`
 * endpoint when every key is Ed25519. Values returned
 * by {@link makeJWKS} are `Object.freeze`d (the set
 * and its `keys` array); the `readonly` markers
 * reflect that runtime guarantee.
 */
export interface Ed25519JWKSet {
  readonly keys: readonly Ed25519PublicJWK[]
}

/**
 * Collect every entry's `publicJWK` into a JWK Set
 * shape (RFC 7517 §5) — `{ keys: [...] }`. Accepts a
 * single `KeyContext` (or any `{ publicJWK }`
 * container), an array (including empty), or
 * `undefined`; empty inputs yield `{ keys: [] }`.
 */
export const makeJWKS = <K extends { publicJWK: Ed25519PublicJWK }>(
  keys: K | K[] | undefined,
): Ed25519JWKSet => {
  const jwks: Ed25519PublicJWK[] =
    keys === undefined ?
      [] :
      (Array.isArray(keys) ?
        keys.map((k) => k.publicJWK) :
        [keys.publicJWK]);
  return Object.freeze({ keys: Object.freeze(jwks) });
};
