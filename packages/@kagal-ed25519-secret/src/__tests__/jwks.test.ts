import { describe, expect, it } from 'vitest';

import type { Ed25519PublicJWK } from '../key';
import { makeJWKS } from '../jwks';

// `x` reuses `kid` so each row's JWK is distinct in
// assertions; `makeJWKS` is a passthrough, so the
// literal `x` value (normally 43-char base64url)
// never matters.
const jwk = (kid: string): Ed25519PublicJWK => ({
  kty: 'OKP',
  crv: 'Ed25519',
  x: kid,
  use: 'sig',
  alg: 'EdDSA',
  kid,
});

describe('makeJWKS', () => {
  it('returns { keys: [] } for undefined', () => {
    expect(makeJWKS(undefined)).toEqual({ keys: [] });
  });

  it('returns { keys: [] } for an empty array', () => {
    expect(makeJWKS([])).toEqual({ keys: [] });
  });

  it('returns { keys: [jwk] } for a single container', () => {
    const j = jwk('s1');
    expect(makeJWKS({ publicJWK: j })).toEqual({ keys: [j] });
  });

  it('returns { keys } for a non-empty array, preserving order', () => {
    const a = jwk('a');
    const b = jwk('b');
    const c = jwk('c');
    expect(makeJWKS([
      { publicJWK: a },
      { publicJWK: b },
      { publicJWK: c },
    ])).toEqual({ keys: [a, b, c] });
  });

  it('returns { keys: [jwk] } for a one-element array', () => {
    const j = jwk('only');
    expect(makeJWKS([{ publicJWK: j }])).toEqual({ keys: [j] });
  });

  it('freezes the returned set and its keys array', () => {
    for (const jwks of [
      makeJWKS(undefined),
      makeJWKS([]),
      makeJWKS({ publicJWK: jwk('s1') }),
      makeJWKS([{ publicJWK: jwk('a') }, { publicJWK: jwk('b') }]),
    ]) {
      expect(Object.isFrozen(jwks)).toBe(true);
      expect(Object.isFrozen(jwks.keys)).toBe(true);
    }
  });
});
