import { describe, expect, it } from 'vitest';

import { newEd25519Signer } from '../signer';

describe('newEd25519Signer', () => {
  it('produces a 64-byte signature that verifies under the public key', async () => {
    const { privateKey, publicKey } = await crypto.subtle.generateKey(
      'Ed25519',
      true,
      ['sign', 'verify'],
    ) as CryptoKeyPair;

    const signer = newEd25519Signer(privateKey);
    const message = new TextEncoder().encode('hello');
    const signature = await signer.sign(message);

    expect(signature).toBeInstanceOf(ArrayBuffer);
    expect(signature.byteLength).toBe(64);

    const valid = await crypto.subtle.verify(
      'Ed25519',
      publicKey,
      signature,
      message,
    );
    expect(valid).toBe(true);
  });

  it('produces deterministic signatures for the same input', async () => {
    const { privateKey } = await crypto.subtle.generateKey(
      'Ed25519',
      true,
      ['sign', 'verify'],
    ) as CryptoKeyPair;

    const signer = newEd25519Signer(privateKey);
    const message = new TextEncoder().encode('same input');

    const a = new Uint8Array(await signer.sign(message));
    const b = new Uint8Array(await signer.sign(message));

    expect(a).toEqual(b);
  });
});
