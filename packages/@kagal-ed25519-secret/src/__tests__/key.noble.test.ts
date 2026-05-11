import * as ed from '@noble/ed25519';
import { describe, expect, it } from 'vitest';

import { newKeyPair } from '../key';

const testSeed = new Uint8Array(32).fill(7);

describe('newKeyPair (cross-impl framing)', () => {
  it('exports a raw public key matching @noble/ed25519 for the same seed', async () => {
    const { publicKey } = await newKeyPair(testSeed);
    const exported = new Uint8Array(
      await crypto.subtle.exportKey('raw', publicKey),
    );
    const noble = await ed.getPublicKeyAsync(testSeed);
    expect(exported).toEqual(noble);
  });

  it('produces signatures that verify under @noble/ed25519', async () => {
    const { signKey } = await newKeyPair(testSeed);
    const message = new TextEncoder().encode('webcrypto -> noble');
    const signature = new Uint8Array(
      await crypto.subtle.sign('Ed25519', signKey, message),
    );
    const noblePublic = await ed.getPublicKeyAsync(testSeed);
    expect(await ed.verifyAsync(signature, message, noblePublic)).toBe(true);
  });

  it('verifies signatures produced by @noble/ed25519 under the same seed', async () => {
    const { publicKey } = await newKeyPair(testSeed);
    const message = new TextEncoder().encode('noble -> webcrypto');
    const signature = new Uint8Array(await ed.signAsync(message, testSeed));
    expect(
      await crypto.subtle.verify('Ed25519', publicKey, signature, message),
    ).toBe(true);
  });
});
