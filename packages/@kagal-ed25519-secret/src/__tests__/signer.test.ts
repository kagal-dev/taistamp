import { describe, expect, it } from 'vitest';

import { newSigner, type Signer } from '../signer';

const newKeypair = async (): Promise<CryptoKeyPair> =>
  await crypto.subtle.generateKey(
    'Ed25519',
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;

describe('newSigner', () => {
  it('produces a verifiable 64-byte signature', async () => {
    const { privateKey, publicKey } = await newKeypair();
    const signer: Signer = newSigner(privateKey);
    const message = new TextEncoder().encode('hello world');

    const signature = await signer.sign(message);
    expect(signature.byteLength).toBe(64);

    const valid = await crypto.subtle.verify(
      'Ed25519',
      publicKey,
      signature,
      message,
    );
    expect(valid).toBe(true);
  });

  it('does not verify against a tampered message', async () => {
    const { privateKey, publicKey } = await newKeypair();
    const signer = newSigner(privateKey);
    const message = new TextEncoder().encode('original');

    const signature = await signer.sign(message);
    const tampered = new TextEncoder().encode('tampered');

    const valid = await crypto.subtle.verify(
      'Ed25519',
      publicKey,
      signature,
      tampered,
    );
    expect(valid).toBe(false);
  });

  it('accepts a raw ArrayBuffer input', async () => {
    const { privateKey, publicKey } = await newKeypair();
    const signer = newSigner(privateKey);
    const buffer = new TextEncoder()
      .encode('buffer-source-test').buffer as ArrayBuffer;

    const signature = await signer.sign(buffer);
    const valid = await crypto.subtle.verify(
      'Ed25519',
      publicKey,
      signature,
      buffer,
    );
    expect(valid).toBe(true);
  });

  it('produces deterministic output for the same input (RFC 8032)', async () => {
    const { privateKey } = await newKeypair();
    const signer = newSigner(privateKey);
    const message = new TextEncoder().encode('same input');

    const a = new Uint8Array(await signer.sign(message));
    const b = new Uint8Array(await signer.sign(message));

    expect(a).toEqual(b);
  });

  it('rejects a non-Ed25519 key', async () => {
    const { privateKey } = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    ) as CryptoKeyPair;
    expect(() => newSigner(privateKey))
      .toThrow(/^expected Ed25519 key, got ECDSA$/);
  });

  it('rejects a key without sign usage', async () => {
    const { publicKey } = await newKeypair();
    expect(() => newSigner(publicKey))
      .toThrow(/^expected sign usage, got \[verify\]$/);
  });

  it('prepends the context prefix on the algorithm error', async () => {
    const { privateKey } = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    ) as CryptoKeyPair;
    expect(() => newSigner(privateKey, 'myFn'))
      .toThrow(/^myFn: expected Ed25519 key, got ECDSA$/);
  });

  it('prepends the context prefix on the usage error', async () => {
    const { publicKey } = await newKeypair();
    expect(() => newSigner(publicKey, 'myFn'))
      .toThrow(/^myFn: expected sign usage, got \[verify\]$/);
  });
});
