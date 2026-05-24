import { describe, expect, it } from 'vitest';

import { newVerifier } from '../verifier';

const newKeypair = async (): Promise<CryptoKeyPair> =>
  await crypto.subtle.generateKey(
    'Ed25519',
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;

describe('newVerifier', () => {
  it('returns true for a valid signature', async () => {
    const { privateKey, publicKey } = await newKeypair();
    const verifier = newVerifier(publicKey);
    const message = new TextEncoder().encode('hello world');
    const signature = await crypto.subtle.sign('Ed25519', privateKey, message);

    expect(await verifier.verify(signature, message)).toBe(true);
  });

  it('returns false for a tampered message', async () => {
    const { privateKey, publicKey } = await newKeypair();
    const verifier = newVerifier(publicKey);
    const message = new TextEncoder().encode('original');
    const signature = await crypto.subtle.sign('Ed25519', privateKey, message);
    const tampered = new TextEncoder().encode('tampered');

    expect(await verifier.verify(signature, tampered)).toBe(false);
  });

  it('returns false for a signature from a different key', async () => {
    const { publicKey } = await newKeypair();
    const { privateKey: otherPrivate } = await newKeypair();
    const verifier = newVerifier(publicKey);
    const message = new TextEncoder().encode('payload');
    const signature = await crypto.subtle.sign('Ed25519', otherPrivate, message);

    expect(await verifier.verify(signature, message)).toBe(false);
  });

  it('accepts a string message (UTF-8)', async () => {
    const { privateKey, publicKey } = await newKeypair();
    const verifier = newVerifier(publicKey);
    const signature = await crypto.subtle.sign(
      'Ed25519',
      privateKey,
      new TextEncoder().encode('hello world'),
    );

    expect(await verifier.verify(signature, 'hello world')).toBe(true);
  });

  it('accepts a raw ArrayBuffer input', async () => {
    const { privateKey, publicKey } = await newKeypair();
    const verifier = newVerifier(publicKey);
    const buffer = new TextEncoder()
      .encode('buffer-source-test').buffer as ArrayBuffer;
    const signature = await crypto.subtle.sign('Ed25519', privateKey, buffer);

    expect(await verifier.verify(signature, buffer)).toBe(true);
  });

  it('rejects an unsupported algorithm', async () => {
    const { publicKey } = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    ) as CryptoKeyPair;
    expect(() => newVerifier(publicKey))
      .toThrow(/^unsupported algorithm: ECDSA$/);
  });

  it('rejects a key without verify usage', async () => {
    const { privateKey } = await newKeypair();
    expect(() => newVerifier(privateKey))
      .toThrow(/^expected verify usage, got \[sign\]$/);
  });

  it('prepends the context prefix on the algorithm error', async () => {
    const { publicKey } = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    ) as CryptoKeyPair;
    expect(() => newVerifier(publicKey, 'myFn'))
      .toThrow(/^myFn: unsupported algorithm: ECDSA$/);
  });

  it('prepends the context prefix on the usage error', async () => {
    const { privateKey } = await newKeypair();
    expect(() => newVerifier(privateKey, 'myFn'))
      .toThrow(/^myFn: expected verify usage, got \[sign\]$/);
  });

  it('treats an empty context as no prefix on the algorithm error', async () => {
    const { publicKey } = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    ) as CryptoKeyPair;
    expect(() => newVerifier(publicKey, ''))
      .toThrow(/^unsupported algorithm: ECDSA$/);
  });
});
