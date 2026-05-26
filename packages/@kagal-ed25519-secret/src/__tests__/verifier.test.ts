import { describe, expect, it } from 'vitest';

import { encodeBase64 } from '../utils';
import { importVerifyKey, newVerifier } from '../verifier';

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

describe('importVerifyKey', () => {
  it('imports a raw Ed25519 public key (canonical case)', async () => {
    const { publicKey } = await newKeypair();
    const raw = new Uint8Array(
      await crypto.subtle.exportKey('raw', publicKey),
    );
    const imported = await importVerifyKey('Ed25519', raw);
    expect(imported.algorithm.name).toBe('Ed25519');
    expect(imported.type).toBe('public');
    expect(imported.extractable).toBe(true);
    expect(imported.usages).toEqual(['verify']);
  });

  it('accepts a lowercase algorithm name (DKIM `k=ed25519`)', async () => {
    const { publicKey } = await newKeypair();
    const raw = new Uint8Array(
      await crypto.subtle.exportKey('raw', publicKey),
    );
    const imported = await importVerifyKey('ed25519', raw);
    expect(imported.algorithm.name).toBe('Ed25519');
  });

  it('accepts an upper-case algorithm name', async () => {
    const { publicKey } = await newKeypair();
    const raw = new Uint8Array(
      await crypto.subtle.exportKey('raw', publicKey),
    );
    const imported = await importVerifyKey('ED25519', raw);
    expect(imported.algorithm.name).toBe('Ed25519');
  });

  it('accepts base64-encoded key bytes', async () => {
    const { publicKey } = await newKeypair();
    const raw = new Uint8Array(
      await crypto.subtle.exportKey('raw', publicKey),
    );
    const b64 = encodeBase64(raw);
    const imported = await importVerifyKey('Ed25519', b64);
    expect(imported.algorithm.name).toBe('Ed25519');
  });

  it('round-trips through newVerifier and verifies a signature', async () => {
    const { privateKey, publicKey } = await newKeypair();
    const raw = new Uint8Array(
      await crypto.subtle.exportKey('raw', publicKey),
    );
    const imported = await importVerifyKey('ed25519', raw);
    const verifier = newVerifier(imported);
    const message = new TextEncoder().encode('round-trip');
    const signature = await crypto.subtle.sign(
      'Ed25519', privateKey, message,
    );
    expect(await verifier.verify(signature, message)).toBe(true);
  });

  it('rejects an unsupported algorithm, preserving casing', async () => {
    await expect(importVerifyKey('RSA-PSS', new Uint8Array(32)))
      .rejects.toThrow(/^unsupported algorithm: RSA-PSS$/);
  });

  it('rejects \'rsa\' (the DKIM `k=` default fallthrough)', async () => {
    await expect(importVerifyKey('rsa', new Uint8Array(32)))
      .rejects.toThrow(/^unsupported algorithm: rsa$/);
  });

  it('rejects a wrong-length key', async () => {
    await expect(importVerifyKey('Ed25519', new Uint8Array(16)))
      .rejects.toThrow(/^expected 32-byte Ed25519 key, got 16$/);
  });

  it('rejects undecodable base64', async () => {
    await expect(importVerifyKey('Ed25519', '!!!not-base64!!!'))
      .rejects.toThrow(/^invalid base64$/);
  });

  it('prepends the context prefix on the algorithm error', async () => {
    await expect(importVerifyKey('RSA-PSS', new Uint8Array(32), 'myFn'))
      .rejects.toThrow(/^myFn: unsupported algorithm: RSA-PSS$/);
  });

  it('prepends the context prefix on the length error', async () => {
    await expect(importVerifyKey('Ed25519', new Uint8Array(16), 'myFn'))
      .rejects.toThrow(/^myFn: expected 32-byte Ed25519 key, got 16$/);
  });

  it('prepends the context prefix on the base64 error', async () => {
    await expect(importVerifyKey('Ed25519', '!!!not-base64!!!', 'myFn'))
      .rejects.toThrow(/^myFn: invalid base64$/);
  });

  it('treats an empty context as no prefix on the algorithm error', async () => {
    await expect(importVerifyKey('RSA-PSS', new Uint8Array(32), ''))
      .rejects.toThrow(/^unsupported algorithm: RSA-PSS$/);
  });
});
