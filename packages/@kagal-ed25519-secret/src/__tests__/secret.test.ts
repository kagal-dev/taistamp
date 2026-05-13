import { describe, expect, it } from 'vitest';

import { parseSecretToKey } from '../secret';
import { encodeBase64 } from '../utils';

const testSeed = new Uint8Array(32).fill(7);
const testB64 = encodeBase64(testSeed);

describe('parseSecretToKey', () => {
  it('returns the selector unchanged', async () => {
    const { selector } = await parseSecretToKey(`s1:${testB64}`);
    expect(selector).toBe('s1');
  });

  it('returns the parsed seed as a Uint8Array', async () => {
    const { privateKey } = await parseSecretToKey(`s1:${testB64}`);
    expect(privateKey).toBeInstanceOf(Uint8Array);
    expect(privateKey).toEqual(testSeed);
  });

  it('returns a non-extractable Ed25519 sign-only signKey', async () => {
    const { signKey } = await parseSecretToKey(`s1:${testB64}`);
    expect(signKey.type).toBe('private');
    expect(signKey.algorithm.name).toBe('Ed25519');
    expect(signKey.extractable).toBe(false);
    expect(signKey.usages).toEqual(['sign']);
  });

  it('returns an extractable Ed25519 verify-only public key', async () => {
    const { publicKey } = await parseSecretToKey(`s1:${testB64}`);
    expect(publicKey.type).toBe('public');
    expect(publicKey.algorithm.name).toBe('Ed25519');
    expect(publicKey.extractable).toBe(true);
    expect(publicKey.usages).toEqual(['verify']);
  });

  it('signs with the signer and verifies under the publicKey', async () => {
    const { publicKey, signer } = await parseSecretToKey(`s1:${testB64}`);
    const message = new TextEncoder().encode('parsed-round-trip');
    const signature = await signer.sign(message);
    expect(
      await crypto.subtle.verify('Ed25519', publicKey, signature, message),
    ).toBe(true);
  });

  it('accepts URL-safe base64 (- and _ in place of + and /)', async () => {
    const seed = new Uint8Array(32).fill(0xFF);
    const standard = encodeBase64(seed);
    const urlSafe = standard.replaceAll('+', '-').replaceAll('/', '_');
    expect(urlSafe).not.toBe(standard);

    const { signKey } = await parseSecretToKey(`s1:${urlSafe}`);
    expect(signKey.algorithm.name).toBe('Ed25519');
  });

  it('uses the supplied context as the error prefix', async () => {
    await expect(parseSecretToKey('', 'myConfig'))
      .rejects.toThrow(/^myConfig: expected "selector:base64", got no separator$/);
  });

  describe('format errors', () => {
    it('throws TypeError', async () => {
      await expect(parseSecretToKey(''))
        .rejects.toThrow(TypeError);
    });

    it('rejects an empty string with "no separator"', async () => {
      await expect(parseSecretToKey(''))
        .rejects.toThrow(/^parseSecretToKey: expected "selector:base64", got no separator$/);
    });

    it('rejects a string without a colon with "no separator"', async () => {
      await expect(parseSecretToKey('selector-only'))
        .rejects.toThrow(/^parseSecretToKey: expected "selector:base64", got no separator$/);
    });

    it('rejects more than one colon with the count', async () => {
      await expect(parseSecretToKey(`a:${testB64}:extra`))
        .rejects.toThrow(/^parseSecretToKey: expected "selector:base64", got 3 colon-separated parts$/);
    });

    it('rejects an empty selector', async () => {
      await expect(parseSecretToKey(`:${testB64}`))
        .rejects.toThrow(/^parseSecretToKey: expected "selector:base64", got empty selector$/);
    });

    it('rejects an empty base64 portion', async () => {
      await expect(parseSecretToKey('selector:'))
        .rejects.toThrow(/^parseSecretToKey: expected "selector:base64", got empty base64$/);
    });
  });

  it('rejects a key that is not 32 bytes', async () => {
    const shortB64 = encodeBase64(new Uint8Array(16).fill(7));
    await expect(parseSecretToKey(`s1:${shortB64}`))
      .rejects.toThrow(/parseSecretToKey: expected 32-byte seed, got 16/);
  });

  it('rejects invalid base64 in the key portion', async () => {
    await expect(parseSecretToKey('s1:!!!not-base64!!!'))
      .rejects.toThrow(/^parseSecretToKey: invalid base64$/);
  });

  it('rejects a selector that fails SELECTOR_PATTERN', async () => {
    await expect(parseSecretToKey(`-bad:${testB64}`))
      .rejects.toThrow(/parseSecretToKey: selector must match/);
  });
});
