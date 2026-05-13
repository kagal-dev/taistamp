import { describe, expect, it } from 'vitest';

import { asEd25519Seed, newKeyPair } from '../key';
import { encodeBase64 } from '../utils';

const testSeed = new Uint8Array(32).fill(7);
const testB64 = encodeBase64(testSeed);

describe('asEd25519Seed', () => {
  describe('with bytes input', () => {
    it('returns a Uint8Array byte-equal to the input', () => {
      const seed = asEd25519Seed(testSeed);
      expect(seed).toBeInstanceOf(Uint8Array);
      expect(seed).toHaveLength(32);
      expect(seed).toEqual(testSeed);
    });

    it('defensive-copies the input', () => {
      const mutable = new Uint8Array(testSeed);
      const seed = asEd25519Seed(mutable);
      mutable[0] = 0xFF;
      expect(seed[0]).toBe(7);
    });

    it('throws unprefixed length error when no context is supplied', () => {
      expect(() => asEd25519Seed(new Uint8Array(16)))
        .toThrow(/^expected 32-byte seed, got 16$/);
      expect(() => asEd25519Seed(new Uint8Array(33)))
        .toThrow(/^expected 32-byte seed, got 33$/);
    });

    it('uses the supplied context as the error prefix', () => {
      expect(() => asEd25519Seed(new Uint8Array(16), 'myConfig'))
        .toThrow(/^myConfig: expected 32-byte seed, got 16$/);
    });
  });

  describe('with base64 input', () => {
    it('decodes a 32-byte standard base64 seed', () => {
      expect(asEd25519Seed(testB64)).toEqual(testSeed);
    });

    it('accepts URL-safe base64', () => {
      const seed = new Uint8Array(32).fill(0xFF);
      const standard = encodeBase64(seed);
      const urlSafe = standard.replaceAll('+', '-').replaceAll('/', '_');
      expect(urlSafe).not.toBe(standard);
      expect(asEd25519Seed(urlSafe)).toEqual(seed);
    });

    it('throws unprefixed decode error when no context is supplied', () => {
      expect(() => asEd25519Seed('!!!not-base64!!!'))
        .toThrow(/^invalid base64$/);
    });

    it('throws unprefixed length error when no context is supplied', () => {
      const shortB64 = encodeBase64(new Uint8Array(16));
      expect(() => asEd25519Seed(shortB64))
        .toThrow(/^expected 32-byte seed, got 16$/);
    });

    it('threads the supplied context through to the decode error', () => {
      expect(() => asEd25519Seed('!!!not-base64!!!', 'myConfig'))
        .toThrow(/^myConfig: invalid base64$/);
    });

    it('uses the supplied context on the wrong-length error', () => {
      const shortB64 = encodeBase64(new Uint8Array(16));
      expect(() => asEd25519Seed(shortB64, 'myConfig'))
        .toThrow(/^myConfig: expected 32-byte seed, got 16$/);
    });

    it('preserves the atob rejection as cause on decode error', () => {
      let caught: TypeError | undefined;
      try {
        asEd25519Seed('!!!not-base64!!!');
      } catch (error) {
        caught = error as TypeError;
      }
      expect(caught).toBeInstanceOf(TypeError);
      expect(caught?.cause).toBeDefined();
    });
  });
});

describe('newKeyPair', () => {
  describe('with bytes input', () => {
    it('returns the seed as a Uint8Array, byte-equal to the input', async () => {
      const { privateKey } = await newKeyPair(testSeed);
      expect(privateKey).toBeInstanceOf(Uint8Array);
      expect(privateKey).toHaveLength(32);
      expect(privateKey).toEqual(testSeed);
    });

    it('returns a defensive copy of the input seed', async () => {
      const mutable = new Uint8Array(testSeed);
      const { privateKey } = await newKeyPair(mutable);
      mutable[0] = 0xFF;
      expect(privateKey[0]).toBe(7);
    });

    it('returns a verify-only public and a sign-only non-extractable signKey', async () => {
      const { publicKey, signKey } = await newKeyPair(testSeed);
      expect(signKey.algorithm.name).toBe('Ed25519');
      expect(signKey.extractable).toBe(false);
      expect(signKey.usages).toEqual(['sign']);
      expect(publicKey.algorithm.name).toBe('Ed25519');
      expect(publicKey.extractable).toBe(true);
      expect(publicKey.usages).toEqual(['verify']);
    });

    it('signs with the signKey and verifies with the publicKey', async () => {
      const { publicKey, signKey } = await newKeyPair(testSeed);
      const message = new TextEncoder().encode('keypair-round-trip');
      const signature = await crypto.subtle.sign('Ed25519', signKey, message);
      expect(
        await crypto.subtle.verify('Ed25519', publicKey, signature, message),
      ).toBe(true);
    });

    it('rejects a seed that is not 32 bytes', async () => {
      await expect(newKeyPair(new Uint8Array(16)))
        .rejects.toThrow(/^newKeyPair: expected 32-byte seed, got 16$/);
      await expect(newKeyPair(new Uint8Array(33)))
        .rejects.toThrow(/^newKeyPair: expected 32-byte seed, got 33$/);
    });

    it('uses the supplied context as the error prefix', async () => {
      await expect(newKeyPair(new Uint8Array(16), 'myConfig'))
        .rejects.toThrow(/^myConfig: expected 32-byte seed, got 16$/);
    });
  });

  describe('with base64 input', () => {
    it('produces the same triple as the raw-seed path', async () => {
      const fromB64 = await newKeyPair(testB64);
      const fromSeed = await newKeyPair(testSeed);
      expect(fromB64.privateKey).toEqual(fromSeed.privateKey);

      const bytesFromB64 = new Uint8Array(
        await crypto.subtle.exportKey('raw', fromB64.publicKey),
      );
      const bytesFromSeed = new Uint8Array(
        await crypto.subtle.exportKey('raw', fromSeed.publicKey),
      );
      expect(bytesFromB64).toEqual(bytesFromSeed);

      const message = new TextEncoder().encode('base64-round-trip');
      const signature = await crypto.subtle.sign('Ed25519', fromB64.signKey, message);
      expect(
        await crypto.subtle.verify('Ed25519', fromB64.publicKey, signature, message),
      ).toBe(true);
    });

    it('accepts URL-safe base64', async () => {
      const seed = new Uint8Array(32).fill(0xFF);
      const standard = encodeBase64(seed);
      const urlSafe = standard.replaceAll('+', '-').replaceAll('/', '_');
      expect(urlSafe).not.toBe(standard);

      const { signKey } = await newKeyPair(urlSafe);
      expect(signKey.algorithm.name).toBe('Ed25519');
    });

    it('rejects a decoded seed that is not 32 bytes', async () => {
      const shortB64 = encodeBase64(new Uint8Array(16));
      await expect(newKeyPair(shortB64))
        .rejects.toThrow(/^newKeyPair: expected 32-byte seed, got 16$/);
    });

    it('rejects invalid base64 input', async () => {
      await expect(newKeyPair('!!!not-base64!!!'))
        .rejects.toThrow(/^newKeyPair: invalid base64$/);
    });

    it('threads the supplied context through to the decode error', async () => {
      await expect(newKeyPair('!!!not-base64!!!', 'myConfig'))
        .rejects.toThrow(/^myConfig: invalid base64$/);
    });
  });

  describe('without input', () => {
    it('generates a fresh key-pair when called with no argument', async () => {
      const { privateKey, publicKey, signKey } = await newKeyPair();
      expect(privateKey).toBeInstanceOf(Uint8Array);
      expect(privateKey).toHaveLength(32);
      expect(publicKey.algorithm.name).toBe('Ed25519');
      expect(publicKey.extractable).toBe(true);
      expect(signKey.algorithm.name).toBe('Ed25519');
      expect(signKey.extractable).toBe(false);
    });

    it('generates a fresh key-pair when called with explicit undefined', async () => {
      const { privateKey } = await newKeyPair(undefined);
      expect(privateKey).toBeInstanceOf(Uint8Array);
      expect(privateKey).toHaveLength(32);
    });

    it('produces distinct key-pairs across two seedless calls', async () => {
      const a = await newKeyPair();
      const b = await newKeyPair();
      expect(a.privateKey).not.toEqual(b.privateKey);
      const pubA = new Uint8Array(
        await crypto.subtle.exportKey('raw', a.publicKey),
      );
      const pubB = new Uint8Array(
        await crypto.subtle.exportKey('raw', b.publicKey),
      );
      expect(pubA).not.toEqual(pubB);
    });

    it('signs and verifies with a fresh seedless key-pair', async () => {
      const { publicKey, signKey } = await newKeyPair();
      const message = new TextEncoder().encode('seedless-round-trip');
      const signature = await crypto.subtle.sign('Ed25519', signKey, message);
      expect(
        await crypto.subtle.verify('Ed25519', publicKey, signature, message),
      ).toBe(true);
    });
  });
});
