import { describe, expect, it } from 'vitest';

import { newSecret, parseSecretsToKeys, parseSecretToKey } from '../secret';
import { decodeBase64, encodeBase64 } from '../utils';

const testSeed = new Uint8Array(32).fill(7);
const testB64 = encodeBase64(testSeed);

describe('newSecret', () => {
  it('prefixes the secret with the selector and a colon', () => {
    expect(newSecret('s1').startsWith('s1:')).toBe(true);
  });

  it('encodes a 32-byte seed in the base64 portion', () => {
    const b64 = newSecret('s1').slice('s1:'.length);
    expect(decodeBase64(b64)).toHaveLength(32);
  });

  it('mints a fresh seed on each call', () => {
    expect(newSecret('s1')).not.toBe(newSecret('s1'));
  });

  it('round-trips through parseSecretToKey', async () => {
    const { selector, privateKey } = await parseSecretToKey(newSecret('s1'));
    expect(selector).toBe('s1');
    expect(privateKey).toHaveLength(32);
  });

  it('rejects a selector that fails SELECTOR_PATTERN', () => {
    expect(() => newSecret('-bad')).toThrow(TypeError);
  });

  it('uses the default context as the error prefix', () => {
    expect(() => newSecret('-bad'))
      .toThrow(/^newSecret: selector must match/);
  });

  it('uses the supplied context as the error prefix', () => {
    expect(() => newSecret('-bad', 'myMint'))
      .toThrow(/^myMint: selector must match/);
  });
});

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

  it('surfaces a publicJWK carrying the selector as kid', async () => {
    const { publicJWK } = await parseSecretToKey(`s1:${testB64}`);
    expect(publicJWK.kty).toBe('OKP');
    expect(publicJWK.crv).toBe('Ed25519');
    expect(publicJWK.use).toBe('sig');
    expect(publicJWK.alg).toBe('EdDSA');
    expect(publicJWK.kid).toBe('s1');
  });

  it('signs with the signer and verifies under the publicKey', async () => {
    const { publicKey, signer } = await parseSecretToKey(`s1:${testB64}`);
    const message = new TextEncoder().encode('parsed-round-trip');
    const signature = await signer.sign(message);
    expect(
      await crypto.subtle.verify('Ed25519', publicKey, signature, message),
    ).toBe(true);
  });

  it('round-trips a signature through signer and verifier', async () => {
    const { signer, verifier } = await parseSecretToKey(`s1:${testB64}`);
    const signature = await signer.sign('config-round-trip');
    expect(await verifier.verify(signature, 'config-round-trip')).toBe(true);
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

describe('parseSecretsToKeys', () => {
  describe('input shape', () => {
    it('returns an empty array for an empty string', async () => {
      expect(await parseSecretsToKeys('')).toEqual([]);
    });

    it('returns an empty array for whitespace-only input', async () => {
      expect(await parseSecretsToKeys('   \n\t  ')).toEqual([]);
    });

    it('returns an empty array for punctuation-only input', async () => {
      expect(await parseSecretsToKeys(',;|.\n')).toEqual([]);
    });

    it('parses a single secret', async () => {
      const keys = await parseSecretsToKeys(`s1:${testB64}`);
      expect(keys).toHaveLength(1);
      expect(keys[0].selector).toBe('s1');
    });
  });

  describe('delimiters', () => {
    it('splits on whitespace (newline, tab, space)', async () => {
      const input = `s1:${testB64}\ts2:${testB64} s3:${testB64}\ns4:${testB64}`;
      const keys = await parseSecretsToKeys(input);
      expect(keys.map((k) => k.selector)).toEqual(['s1', 's2', 's3', 's4']);
    });

    it('splits on comma-separated secrets', async () => {
      const input = `s1:${testB64},s2:${testB64}`;
      const keys = await parseSecretsToKeys(input);
      expect(keys.map((k) => k.selector)).toEqual(['s1', 's2']);
    });

    it('splits on mixed whitespace and punctuation', async () => {
      const input = `s1:${testB64}, s2:${testB64};\ts3:${testB64}\n`;
      const keys = await parseSecretsToKeys(input);
      expect(keys.map((k) => k.selector)).toEqual(['s1', 's2', 's3']);
    });

    it('drops empty fragments from leading, trailing, and consecutive delimiters', async () => {
      const input = `,,,s1:${testB64},,,s2:${testB64},,,`;
      const keys = await parseSecretsToKeys(input);
      expect(keys.map((k) => k.selector)).toEqual(['s1', 's2']);
    });

    it('preserves input order', async () => {
      const input = `c:${testB64} a:${testB64} b:${testB64}`;
      const keys = await parseSecretsToKeys(input);
      expect(keys.map((k) => k.selector)).toEqual(['c', 'a', 'b']);
    });
  });

  describe('strict mode (default)', () => {
    it('returns all entries when every entry parses', async () => {
      const input = `a:${testB64} b:${testB64}`;
      const keys = await parseSecretsToKeys(input);
      expect(keys.map((k) => k.selector)).toEqual(['a', 'b']);
    });

    it('throws on the malformed entry, naming the 1-based index', async () => {
      const input = `s1:${testB64} bogus s3:${testB64}`;
      await expect(parseSecretsToKeys(input))
        .rejects.toThrow(/^parseSecretsToKeys: secret 2: /);
    });

    it('threads the supplied context through to the per-entry error', async () => {
      const input = `s1:${testB64} bogus`;
      await expect(parseSecretsToKeys(input, true, 'myConfig'))
        .rejects.toThrow(/^myConfig: secret 2: /);
    });

    it('explicit strict=true matches the default behaviour', async () => {
      const input = `s1:${testB64} bogus`;
      await expect(parseSecretsToKeys(input, true))
        .rejects.toThrow(/^parseSecretsToKeys: secret 2: /);
    });

    it('treats `:` alone as a single token and identifies it by index', async () => {
      const input = `s1:${testB64} : s3:${testB64}`;
      await expect(parseSecretsToKeys(input))
        .rejects.toThrow(/^parseSecretsToKeys: secret 2: .+ empty selector/);
    });
  });

  describe('lenient mode (strict: false)', () => {
    it('skips malformed entries and preserves order among the successes', async () => {
      const input = `s1:${testB64} bogus s3:${testB64}`;
      const keys = await parseSecretsToKeys(input, false);
      expect(keys.map((k) => k.selector)).toEqual(['s1', 's3']);
    });

    it('returns an empty array when every entry fails', async () => {
      const keys = await parseSecretsToKeys('bogus1 bogus2 bogus3', false);
      expect(keys).toEqual([]);
    });

    it('returns all entries when no entry fails', async () => {
      const input = `a:${testB64} b:${testB64}`;
      const keys = await parseSecretsToKeys(input, false);
      expect(keys.map((k) => k.selector)).toEqual(['a', 'b']);
    });

    it('skips entries regardless of which check rejects them', async () => {
      const shortB64 = encodeBase64(new Uint8Array(16).fill(7));
      const input = [
        `s1:${testB64}`, // OK
        'bogus', // no separator
        'a:b:c', // too many colons
        ':', // empty selector
        `:${testB64}`, // empty selector
        's:', // empty base64
        `s:${shortB64}`, // wrong seed length
        `-bad:${testB64}`, // bad selector pattern
        `s9:${testB64}`, // OK
      ].join(' ');
      const keys = await parseSecretsToKeys(input, false);
      expect(keys.map((k) => k.selector)).toEqual(['s1', 's9']);
    });
  });
});
