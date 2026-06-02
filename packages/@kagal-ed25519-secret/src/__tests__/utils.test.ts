// cspell:words AAEC

import { describe, expect, it } from 'vitest';

import {
  asBytes,
  decodeASCII,
  decodeBase64,
  encodeBase64,
  encodeKey,
  getRandom,
  splitFirst,
  splitLast,
} from '../utils';

describe('encodeBase64', () => {
  it('returns the empty string on empty input', () => {
    expect(encodeBase64(new Uint8Array(0))).toBe('');
  });

  it('emits two `=` of padding for a 1-byte input', () => {
    expect(encodeBase64(new Uint8Array([0xFF]))).toBe('/w==');
  });

  it('emits one `=` of padding for a 2-byte input', () => {
    expect(encodeBase64(new Uint8Array([0xFF, 0xFF]))).toBe('//8=');
  });

  it('emits no padding for a 3-byte input', () => {
    expect(encodeBase64(new Uint8Array([0, 1, 2]))).toBe('AAEC');
  });

  it('round-trips every byte value through decodeBase64', () => {
    const range = new Uint8Array(256);
    for (let i = 0; i < 256; i++) range[i] = i;
    expect(decodeBase64(encodeBase64(range))).toEqual(range);
  });

  it('emits only standard-alphabet characters (never `-` or `_`)', () => {
    // bytes that produce `+` and `/` in the standard alphabet
    const bytes = new Uint8Array([0xFB, 0xEF, 0xFF]);
    expect(encodeBase64(bytes)).toMatch(/^[\d+/=A-Za-z]*$/);
  });

  it('encodes a subarray view, not the underlying buffer', () => {
    const full = new Uint8Array([0, 1, 2, 3, 4, 5]);
    expect(encodeBase64(full.subarray(2, 5)))
      .toBe(encodeBase64(new Uint8Array([2, 3, 4])));
  });
});

describe('decodeBase64', () => {
  it('decodes standard base64', () => {
    expect(decodeBase64('AAEC')).toEqual(new Uint8Array([0, 1, 2]));
  });

  it('decodes URL-safe base64', () => {
    // standard '+/8=' (= [0xFB, 0xFF]) → URL-safe '-_8='
    expect(decodeBase64('-_8=')).toEqual(new Uint8Array([0xFB, 0xFF]));
  });

  it('accepts unpadded URL-safe input', () => {
    // standard '+/8=' stripped of padding → URL-safe '-_8'
    expect(decodeBase64('-_8')).toEqual(new Uint8Array([0xFB, 0xFF]));
  });

  it('throws TypeError on input atob rejects', () => {
    expect(() => decodeBase64('!!!not-base64!!!')).toThrow(TypeError);
  });

  it('omits the prefix when no context is given', () => {
    expect(() => decodeBase64('!!!not-base64!!!'))
      .toThrow(/^invalid base64$/);
  });

  it('prepends the context prefix when given', () => {
    expect(() => decodeBase64('!!!not-base64!!!', 'myConfig'))
      .toThrow(/^myConfig: invalid base64$/);
  });

  it('treats an empty context as no prefix', () => {
    expect(() => decodeBase64('!!!not-base64!!!', ''))
      .toThrow(/^invalid base64$/);
  });

  it('preserves the underlying rejection as `cause`', () => {
    try {
      decodeBase64('!!!not-base64!!!');
      expect.fail('expected decodeBase64 to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(TypeError);
      expect((error as TypeError).cause).toBeDefined();
    }
  });
});

describe('decodeASCII', () => {
  it('returns the empty string on empty input', () => {
    expect(decodeASCII(new Uint8Array(0))).toBe('');
  });

  it('decodes printable ASCII bytes', () => {
    // '@a1' — '@' (0x40), 'a' (0x61), '1' (0x31)
    expect(decodeASCII(new Uint8Array([0x40, 0x61, 0x31]))).toBe('@a1');
  });

  it('accepts the 0x00 and 0x7F boundaries', () => {
    // NUL and DEL are valid 7-bit ASCII, not rejected
    const decoded = decodeASCII(new Uint8Array([0x00, 0x7F]));
    expect(decoded).toHaveLength(2);
    // charCodeAt reads the raw byte value at each index
    /* eslint-disable unicorn/prefer-code-point */
    expect(decoded.charCodeAt(0)).toBe(0x00);
    expect(decoded.charCodeAt(1)).toBe(0x7F);
    /* eslint-enable unicorn/prefer-code-point */
  });

  it('decodes a subarray view, not the underlying buffer', () => {
    const full = new Uint8Array([0x78, 0x40, 0x61, 0x31, 0x78]);
    expect(decodeASCII(full.subarray(1, 4))).toBe('@a1');
  });

  it('rejects a 0x80 byte', () => {
    expect(() => decodeASCII(new Uint8Array([0x80])))
      .toThrow(/^expected 7-bit ASCII, got 0x80$/);
  });

  it('rejects a 0xFF byte', () => {
    expect(() => decodeASCII(new Uint8Array([0x41, 0xFF])))
      .toThrow(/^expected 7-bit ASCII, got 0xff$/);
  });

  it('prepends the context prefix when given', () => {
    expect(() => decodeASCII(new Uint8Array([0x80]), 'myConfig'))
      .toThrow(/^myConfig: expected 7-bit ASCII, got 0x80$/);
  });

  it('treats an empty context as no prefix', () => {
    expect(() => decodeASCII(new Uint8Array([0x80]), ''))
      .toThrow(/^expected 7-bit ASCII, got 0x80$/);
  });
});

const newEd25519Pair = () =>
  crypto.subtle.generateKey(
    { name: 'Ed25519' }, true, ['sign', 'verify'],
  ) as Promise<CryptoKeyPair>;

const nonExtractablePublicKey = async (): Promise<CryptoKey> => {
  const { publicKey } = await newEd25519Pair();
  const raw = await crypto.subtle.exportKey('raw', publicKey);
  return crypto.subtle.importKey(
    'raw', raw, { name: 'Ed25519' }, false, ['verify'],
  );
};

describe('encodeKey', () => {
  it('encodes an extractable Ed25519 public key', async () => {
    const { publicKey } = await newEd25519Pair();
    const encoded = await encodeKey(publicKey);
    expect(encoded).toMatch(/^[\d+/=A-Za-z]*$/);
    expect(decodeBase64(encoded)).toHaveLength(32);
  });

  it('round-trips through decodeBase64 + importKey raw', async () => {
    const { publicKey } = await newEd25519Pair();
    const encoded = await encodeKey(publicKey);
    const reimported = await crypto.subtle.importKey(
      'raw', decodeBase64(encoded),
      { name: 'Ed25519' }, true, ['verify'],
    );
    expect(await encodeKey(reimported)).toBe(encoded);
  });

  it('rejects an unsupported algorithm (HMAC)', async () => {
    const hmac = await crypto.subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256' }, true, ['sign'],
    );
    await expect(encodeKey(hmac as CryptoKey))
      .rejects.toThrow(TypeError);
  });

  it('rejects an unsupported algorithm (ECDSA P-256)', async () => {
    const { publicKey } = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, ['sign', 'verify'],
    ) as CryptoKeyPair;
    await expect(encodeKey(publicKey))
      .rejects.toThrow(/^unsupported algorithm: ECDSA$/);
  });

  it('rejects a private key', async () => {
    const { privateKey } = await newEd25519Pair();
    await expect(encodeKey(privateKey))
      .rejects.toThrow(/^expected public key, got private$/);
  });

  it('rejects a non-extractable public key', async () => {
    const key = await nonExtractablePublicKey();
    await expect(encodeKey(key))
      .rejects.toThrow(TypeError);
  });

  it('omits the prefix on an unsupported algorithm', async () => {
    const hmac = await crypto.subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256' }, true, ['sign'],
    );
    await expect(encodeKey(hmac as CryptoKey))
      .rejects.toThrow(/^unsupported algorithm: HMAC$/);
  });

  it('prepends the context prefix on an unsupported algorithm', async () => {
    const hmac = await crypto.subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256' }, true, ['sign'],
    );
    await expect(encodeKey(hmac as CryptoKey, 'myConfig'))
      .rejects.toThrow(/^myConfig: unsupported algorithm: HMAC$/);
  });

  it('treats an empty context as no prefix on an unsupported algorithm', async () => {
    const hmac = await crypto.subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256' }, true, ['sign'],
    );
    await expect(encodeKey(hmac as CryptoKey, ''))
      .rejects.toThrow(/^unsupported algorithm: HMAC$/);
  });

  it('omits the prefix on export failure', async () => {
    const key = await nonExtractablePublicKey();
    await expect(encodeKey(key))
      .rejects.toThrow(/^cannot export key as raw$/);
  });

  it('prepends the context prefix on export failure', async () => {
    const key = await nonExtractablePublicKey();
    await expect(encodeKey(key, 'myConfig'))
      .rejects.toThrow(/^myConfig: cannot export key as raw$/);
  });

  it('preserves the underlying rejection as `cause`', async () => {
    const key = await nonExtractablePublicKey();
    try {
      await encodeKey(key);
      expect.fail('expected encodeKey to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(TypeError);
      expect((error as TypeError).cause).toBeDefined();
    }
  });
});

describe('getRandom', () => {
  it('returns a Uint8Array of the requested length', () => {
    expect(getRandom(0)).toHaveLength(0);
    expect(getRandom(16)).toHaveLength(16);
    expect(getRandom(32)).toHaveLength(32);
  });

  it('produces distinct outputs across two calls', () => {
    expect(getRandom(32)).not.toEqual(getRandom(32));
  });

  it('rejects a negative length', () => {
    expect(() => getRandom(-1))
      .toThrow(/^expected non-negative integer length, got -1$/);
  });

  it('rejects a non-integer length', () => {
    expect(() => getRandom(1.5))
      .toThrow(/^expected non-negative integer length, got 1\.5$/);
  });

  it('rejects NaN', () => {
    expect(() => getRandom(Number.NaN))
      .toThrow(/^expected non-negative integer length, got NaN$/);
  });

  it('prepends the context prefix when given', () => {
    expect(() => getRandom(-1, 'myConfig'))
      .toThrow(/^myConfig: expected non-negative integer length, got -1$/);
  });

  it('treats an empty context as no prefix', () => {
    expect(() => getRandom(-1, ''))
      .toThrow(/^expected non-negative integer length, got -1$/);
  });
});

describe('asBytes', () => {
  it('defensive-copies a bytes input', () => {
    const mutable = new Uint8Array([1, 2, 3]);
    const copy = asBytes(mutable);
    mutable[0] = 0xFF;
    expect(copy[0]).toBe(1);
  });

  it('decodes a base64 string', () => {
    expect(asBytes('AAEC')).toEqual(new Uint8Array([0, 1, 2]));
  });

  it('threads context through to the decode error', () => {
    expect(() => asBytes('!!!not-base64!!!', 'myConfig'))
      .toThrow(/^myConfig: invalid base64$/);
  });

  it('omits the prefix when no context is given', () => {
    expect(() => asBytes('!!!not-base64!!!'))
      .toThrow(/^invalid base64$/);
  });

  it('preserves the underlying rejection as `cause`', () => {
    try {
      asBytes('!!!not-base64!!!');
      expect.fail('expected asBytes to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(TypeError);
      expect((error as TypeError).cause).toBeDefined();
    }
  });
});

describe('splitFirst', () => {
  it('returns { rest: [] } for undefined', () => {
    expect(splitFirst(undefined)).toEqual({ rest: [] });
  });

  it('returns { rest: [] } for an empty array', () => {
    expect(splitFirst([])).toEqual({ rest: [] });
  });

  it('returns { first, rest: [] } for a single non-array value', () => {
    expect(splitFirst('only')).toEqual({ first: 'only', rest: [] });
  });

  it('returns { first: 0, rest: [] } for 0', () => {
    expect(splitFirst(0)).toEqual({ first: 0, rest: [] });
  });

  it('returns { first: "", rest: [] } for an empty string', () => {
    expect(splitFirst('')).toEqual({ first: '', rest: [] });
  });

  it('returns { first: false, rest: [] } for false', () => {
    expect(splitFirst(false)).toEqual({ first: false, rest: [] });
  });

  it('returns { first: NaN, rest: [] } for NaN', () => {
    expect(splitFirst(Number.NaN)).toEqual({ first: Number.NaN, rest: [] });
  });

  it('returns { first, rest } for a non-empty array, preserving order', () => {
    expect(splitFirst(['a', 'b', 'c']))
      .toEqual({ first: 'a', rest: ['b', 'c'] });
  });

  it('returns { first, rest: [] } for a one-element array', () => {
    expect(splitFirst(['only'])).toEqual({ first: 'only', rest: [] });
  });
});

describe('splitLast', () => {
  it('returns { rest: [] } for undefined', () => {
    expect(splitLast(undefined)).toEqual({ rest: [] });
  });

  it('returns { rest: [] } for an empty array', () => {
    expect(splitLast([])).toEqual({ rest: [] });
  });

  it('returns { last, rest: [] } for a single non-array value', () => {
    expect(splitLast('only')).toEqual({ last: 'only', rest: [] });
  });

  it('returns { last: 0, rest: [] } for 0', () => {
    expect(splitLast(0)).toEqual({ last: 0, rest: [] });
  });

  it('returns { last: "", rest: [] } for an empty string', () => {
    expect(splitLast('')).toEqual({ last: '', rest: [] });
  });

  it('returns { last: false, rest: [] } for false', () => {
    expect(splitLast(false)).toEqual({ last: false, rest: [] });
  });

  it('returns { last: NaN, rest: [] } for NaN', () => {
    expect(splitLast(Number.NaN)).toEqual({ last: Number.NaN, rest: [] });
  });

  it('returns { last, rest } for a non-empty array, preserving order', () => {
    expect(splitLast(['a', 'b', 'c']))
      .toEqual({ last: 'c', rest: ['a', 'b'] });
  });

  it('returns { last, rest: [] } for a one-element array', () => {
    expect(splitLast(['only'])).toEqual({ last: 'only', rest: [] });
  });
});
