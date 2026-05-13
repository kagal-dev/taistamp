// cspell:words AAEC

import { describe, expect, it } from 'vitest';

import { asBytes, decodeBase64, encodeBase64, getRandom } from '../utils';

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
