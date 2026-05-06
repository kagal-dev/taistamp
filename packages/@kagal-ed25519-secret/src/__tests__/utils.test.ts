// cspell:words AAEC

import { describe, expect, it } from 'vitest';

import { decodeBase64, encodeBase64 } from '../utils';

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
