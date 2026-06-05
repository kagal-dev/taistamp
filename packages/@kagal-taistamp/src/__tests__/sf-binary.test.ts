import { describe, expect, it } from 'vitest';

import {
  decodeSFBinary,
  encodeSFBinary,
  SF_BINARY_PATTERN,
} from '../utils';

describe('SF_BINARY_PATTERN', () => {
  it('accepts well-formed sf-binary items', () => {
    const accepted = [
      '::', // empty payload is valid sf-binary
      ':QQ==:', // 1 octet, two-char padding
      ':QUI=:', // 2 octets, one-char padding
      ':QUJD:', // 3 octets, unpadded
      ':QUJDRA==:', // 4 octets, two groups
      ':+/A=:', // `+` and `/` are standard-alphabet
    ];
    for (const value of accepted) {
      expect(SF_BINARY_PATTERN.test(value), value).toBe(true);
    }
  });

  it('rejects malformed or non-standard items', () => {
    // cspell:disable-next-line
    const group = 'QUJD'; // one valid base64 group
    const rejected = [
      '', // no framing at all
      ':', // lone colon
      group, // missing both colons
      `:${group}`, // missing trailing colon
      `${group}:`, // missing leading colon
      ':QQ:', // missing required padding
      ':Q===:', // over-padded
      ':QU I=:', // whitespace inside
      ':-_A=:', // URL-safe alphabet
      ':QQ==:, :QQ==:', // duplicated field joined by Headers
    ];
    for (const value of rejected) {
      expect(SF_BINARY_PATTERN.test(value), value).toBe(false);
    }
  });
});

describe('encodeSFBinary', () => {
  it('wraps standard base64 in colons', () => {
    expect(encodeSFBinary(new Uint8Array([0x41, 0x42, 0x43]))).toBe(':QUJD:');
  });

  it('pads 1- and 2-octet remainders', () => {
    expect(encodeSFBinary(new Uint8Array([0x41]))).toBe(':QQ==:');
    expect(encodeSFBinary(new Uint8Array([0x41, 0x42]))).toBe(':QUI=:');
  });

  it('uses the standard alphabet, not URL-safe', () => {
    expect(encodeSFBinary(new Uint8Array([0xFB, 0xEF, 0xBE]))).toBe(':++++:');
    expect(encodeSFBinary(new Uint8Array([0xFF]))).toBe(':/w==:');
  });

  it('encodes empty bytes as the empty payload', () => {
    expect(encodeSFBinary(new Uint8Array(0))).toBe('::');
  });

  it('produces output satisfying SF_BINARY_PATTERN', () => {
    for (const length of [63, 64, 65]) {
      const bytes = Uint8Array.from({ length }, (_, i) => i);
      const encoded = encodeSFBinary(bytes);
      expect(SF_BINARY_PATTERN.test(encoded), encoded).toBe(true);
    }
  });
});

describe('decodeSFBinary', () => {
  it('strips the framing and decodes the payload', () => {
    expect(decodeSFBinary(':QUJD:'))
      .toEqual(new Uint8Array([0x41, 0x42, 0x43]));
  });

  it('decodes padded payloads', () => {
    expect(decodeSFBinary(':QQ==:')).toEqual(new Uint8Array([0x41]));
    expect(decodeSFBinary(':QUI=:')).toEqual(new Uint8Array([0x41, 0x42]));
  });

  it('decodes the standard alphabet', () => {
    expect(decodeSFBinary(':++++:'))
      .toEqual(new Uint8Array([0xFB, 0xEF, 0xBE]));
    expect(decodeSFBinary(':/w==:')).toEqual(new Uint8Array([0xFF]));
  });

  it('decodes the empty payload to empty bytes', () => {
    expect(decodeSFBinary('::')).toEqual(new Uint8Array(0));
  });

  it('round-trips through encodeSFBinary', () => {
    // one length per padding class: none, `==`, `=`;
    // descending from 0xFF so the top byte value is covered
    for (const length of [129, 64, 65]) {
      const bytes = Uint8Array.from({ length }, (_, i) => 0xFF - i);
      expect(decodeSFBinary(encodeSFBinary(bytes)), `length ${length}`)
        .toEqual(bytes);
    }
  });

  it('throws TypeError on anything SF_BINARY_PATTERN rejects', () => {
    const rejected = [
      '', // no framing at all
      ':', // lone colon
      'QQ==', // missing both colons
      ':QQ==', // missing trailing colon
      'QQ==:', // missing leading colon
      ':QQ:', // missing required padding
      ':-_A=:', // URL-safe alphabet
      ':@@@@:', // not base64 at all
    ];
    for (const value of rejected) {
      expect(SF_BINARY_PATTERN.test(value), value).toBe(false);
      expect(() => decodeSFBinary(value), value).toThrow(TypeError);
      expect(() => decodeSFBinary(value), value)
        .toThrow(/^invalid sf-binary$/);
    }
  });

  it('prefixes the error with context', () => {
    expect(() => decodeSFBinary('QQ==', 'sig'))
      .toThrow(/^sig: invalid sf-binary$/);
  });
});
