import { describe, expect, it } from 'vitest';

import { asNonce, extractNonce, newNonce, TAI64N_HEADER_NONCE } from '..';
import { encodeSFBinary, SF_BINARY_PATTERN } from '../utils';

describe('asNonce', () => {
  it('brands conformant wire forms within the length range', () => {
    const accepted = [
      ':YWJjZGVmZw==:', // 7 octets — decoded minimum, wire 14
      ':YWJjZGVmZ2hp:', // 9 octets, unpadded
      encodeSFBinary(new Uint8Array(129)), // decoded maximum, wire 174
    ];
    for (const value of accepted) {
      expect(asNonce(value), value).toBe(value);
    }
  });

  it('returns undefined for every treat-as-absent case', () => {
    const rejected = [
      '', // empty field value
      '::', // zero-length nonce
      ':QQ==:', // 1 octet — below the decoded minimum
      encodeSFBinary(new Uint8Array(130)), // above the decoded maximum
      'YWJjZGVmZw==', // missing framing
      ':YWJjZGVmZ_==:', // URL-safe alphabet
      ':YWJjZGVmZw==:, :YWJjZGVmZw==:', // duplicated field joined by Headers
    ];
    for (const value of rejected) {
      expect(asNonce(value), value).toBeUndefined();
    }
  });
});

describe('extractNonce', () => {
  it('returns the branded nonce from the request headers', () => {
    const nonce = newNonce();
    const headers = new Headers({ [TAI64N_HEADER_NONCE]: nonce });
    expect(extractNonce(headers)).toBe(nonce);
  });

  it('returns undefined when the field is missing', () => {
    expect(extractNonce(new Headers())).toBeUndefined();
  });

  it('returns undefined for a malformed field', () => {
    const headers = new Headers({ [TAI64N_HEADER_NONCE]: ':QQ==:' });
    expect(extractNonce(headers)).toBeUndefined();
  });

  it('returns undefined for a duplicated field', () => {
    const headers = new Headers();
    headers.append(TAI64N_HEADER_NONCE, ':YWJjZGVmZw==:');
    headers.append(TAI64N_HEADER_NONCE, ':YWJjZGVmZw==:');
    expect(extractNonce(headers)).toBeUndefined();
  });
});

describe('newNonce', () => {
  it('mints a branded nonce of the default length', () => {
    const nonce = newNonce();
    expect(SF_BINARY_PATTERN.test(nonce)).toBe(true);
    expect(nonce).toHaveLength(26); // 16 bytes → 24 base64 chars + colons
    expect(asNonce(nonce)).toBe(nonce);
  });

  it('accepts both spec §5.4 decoded bounds', () => {
    const bounds = [
      { byteLength: 7, wireLength: 14 },
      { byteLength: 129, wireLength: 174 },
    ];
    for (const { byteLength, wireLength } of bounds) {
      const nonce = newNonce(byteLength);
      expect(nonce, `${byteLength}`).toHaveLength(wireLength);
      expect(asNonce(nonce), `${byteLength}`).toBe(nonce);
    }
  });

  it('throws TypeError outside the bounds and for non-integers', () => {
    const rejected = [6, 130, 0, -1, 7.5, Number.NaN];
    for (const byteLength of rejected) {
      expect(() => newNonce(byteLength), `${byteLength}`)
        .toThrow(TypeError);
      expect(() => newNonce(byteLength), `${byteLength}`).toThrow(
        /^newNonce: expected integer byte length within 7\.\.129, got /,
      );
    }
  });

  it('prefixes the error with context', () => {
    expect(() => newNonce(6, 'probe')).toThrow(
      /^probe: expected integer byte length within 7\.\.129, got 6$/,
    );
  });

  it('treats an empty context as no prefix', () => {
    expect(() => newNonce(6, '')).toThrow(
      /^expected integer byte length within 7\.\.129, got 6$/,
    );
  });

  it('mints a fresh value per call', () => {
    expect(newNonce()).not.toBe(newNonce());
  });
});
