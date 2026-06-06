import { describe, expect, it } from 'vitest';

import { asSignature, extractSignature, TAI64N_HEADER_SIGNATURE } from '..';
import { encodeSFBinary } from '../utils';

const signature = Uint8Array.from({ length: 64 }, (_, i) => i);
const wire = encodeSFBinary(signature);

describe('asSignature', () => {
  it('decodes a 64-octet sf-binary signature', () => {
    expect(asSignature(wire)).toEqual(signature);
  });

  it('returns undefined for every malformed wire value', () => {
    const rejected = [
      '', // empty field value
      '::', // empty payload
      encodeSFBinary(new Uint8Array(63)), // one octet short
      encodeSFBinary(new Uint8Array(65)), // one octet long
      wire.slice(1, -1), // missing framing
      `:${'A'.repeat(85)}_==:`, // URL-safe alphabet
      `${wire}, ${wire}`, // duplicated field joined by Headers
    ];
    for (const value of rejected) {
      expect(asSignature(value), JSON.stringify(value)).toBeUndefined();
    }
  });
});

describe('extractSignature', () => {
  it('returns the decoded signature from response headers', () => {
    const headers = new Headers({ [TAI64N_HEADER_SIGNATURE]: wire });
    expect(extractSignature(headers)).toEqual(signature);
  });

  it('returns undefined when the field is missing', () => {
    expect(extractSignature(new Headers())).toBeUndefined();
  });

  it('returns undefined for a malformed field', () => {
    const headers = new Headers({ [TAI64N_HEADER_SIGNATURE]: '::' });
    expect(extractSignature(headers)).toBeUndefined();
  });

  it('returns undefined for a duplicated field', () => {
    const headers = new Headers();
    headers.append(TAI64N_HEADER_SIGNATURE, wire);
    headers.append(TAI64N_HEADER_SIGNATURE, wire);
    expect(extractSignature(headers)).toBeUndefined();
  });
});
