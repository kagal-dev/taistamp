import { describe, expect, it } from 'vitest';

import { newKeys } from '../key';
import { makeKeyRecords } from '../key-record';
import { decodeBase64, encodeKey } from '../utils';

const testSeed = new Uint8Array(32).fill(7);

describe('makeKeyRecords', () => {
  describe('cardinality', () => {
    it('returns {} for undefined input', async () => {
      expect(await makeKeyRecords(undefined)).toEqual({});
    });

    it('returns {} for an empty array', async () => {
      expect(await makeKeyRecords([])).toEqual({});
    });

    it('returns one entry for a single input, keyed by selector', async () => {
      const { publicKey } = await newKeys(testSeed);
      const records = await makeKeyRecords({ publicKey, selector: 's1' });
      expect(Object.keys(records)).toEqual(['s1']);
    });

    it('returns one entry per array input, keyed by selector', async () => {
      const { publicKey } = await newKeys(testSeed);
      const records = await makeKeyRecords([
        { publicKey, selector: 's1' },
        { publicKey, selector: 's2' },
        { publicKey, selector: 's3' },
      ]);
      expect(Object.keys(records)).toEqual(['s1', 's2', 's3']);
    });

    it('last-write-wins on duplicate selectors', async () => {
      const a = await newKeys(new Uint8Array(32).fill(1));
      const b = await newKeys(new Uint8Array(32).fill(2));
      const records = await makeKeyRecords([
        { publicKey: a.publicKey, selector: 'dup' },
        { publicKey: b.publicKey, selector: 'dup' },
      ]);
      expect(Object.keys(records)).toEqual(['dup']);
      expect(records['dup'].p).toBe(await encodeKey(b.publicKey));
    });

    it('freezes the returned object', async () => {
      const { publicKey } = await newKeys(testSeed);
      const records = await makeKeyRecords({ publicKey, selector: 's1' });
      expect(Object.isFrozen(records)).toBe(true);
    });
  });

  describe('record shape', () => {
    it('derives k from the key algorithm and produces a 32-byte base64 p', async () => {
      const { publicKey } = await newKeys(testSeed);
      const records = await makeKeyRecords({ publicKey, selector: 's1' });
      const record = records['s1'];
      expect(record.k).toBe('ed25519');
      const { p } = record;
      if (p === undefined) throw new Error('expected a published key');
      expect(decodeBase64(p)).toHaveLength(32);
    });

    it('p matches encodeKey(publicKey) byte-for-byte', async () => {
      const { publicKey } = await newKeys(testSeed);
      const records = await makeKeyRecords({ publicKey, selector: 's1' });
      expect(records['s1'].p).toBe(await encodeKey(publicKey));
    });

    it('omits v when no template is supplied', async () => {
      const { publicKey } = await newKeys(testSeed);
      const records = await makeKeyRecords({ publicKey, selector: 's1' });
      const record = records['s1'];
      expect(record.v).toBeUndefined();
      expect(Object.hasOwn(record, 'v')).toBe(false);
    });

    it('doesn\'t store the selector on the record itself', async () => {
      const { publicKey } = await newKeys(testSeed);
      const records = await makeKeyRecords({ publicKey, selector: 's1' });
      const record = records['s1'];
      expect(Object.hasOwn(record, 'selector')).toBe(false);
      expect(Object.hasOwn(record, 's')).toBe(false);
    });
  });

  describe('revocation', () => {
    it('emits a revocation record (p: undefined, no k) when publicKey is omitted', async () => {
      const records = await makeKeyRecords({ selector: 's1' });
      const record = records['s1'];
      // No key to name, so `k=` is omitted entirely.
      expect(record.k).toBeUndefined();
      expect(Object.hasOwn(record, 'k')).toBe(false);
      expect(record.p).toBeUndefined();
      // present-but-undefined, so it serialises as an
      // empty `p=` (RFC 6376 §3.6.1), not an absent tag.
      expect(Object.hasOwn(record, 'p')).toBe(true);
    });

    it('drops a template k from a revocation record but keeps other tags', async () => {
      const records = await makeKeyRecords(
        { selector: 's1' },
        { k: 'rsa-sha256', v: 'DKIM1' },
      );
      const record = records['s1'];
      // No key to name, so a template `k=` is stripped
      // rather than left to advertise an absent key.
      expect(record.k).toBeUndefined();
      expect(Object.hasOwn(record, 'k')).toBe(false);
      // other template tags still flow through.
      expect(record.v).toBe('DKIM1');
      expect(record.p).toBeUndefined();
      expect(Object.hasOwn(record, 'p')).toBe(true);
    });
  });

  describe('template', () => {
    it('flows v from the template into the output', async () => {
      const { publicKey } = await newKeys(testSeed);
      const records = await makeKeyRecords(
        { publicKey, selector: 's1' },
        { v: 'DKIM1' },
      );
      expect(records['s1'].v).toBe('DKIM1');
    });

    it('flows typed extras from the template into the output', async () => {
      const { publicKey } = await newKeys(testSeed);
      const records = await makeKeyRecords(
        { publicKey, selector: 's1' },
        { v: 'DKIM1', h: 'sha256', s: 'email' },
      );
      const record = records['s1'];
      expect(record.v).toBe('DKIM1');
      expect(record.h).toBe('sha256');
      expect(record.s).toBe('email');
      expect(record.k).toBe('ed25519');
    });

    it('applies the template to every entry of an array input', async () => {
      const { publicKey } = await newKeys(testSeed);
      const records = await makeKeyRecords(
        [
          { publicKey, selector: 's1' },
          { publicKey, selector: 's2' },
        ],
        { v: 'DKIM1' },
      );
      expect(records['s1'].v).toBe('DKIM1');
      expect(records['s2'].v).toBe('DKIM1');
    });

    it('template entries cannot override the synthesised k/p', async () => {
      const { publicKey } = await newKeys(testSeed);
      const records = await makeKeyRecords(
        { publicKey, selector: 's1' },
        { k: 'rsa-sha256', p: 'malicious-base64' },
      );
      expect(records['s1'].k).toBe('ed25519');
      expect(records['s1'].p).toBe(await encodeKey(publicKey));
    });
  });

  describe('key material', () => {
    it('encodes distinct public keys to distinct p values', async () => {
      const a = await newKeys(new Uint8Array(32).fill(1));
      const b = await newKeys(new Uint8Array(32).fill(2));
      const c = await newKeys(new Uint8Array(32).fill(3));
      const records = await makeKeyRecords([
        { publicKey: a.publicKey, selector: 's1' },
        { publicKey: b.publicKey, selector: 's2' },
        { publicKey: c.publicKey, selector: 's3' },
      ]);
      expect(records['s1'].p).toBe(await encodeKey(a.publicKey));
      expect(records['s2'].p).toBe(await encodeKey(b.publicKey));
      expect(records['s3'].p).toBe(await encodeKey(c.publicKey));
    });
  });

  describe('error context', () => {
    it('throws under the bare context for a single failing input', async () => {
      const { signKey } = await newKeys(testSeed);
      await expect(makeKeyRecords({ publicKey: signKey, selector: 's1' }))
        .rejects.toThrow(/^makeKeyRecords: /);
    });

    it('uses the supplied context as the error prefix', async () => {
      const { signKey } = await newKeys(testSeed);
      await expect(makeKeyRecords(
        { publicKey: signKey, selector: 's1' },
        undefined,
        'myConfig',
      )).rejects.toThrow(/^myConfig: /);
    });

    it('disambiguates which array entry failed via input N', async () => {
      const { publicKey, signKey } = await newKeys(testSeed);
      await expect(makeKeyRecords([
        { publicKey, selector: 's1' },
        { publicKey: signKey, selector: 's2' },
      ])).rejects.toThrow(/^makeKeyRecords: input 1: /);
    });
  });
});
