import { describe, expect, it } from 'vitest';

import { newKeys } from '../key';
import {
  makeKeyRecords,
  parseKeyRecord,
  parseRecordToKey,
  parseRecordToVerifier,
} from '../key-record';
import { decodeBase64, encodeBase64, encodeKey } from '../utils';

const testSeed = new Uint8Array(32).fill(7);

const KEY32 = new Uint8Array(32);
for (let i = 0; i < 32; i++) KEY32[i] = i;
const KEY32_B64 = encodeBase64(KEY32);
const RECORD = `v=tai1; k=ed25519; p=${KEY32_B64}`;

const ed25519Record = async (seed: Uint8Array = testSeed) => {
  const keys = await newKeys(seed);
  const record = `v=tai1; k=ed25519; p=${await encodeKey(keys.publicKey)}`;
  return { keys, record };
};

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

describe('parseKeyRecord', () => {
  describe('string input', () => {
    it('parses an unquoted single tag-list', () => {
      const record = parseKeyRecord(RECORD);
      expect(record.v).toBe('tai1');
      expect(record.k).toBe('ed25519');
      expect(record.p).toEqual(KEY32);
      expect(Object.keys(record)).toHaveLength(3);
    });

    it('parses a DoH-style quoted single string', () => {
      const record = parseKeyRecord(`"${RECORD}"`);
      expect(record.v).toBe('tai1');
      expect(record.k).toBe('ed25519');
      expect(record.p).toEqual(KEY32);
    });

    it('concatenates a DoH-style multi-string with whitespace between quotes', () => {
      const split = `"v=tai1; k=ed" "25519; p=${KEY32_B64}"`;
      const record = parseKeyRecord(split);
      expect(record.v).toBe('tai1');
      expect(record.k).toBe('ed25519');
      expect(record.p).toEqual(KEY32);
    });

    it('concatenates adjacent quoted strings with no separating whitespace', () => {
      const split = `"v=tai1; k=ed25519; ""p=${KEY32_B64}"`;
      const record = parseKeyRecord(split);
      expect(record.p).toEqual(KEY32);
    });

    it('tolerates leading and trailing whitespace on the whole input', () => {
      expect(parseKeyRecord(`   ${RECORD}   `).p).toEqual(KEY32);
    });

    it('accepts a trailing `;`', () => {
      expect(parseKeyRecord(`${RECORD};`).p).toEqual(KEY32);
    });

    it('tolerates whitespace around `=` per RFC 6376 §3.2 FWS', () => {
      const record = parseKeyRecord(
        `v = tai1 ; k =  ed25519 ; p = ${KEY32_B64}`,
      );
      expect(record.v).toBe('tai1');
      expect(record.k).toBe('ed25519');
      expect(record.p).toEqual(KEY32);
    });
  });

  describe('array input', () => {
    it('concatenates a string[] with no intervening whitespace', () => {
      const split = ['v=tai1; k=ed', `25519; p=${KEY32_B64}`];
      const record = parseKeyRecord(split);
      expect(record.v).toBe('tai1');
      expect(record.k).toBe('ed25519');
      expect(record.p).toEqual(KEY32);
    });

    it('accepts a single-element string[]', () => {
      expect(parseKeyRecord([RECORD]).p).toEqual(KEY32);
    });
  });

  describe('p= semantics', () => {
    it('returns undefined p for an empty `p=` (revoked)', () => {
      const record = parseKeyRecord('v=tai1; k=ed25519; p=');
      expect(record.p).toBeUndefined();
    });

    it('strips internal whitespace from `p=` before decoding (RFC 6376 §3.6.1)', () => {
      const split = `${KEY32_B64.slice(0, 22)} ${KEY32_B64.slice(22)}`;
      const record = parseKeyRecord(`v=tai1; k=ed25519; p=${split}`);
      expect(record.p).toEqual(KEY32);
    });

    it('throws when `p=` is missing', () => {
      expect(() => parseKeyRecord('v=tai1; k=ed25519'))
        .toThrow(/^missing tag: p$/);
    });

    it('throws when `p=` is undecodable', () => {
      expect(() => parseKeyRecord('v=tai1; k=ed25519; p=!!!not-base64!!!'))
        .toThrow(/^p: invalid base64$/);
    });
  });

  describe('empty vs omitted v/k', () => {
    it('reports omitted `v` as undefined', () => {
      const record = parseKeyRecord(`k=ed25519; p=${KEY32_B64}`);
      expect(record.v).toBeUndefined();
    });

    it('reports empty `v=` as empty string', () => {
      const record = parseKeyRecord(`v=; k=ed25519; p=${KEY32_B64}`);
      expect(record.v).toBe('');
    });

    it('reports omitted `k` as undefined', () => {
      const record = parseKeyRecord(`v=tai1; p=${KEY32_B64}`);
      expect(record.k).toBeUndefined();
    });

    it('reports empty `k=` as empty string', () => {
      const record = parseKeyRecord(`v=tai1; k=; p=${KEY32_B64}`);
      expect(record.k).toBe('');
    });
  });

  describe('unknown tags', () => {
    it('keeps unknown tags as own properties, in insertion order', () => {
      const record = parseKeyRecord(
        `v=tai1; h=sha256; k=ed25519; s=email; p=${KEY32_B64}; t=y`,
      );
      const extras = Object.entries(record).filter(
        ([k]) => k !== 'v' && k !== 'k' && k !== 'p',
      );
      expect(extras).toEqual([
        ['h', 'sha256'],
        ['s', 'email'],
        ['t', 'y'],
      ]);
    });

    it('preserves all tags in input order including v, k, p', () => {
      const record = parseKeyRecord(
        `v=tai1; h=sha256; k=ed25519; s=email; p=${KEY32_B64}; t=y`,
      );
      expect(Object.keys(record)).toEqual([
        'v', 'h', 'k', 's', 'p', 't',
      ]);
    });
  });

  describe('case sensitivity', () => {
    it('treats `V=` and `v=` as distinct tags (no collapse)', () => {
      const record = parseKeyRecord(
        `V=DKIM1; v=tai1; k=ed25519; p=${KEY32_B64}`,
      );
      expect(record.v).toBe('tai1');
      expect(record['V']).toBe('DKIM1');
    });
  });

  describe('syntax errors', () => {
    it('throws on empty input string', () => {
      expect(() => parseKeyRecord('')).toThrow(/^empty input$/);
    });

    it('throws on whitespace-only input', () => {
      expect(() => parseKeyRecord('   ')).toThrow(/^empty input$/);
    });

    it('throws on empty array input', () => {
      expect(() => parseKeyRecord([])).toThrow(/^empty input$/);
    });

    it('throws on an empty tag-list (just `;`)', () => {
      expect(() => parseKeyRecord(';')).toThrow(/^empty tag-list$/);
    });

    it('throws on a tag-spec without `=`', () => {
      expect(() => parseKeyRecord(`v=tai1; broken; p=${KEY32_B64}`))
        .toThrow(/^invalid tag-spec: broken$/);
    });

    it('throws on a tag-name starting with a digit', () => {
      expect(() => parseKeyRecord(`9bad=x; p=${KEY32_B64}`))
        .toThrow(/^invalid tag-spec: /);
    });

    it('throws on a tag-name containing `-` (outside the allowed set)', () => {
      expect(() => parseKeyRecord(`bad-name=x; p=${KEY32_B64}`))
        .toThrow(/^invalid tag-spec: /);
    });

    it('throws on duplicate tag names', () => {
      expect(() => parseKeyRecord(`v=tai1; v=tai2; p=${KEY32_B64}`))
        .toThrow(/^duplicate tag: v$/);
    });

    it('throws on an unclosed quoted character-string', () => {
      expect(() => parseKeyRecord(`"v=tai1; k=ed25519; p=${KEY32_B64}`))
        .toThrow(/^unclosed quoted character-string$/);
    });

    it('throws on stray characters between quoted runs', () => {
      const split = `"v=tai1; k=ed25519;"garbage"p=${KEY32_B64}"`;
      expect(() => parseKeyRecord(split))
        .toThrow(/^stray characters outside quoted character-string$/);
    });

    it('throws on a leading empty tag-spec from `;`', () => {
      expect(() => parseKeyRecord(`;v=tai1; k=ed25519; p=${KEY32_B64}`))
        .toThrow(/^empty tag-spec$/);
    });

    it('throws on an interior empty tag-spec from `;;`', () => {
      expect(() => parseKeyRecord(`v=tai1;; k=ed25519; p=${KEY32_B64}`))
        .toThrow(/^empty tag-spec$/);
    });
  });

  describe('context prefix', () => {
    it('omits the prefix when no context is given', () => {
      expect(() => parseKeyRecord('v=tai1; k=ed25519'))
        .toThrow(/^missing tag: p$/);
    });

    it('prepends `${context}: ` on missing-tag errors', () => {
      expect(() => parseKeyRecord('v=tai1; k=ed25519', 'fetchKey'))
        .toThrow(/^fetchKey: missing tag: p$/);
    });

    it('prepends `${context}: ` on syntax errors', () => {
      expect(() => parseKeyRecord('', 'fetchKey'))
        .toThrow(/^fetchKey: empty input$/);
    });

    it('prepends `${context}: ` on duplicate-tag errors', () => {
      expect(() => parseKeyRecord(`v=tai1; v=tai2; p=${KEY32_B64}`, 'fetchKey'))
        .toThrow(/^fetchKey: duplicate tag: v$/);
    });

    it('threads context through to the `p` base64 error', () => {
      expect(() =>
        parseKeyRecord('v=tai1; k=ed25519; p=!!!not-base64!!!', 'fetchKey'),
      ).toThrow(/^fetchKey: p: invalid base64$/);
    });

    it('threads context through quote-parsing errors', () => {
      expect(() =>
        parseKeyRecord(`"v=tai1; k=ed25519; p=${KEY32_B64}`, 'fetchKey'),
      ).toThrow(/^fetchKey: unclosed quoted character-string$/);
    });
  });

  describe('returned shape', () => {
    it('returns Uint8Array (not a Buffer or array) for p', () => {
      const record = parseKeyRecord(RECORD);
      expect(record.p).toBeInstanceOf(Uint8Array);
    });
  });
});

describe('round-trip', () => {
  it('makeKeyRecords output reparses to the same v/k/p plus template extras', async () => {
    const { publicKey } = await newKeys(testSeed);
    const records = await makeKeyRecords(
      { publicKey, selector: 's1' },
      { v: 'tai1', h: 'sha256', s: 'email' },
    );
    const record = records['s1'];
    const tagList = Object.entries(record)
      .map(([name, value]) => `${name}=${value}`)
      .join('; ');
    const parsed = parseKeyRecord(tagList);
    expect(parsed.v).toBe('tai1');
    expect(parsed.k).toBe('ed25519');
    expect(parsed['h']).toBe('sha256');
    expect(parsed['s']).toBe('email');
    expect(parsed.p).toEqual(decodeBase64(await encodeKey(publicKey)));
  });
});

describe('parseRecordToKey', () => {
  it('imports p into a verify-only Ed25519 CryptoKey', async () => {
    const { record } = await ed25519Record();
    const { p } = await parseRecordToKey(record);
    if (p === undefined) throw new Error('expected a key');
    expect(p.algorithm.name).toBe('Ed25519');
    expect(p.type).toBe('public');
    expect(p.extractable).toBe(true);
    expect(p.usages).toEqual(['verify']);
  });

  it('preserves v, k, and unknown tags alongside the key', async () => {
    const { publicKey } = await newKeys(testSeed);
    const record =
      `v=tai1; k=ed25519; h=sha256; p=${await encodeKey(publicKey)}`;
    const parsed = await parseRecordToKey(record);
    expect(parsed.v).toBe('tai1');
    expect(parsed.k).toBe('ed25519');
    expect(parsed['h']).toBe('sha256');
    expect(parsed.p).toBeDefined();
  });

  it('carries a revoked record through as p: undefined', async () => {
    const parsed = await parseRecordToKey('v=tai1; k=ed25519; p=');
    expect(parsed.p).toBeUndefined();
    expect(parsed.v).toBe('tai1');
    expect(parsed.k).toBe('ed25519');
  });

  it('round-trips: the imported key verifies a matching signature', async () => {
    const { keys, record } = await ed25519Record();
    const { p } = await parseRecordToKey(record);
    if (p === undefined) throw new Error('expected a key');
    const message = new TextEncoder().encode('payload');
    const signature = await crypto.subtle.sign(
      'Ed25519', keys.signKey, message,
    );
    expect(await crypto.subtle.verify('Ed25519', p, signature, message))
      .toBe(true);
  });

  it('defaults absent k= to rsa and rejects it', async () => {
    const { publicKey } = await newKeys(testSeed);
    const record = `v=tai1; p=${await encodeKey(publicKey)}`;
    await expect(parseRecordToKey(record))
      .rejects.toThrow(/^parseRecordToKey: unsupported algorithm: rsa$/);
  });

  it('rejects an empty k= rather than folding it into rsa', async () => {
    const { publicKey } = await newKeys(testSeed);
    const record = `v=tai1; k=; p=${await encodeKey(publicKey)}`;
    await expect(parseRecordToKey(record))
      .rejects.toThrow(/^parseRecordToKey: unsupported algorithm: $/);
  });

  it('rejects an explicit unsupported k=', async () => {
    const { publicKey } = await newKeys(testSeed);
    const record = `v=tai1; k=ed448; p=${await encodeKey(publicKey)}`;
    await expect(parseRecordToKey(record))
      .rejects.toThrow(/^parseRecordToKey: unsupported algorithm: ed448$/);
  });

  it('rejects a wrong-length key (via importVerifyKey)', async () => {
    const short = encodeBase64(new Uint8Array(16));
    await expect(parseRecordToKey(`v=tai1; k=ed25519; p=${short}`))
      .rejects.toThrow(
        /^parseRecordToKey: expected 32-byte Ed25519 key, got 16$/,
      );
  });

  it('rejects a malformed record (via parseKeyRecord)', async () => {
    await expect(parseRecordToKey('v=tai1; k=ed25519'))
      .rejects.toThrow(/^parseRecordToKey: missing tag: p$/);
  });

  it('threads context through a parse error', async () => {
    await expect(parseRecordToKey('v=tai1; k=ed25519', 'fetchKey'))
      .rejects.toThrow(/^fetchKey: missing tag: p$/);
  });

  it('threads context through an import error', async () => {
    const { publicKey } = await newKeys(testSeed);
    const record = `v=tai1; p=${await encodeKey(publicKey)}`;
    await expect(parseRecordToKey(record, 'fetchKey'))
      .rejects.toThrow(/^fetchKey: unsupported algorithm: rsa$/);
  });
});

describe('parseRecordToVerifier', () => {
  it('wraps p in a Verifier that verifies a matching signature', async () => {
    const { keys, record } = await ed25519Record();
    const { p } = await parseRecordToVerifier(record);
    if (p === undefined) throw new Error('expected a verifier');
    const message = new TextEncoder().encode('payload');
    const signature = await crypto.subtle.sign(
      'Ed25519', keys.signKey, message,
    );
    expect(await p.verify(signature, message)).toBe(true);
  });

  it('preserves v, k, and unknown tags alongside the verifier', async () => {
    const { publicKey } = await newKeys(testSeed);
    const record =
      `v=tai1; k=ed25519; h=sha256; p=${await encodeKey(publicKey)}`;
    const parsed = await parseRecordToVerifier(record);
    expect(parsed.v).toBe('tai1');
    expect(parsed.k).toBe('ed25519');
    expect(parsed['h']).toBe('sha256');
    expect(parsed.p).toBeDefined();
  });

  it('carries a revoked record through as p: undefined', async () => {
    const parsed = await parseRecordToVerifier('v=tai1; k=ed25519; p=');
    expect(parsed.p).toBeUndefined();
    expect(parsed.k).toBe('ed25519');
  });

  it('defaults the error prefix to parseRecordToVerifier', async () => {
    const { publicKey } = await newKeys(testSeed);
    const record = `v=tai1; p=${await encodeKey(publicKey)}`;
    await expect(parseRecordToVerifier(record))
      .rejects.toThrow(/^parseRecordToVerifier: unsupported algorithm: rsa$/);
  });

  it('rejects absent k= (rsa default), threading context', async () => {
    const { publicKey } = await newKeys(testSeed);
    const record = `v=tai1; p=${await encodeKey(publicKey)}`;
    await expect(parseRecordToVerifier(record, 'fetchVerifier'))
      .rejects.toThrow(/^fetchVerifier: unsupported algorithm: rsa$/);
  });
});
