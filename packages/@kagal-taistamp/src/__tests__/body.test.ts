import { describe, expect, it } from 'vitest';

import { readASCII, readLabel, TAI64N_CONTENT_LENGTH } from '..';

const label = '@4000000069f2594108a48640';

describe('readASCII', () => {
  it('decodes an ASCII response body one code point per byte', async () => {
    expect(await readASCII(new Response(label))).toBe(label);
  });

  it('returns the empty string for an empty body', async () => {
    expect(await readASCII(new Response(''))).toBe('');
  });

  it('preserves the 0x00 and 0x7F boundaries', async () => {
    const decoded = await readASCII(new Response(new Uint8Array([0x00, 0x7F])));
    expect(decoded).toHaveLength(2);
    // charCodeAt reads the raw byte value at each index
    /* eslint-disable unicorn/prefer-code-point */
    expect(decoded.charCodeAt(0)).toBe(0x00);
    expect(decoded.charCodeAt(1)).toBe(0x7F);
    /* eslint-enable unicorn/prefer-code-point */
  });

  it('throws TypeError on a byte outside 7-bit ASCII', async () => {
    await expect(readASCII(new Response(new Uint8Array([0x80]))))
      .rejects.toThrow(TypeError);
  });

  it('forwards context as the error prefix', async () => {
    await expect(readASCII(new Response(new Uint8Array([0x80])), 'body'))
      .rejects.toThrow(/^body: expected 7-bit ASCII, got 0x80$/);
  });
});

describe('readLabel', () => {
  it('returns the label for a well-formed 25-octet body', async () => {
    expect(label).toHaveLength(TAI64N_CONTENT_LENGTH);
    expect(await readLabel(new Response(label))).toBe(label);
  });

  it('throws TypeError when the body is not 25 octets', async () => {
    await expect(readLabel(new Response('@too-short')))
      .rejects.toThrow(/expected 25-octet TAI64N label, got 10/);
  });

  it('throws TypeError on an empty body', async () => {
    await expect(readLabel(new Response('')))
      .rejects.toThrow(/got 0/);
  });

  it('throws TypeError on a non-ASCII octet in a 25-octet body', async () => {
    const body = new Uint8Array(TAI64N_CONTENT_LENGTH).fill(0x80);
    await expect(readLabel(new Response(body)))
      .rejects.toThrow(/expected 7-bit ASCII, got 0x80/);
  });

  it('prefixes the length error with context', async () => {
    await expect(readLabel(new Response('@too-short'), 'body'))
      .rejects.toThrow(/^body: expected 25-octet TAI64N label, got 10$/);
  });

  it('treats an empty context as no prefix', async () => {
    await expect(readLabel(new Response('@too-short'), ''))
      .rejects.toThrow(/^expected 25-octet TAI64N label, got 10$/);
  });
});
