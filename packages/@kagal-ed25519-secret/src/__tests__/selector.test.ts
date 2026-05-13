import { describe, expect, it } from 'vitest';

import {
  assertValidSelector,
  isValidSelector,
  SELECTOR_PATTERN,
} from '../selector';

describe('isValidSelector', () => {
  it('accepts a single letter', () => {
    expect(isValidSelector('a')).toBe(true);
  });

  it('accepts letters, digits, underscore, and hyphen after a leading letter', () => {
    expect(isValidSelector('sel_2026-q2')).toBe(true);
  });

  it('accepts the maximum 63-char length', () => {
    expect(isValidSelector(`a${'b'.repeat(62)}`)).toBe(true);
  });

  it('rejects an empty string', () => {
    expect(isValidSelector('')).toBe(false);
  });

  it('rejects a leading digit', () => {
    expect(isValidSelector('2026q2')).toBe(false);
  });

  it('rejects a leading hyphen', () => {
    expect(isValidSelector('-sel')).toBe(false);
  });

  it('rejects a leading underscore', () => {
    expect(isValidSelector('_sel')).toBe(false);
  });

  it('rejects a trailing hyphen', () => {
    expect(isValidSelector('sel-')).toBe(false);
  });

  it('rejects a trailing underscore', () => {
    expect(isValidSelector('sel_')).toBe(false);
  });

  it('rejects whitespace', () => {
    expect(isValidSelector('has spaces')).toBe(false);
  });

  it('rejects a dot (multi-label selectors are not supported)', () => {
    expect(isValidSelector('a.b')).toBe(false);
  });

  it('rejects 64 characters', () => {
    expect(isValidSelector(`a${'b'.repeat(63)}`)).toBe(false);
  });
});

describe('assertValidSelector', () => {
  it('returns silently for a valid selector', () => {
    expect(() => assertValidSelector('sel2026q2')).not.toThrow();
  });

  it('omits the prefix when no context is given', () => {
    expect(() => assertValidSelector('bad selector'))
      .toThrow(/^selector must match /);
  });

  it('prepends the context prefix when given', () => {
    expect(() => assertValidSelector('bad selector', 'myFn'))
      .toThrow(/^myFn: selector must match /);
  });

  it('names the pattern and quotes the input', () => {
    try {
      assertValidSelector('a b');
      expect.fail('expected throw');
    } catch (error) {
      expect(error).toBeInstanceOf(TypeError);
      const msg = (error as Error).message;
      expect(msg).toContain(SELECTOR_PATTERN.source);
      expect(msg).toContain('"a b"');
    }
  });
});
