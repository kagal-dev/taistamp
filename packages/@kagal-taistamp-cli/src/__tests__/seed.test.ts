import {
  decodeBase64,
  parseSecretToKey,
  SELECTOR_PATTERN,
} from '@kagal/ed25519-secret';
import { consola } from 'consola';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { mintSecret, seedNew } from '../commands/seed';

const runSeedNew = async (
  arguments_: Record<string, unknown>,
): Promise<void> => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await seedNew.run?.({ args: arguments_ } as any);
};

describe('mintSecret', () => {
  it('defaults the selector to "default"', () => {
    const secret = mintSecret();
    const [selector] = secret.split(':');
    expect(selector).toBe('default');
  });

  it('emits a 32-byte base64 seed after the selector', () => {
    const secret = mintSecret('s1');
    const [selector, b64] = secret.split(':');
    expect(selector).toBe('s1');
    expect(decodeBase64(b64)).toHaveLength(32);
  });

  it('accepts every selector that matches SELECTOR_PATTERN', () => {
    for (const selector of ['s1', 'selector1', 'a', 'a-b_c', 'A1']) {
      expect(SELECTOR_PATTERN.test(selector)).toBe(true);
      expect(mintSecret(selector).startsWith(`${selector}:`)).toBe(true);
    }
  });

  it.each([
    ['leading digit', '1bad'],
    ['contains dot', 'a.b'],
    ['trailing hyphen', 'a-'],
    ['empty', ''],
    ['too long', 'a'.repeat(64)],
  ])('rejects invalid selector (%s)', (_label, selector) => {
    expect(() => mintSecret(selector)).toThrow(TypeError);
  });

  it('threads context into the thrown error message', () => {
    expect(() => mintSecret('1bad', 'unit-test')).toThrow(/^unit-test: /);
  });

  it('round-trips through parseSecretToKey', async () => {
    const secret = mintSecret('s1');
    const config = await parseSecretToKey(secret);
    expect(config.selector).toBe('s1');
    expect(config.privateKey).toHaveLength(32);
  });

  it('produces distinct seeds on consecutive calls', () => {
    const a = mintSecret('s1').split(':')[1];
    const b = mintSecret('s1').split(':')[1];
    expect(a).not.toBe(b);
  });
});

describe('seedNew.run', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    process.exitCode = undefined;
  });

  it('logs the minted secret on success', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    await runSeedNew({ selector: 's1' });
    expect(log).toHaveBeenCalledTimes(1);
    expect(String(log.mock.calls[0][0])).toMatch(/^s1:/);
    expect(process.exitCode).toBeUndefined();
  });

  it('sets exitCode and reports on invalid selector', async () => {
    const fail = vi.spyOn(consola, 'fail').mockImplementation(() => {});
    vi.spyOn(console, 'log').mockImplementation(() => {});
    await runSeedNew({ selector: '1bad' });
    expect(process.exitCode).toBe(1);
    expect(fail).toHaveBeenCalled();
  });
});
