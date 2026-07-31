import { runCommand } from 'citty';
import { consola } from 'consola';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { seedNew } from '../commands/seed';

const runSeedNew = async (
  arguments_: Record<string, unknown>,
): Promise<void> => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await seedNew.run?.({ args: arguments_ } as any);
};

describe('seedNew.run', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    process.exitCode = undefined;
  });

  it('logs the minted secret and its TXT record', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    await runSeedNew({ selector: 's1' });
    expect(log).toHaveBeenCalledTimes(2);
    expect(String(log.mock.calls[0][0])).toMatch(/^s1:/);
    expect(String(log.mock.calls[1][0])).toMatch(
      /^s1\._taistamp TXT "v=tai1; k=ed25519; p=[\d+/A-Za-z]{43}="$/,
    );
    expect(process.exitCode).toBeUndefined();
  });

  it('defaults the selector to "default" via the positional', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    await runCommand(seedNew, { rawArgs: [] });
    expect(String(log.mock.calls[0][0])).toMatch(/^default:/);
    expect(process.exitCode).toBeUndefined();
  });

  it('sets exitCode and reports on invalid selector', async () => {
    const error = vi.spyOn(consola, 'error').mockImplementation(() => {});
    vi.spyOn(console, 'log').mockImplementation(() => {});
    await runSeedNew({ selector: '1bad' });
    expect(process.exitCode).toBe(1);
    expect(error).toHaveBeenCalled();
  });
});
