import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { main } from '../index';

describe('taistamp-cli', () => {
  it('exposes a main command', () => {
    expect(main).toBeDefined();
  });

  it('declares probe and seed subcommands', () => {
    expect(main.subCommands).toBeDefined();
    expect(main.subCommands).toHaveProperty('probe');
    expect(main.subCommands).toHaveProperty('seed');
  });

  it('exposes `seed new` as a nested subcommand', () => {
    expect(main.subCommands).toHaveProperty('seed.subCommands.new');
  });
});

const runSetup = async (envFile?: string): Promise<void> => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await main.setup?.({ args: { envFile } } as any);
};

/** Write `content` as an env file in a fresh temp dir. */
const withEnvFile = async (
  content: string,
  use: (file: string) => Promise<void>,
): Promise<void> => {
  const directory = mkdtempSync(path.join(tmpdir(), 'taistamp-cli-'));
  const file = path.join(directory, 'env');
  writeFileSync(file, content);
  try {
    await use(file);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
};

describe('main.setup — --env-file', () => {
  afterEach(() => {
    delete process.env.TAISTAMP_CLI_TEST_VAR;
  });

  it('loads variables from the given file', async () => {
    await withEnvFile('TAISTAMP_CLI_TEST_VAR=from-file\n', async (file) => {
      await runSetup(file);
      expect(process.env.TAISTAMP_CLI_TEST_VAR).toBe('from-file');
    });
  });

  it('never overrides the real environment', async () => {
    process.env.TAISTAMP_CLI_TEST_VAR = 'from-environment';
    await withEnvFile('TAISTAMP_CLI_TEST_VAR=from-file\n', async (file) => {
      await runSetup(file);
      expect(process.env.TAISTAMP_CLI_TEST_VAR).toBe('from-environment');
    });
  });

  it('throws a TypeError for a missing file', async () => {
    await expect(runSetup('/no/such/.env')).rejects.toThrow(TypeError);
  });

  it('tolerates the absence of --env-file and ./.env', async () => {
    await expect(runSetup()).resolves.toBeUndefined();
  });
});
