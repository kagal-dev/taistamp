import { describe, expect, it } from 'vitest';

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
