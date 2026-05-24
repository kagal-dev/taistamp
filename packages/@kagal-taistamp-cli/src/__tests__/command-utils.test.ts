import { consola } from 'consola';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { reportCommandError } from '../commands/command-utils';

describe('reportCommandError', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('routes TypeError to consola.fail with the message only', () => {
    const fail = vi.spyOn(consola, 'fail').mockImplementation(() => {});
    reportCommandError(new TypeError('bad input'));
    expect(fail).toHaveBeenCalledWith('bad input');
  });

  it('routes other Error to consola.error with the instance', () => {
    const error = vi.spyOn(consola, 'error').mockImplementation(() => {});
    const err = new Error('boom');
    reportCommandError(err);
    expect(error).toHaveBeenCalledWith(err);
  });

  it('routes string throws to consola.error with the string', () => {
    const error = vi.spyOn(consola, 'error').mockImplementation(() => {});
    reportCommandError('plain string');
    expect(error).toHaveBeenCalledWith('plain string');
  });

  it('stringifies non-Error, non-string throws', () => {
    const error = vi.spyOn(consola, 'error').mockImplementation(() => {});
    reportCommandError({ weird: true });
    expect(error).toHaveBeenCalledWith('[object Object]');
  });
});
