// cspell:words unstub
import { parseSecretToKey } from '@kagal/ed25519-secret';
import {
  newTaistampHandler,
  readLabel,
  TAI64N_CONTENT_LENGTH,
  TAI64N_HEADER_KEY_SELECTOR,
  TAI64N_HEADER_LEAP_SECONDS,
  TAI64N_HEADER_NONCE,
  TAI64N_HEADER_SIGNATURE,
  TAISTAMP_PATH,
} from '@kagal/taistamp';
import { consola } from 'consola';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import {
  buildKeyMap,
  collectSecretSources,
  probe,
  probeEndpoint,
  type ProbeResult,
  resolveProbeURL,
} from '../commands/probe';
import { mintSecret } from '../commands/seed';

beforeAll(() => {
  // Silence consola noise from buildKeyMap's per-key info log
  // and from probeEndpoint's CLI-facing messages.
  consola.level = -999;
});

const probeURL = new URL(`https://example.test${TAISTAMP_PATH}`);

const fetchFromHandler =
  (handler: (request: Request) => Promise<Response>): typeof fetch =>
    async (input, init) =>
      handler(new Request(input.toString(), init));

const tamperingFetch = (
  handler: (request: Request) => Promise<Response>,
  transform: (headers: Headers, body: string) =>
  { body: string; headers: Headers },
): typeof fetch => async (input, init) => {
  const original = await handler(new Request(input.toString(), init));
  const body = await readLabel(original);
  const next = transform(new Headers(original.headers), body);
  return new Response(next.body, {
    status: original.status,
    statusText: original.statusText,
    headers: next.headers,
  });
};

const findStep = (result: ProbeResult, label: string) =>
  result.steps.find((s) => s.label === label);

const stubGlobalFetch = (
  handler: (request: Request) => Promise<Response>,
): void => {
  vi.stubGlobal(
    'fetch',
    async (input: RequestInfo | URL, init?: RequestInit) =>
      handler(new Request(input.toString(), init)),
  );
};

const runProbe = async (
  arguments_: Record<string, unknown>,
): Promise<void> => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await probe.run?.({ args: arguments_ } as any);
};

describe('resolveProbeURL', () => {
  it('appends TAISTAMP_PATH when input is a bare origin', () => {
    const url = resolveProbeURL('https://example.com/');
    expect(url.pathname).toBe(TAISTAMP_PATH);
    expect(url.origin).toBe('https://example.com');
  });

  it('treats hostname-only as bare origin', () => {
    const url = resolveProbeURL('https://example.com');
    expect(url.pathname).toBe(TAISTAMP_PATH);
  });

  it('preserves an explicit path', () => {
    const url = resolveProbeURL('https://example.com/foo/bar');
    expect(url.pathname).toBe('/foo/bar');
  });

  it('drops the query string', () => {
    const url = resolveProbeURL('https://example.com/?foo=bar');
    expect(url.pathname).toBe(TAISTAMP_PATH);
    expect(url.search).toBe('');
  });

  it('drops the hash fragment', () => {
    const url = resolveProbeURL('https://example.com/foo#frag');
    expect(url.pathname).toBe('/foo');
    expect(url.hash).toBe('');
  });

  it('drops embedded userinfo', () => {
    const url = resolveProbeURL('https://user:pass@example.com/');
    expect(url.username).toBe('');
    expect(url.password).toBe('');
    expect(url.pathname).toBe(TAISTAMP_PATH);
  });

  it('throws on an invalid URL', () => {
    expect(() => resolveProbeURL('not a url')).toThrow();
  });
});

describe('collectSecretSources', () => {
  it('returns empty when no inline or env supplied', () => {
    expect(collectSecretSources([], [], {})).toEqual([]);
  });

  it('preserves inline order', () => {
    expect(collectSecretSources(['a:1', 'b:2'], [], {}))
      .toEqual(['a:1', 'b:2']);
  });

  it('appends env-var values after inline', () => {
    expect(
      collectSecretSources(['a:1'], ['FOO'], { FOO: 'b:2' }),
    ).toEqual(['a:1', 'b:2']);
  });

  it('throws TypeError when env var is missing', () => {
    expect(() => collectSecretSources([], ['MISSING'], {}))
      .toThrow(TypeError);
  });

  it('throws TypeError when env var is empty', () => {
    expect(() => collectSecretSources([], ['EMPTY'], { EMPTY: '' }))
      .toThrow(TypeError);
  });

  it('mentions the offending env var name in the message', () => {
    expect(() => collectSecretSources([], ['NEEDED'], {}))
      .toThrow(/NEEDED/);
  });

  it('falls back to process.env when env arg is omitted', () => {
    process.env.TAISTAMP_TEST_VAR = 'x:1';
    try {
      expect(collectSecretSources([], ['TAISTAMP_TEST_VAR']))
        .toEqual(['x:1']);
    } finally {
      delete process.env.TAISTAMP_TEST_VAR;
    }
  });
});

describe('buildKeyMap', () => {
  it('returns an empty Map for empty sources', async () => {
    const map = await buildKeyMap([]);
    expect(map.size).toBe(0);
  });

  it('parses one source into one keyed entry', async () => {
    const secret = mintSecret('t1');
    const map = await buildKeyMap([secret]);
    expect(map.size).toBe(1);
    expect(map.get('t1')).toBeDefined();
  });

  it('parses multiple tokens from one source', async () => {
    const source = `${mintSecret('a')} ${mintSecret('b')}`;
    const map = await buildKeyMap([source]);
    expect(map.size).toBe(2);
    expect(map.get('a')).toBeDefined();
    expect(map.get('b')).toBeDefined();
  });

  it('later source wins on selector collision', async () => {
    const first = mintSecret('t1');
    const second = mintSecret('t1');
    const expected = await parseSecretToKey(second);
    const map = await buildKeyMap([first, second]);
    expect(map.get('t1')?.publicJWK.x).toBe(expected.publicJWK.x);
  });

  it('throws on malformed input in strict mode', async () => {
    await expect(buildKeyMap(['not-a-secret'])).rejects.toThrow();
  });
});

describe('probeEndpoint — verify mode', () => {
  it('passes against a matching signed handler', async () => {
    const secret = mintSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([secret]);
    const result = await probeEndpoint({
      fetchFn: fetchFromHandler(handler),
      keys,
      mode: 'verify',
      url: probeURL,
    });
    expect(result.ok).toBe(true);
    expect(findStep(result, 'signature verified')?.ok).toBe(true);
  });

  it('fails at selector matched when selector is absent from bag', async () => {
    const serverSecret = mintSecret('server');
    const operatorSecret = mintSecret('operator');
    const config = await parseSecretToKey(serverSecret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([operatorSecret]);
    const result = await probeEndpoint({
      fetchFn: fetchFromHandler(handler),
      keys,
      mode: 'verify',
      url: probeURL,
    });
    expect(result.ok).toBe(false);
    const step = findStep(result, 'selector matched');
    expect(step?.ok).toBe(false);
    expect(step?.detail).toMatch(/server/);
    expect(step?.detail).toMatch(/trusted bag/);
  });

  it('fails at selector matched when the header is absent', async () => {
    const secret = mintSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([secret]);
    const result = await probeEndpoint({
      fetchFn: tamperingFetch(handler, (headers, body) => {
        headers.delete(TAI64N_HEADER_KEY_SELECTOR);
        return { body, headers };
      }),
      keys,
      mode: 'verify',
      url: probeURL,
    });
    expect(result.ok).toBe(false);
    const step = findStep(result, 'selector matched');
    expect(step?.ok).toBe(false);
    expect(step?.detail).toMatch(/missing/);
  });

  it('fails at signature verified when sig bytes are tampered', async () => {
    const secret = mintSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([secret]);
    const result = await probeEndpoint({
      fetchFn: tamperingFetch(handler, (headers, body) => {
        headers.set(
          TAI64N_HEADER_SIGNATURE,
          `:${'A'.repeat(86)}==:`,
        );
        return { body, headers };
      }),
      keys,
      mode: 'verify',
      url: probeURL,
    });
    expect(result.ok).toBe(false);
    const step = findStep(result, 'signature verified');
    expect(step?.ok).toBe(false);
  });

  it('fails at signature header when the header is malformed', async () => {
    const secret = mintSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([secret]);
    const result = await probeEndpoint({
      fetchFn: tamperingFetch(handler, (headers, body) => {
        headers.set(TAI64N_HEADER_SIGNATURE, ':bad:');
        return { body, headers };
      }),
      keys,
      mode: 'verify',
      url: probeURL,
    });
    expect(result.ok).toBe(false);
    expect(findStep(result, 'signature header')?.ok).toBe(false);
    expect(findStep(result, 'signature verified')).toBeUndefined();
  });

  it('fails at signature header when the header is absent', async () => {
    const secret = mintSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([secret]);
    const result = await probeEndpoint({
      fetchFn: tamperingFetch(handler, (headers, body) => {
        headers.delete(TAI64N_HEADER_SIGNATURE);
        return { body, headers };
      }),
      keys,
      mode: 'verify',
      url: probeURL,
    });
    expect(result.ok).toBe(false);
    expect(findStep(result, 'signature header')?.ok).toBe(false);
  });

  it('fails at nonce echoed when the server drops TAI-Nonce', async () => {
    const secret = mintSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([secret]);
    const result = await probeEndpoint({
      fetchFn: tamperingFetch(handler, (headers, body) => {
        headers.delete(TAI64N_HEADER_NONCE);
        return { body, headers };
      }),
      keys,
      mode: 'verify',
      url: probeURL,
    });
    expect(result.ok).toBe(false);
    const step = findStep(result, 'nonce echoed');
    expect(step?.ok).toBe(false);
    expect(step?.detail).toMatch(/^expected /);
    expect(step?.detail).toMatch(/\(missing\)$/);
  });

  it('fails at fetch endpoint on transport error', async () => {
    const keys = await buildKeyMap([mintSecret('ts1')]);
    const result = await probeEndpoint({
      fetchFn: async () => {
        throw new Error('connection refused');
      },
      keys,
      mode: 'verify',
      url: probeURL,
    });
    expect(result.ok).toBe(false);
    const step = findStep(result, 'fetch endpoint');
    expect(step?.ok).toBe(false);
    expect(step?.detail).toMatch(/connection refused/);
  });

  it('fails at fetch endpoint with a timeout verdict', async () => {
    const keys = await buildKeyMap([mintSecret('ts1')]);
    const result = await probeEndpoint({
      fetchFn: async () => {
        throw new DOMException('aborted', 'TimeoutError');
      },
      keys,
      mode: 'verify',
      url: probeURL,
    });
    expect(result.ok).toBe(false);
    const step = findStep(result, 'fetch endpoint');
    expect(step?.ok).toBe(false);
    expect(step?.detail).toMatch(/^timed out after \d+ ms$/);
  });

  it('fails at fetch endpoint on non-OK HTTP status', async () => {
    const keys = await buildKeyMap([mintSecret('ts1')]);
    const result = await probeEndpoint({
      fetchFn: async () => new Response('not found', {
        status: 404,
        statusText: 'Not Found',
      }),
      keys,
      mode: 'verify',
      url: probeURL,
    });
    expect(result.ok).toBe(false);
    expect(findStep(result, 'fetch endpoint')?.ok).toBe(false);
  });

  it('fails at body shape when the body length is wrong', async () => {
    const secret = mintSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([secret]);
    const result = await probeEndpoint({
      fetchFn: tamperingFetch(handler, (headers, body) => ({
        body: body + 'x',
        headers,
      })),
      keys,
      mode: 'verify',
      url: probeURL,
    });
    expect(result.ok).toBe(false);
    const step = findStep(result, 'body shape');
    expect(step?.ok).toBe(false);
    expect(step?.detail).toMatch(
      new RegExp(`expected ${TAI64N_CONTENT_LENGTH}-octet TAI64N label`),
    );
    expect(findStep(result, 'leap-seconds header')).toBeUndefined();
  });

  it('fails at body shape on a non-ASCII body', async () => {
    const secret = mintSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([secret]);
    const result = await probeEndpoint({
      fetchFn: async (input, init) => {
        const original = await handler(new Request(input.toString(), init));
        // 25 octets — passes the length gate, fails ASCII decode
        const body = new Uint8Array(TAI64N_CONTENT_LENGTH).fill(0x80);
        return new Response(body, {
          status: original.status,
          headers: new Headers(original.headers),
        });
      },
      keys,
      mode: 'verify',
      url: probeURL,
    });
    expect(result.ok).toBe(false);
    const step = findStep(result, 'body shape');
    expect(step?.ok).toBe(false);
    expect(step?.detail).toMatch(/^expected 7-bit ASCII, got 0x80$/);
    expect(findStep(result, 'leap-seconds header')).toBeUndefined();
  });

  it.each([
    ['absent', (h: Headers) => {
      h.delete(TAI64N_HEADER_LEAP_SECONDS);
    }, /missing$/],
    ['non-integer', (h: Headers) => {
      h.set(TAI64N_HEADER_LEAP_SECONDS, 'foo');
    }, /^expected non-negative integer, got foo$/],
    ['negative', (h: Headers) => {
      h.set(TAI64N_HEADER_LEAP_SECONDS, '-1');
    }, /^expected non-negative integer, got -1$/],
    ['empty', (h: Headers) => {
      h.set(TAI64N_HEADER_LEAP_SECONDS, '');
    }, /^expected non-negative integer, got \(empty\)$/],
  ])(
    'fails at leap-seconds header when the value is %s',
    async (_label, tamper, detail) => {
      const secret = mintSecret('ts1');
      const config = await parseSecretToKey(secret);
      const handler = newTaistampHandler({
        selector: config.selector,
        signer: config.signer,
      });
      const keys = await buildKeyMap([secret]);
      const result = await probeEndpoint({
        fetchFn: tamperingFetch(handler, (headers, body) => {
          tamper(headers);
          return { body, headers };
        }),
        keys,
        mode: 'verify',
        url: probeURL,
      });
      expect(result.ok).toBe(false);
      const step = findStep(result, 'leap-seconds header');
      expect(step?.ok).toBe(false);
      expect(step?.detail).toMatch(detail);
      expect(findStep(result, 'signature header')).toBeUndefined();
    },
  );
});

describe('probeEndpoint — reachable mode', () => {
  it('passes against a signed handler with info steps', async () => {
    const secret = mintSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const result = await probeEndpoint({
      fetchFn: fetchFromHandler(handler),
      mode: 'reachable',
      url: probeURL,
    });
    expect(result.ok).toBe(true);
    const selectorStep = findStep(result, 'selector advertised');
    const signatureStep = findStep(result, 'signature advertised');
    expect(selectorStep?.kind).toBe('info');
    expect(signatureStep?.kind).toBe('info');
    expect(selectorStep?.detail).toBe('ts1');
    expect(signatureStep?.detail).toMatch(/^:[\d+/A-Za-z_-]+={0,2}:$/);
  });

  it('passes against an unsigned handler with (missing) markers', async () => {
    const handler = newTaistampHandler();
    const result = await probeEndpoint({
      fetchFn: fetchFromHandler(handler),
      mode: 'reachable',
      url: probeURL,
    });
    expect(result.ok).toBe(true);
    expect(findStep(result, 'selector advertised')?.detail)
      .toBe('(missing)');
    expect(findStep(result, 'signature advertised')?.detail)
      .toBe('(missing)');
  });

  it('fails on transport error in reachable mode', async () => {
    const result = await probeEndpoint({
      fetchFn: async () => {
        throw new Error('timeout');
      },
      mode: 'reachable',
      url: probeURL,
    });
    expect(result.ok).toBe(false);
    expect(findStep(result, 'fetch endpoint')?.ok).toBe(false);
  });
});

describe('probe.run', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    process.exitCode = undefined;
  });

  it('runs in reachable mode when no secrets are supplied', async () => {
    stubGlobalFetch(newTaistampHandler());
    await runProbe({ url: probeURL.toString() });
    expect(process.exitCode).toBeUndefined();
  });

  it('runs in verify mode when --secret is supplied', async () => {
    const secret = mintSecret('ts1');
    const config = await parseSecretToKey(secret);
    stubGlobalFetch(newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    }));
    await runProbe({ url: probeURL.toString(), secret });
    expect(process.exitCode).toBeUndefined();
  });

  it('sets exitCode on an invalid URL', async () => {
    await runProbe({ url: 'not a url' });
    expect(process.exitCode).toBe(1);
  });

  it('sets exitCode when --secret-env names a missing var', async () => {
    await runProbe({ url: probeURL.toString(), secretEnv: 'NOT_SET_XYZ' });
    expect(process.exitCode).toBe(1);
  });
});
