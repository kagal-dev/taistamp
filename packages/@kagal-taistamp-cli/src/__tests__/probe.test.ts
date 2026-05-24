// cspell:words unstub
import {
  type KeyConfig,
  newSecret,
  parseSecretToKey,
} from '@kagal/ed25519-secret';
import {
  newTaistampHandler,
  readLabel,
  TAISTAMP_CONTENT_LENGTH,
  TAISTAMP_HEADER_KEY_SELECTOR,
  TAISTAMP_HEADER_LEAP_SECONDS,
  TAISTAMP_HEADER_NONCE,
  TAISTAMP_HEADER_SIGNATURE,
  TAISTAMP_PATH,
} from '@kagal/taistamp';
import { consola } from 'consola';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import {
  buildKeyMap,
  collectSecretSources,
  type GetVerifierFn,
  probe,
  probeEndpoint,
  resolveProbeURL,
  STEP_LABELS,
} from '../commands/probe';

beforeAll(() => {
  // Silence consola noise in tests that don't capture
  // output; capturing tests install mockConsola instead.
  consola.level = -999;
});

const probeURL = new URL(`https://example.test${TAISTAMP_PATH}`);

const fetchFromHandler =
  (handler: (request: Request) => Promise<Response>): typeof fetch =>
    async (input, init) =>
      handler(new Request(input.toString(), init));

/**
 * Map-backed GetVerifierFn over a parsed key bag — the
 * same shape `probe.run` installs.
 */
const mapGetVerifier = (
  keys: ReadonlyMap<string, KeyConfig>,
): GetVerifierFn => (selector) => keys.get(selector)?.verifier;

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

type Captured = Record<string, string[]>;

/**
 * Replace consola's type methods with capturing mocks and
 * return the per-type line record. Each call resets the
 * capture; the mocks bypass the level filter.
 */
const mockConsola = (): Captured => {
  const captured: Captured = {};
  consola.mockTypes((type) => (...parts: unknown[]) => {
    (captured[type] ??= []).push(parts.map(String).join(' '));
  });
  return captured;
};

interface ReportedStep {
  detail: string
  type: 'error' | 'info' | 'success'
}

/**
 * Recover a reported step from the captured consola lines:
 * the consola type carries the verdict, the text after the
 * `label: ` prefix carries the detail.
 */
const findStep = (
  captured: Captured,
  label: string,
): ReportedStep | undefined => {
  for (const type of ['success', 'error', 'info'] as const) {
    const line = captured[type]?.find(
      (message) => message.startsWith(`${label}: `),
    );
    if (line !== undefined) {
      return { detail: line.slice(label.length + 2), type };
    }
  }
  return undefined;
};

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

  it('defaults a bare hostname to https', () => {
    const url = resolveProbeURL('example.com');
    expect(url.protocol).toBe('https:');
    expect(url.host).toBe('example.com');
    expect(url.pathname).toBe(TAISTAMP_PATH);
  });

  it('lowercases the host', () => {
    const url = resolveProbeURL('Example.Com');
    expect(url.protocol).toBe('https:');
    expect(url.host).toBe('example.com');
    expect(url.pathname).toBe(TAISTAMP_PATH);
  });

  it('treats host:port as host and port, not scheme', () => {
    const url = resolveProbeURL('example.com:8443');
    expect(url.protocol).toBe('https:');
    expect(url.host).toBe('example.com:8443');
    expect(url.pathname).toBe(TAISTAMP_PATH);
  });

  it('treats localhost:port as host and port', () => {
    const url = resolveProbeURL('localhost:3000');
    expect(url.protocol).toBe('https:');
    expect(url.host).toBe('localhost:3000');
    expect(url.pathname).toBe(TAISTAMP_PATH);
  });

  it('preserves an explicit path on a scheme-less input', () => {
    const url = resolveProbeURL('example.com/foo');
    expect(url.protocol).toBe('https:');
    expect(url.pathname).toBe('/foo');
  });

  it('defaults a protocol-relative input to https', () => {
    const url = resolveProbeURL('//example.com');
    expect(url.protocol).toBe('https:');
    expect(url.host).toBe('example.com');
    expect(url.pathname).toBe(TAISTAMP_PATH);
  });

  it('accepts an IPv6 host:port', () => {
    const url = resolveProbeURL('[::1]:8787');
    expect(url.protocol).toBe('https:');
    expect(url.host).toBe('[::1]:8787');
    expect(url.pathname).toBe(TAISTAMP_PATH);
  });

  it('drops userinfo from a scheme-less input', () => {
    const url = resolveProbeURL('user@example.com');
    expect(url.username).toBe('');
    expect(url.host).toBe('example.com');
    expect(url.pathname).toBe(TAISTAMP_PATH);
  });

  it('keeps an explicit http scheme', () => {
    const url = resolveProbeURL('http://localhost:8787');
    expect(url.protocol).toBe('http:');
    expect(url.host).toBe('localhost:8787');
    expect(url.pathname).toBe(TAISTAMP_PATH);
  });

  it('normalises an uppercase scheme and host', () => {
    const url = resolveProbeURL('HTTP://EXAMPLE.COM');
    expect(url.protocol).toBe('http:');
    expect(url.host).toBe('example.com');
    expect(url.pathname).toBe(TAISTAMP_PATH);
  });

  it('accepts a single-slash scheme as the parser does', () => {
    const url = resolveProbeURL('http:/example.com');
    expect(url.protocol).toBe('http:');
    expect(url.host).toBe('example.com');
    expect(url.pathname).toBe(TAISTAMP_PATH);
  });

  it('accepts backslashes as the parser does', () => {
    const url = resolveProbeURL(String.raw`http:\\example.com`);
    expect(url.protocol).toBe('http:');
    expect(url.host).toBe('example.com');
    expect(url.pathname).toBe(TAISTAMP_PATH);
  });

  it('swallows an opaque scheme as userinfo', () => {
    const url = resolveProbeURL('mailto:user@example.com');
    expect(url.protocol).toBe('https:');
    expect(url.host).toBe('example.com');
    expect(url.username).toBe('');
  });

  it('rejects a slash-less scheme', () => {
    expect(() => resolveProbeURL('http:example.com')).toThrow();
  });

  it('rejects an unsupported scheme', () => {
    expect(() => resolveProbeURL('ftp://example.com')).toThrow();
  });

  it('rejects a digit-led scheme attempt', () => {
    expect(() => resolveProbeURL('1foo://host')).toThrow();
  });

  it('rejects a non-HTTP(S) scheme attempt', () => {
    expect(() => resolveProbeURL('web+ap://host')).toThrow();
  });

  it('throws on an invalid URL', () => {
    expect(() => resolveProbeURL('not a url')).toThrow();
  });

  it('throws on empty input', () => {
    expect(() => resolveProbeURL('')).toThrow();
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
    const secret = newSecret('t1');
    const map = await buildKeyMap([secret]);
    expect(map.size).toBe(1);
    expect(map.get('t1')).toBeDefined();
  });

  it('reports each loaded key with its DNS TXT record value', async () => {
    const captured = mockConsola();
    await buildKeyMap([newSecret('ts1')]);
    const line = captured.info?.find(
      (message) => message.startsWith('loaded key: ts1 '),
    );
    expect(line).toMatch(
      /^loaded key: ts1 TXT "v=tai1; k=ed25519; p=[\d+/A-Za-z]{43}="$/,
    );
  });

  it('parses multiple tokens from one source', async () => {
    const source = `${newSecret('a')} ${newSecret('b')}`;
    const map = await buildKeyMap([source]);
    expect(map.size).toBe(2);
    expect(map.get('a')).toBeDefined();
    expect(map.get('b')).toBeDefined();
  });

  it('later source wins on selector collision', async () => {
    const first = newSecret('t1');
    const second = newSecret('t1');
    const expected = await parseSecretToKey(second);
    const map = await buildKeyMap([first, second]);
    expect(map.get('t1')?.publicJWK.x).toBe(expected.publicJWK.x);
  });

  it('throws on malformed input in strict mode', async () => {
    await expect(buildKeyMap(['not-a-secret'])).rejects.toThrow();
  });
});

describe('probeEndpoint — with a verifier resolver', () => {
  it('passes against a matching signed handler', async () => {
    const secret = newSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([secret]);
    const out = mockConsola();
    const ok = await probeEndpoint({
      getVerifier: mapGetVerifier(keys),
      fetchFn: fetchFromHandler(handler),
      url: probeURL,
    });
    expect(ok).toBe(true);
    expect(findStep(out, STEP_LABELS.signatureVerified)?.type).toBe('success');
  });

  it('reports the decoded UTC instant on the verified label', async () => {
    const secret = newSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([secret]);
    const out = mockConsola();
    const ok = await probeEndpoint({
      getVerifier: mapGetVerifier(keys),
      fetchFn: fetchFromHandler(handler),
      url: probeURL,
    });
    expect(ok).toBe(true);
    const step = findStep(out, STEP_LABELS.signatureVerified);
    expect(step?.type).toBe('success');
    expect(step?.detail).toMatch(
      /^@[\da-f]{24} \(\d{4}-\d\d-\d\dT[\d:.]+Z\)$/,
    );
  });

  it('fails at selector matched when no verifier resolves', async () => {
    const serverSecret = newSecret('server');
    const operatorSecret = newSecret('operator');
    const config = await parseSecretToKey(serverSecret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([operatorSecret]);
    const out = mockConsola();
    const ok = await probeEndpoint({
      getVerifier: mapGetVerifier(keys),
      fetchFn: fetchFromHandler(handler),
      url: probeURL,
    });
    expect(ok).toBe(false);
    const step = findStep(out, STEP_LABELS.selectorMatched);
    expect(step?.type).toBe('error');
    expect(step?.detail).toBe('no verifier for server');
  });

  it('fails at selector matched when the header is absent', async () => {
    const secret = newSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([secret]);
    const out = mockConsola();
    const ok = await probeEndpoint({
      getVerifier: mapGetVerifier(keys),
      fetchFn: tamperingFetch(handler, (headers, body) => {
        headers.delete(TAISTAMP_HEADER_KEY_SELECTOR);
        return { body, headers };
      }),
      url: probeURL,
    });
    expect(ok).toBe(false);
    const step = findStep(out, STEP_LABELS.selectorMatched);
    expect(step?.type).toBe('error');
    expect(step?.detail).toMatch(/missing/);
  });

  it('fails at signature verified when sig bytes are tampered', async () => {
    const secret = newSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([secret]);
    const out = mockConsola();
    const ok = await probeEndpoint({
      getVerifier: mapGetVerifier(keys),
      fetchFn: tamperingFetch(handler, (headers, body) => {
        headers.set(
          TAISTAMP_HEADER_SIGNATURE,
          `:${'A'.repeat(86)}==:`,
        );
        return { body, headers };
      }),
      url: probeURL,
    });
    expect(ok).toBe(false);
    const step = findStep(out, STEP_LABELS.signatureVerified);
    expect(step?.type).toBe('error');
  });

  it.each([
    ['absent', (h: Headers) => {
      h.delete(TAISTAMP_HEADER_SIGNATURE);
    }, /missing$/],
    ['not sf-binary', (h: Headers) => {
      h.set(TAISTAMP_HEADER_SIGNATURE, ':bad:');
    }, /^malformed /],
    ['URL-safe base64', (h: Headers) => {
      h.set(TAISTAMP_HEADER_SIGNATURE, `:${'_'.repeat(86)}==:`);
    }, /^malformed /],
    ['unpadded', (h: Headers) => {
      h.set(TAISTAMP_HEADER_SIGNATURE, `:${'A'.repeat(86)}:`);
    }, /^malformed /],
    ['not 64 octets', (h: Headers) => {
      h.set(TAISTAMP_HEADER_SIGNATURE, `:${'A'.repeat(88)}:`);
    }, /^malformed /],
  ])(
    'fails at signature header when the header is %s',
    async (_label, tamper, detail) => {
      const secret = newSecret('ts1');
      const config = await parseSecretToKey(secret);
      const handler = newTaistampHandler({
        selector: config.selector,
        signer: config.signer,
      });
      const keys = await buildKeyMap([secret]);
      const out = mockConsola();
      const ok = await probeEndpoint({
        getVerifier: mapGetVerifier(keys),
        fetchFn: tamperingFetch(handler, (headers, body) => {
          tamper(headers);
          return { body, headers };
        }),
        url: probeURL,
      });
      expect(ok).toBe(false);
      const step = findStep(out, STEP_LABELS.signatureHeader);
      expect(step?.type).toBe('error');
      expect(step?.detail).toMatch(detail);
      expect(findStep(out, STEP_LABELS.signatureVerified)).toBeUndefined();
    },
  );

  it('fails at nonce echoed when the server drops TAI-Nonce', async () => {
    const secret = newSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([secret]);
    const out = mockConsola();
    const ok = await probeEndpoint({
      getVerifier: mapGetVerifier(keys),
      fetchFn: tamperingFetch(handler, (headers, body) => {
        headers.delete(TAISTAMP_HEADER_NONCE);
        return { body, headers };
      }),
      url: probeURL,
    });
    expect(ok).toBe(false);
    const step = findStep(out, STEP_LABELS.nonceEchoed);
    expect(step?.type).toBe('error');
    expect(step?.detail).toMatch(/^expected /);
    expect(step?.detail).toMatch(/\(missing\)$/);
  });

  it('fails at nonce echoed when the echoed nonce differs', async () => {
    const secret = newSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([secret]);
    const out = mockConsola();
    const ok = await probeEndpoint({
      getVerifier: mapGetVerifier(keys),
      fetchFn: tamperingFetch(handler, (headers, body) => {
        headers.set(TAISTAMP_HEADER_NONCE, `:${'A'.repeat(22)}==:`);
        return { body, headers };
      }),
      url: probeURL,
    });
    expect(ok).toBe(false);
    const step = findStep(out, STEP_LABELS.nonceEchoed);
    expect(step?.type).toBe('error');
    expect(step?.detail).toMatch(/^expected /);
    expect(step?.detail).toMatch(/got :A{22}==:$/);
  });

  it('fails at fetch endpoint on transport error', async () => {
    const keys = await buildKeyMap([newSecret('ts1')]);
    const out = mockConsola();
    const ok = await probeEndpoint({
      getVerifier: mapGetVerifier(keys),
      fetchFn: async () => {
        throw new Error('connection refused');
      },
      url: probeURL,
    });
    expect(ok).toBe(false);
    const step = findStep(out, STEP_LABELS.fetch);
    expect(step?.type).toBe('error');
    expect(step?.detail).toMatch(/connection refused/);
  });

  it('fails at fetch endpoint with a timeout verdict', async () => {
    const keys = await buildKeyMap([newSecret('ts1')]);
    const out = mockConsola();
    const ok = await probeEndpoint({
      getVerifier: mapGetVerifier(keys),
      fetchFn: async () => {
        throw new DOMException('aborted', 'TimeoutError');
      },
      url: probeURL,
    });
    expect(ok).toBe(false);
    const step = findStep(out, STEP_LABELS.fetch);
    expect(step?.type).toBe('error');
    expect(step?.detail).toMatch(/^timed out after \d+ ms$/);
  });

  it('fails at http status on non-OK HTTP status', async () => {
    const keys = await buildKeyMap([newSecret('ts1')]);
    const out = mockConsola();
    const ok = await probeEndpoint({
      getVerifier: mapGetVerifier(keys),
      fetchFn: async () => new Response('not found', {
        status: 404,
        statusText: 'Not Found',
      }),
      url: probeURL,
    });
    expect(ok).toBe(false);
    expect(findStep(out, STEP_LABELS.fetch)?.type).toBe('success');
    const step = findStep(out, STEP_LABELS.httpStatus);
    expect(step?.type).toBe('error');
    expect(step?.detail).toBe('404 Not Found');
  });

  it('fails at body shape when the body length is wrong', async () => {
    const secret = newSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([secret]);
    const out = mockConsola();
    const ok = await probeEndpoint({
      getVerifier: mapGetVerifier(keys),
      fetchFn: tamperingFetch(handler, (headers, body) => ({
        body: body + 'x',
        headers,
      })),
      url: probeURL,
    });
    expect(ok).toBe(false);
    expect(findStep(out, STEP_LABELS.bodyRead)?.type).toBe('success');
    const step = findStep(out, STEP_LABELS.bodyShape);
    expect(step?.type).toBe('error');
    expect(step?.detail).toBe(
      `expected ${TAISTAMP_CONTENT_LENGTH} octets, ` +
      `got ${TAISTAMP_CONTENT_LENGTH + 1}`,
    );
    expect(findStep(out, STEP_LABELS.leapSeconds)).toBeUndefined();
  });

  it('fails at body read on a non-ASCII body', async () => {
    const secret = newSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([secret]);
    const out = mockConsola();
    const ok = await probeEndpoint({
      getVerifier: mapGetVerifier(keys),
      fetchFn: async (input, init) => {
        const original = await handler(new Request(input.toString(), init));
        // label-length body of 0x80 octets — the ASCII
        // read fails before the length is ever checked
        const body = new Uint8Array(TAISTAMP_CONTENT_LENGTH).fill(0x80);
        return new Response(body, {
          status: original.status,
          headers: new Headers(original.headers),
        });
      },
      url: probeURL,
    });
    expect(ok).toBe(false);
    const step = findStep(out, STEP_LABELS.bodyRead);
    expect(step?.type).toBe('error');
    expect(step?.detail).toMatch(/^expected 7-bit ASCII, got 0x80$/);
    expect(findStep(out, STEP_LABELS.bodyShape)).toBeUndefined();
    expect(findStep(out, STEP_LABELS.leapSeconds)).toBeUndefined();
  });

  it.each([
    ['absent', (h: Headers) => {
      h.delete(TAISTAMP_HEADER_LEAP_SECONDS);
    }, /missing$/],
    ['non-integer', (h: Headers) => {
      h.set(TAISTAMP_HEADER_LEAP_SECONDS, 'foo');
    }, /^expected u32 leap-seconds, got foo$/],
    ['negative', (h: Headers) => {
      h.set(TAISTAMP_HEADER_LEAP_SECONDS, '-1');
    }, /^expected u32 leap-seconds, got -1$/],
    ['out of u32 range', (h: Headers) => {
      h.set(TAISTAMP_HEADER_LEAP_SECONDS, '9999999999');
    }, /^expected u32 leap-seconds, got 9999999999$/],
    ['empty', (h: Headers) => {
      h.set(TAISTAMP_HEADER_LEAP_SECONDS, '');
    }, /^expected u32 leap-seconds, got \(empty\)$/],
  ])(
    'fails at leap-seconds header when the value is %s',
    async (_label, tamper, detail) => {
      const secret = newSecret('ts1');
      const config = await parseSecretToKey(secret);
      const handler = newTaistampHandler({
        selector: config.selector,
        signer: config.signer,
      });
      const keys = await buildKeyMap([secret]);
      const out = mockConsola();
      const ok = await probeEndpoint({
        getVerifier: mapGetVerifier(keys),
        fetchFn: tamperingFetch(handler, (headers, body) => {
          tamper(headers);
          return { body, headers };
        }),
        url: probeURL,
      });
      expect(ok).toBe(false);
      const step = findStep(out, STEP_LABELS.leapSeconds);
      expect(step?.type).toBe('error');
      expect(step?.detail).toMatch(detail);
      expect(findStep(out, STEP_LABELS.signatureHeader)).toBeUndefined();
    },
  );
});

describe('probeEndpoint — resolver contract', () => {
  it('passes the advertised selector and the URL hostname', async () => {
    const secret = newSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([secret]);
    const seen: string[][] = [];
    const ok = await probeEndpoint({
      getVerifier: (selector, domain) => {
        seen.push([selector, domain]);
        return keys.get(selector)?.verifier;
      },
      fetchFn: fetchFromHandler(handler),
      url: probeURL,
    });
    expect(ok).toBe(true);
    expect(seen).toEqual([['ts1', 'example.test']]);
  });

  it('awaits an asynchronous resolver', async () => {
    const secret = newSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const keys = await buildKeyMap([secret]);
    const out = mockConsola();
    const ok = await probeEndpoint({
      getVerifier: async (selector) => keys.get(selector)?.verifier,
      fetchFn: fetchFromHandler(handler),
      url: probeURL,
    });
    expect(ok).toBe(true);
    expect(findStep(out, STEP_LABELS.signatureVerified)?.type)
      .toBe('success');
  });

  it('fails at selector matched when the resolver throws', async () => {
    const secret = newSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const out = mockConsola();
    const ok = await probeEndpoint({
      getVerifier: () => {
        throw new Error('resolver exploded');
      },
      fetchFn: fetchFromHandler(handler),
      url: probeURL,
    });
    expect(ok).toBe(false);
    const step = findStep(out, STEP_LABELS.selectorMatched);
    expect(step?.type).toBe('error');
    expect(step?.detail).toBe('resolver exploded');
    expect(findStep(out, STEP_LABELS.bodyRead)).toBeUndefined();
  });
});

describe('probeEndpoint — without a resolver', () => {
  it('passes against a signed handler with info steps', async () => {
    const secret = newSecret('ts1');
    const config = await parseSecretToKey(secret);
    const handler = newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    });
    const out = mockConsola();
    const ok = await probeEndpoint({
      fetchFn: fetchFromHandler(handler),
      url: probeURL,
    });
    expect(ok).toBe(true);
    const selectorStep = findStep(out, STEP_LABELS.selectorAdvertised);
    const signatureStep = findStep(out, STEP_LABELS.signatureAdvertised);
    expect(selectorStep?.type).toBe('info');
    expect(signatureStep?.type).toBe('info');
    expect(selectorStep?.detail).toBe('ts1');
    expect(signatureStep?.detail).toMatch(/^:[\d+/A-Za-z]{86}==:$/);
  });

  it('passes against an unsigned handler with (missing) markers', async () => {
    const handler = newTaistampHandler();
    const out = mockConsola();
    const ok = await probeEndpoint({
      fetchFn: fetchFromHandler(handler),
      url: probeURL,
    });
    expect(ok).toBe(true);
    expect(findStep(out, STEP_LABELS.selectorAdvertised)?.detail)
      .toBe('(missing)');
    expect(findStep(out, STEP_LABELS.signatureAdvertised)?.detail)
      .toBe('(missing)');
  });

  it('fails on transport error', async () => {
    const out = mockConsola();
    const ok = await probeEndpoint({
      fetchFn: async () => {
        throw new Error('timeout');
      },
      url: probeURL,
    });
    expect(ok).toBe(false);
    expect(findStep(out, STEP_LABELS.fetch)?.type).toBe('error');
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
    const secret = newSecret('ts1');
    const config = await parseSecretToKey(secret);
    stubGlobalFetch(newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    }));
    await runProbe({ url: probeURL.toString(), secret });
    expect(process.exitCode).toBeUndefined();
  });

  it('merges repeated --secret values into the bag', async () => {
    const first = newSecret('ts1');
    const second = newSecret('ts2');
    const config = await parseSecretToKey(second);
    stubGlobalFetch(newTaistampHandler({
      selector: config.selector,
      signer: config.signer,
    }));
    await runProbe({ url: probeURL.toString(), secret: [first, second] });
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

  it('sets exitCode when a --secret value is malformed', async () => {
    stubGlobalFetch(newTaistampHandler());
    await runProbe({ url: probeURL.toString(), secret: 'not-a-valid-secret' });
    expect(process.exitCode).toBe(1);
  });

  it('sets exitCode when the probe fails', async () => {
    const clientSecret = newSecret('ts1');
    const serverSecret = newSecret('ts2');
    const serverConfig = await parseSecretToKey(serverSecret);
    stubGlobalFetch(newTaistampHandler({
      selector: serverConfig.selector,
      signer: serverConfig.signer,
    }));
    await runProbe({ url: probeURL.toString(), secret: clientSecret });
    expect(process.exitCode).toBe(1);
  });
});
