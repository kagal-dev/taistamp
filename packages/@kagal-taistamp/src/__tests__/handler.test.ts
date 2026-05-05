import { describe, expect, it } from 'vitest';

import {
  asLeapSeconds,
  asNonce,
  extractLeapSeconds,
  newEd25519Signer,
  newTaistampHandler,
  TAI64N_CONTENT_LENGTH,
  TAI64N_CONTENT_TYPE,
  TAI64N_HEADER_KEY_SELECTOR,
  TAI64N_HEADER_LEAP_SECONDS,
  TAI64N_HEADER_NONCE,
  TAI64N_HEADER_SIGNATURE,
  TAI64N_PATH,
  TAI_LEAP_SECONDS,
  taistampSignedPayload,
} from '..';

const baseURL = `https://example.com${TAI64N_PATH}`;

const decodeStructuredBinary = (value: string): ArrayBuffer => {
  const trimmed = value.startsWith(':') && value.endsWith(':') ?
    value.slice(1, -1) :
    value;
  const bytes = Uint8Array.from(atob(trimmed), (c) => c.codePointAt(0) ?? 0);
  return bytes.buffer as ArrayBuffer;
};

const newKeypair = async (): Promise<CryptoKeyPair> =>
  await crypto.subtle.generateKey(
    'Ed25519',
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;

describe('newTaistampHandler', () => {
  describe('unsigned (no signer configured)', () => {
    const handler = newTaistampHandler();

    it('returns a 25-byte TAI64N label on GET', async () => {
      const response = await handler(new Request(baseURL));

      expect(response.status).toBe(200);
      expect(response.headers.get('content-type')).toBe(TAI64N_CONTENT_TYPE);
      expect(response.headers.get('content-length'))
        .toBe(String(TAI64N_CONTENT_LENGTH));
      expect(response.headers.get('cache-control')).toBe('no-store');
      expect(response.headers.get(TAI64N_HEADER_LEAP_SECONDS))
        .toBe(String(TAI_LEAP_SECONDS));

      const body = await response.text();
      expect(body).toMatch(/^@[0-9a-f]{24}$/);
      expect(body).toHaveLength(TAI64N_CONTENT_LENGTH);
    });

    it('omits the body on HEAD but keeps the headers', async () => {
      const response = await handler(
        new Request(baseURL, { method: 'HEAD' }),
      );

      expect(response.status).toBe(200);
      expect(response.headers.get('content-length'))
        .toBe(String(TAI64N_CONTENT_LENGTH));
      expect(response.headers.get('content-type')).toBe(TAI64N_CONTENT_TYPE);
      expect(await response.text()).toBe('');
    });

    it('echoes a TAI-Nonce header when present', async () => {
      const nonce = ':b3BhcXVlLW5vbmNlLXZhbHVlLXg=:';
      const response = await handler(new Request(baseURL, {
        headers: { [TAI64N_HEADER_NONCE]: nonce },
      }));

      expect(response.headers.get(TAI64N_HEADER_NONCE)).toBe(nonce);
      expect(response.headers.get(TAI64N_HEADER_SIGNATURE)).toBeNull();
    });

    it('omits TAI-Nonce when the request did not send one', async () => {
      const response = await handler(new Request(baseURL));

      expect(response.headers.get(TAI64N_HEADER_NONCE)).toBeNull();
      expect(response.headers.get(TAI64N_HEADER_SIGNATURE)).toBeNull();
    });

    it('returns 405 for non-GET/HEAD methods', async () => {
      for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) {
        const response = await handler(new Request(baseURL, { method }));
        expect(response.status).toBe(405);
        expect(response.headers.get('allow')).toBe('GET, HEAD');
      }
    });

    it('treats a duplicated TAI-Nonce as absent', async () => {
      const response = await handler(new Request(baseURL, {
        headers: [
          [TAI64N_HEADER_NONCE, ':b3BhcXVlLW5vbmNlLXZhbHVlLXg=:'],
          [TAI64N_HEADER_NONCE, ':ZnJlc2gtY2xpZW50LW5vbmNl:'],
        ],
      }));

      expect(response.status).toBe(200);
      expect(response.headers.get(TAI64N_HEADER_NONCE)).toBeNull();
      expect(response.headers.get(TAI64N_HEADER_SIGNATURE)).toBeNull();
    });

    it('treats an empty TAI-Nonce as absent', async () => {
      const response = await handler(new Request(baseURL, {
        headers: { [TAI64N_HEADER_NONCE]: '' },
      }));

      expect(response.status).toBe(200);
      expect(response.headers.get(TAI64N_HEADER_NONCE)).toBeNull();
      expect(response.headers.get(TAI64N_HEADER_SIGNATURE)).toBeNull();
    });

    it('treats a malformed sf-binary TAI-Nonce as absent', async () => {
      for (const malformed of [
        'not-sf-binary',
        ':missing-trailing-colon',
        'missing-leading-colon:',
        '::',
        ':bad!chars:',
        ':AB=:',
      ]) {
        const response = await handler(new Request(baseURL, {
          headers: { [TAI64N_HEADER_NONCE]: malformed },
        }));

        expect(response.status).toBe(200);
        expect(response.headers.get(TAI64N_HEADER_NONCE)).toBeNull();
        expect(response.headers.get(TAI64N_HEADER_SIGNATURE)).toBeNull();
      }
    });
  });

  describe('signed (signer configured)', () => {
    const selector = 'sel2026q2';

    it('adds verifiable TAI-Signature + TAI-Key-Selector when nonce present', async () => {
      const { privateKey, publicKey } = await newKeypair();
      const handler = newTaistampHandler({
        selector,
        signer: newEd25519Signer(privateKey),
      });
      const nonce = ':ZnJlc2gtY2xpZW50LW5vbmNl:';

      const response = await handler(new Request(baseURL, {
        headers: { [TAI64N_HEADER_NONCE]: nonce },
      }));

      const label = await response.text();
      const signature = response.headers.get(TAI64N_HEADER_SIGNATURE);
      expect(signature).not.toBeNull();
      expect(signature).toMatch(/^:[A-Za-z0-9+/]+={0,2}:$/);
      expect(response.headers.get(TAI64N_HEADER_KEY_SELECTOR)).toBe(selector);
      expect(response.headers.get(TAI64N_HEADER_NONCE)).toBe(nonce);

      const leapSeconds = extractLeapSeconds(response.headers);
      expect(leapSeconds).toBeDefined();
      const message = taistampSignedPayload(
        label,
        leapSeconds!,
        selector,
        asNonce(nonce)!,
      );
      const valid = await crypto.subtle.verify(
        'Ed25519',
        publicKey,
        decodeStructuredBinary(signature!),
        message,
      );
      expect(valid).toBe(true);
    });

    it('omits TAI-Signature and TAI-Key-Selector when no nonce is sent', async () => {
      const { privateKey } = await newKeypair();
      const handler = newTaistampHandler({
        selector,
        signer: newEd25519Signer(privateKey),
      });

      const response = await handler(new Request(baseURL));

      expect(response.headers.get(TAI64N_HEADER_SIGNATURE)).toBeNull();
      expect(response.headers.get(TAI64N_HEADER_KEY_SELECTOR)).toBeNull();
      expect(response.headers.get(TAI64N_HEADER_NONCE)).toBeNull();
    });

    it('does not sign HEAD responses even with a nonce', async () => {
      const { privateKey } = await newKeypair();
      const handler = newTaistampHandler({
        selector,
        signer: newEd25519Signer(privateKey),
      });
      const nonce = ':aGVhZC1ub25jZS12YWx1ZQ==:';

      const response = await handler(new Request(baseURL, {
        method: 'HEAD',
        headers: { [TAI64N_HEADER_NONCE]: nonce },
      }));

      expect(response.status).toBe(200);
      expect(response.headers.get(TAI64N_HEADER_NONCE)).toBe(nonce);
      expect(response.headers.get(TAI64N_HEADER_SIGNATURE)).toBeNull();
      expect(response.headers.get(TAI64N_HEADER_KEY_SELECTOR)).toBeNull();
    });

    it('treats a nonce shorter than 14 octets as absent', async () => {
      const { privateKey } = await newKeypair();
      const handler = newTaistampHandler({
        selector,
        signer: newEd25519Signer(privateKey),
      });
      const shortNonce = ':YWJjZA==:'; // 10 octets

      const response = await handler(new Request(baseURL, {
        headers: { [TAI64N_HEADER_NONCE]: shortNonce },
      }));

      expect(response.headers.get(TAI64N_HEADER_NONCE)).toBeNull();
      expect(response.headers.get(TAI64N_HEADER_SIGNATURE)).toBeNull();
      expect(response.headers.get(TAI64N_HEADER_KEY_SELECTOR)).toBeNull();
    });

    it('treats a nonce longer than 174 octets as absent', async () => {
      const { privateKey } = await newKeypair();
      const handler = newTaistampHandler({
        selector,
        signer: newEd25519Signer(privateKey),
      });
      const longNonce = `:${'A'.repeat(176)}:`; // 178 octets

      const response = await handler(new Request(baseURL, {
        headers: { [TAI64N_HEADER_NONCE]: longNonce },
      }));

      expect(response.headers.get(TAI64N_HEADER_NONCE)).toBeNull();
      expect(response.headers.get(TAI64N_HEADER_SIGNATURE)).toBeNull();
      expect(response.headers.get(TAI64N_HEADER_KEY_SELECTOR)).toBeNull();
    });

    it('signature does not verify against a tampered nonce', async () => {
      const { privateKey, publicKey } = await newKeypair();
      const handler = newTaistampHandler({
        selector,
        signer: newEd25519Signer(privateKey),
      });
      const nonce = ':cmVhbC1ub25jZS12YWx1ZQ==:';

      const response = await handler(new Request(baseURL, {
        headers: { [TAI64N_HEADER_NONCE]: nonce },
      }));

      const label = await response.text();
      const signature = response.headers.get(TAI64N_HEADER_SIGNATURE)!;
      const tampered = taistampSignedPayload(
        label,
        TAI_LEAP_SECONDS,
        selector,
        asNonce(':Zm9yZ2VkLW5vbmNlLXh4eA==:')!,
      );

      const valid = await crypto.subtle.verify(
        'Ed25519',
        publicKey,
        decodeStructuredBinary(signature),
        tampered,
      );
      expect(valid).toBe(false);
    });

    it('signature does not verify against a tampered leap-seconds count', async () => {
      const { privateKey, publicKey } = await newKeypair();
      const handler = newTaistampHandler({
        selector,
        signer: newEd25519Signer(privateKey),
      });
      const nonce = ':bm9uY2UtcGFkZGluZy14:';

      const response = await handler(new Request(baseURL, {
        headers: { [TAI64N_HEADER_NONCE]: nonce },
      }));

      const label = await response.text();
      const signature = response.headers.get(TAI64N_HEADER_SIGNATURE)!;
      const tampered = taistampSignedPayload(
        label,
        asLeapSeconds(TAI_LEAP_SECONDS + 1)!,
        selector,
        asNonce(nonce)!,
      );

      const valid = await crypto.subtle.verify(
        'Ed25519',
        publicKey,
        decodeStructuredBinary(signature),
        tampered,
      );
      expect(valid).toBe(false);
    });

    it('signature does not verify against a tampered selector', async () => {
      const { privateKey, publicKey } = await newKeypair();
      const handler = newTaistampHandler({
        selector,
        signer: newEd25519Signer(privateKey),
      });
      const nonce = ':bm9uY2UtcGFkZGluZy14:';

      const response = await handler(new Request(baseURL, {
        headers: { [TAI64N_HEADER_NONCE]: nonce },
      }));

      const label = await response.text();
      const signature = response.headers.get(TAI64N_HEADER_SIGNATURE)!;
      const tampered = taistampSignedPayload(
        label,
        TAI_LEAP_SECONDS,
        'rogueKey',
        asNonce(nonce)!,
      );

      const valid = await crypto.subtle.verify(
        'Ed25519',
        publicKey,
        decodeStructuredBinary(signature),
        tampered,
      );
      expect(valid).toBe(false);
    });
  });

  describe('configuration', () => {
    it('throws when signer is set without selector', async () => {
      const { privateKey } = await newKeypair();
      expect(() => newTaistampHandler({
        signer: newEd25519Signer(privateKey),
      })).toThrow(/signer and selector must be set together/);
    });

    it('throws when selector is set without signer', () => {
      expect(() => newTaistampHandler({
        selector: 'orphan',
      })).toThrow(/signer and selector must be set together/);
    });

    it('throws on selector with invalid characters', async () => {
      const { privateKey } = await newKeypair();
      expect(() => newTaistampHandler({
        selector: 'has spaces',
        signer: newEd25519Signer(privateKey),
      })).toThrow(/selector must match/);
    });

    it('throws on empty selector', async () => {
      const { privateKey } = await newKeypair();
      expect(() => newTaistampHandler({
        selector: '',
        signer: newEd25519Signer(privateKey),
      })).toThrow(/selector must match/);
    });

    it('throws on selector starting with a digit', async () => {
      const { privateKey } = await newKeypair();
      expect(() => newTaistampHandler({
        selector: '2026q2',
        signer: newEd25519Signer(privateKey),
      })).toThrow(/selector must match/);
    });

    it('throws on selector longer than 63 chars', async () => {
      const { privateKey } = await newKeypair();
      expect(() => newTaistampHandler({
        selector: `a${'b'.repeat(63)}`,
        signer: newEd25519Signer(privateKey),
      })).toThrow(/selector must match/);
    });
  });
});

describe('taistampSignedPayload', () => {
  it('frames as DOMAIN_SEPARATOR || label || leapU32BE || selectorLen || selector || nonce', () => {
    const label = '@4000000069f2594108a48640';
    const selector = 'sel2026q2';
    const nonce = asNonce(':YWJjZGVmZ2hp:')!;
    const leap = asLeapSeconds(37)!;

    const view = new Uint8Array(
      taistampSignedPayload(label, leap, selector, nonce),
    );

    const separator = new TextEncoder().encode('taistamp-v1\0');
    expect(view.slice(0, separator.length)).toEqual(separator);

    const labelBytes = new TextEncoder().encode(label);
    const labelStart = separator.length;
    expect(view.slice(labelStart, labelStart + labelBytes.length))
      .toEqual(labelBytes);

    const leapStart = labelStart + labelBytes.length;
    expect(view[leapStart]).toBe(0);
    expect(view[leapStart + 1]).toBe(0);
    expect(view[leapStart + 2]).toBe(0);
    expect(view[leapStart + 3]).toBe(leap);

    const selectorLengthStart = leapStart + 4;
    const selectorBytes = new TextEncoder().encode(selector);
    expect(view[selectorLengthStart]).toBe(selectorBytes.length);

    const selectorStart = selectorLengthStart + 1;
    expect(view.slice(selectorStart, selectorStart + selectorBytes.length))
      .toEqual(selectorBytes);

    const nonceBytes = new TextEncoder().encode(nonce);
    expect(view.slice(selectorStart + selectorBytes.length))
      .toEqual(nonceBytes);
  });
});

describe('asLeapSeconds', () => {
  it('returns 0 branded for the minimum', () => {
    expect(asLeapSeconds(0)).toBe(0);
  });

  it('returns 2^32 - 1 branded for the maximum', () => {
    expect(asLeapSeconds(0xFF_FF_FF_FF)).toBe(0xFF_FF_FF_FF);
  });

  it('returns undefined for negative', () => {
    expect(asLeapSeconds(-1)).toBeUndefined();
  });

  it('returns undefined when value equals 2^32', () => {
    expect(asLeapSeconds(0x1_00_00_00_00)).toBeUndefined();
  });

  it('returns undefined for a non-integer', () => {
    expect(asLeapSeconds(37.5)).toBeUndefined();
  });

  it('returns undefined for NaN', () => {
    expect(asLeapSeconds(Number.NaN)).toBeUndefined();
  });
});

const leapSecondsHeaders = (value: string): Headers =>
  new Headers({ [TAI64N_HEADER_LEAP_SECONDS]: value });

describe('extractLeapSeconds', () => {
  it('returns 0 branded for the minimum', () => {
    expect(extractLeapSeconds(leapSecondsHeaders('0'))).toBe(0);
  });

  it('returns 2^32 - 1 branded for the maximum', () => {
    expect(extractLeapSeconds(leapSecondsHeaders(String(0xFF_FF_FF_FF))))
      .toBe(0xFF_FF_FF_FF);
  });

  it('returns the current TAI_LEAP_SECONDS value', () => {
    expect(extractLeapSeconds(leapSecondsHeaders(String(TAI_LEAP_SECONDS))))
      .toBe(TAI_LEAP_SECONDS);
  });

  it('returns undefined when the header is missing', () => {
    expect(extractLeapSeconds(new Headers())).toBeUndefined();
  });

  it('returns undefined for an empty header', () => {
    expect(extractLeapSeconds(leapSecondsHeaders(''))).toBeUndefined();
  });

  it('returns undefined for negative', () => {
    expect(extractLeapSeconds(leapSecondsHeaders('-1'))).toBeUndefined();
  });

  it('returns undefined when value equals 2^32', () => {
    expect(extractLeapSeconds(leapSecondsHeaders(String(0x1_00_00_00_00))))
      .toBeUndefined();
  });

  it('returns undefined for a non-integer', () => {
    expect(extractLeapSeconds(leapSecondsHeaders('37.5'))).toBeUndefined();
  });

  it('returns undefined for non-numeric input', () => {
    expect(extractLeapSeconds(leapSecondsHeaders('abc'))).toBeUndefined();
  });

  it('returns undefined for hex notation', () => {
    expect(extractLeapSeconds(leapSecondsHeaders('0x25'))).toBeUndefined();
  });

  it('returns undefined for decimal with fractional part', () => {
    expect(extractLeapSeconds(leapSecondsHeaders('37.0'))).toBeUndefined();
  });

  it('returns undefined for whitespace-only input', () => {
    expect(extractLeapSeconds(leapSecondsHeaders('   '))).toBeUndefined();
  });
});
