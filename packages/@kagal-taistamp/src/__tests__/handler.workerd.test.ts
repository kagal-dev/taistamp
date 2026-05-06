import { newSigner } from '@kagal/ed25519-secret';
import { env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

import {
  asNonce,
  composeSignaturePayload,
  extractLeapSeconds,
  newTaistampHandler,
  TAI64N_HEADER_KEY_SELECTOR,
  TAI64N_HEADER_NONCE,
  TAI64N_HEADER_SIGNATURE,
  TAI64N_PATH,
} from '..';

const baseURL = `https://example.com${TAI64N_PATH}`;

const decodeStructuredBinary = (value: string): ArrayBuffer =>
  Uint8Array.from(atob(value.slice(1, -1)), (c) => c.codePointAt(0) ?? 0)
    .buffer as ArrayBuffer;

describe('newTaistampHandler (workerd pool)', () => {
  it('signed response verifies under workerd WebCrypto', async () => {
    expect(env).toBeDefined();

    const keypair = await crypto.subtle.generateKey(
      'Ed25519',
      true,
      ['sign', 'verify'],
    ) as CryptoKeyPair;

    const selector = 'test1';
    const nonce = ':AAAAAAAAAAAAAAAAAAAAAA==:';
    const handler = newTaistampHandler({
      selector,
      signer: newSigner(keypair.privateKey),
    });

    const response = await handler(
      new Request(baseURL, {
        headers: { [TAI64N_HEADER_NONCE]: nonce },
      }),
    );

    expect(response.status).toBe(200);
    const label = await response.text();
    const leap = extractLeapSeconds(response.headers);
    expect(leap).toBeDefined();
    expect(response.headers.get(TAI64N_HEADER_KEY_SELECTOR)).toBe(selector);

    const sigHeader = response.headers.get(TAI64N_HEADER_SIGNATURE);
    expect(sigHeader).not.toBeNull();
    const signature = decodeStructuredBinary(sigHeader!);

    const payload = composeSignaturePayload(label, leap!, selector, asNonce(nonce)!);
    const ok = await crypto.subtle.verify(
      'Ed25519',
      keypair.publicKey,
      signature,
      payload,
    );
    expect(ok).toBe(true);
  });
});
