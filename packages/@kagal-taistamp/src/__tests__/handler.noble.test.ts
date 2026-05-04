import * as ed from '@noble/ed25519';
import { describe, expect, it } from 'vitest';

import {
  asNonce,
  newEd25519Signer,
  newTaistampHandler,
  TAI64N_HEADER_KEY_SELECTOR,
  TAI64N_HEADER_LEAP_SECONDS,
  TAI64N_HEADER_NONCE,
  TAI64N_HEADER_SIGNATURE,
  TAI64N_PATH,
  taistampSignedPayload,
} from '..';

const baseURL = `https://example.com${TAI64N_PATH}`;

const decodeStructuredBinary = (value: string): Uint8Array =>
  Uint8Array.from(atob(value.slice(1, -1)), (c) => c.codePointAt(0) ?? 0);

describe('newTaistampHandler (cross-impl: WebCrypto sign, noble verify)', () => {
  it('signed response verifies under @noble/ed25519', async () => {
    const keypair = await crypto.subtle.generateKey(
      'Ed25519',
      true,
      ['sign', 'verify'],
    ) as CryptoKeyPair;

    const publicKeyBytes = new Uint8Array(
      await crypto.subtle.exportKey('raw', keypair.publicKey),
    );

    const selector = 'test1';
    const nonce = ':AAAAAAAAAAAAAAAAAAAAAA==:';
    const handler = newTaistampHandler({
      selector,
      signer: newEd25519Signer(keypair.privateKey),
    });

    const response = await handler(
      new Request(baseURL, {
        headers: { [TAI64N_HEADER_NONCE]: nonce },
      }),
    );

    expect(response.status).toBe(200);
    const label = await response.text();
    const leap = Number(response.headers.get(TAI64N_HEADER_LEAP_SECONDS));
    expect(response.headers.get(TAI64N_HEADER_KEY_SELECTOR)).toBe(selector);

    const sigHeader = response.headers.get(TAI64N_HEADER_SIGNATURE);
    expect(sigHeader).not.toBeNull();
    const signature = decodeStructuredBinary(sigHeader!);

    const payload = new Uint8Array(
      taistampSignedPayload(label, leap, selector, asNonce(nonce)!),
    );

    const ok = await ed.verifyAsync(signature, payload, publicKeyBytes);
    expect(ok).toBe(true);
  });
});
