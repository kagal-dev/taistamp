import { decodeBase64, newSigner } from '@kagal/ed25519-secret';
import * as ed from '@noble/ed25519';
import { describe, expect, it } from 'vitest';

import {
  asNonce,
  composeSignaturePayload,
  extractLeapSeconds,
  newTaistampHandler,
  readLabel,
  TAI64N_HEADER_KEY_SELECTOR,
  TAI64N_HEADER_NONCE,
  TAI64N_HEADER_SIGNATURE,
  TAISTAMP_PATH,
} from '..';

const baseURL = `https://example.com${TAISTAMP_PATH}`;

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
      signer: newSigner(keypair.privateKey),
    });

    const response = await handler(
      new Request(baseURL, {
        headers: { [TAI64N_HEADER_NONCE]: nonce },
      }),
    );

    expect(response.status).toBe(200);
    const label = await readLabel(response);
    const leap = extractLeapSeconds(response.headers);
    expect(leap).toBeDefined();
    expect(response.headers.get(TAI64N_HEADER_KEY_SELECTOR)).toBe(selector);

    const sigHeader = response.headers.get(TAI64N_HEADER_SIGNATURE);
    expect(sigHeader).not.toBeNull();
    const signature = decodeBase64(sigHeader!.slice(1, -1));

    const payload = new Uint8Array(
      composeSignaturePayload(label, leap!, selector, asNonce(nonce)!),
    );

    const ok = await ed.verifyAsync(signature, payload, publicKeyBytes);
    expect(ok).toBe(true);
  });
});
