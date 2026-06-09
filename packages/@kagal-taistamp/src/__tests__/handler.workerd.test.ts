import { decodeBase64, newSigner } from '@kagal/ed25519-secret';
import { env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

import {
  asNonce,
  composeSignaturePayload,
  extractLeapSeconds,
  newTaistampHandler,
  readLabel,
  TAISTAMP_HEADER_KEY_SELECTOR,
  TAISTAMP_HEADER_NONCE,
  TAISTAMP_HEADER_SIGNATURE,
  TAISTAMP_PATH,
} from '..';

const baseURL = `https://example.com${TAISTAMP_PATH}`;

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
        headers: { [TAISTAMP_HEADER_NONCE]: nonce },
      }),
    );

    expect(response.status).toBe(200);
    const label = await readLabel(response);
    const leap = extractLeapSeconds(response.headers);
    expect(leap).toBeDefined();
    expect(response.headers.get(TAISTAMP_HEADER_KEY_SELECTOR)).toBe(selector);

    const sigHeader = response.headers.get(TAISTAMP_HEADER_SIGNATURE);
    expect(sigHeader).not.toBeNull();
    const signature = decodeBase64(sigHeader!.slice(1, -1));

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
