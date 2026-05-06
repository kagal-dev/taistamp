import { describe, expect, it } from 'vitest';

import {
  newTaistampHandler,
  TAI64N_HEADER_NONCE,
  TAI64N_PATH,
} from '..';

const baseURL = `https://example.com${TAI64N_PATH}`;

const exposeHeaders =
  'TAI-Leap-Seconds, TAI-Nonce, TAI-Key-Selector, TAI-Signature';

describe('CORS', () => {
  it('answers OPTIONS with default cors=*', async () => {
    const handler = newTaistampHandler();
    const response = await handler(
      new Request(baseURL, { method: 'OPTIONS' }),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get('access-control-allow-origin')).toBe('*');
    expect(response.headers.get('access-control-allow-methods'))
      .toBe('GET, HEAD');
    expect(response.headers.get('access-control-allow-headers'))
      .toBe(TAI64N_HEADER_NONCE);
    expect(response.headers.get('access-control-expose-headers'))
      .toBe(exposeHeaders);
    expect(response.headers.get('vary')).toBeNull();
  });

  it('honours a specific origin and adds Vary: Origin', async () => {
    const origin = 'https://example.com';
    const handler = newTaistampHandler({ cors: origin });
    const response = await handler(
      new Request(baseURL, { method: 'OPTIONS' }),
    );

    expect(response.headers.get('access-control-allow-origin'))
      .toBe(origin);
    expect(response.headers.get('vary')).toBe('Origin');
  });

  it('treats empty cors as the wildcard default', async () => {
    const handler = newTaistampHandler({ cors: '' });
    const response = await handler(
      new Request(baseURL, { method: 'OPTIONS' }),
    );

    expect(response.headers.get('access-control-allow-origin')).toBe('*');
    expect(response.headers.get('vary')).toBeNull();
  });

  it('answers OPTIONS with 200 and Allow even when cors=false', async () => {
    const handler = newTaistampHandler({ cors: false });
    const response = await handler(
      new Request(baseURL, { method: 'OPTIONS' }),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get('allow')).toBe('GET, HEAD, OPTIONS');
    expect(response.headers.get('access-control-allow-origin')).toBeNull();
    expect(response.headers.get('access-control-allow-methods')).toBeNull();
    expect(response.headers.get('access-control-allow-headers')).toBeNull();
    expect(response.headers.get('access-control-expose-headers')).toBeNull();
  });

  it('advertises Allow: GET, HEAD, OPTIONS on 405 when CORS on', async () => {
    const handler = newTaistampHandler();
    const response = await handler(
      new Request(baseURL, { method: 'POST' }),
    );

    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('GET, HEAD, OPTIONS');
    expect(response.headers.get('access-control-allow-origin')).toBe('*');
  });

  it('advertises Allow: GET, HEAD, OPTIONS on 405 when cors=false', async () => {
    const handler = newTaistampHandler({ cors: false });
    const response = await handler(
      new Request(baseURL, { method: 'POST' }),
    );

    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('GET, HEAD, OPTIONS');
    expect(response.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('puts Allow-Origin and Expose-Headers on GET when CORS on', async () => {
    const handler = newTaistampHandler();
    const response = await handler(new Request(baseURL));

    expect(response.headers.get('access-control-allow-origin')).toBe('*');
    expect(response.headers.get('access-control-expose-headers'))
      .toBe(exposeHeaders);
  });

  it('puts Allow-Origin and Expose-Headers on HEAD when CORS on', async () => {
    const handler = newTaistampHandler();
    const response = await handler(
      new Request(baseURL, { method: 'HEAD' }),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get('access-control-allow-origin')).toBe('*');
    expect(response.headers.get('access-control-expose-headers'))
      .toBe(exposeHeaders);
  });

  it('echoes a scoped origin on GET and adds Vary: Origin', async () => {
    const origin = 'https://example.com';
    const handler = newTaistampHandler({ cors: origin });
    const response = await handler(new Request(baseURL));

    expect(response.status).toBe(200);
    expect(response.headers.get('access-control-allow-origin'))
      .toBe(origin);
    expect(response.headers.get('access-control-expose-headers'))
      .toBe(exposeHeaders);
    expect(response.headers.get('vary')).toBe('Origin');
  });

  it('echoes a scoped origin on 405 and adds Vary: Origin', async () => {
    const origin = 'https://example.com';
    const handler = newTaistampHandler({ cors: origin });
    const response = await handler(
      new Request(baseURL, { method: 'POST' }),
    );

    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('GET, HEAD, OPTIONS');
    expect(response.headers.get('access-control-allow-origin'))
      .toBe(origin);
    expect(response.headers.get('vary')).toBe('Origin');
  });

  it('omits CORS headers when cors=false', async () => {
    const handler = newTaistampHandler({ cors: false });
    const response = await handler(new Request(baseURL));

    expect(response.status).toBe(200);
    expect(response.headers.get('access-control-allow-origin')).toBeNull();
    expect(response.headers.get('access-control-expose-headers')).toBeNull();
  });

  it('puts Allow-Origin on a duplicate-nonce 200', async () => {
    const handler = newTaistampHandler();
    const response = await handler(new Request(baseURL, {
      headers: [
        [TAI64N_HEADER_NONCE, ':b3BhcXVlLW5vbmNlLXZhbHVlLXg=:'],
        [TAI64N_HEADER_NONCE, ':ZnJlc2gtY2xpZW50LW5vbmNl:'],
      ],
    }));

    expect(response.status).toBe(200);
    expect(response.headers.get('access-control-allow-origin')).toBe('*');
  });
});
