import {
  TAISTAMP_HEADER_KEY_SELECTOR,
  TAISTAMP_HEADER_LEAP_SECONDS,
  TAISTAMP_HEADER_NONCE,
  TAISTAMP_HEADER_SIGNATURE,
} from './const';

// `Access-Control-Allow-Methods` (Fetch) is the list
// of methods JS would ever preflight, so `OPTIONS` is
// omitted. This is intentionally narrower than the
// `Allow` header (RFC 9110 §9.3.7 method discovery,
// `GET, HEAD, OPTIONS`) the handler itself emits.
const CORS_ALLOW_METHODS = 'GET, HEAD';
const CORS_ALLOW_HEADERS = TAISTAMP_HEADER_NONCE;
const CORS_EXPOSE_HEADERS = [
  TAISTAMP_HEADER_LEAP_SECONDS,
  TAISTAMP_HEADER_NONCE,
  TAISTAMP_HEADER_KEY_SELECTOR,
  TAISTAMP_HEADER_SIGNATURE,
].join(', ');
// Spec §5.2 SHOULDs at least 600s; 10 minutes is the
// floor the spec example uses and keeps high-traffic
// cross-origin clients off a pre-flight per fetch.
const CORS_MAX_AGE = '600';

/**
 * The three CORS header maps the handler splices into
 * responses, keyed by response kind.
 *
 * - `preflight` — added to `OPTIONS 200` replies.
 * - `response` — added to successful `GET` / `HEAD`
 *   replies; carries `Access-Control-Expose-Headers`
 *   so browser JS can read the `TAI-*` headers.
 * - `error` — added to `405` replies; just the origin
 *   header (and `Vary` when scoped).
 */
export type CORSHeaderSets = {
  error: Record<string, string>
  preflight: Record<string, string>
  response: Record<string, string>
};

/**
 * Pre-bake the three CORS header maps the handler
 * splices into responses, keyed by response kind.
 * `cors === false` collapses every map to `{}` so the
 * spread is a no-op; missing or empty input falls back
 * to `'*'`; `cors === '*'` skips `Vary: Origin` (a
 * wildcard does not vary by origin); a scoped origin
 * adds `Vary: Origin` so caches can keep per-origin
 * variants distinct.
 */
export const buildCORSHeaders = (
  cors: false | string | undefined,
): CORSHeaderSets => {
  if (cors === false) {
    return { error: {}, preflight: {}, response: {} };
  }
  const origin = cors || '*';
  const vary: Record<string, string> =
    origin === '*' ? {} : { vary: 'Origin' };
  return {
    error: {
      'access-control-allow-origin': origin,
      ...vary,
    },
    preflight: {
      'access-control-allow-origin': origin,
      'access-control-allow-methods': CORS_ALLOW_METHODS,
      'access-control-allow-headers': CORS_ALLOW_HEADERS,
      'access-control-expose-headers': CORS_EXPOSE_HEADERS,
      'access-control-max-age': CORS_MAX_AGE,
      ...vary,
    },
    response: {
      'access-control-allow-origin': origin,
      'access-control-expose-headers': CORS_EXPOSE_HEADERS,
      ...vary,
    },
  };
};
