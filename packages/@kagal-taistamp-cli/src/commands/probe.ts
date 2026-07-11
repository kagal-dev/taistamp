import {
  type Bytes,
  type KeyConfig,
  parseSecretsToKeys,
  type Verifier,
} from '@kagal/ed25519-secret';
import {
  composeSignaturePayload,
  extractLeapSeconds,
  extractSignature,
  type LeapSeconds,
  newNonce,
  type Nonce,
  readASCII,
  tai64nLabelToUTC,
  TAISTAMP_CONTENT_LENGTH,
  TAISTAMP_HEADER_KEY_SELECTOR,
  TAISTAMP_HEADER_LEAP_SECONDS,
  TAISTAMP_HEADER_NONCE,
  TAISTAMP_HEADER_SIGNATURE,
  TAISTAMP_PATH,
} from '@kagal/taistamp';
import { defineCommand } from 'citty';
import { consola } from 'consola';

import { makeKeyRecordTXT } from '../utils';

import { ENV_FILE_ARG, reportCommandError } from './command-utils';

// Context label prepended to errors thrown under the
// `taistamp probe` subcommand.
const PROBE_CONTEXT = 'taistamp probe';
// Cap a single endpoint fetch so an unresponsive host
// fails the probe with a clear verdict instead of hanging
// the CLI indefinitely.
const PROBE_TIMEOUT_MS = 10_000;

/**
 * Coerce a CLI flag value (citty's bundled arg parser
 * yields `string`, `string[]`, or `undefined` for
 * repeated string flags) into a flat `string[]`.
 */
const asStringArray = (value: unknown): string[] => {
  if (value === undefined) return [];
  if (Array.isArray(value)) return value.map(String);
  return [String(value)];
};

// Does the input already attempt a scheme? ufo's
// PROTOCOL_STRICT_REGEX, minus the NUL byte a CLI
// argument can't carry — deliberately as lax as the URL
// parser itself, so scheme attempts reach the parser
// unmangled instead of being prefixed into a bogus host.
const SCHEME_PREFIX = /^[\s\w+.-]{2,}:[/\\]{1,2}/;

/**
 * Parse a candidate endpoint URL, accepting only the
 * schemes the probe can fetch. Input without a scheme
 * attempt is parsed under the implied `https://`; any
 * other scheme is rejected.
 */
const asHTTPURL = (value: string): undefined | URL => {
  const url =
    URL.parse(SCHEME_PREFIX.test(value) ? value : `https://${value}`);
  return url?.protocol === 'http:' || url?.protocol === 'https:' ?
    url :
    undefined;
};

/**
 * Resolve a CLI-supplied URL to the absolute taistamp
 * endpoint. Scheme-less input (`example.com`,
 * `localhost:3000`) is parsed under the implied
 * `https://` — a web convention, taistamp itself is
 * transport-agnostic. The path is smart-appended only
 * when the input is a bare origin (`/`); an explicit path
 * passes through unchanged so operators can probe mounted
 * variants. The result is rebuilt from the input's
 * `origin` and pathname only — query strings, hash
 * fragments, and embedded userinfo are dropped because
 * the taistamp wire shape carries none of them.
 */
export const resolveProbeURL = (input: string): URL => {
  const source = asHTTPURL(input);
  if (source === undefined) {
    throw new TypeError(`invalid endpoint URL: ${input}`);
  }
  const pathname =
    source.pathname === '/' ? TAISTAMP_PATH : source.pathname;
  return new URL(pathname, source.origin);
};

/**
 * Collect raw secret source strings from `--secret`
 * values and `--secret-env` variable contents. Each
 * returned string still needs `parseSecretsToKeys` —
 * sources may carry one or many `selector:base64`
 * tokens. An empty result is legal: the probe falls
 * back to a no-verification reachability check.
 *
 * @throws TypeError when a referenced env var is missing
 *   or empty
 */
export const collectSecretSources = (
  inline: readonly string[],
  envNames: readonly string[],
  env: Readonly<Record<string, string | undefined>> = process.env,
): string[] => {
  const sources: string[] = [...inline];
  for (const name of envNames) {
    const value = env[name];
    if (!value) {
      throw new TypeError(
        `collectSecretSources: env var ${name} is missing or empty`,
      );
    }
    sources.push(value);
  }
  return sources;
};

/**
 * Parse every secret source via `parseSecretsToKeys` and
 * merge the results into a Map keyed by selector. Later
 * sources win on selector collision. An empty `sources`
 * list (or sources that yield no tokens) returns an
 * empty map; the caller decides whether that's a
 * reachability-only probe or a misconfiguration. Each
 * loaded key is reported with its DNS TXT key-record
 * value, ready to publish under the selector.
 */
export const buildKeyMap = async (
  sources: readonly string[],
  context: string = 'buildKeyMap',
): Promise<Map<string, KeyConfig>> => {
  const parsed = await Promise.all(
    sources.map((source, index) =>
      parseSecretsToKeys(source, true, `${context}: source ${index + 1}`),
    ),
  );
  const map = new Map<string, KeyConfig>();
  for (const key of parsed.flat()) {
    map.set(key.selector, key);
    const record = await makeKeyRecordTXT(key, context);
    consola.info(`loaded key: ${key.selector} TXT ${record}`);
  }
  return map;
};

/**
 * Resolve a {@link Verifier} for the selector an endpoint
 * advertises. `undefined` means the source holds no
 * verifier for the selector; a throw means resolution
 * itself failed. Implementations may be synchronous or
 * asynchronous — the probe awaits the result either way.
 *
 * @param selector - selector advertised by the endpoint
 * @param domain - hostname the probed response came from
 */
export type GetVerifierFn = (
  selector: string,
  domain: string,
) => Promise<undefined | Verifier> | undefined | Verifier;

/**
 * Inputs to {@link probeEndpoint}. `fetchFn` defaults to
 * the global `fetch`; tests inject a stub handler so the
 * probe runs in-process against a real
 * `newTaistampHandler`. Without `getVerifier` the probe
 * has nothing to verify against: it stops after the
 * reachability gates and reports the advertised headers
 * as informational.
 */
export interface ProbeOptions {
  fetchFn?: typeof fetch
  getVerifier?: GetVerifierFn
  url: URL
}

/**
 * What a state function hands the trampoline: the next
 * state function, already bound to its state, or the
 * final probe verdict. The driver in {@link probeEndpoint}
 * keeps calling until a verdict comes back, so each state
 * function returns its successor instead of calling it —
 * the stack unwinds between steps.
 */
type ProbeNext = (() => ProbeNext | Promise<ProbeNext>) | boolean;

/**
 * Probe state at the start of a run. Each state function
 * consumes one phase interface and hands the trampoline a
 * thunk over the phase it produced. The `Omit` chain
 * below prunes each field at its last reader, so a
 * mis-ordered dereference is a compile error rather than
 * `undefined` at runtime.
 */
interface ProbeInputs {
  fetchFn: typeof fetch
  getVerifier?: GetVerifierFn
  nonce: Nonce
  url: URL
}

/** After the fetch: `fetchFn` is consumed. */
interface Responded extends Omit<ProbeInputs, 'fetchFn'> {
  response: Response
}

/**
 * After verifier resolution: `getVerifier` and `url` are
 * consumed; the resolved selector/verifier pair travels
 * on.
 */
interface Resolved extends Omit<Responded, 'getVerifier' | 'url'> {
  selector: string
  verifier: Verifier
}

/** After the body read. */
interface Bodied extends Resolved {
  body: string
}

/** After the leap-seconds header parse. */
interface Leaped extends Bodied {
  leap: LeapSeconds
}

/**
 * After the signature header parse — the last reader of
 * the response, so it's pruned here. Everything signature
 * verification consumes.
 */
interface Verifiable extends Omit<Leaped, 'response'> {
  signature: Bytes
}

/**
 * Canonical step labels in probe order. Shared with the
 * test suite so `findStep` assertions track renames at
 * compile time instead of drifting against literals.
 */
export const STEP_LABELS = {
  fetch: 'fetch endpoint',
  httpStatus: 'http status',
  nonceEchoed: 'nonce echoed',
  selectorAdvertised: 'selector advertised',
  signatureAdvertised: 'signature advertised',
  selectorMatched: 'selector matched',
  bodyRead: 'body read',
  bodyShape: 'body shape',
  leapSeconds: 'leap-seconds header',
  signatureHeader: 'signature header',
  signatureVerified: 'signature verified',
} as const;

/**
 * Report a gate verdict the moment the state function
 * resolves it — consola success or error with the step
 * label and detail — and return the verdict so call sites
 * can branch on it.
 */
const gate = (label: string, ok: boolean, detail: string): boolean => {
  const message = `${label}: ${detail}`;
  if (ok) consola.success(message);
  else consola.error(message);
  return ok;
};

/**
 * Report an informational line. Info lines never affect
 * the probe verdict; a resolver-less probe uses them to
 * surface the advertised headers.
 */
const info = (label: string, detail: string): void => {
  consola.info(`${label}: ${detail}`);
};

const describeFetchError = (error: unknown): string => {
  if (error instanceof Error) {
    return error.name === 'TimeoutError' ?
      `timed out after ${PROBE_TIMEOUT_MS} ms` :
      error.message;
  }
  return String(error);
};

// Render the verified label with the UTC instant it
// encodes, so an operator reads the signed time rather
// than only the wire form. taistamp serves
// millisecond-granular labels, so `new Date(...)`
// round-trips without loss. `tai64nLabelToUTC` returns
// `undefined` only for a body that cleared the length gate
// without being a TAI64N label — unreachable from a
// conforming handler, where the raw label then stands on
// its own.
const describeLabel = (label: string, leap: LeapSeconds): string => {
  const utc = tai64nLabelToUTC(label, leap);
  return utc === undefined ?
    label :
    `${label} (${new Date(utc).toISOString()})`;
};

// I/O: send the nonce'd GET. Gates only on transport
// failure; the HTTP status is checkStatus's verdict.
const fetchEndpoint = async (s: ProbeInputs): Promise<ProbeNext> => {
  let response: Response;
  try {
    response = await s.fetchFn(s.url, {
      method: 'GET',
      headers: { [TAISTAMP_HEADER_NONCE]: s.nonce },
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
  } catch (error) {
    return gate(STEP_LABELS.fetch, false, describeFetchError(error));
  }
  gate(STEP_LABELS.fetch, true, 'response received');
  return () => checkStatus({
    getVerifier: s.getVerifier, nonce: s.nonce, response, url: s.url,
  });
};

const checkStatus = (s: Responded): ProbeNext => {
  const detail = `${s.response.status} ${s.response.statusText}`.trim();
  if (!gate(STEP_LABELS.httpStatus, s.response.ok, detail)) return false;
  return () => checkNonceEcho(s);
};

const checkNonceEcho = (s: Responded): ProbeNext => {
  const echoed = s.response.headers.get(TAISTAMP_HEADER_NONCE);
  const ok = echoed === s.nonce;
  const detail = ok ?
    'matched' :
    `expected ${s.nonce}, got ${echoed ?? '(missing)'}`;
  if (!gate(STEP_LABELS.nonceEchoed, ok, detail)) return false;
  return () => resolveVerifier(s);
};

// Resolve a verifier for the advertised selector. With no
// resolver installed there is nothing to verify against:
// the probe reports the advertised headers as
// informational and ends as a plain reachability check.
const resolveVerifier = async (s: Responded): Promise<ProbeNext> => {
  const selector = s.response.headers.get(TAISTAMP_HEADER_KEY_SELECTOR);
  if (s.getVerifier === undefined) {
    info(STEP_LABELS.selectorAdvertised, selector ?? '(missing)');
    info(
      STEP_LABELS.signatureAdvertised,
      s.response.headers.get(TAISTAMP_HEADER_SIGNATURE) ?? '(missing)',
    );
    return true;
  }
  if (selector === null) {
    return gate(
      STEP_LABELS.selectorMatched, false,
      `${TAISTAMP_HEADER_KEY_SELECTOR} missing`,
    );
  }
  try {
    const verifier = await s.getVerifier(selector, s.url.hostname);
    if (verifier === undefined) {
      return gate(
        STEP_LABELS.selectorMatched, false,
        `no verifier for ${selector}`,
      );
    }
    gate(STEP_LABELS.selectorMatched, true, selector);
    return () => readBody({
      nonce: s.nonce, response: s.response, selector, verifier,
    });
  } catch (error) {
    return gate(
      STEP_LABELS.selectorMatched, false,
      error instanceof Error ? error.message : String(error),
    );
  }
};

// I/O: read the body as raw ASCII octets. A non-ASCII
// octet fails here with the reader's message; the length
// is checkBodyShape's verdict.
const readBody = async (s: Resolved): Promise<ProbeNext> => {
  let body: string;
  try {
    body = await readASCII(s.response);
  } catch (error) {
    return gate(
      STEP_LABELS.bodyRead, false,
      error instanceof Error ? error.message : String(error),
    );
  }
  gate(STEP_LABELS.bodyRead, true, `${body.length} octets`);
  return () => checkBodyShape({ ...s, body });
};

// Validate: the body is exactly one TAI64N label long.
const checkBodyShape = (s: Bodied): ProbeNext => {
  const ok = s.body.length === TAISTAMP_CONTENT_LENGTH;
  const detail = ok ?
    `${s.body.length} octets` :
    `expected ${TAISTAMP_CONTENT_LENGTH} octets, got ${s.body.length}`;
  if (!gate(STEP_LABELS.bodyShape, ok, detail)) return false;
  return () => parseLeapHeader(s);
};

const parseLeapHeader = (s: Bodied): ProbeNext => {
  const leap = extractLeapSeconds(s.response.headers);
  if (leap === undefined) {
    // `extractLeapSeconds` collapses every "treat as
    // unsigned" case (missing, empty, non-decimal,
    // out-of-u32-range) into one `undefined`; re-read the
    // raw header only to name the missing-vs-malformed
    // split in the failure detail.
    const raw = s.response.headers.get(TAISTAMP_HEADER_LEAP_SECONDS);
    return gate(
      STEP_LABELS.leapSeconds, false,
      raw === null ?
        `${TAISTAMP_HEADER_LEAP_SECONDS} missing` :
        `expected u32 leap-seconds, got ${raw || '(empty)'}`,
    );
  }
  gate(STEP_LABELS.leapSeconds, true, String(leap));
  return () => parseSignatureHeader({ ...s, leap });
};

// Parse: decode the signature header to raw bytes. Last
// reader of the response; the next phase omits it.
const parseSignatureHeader = (s: Leaped): ProbeNext => {
  const signature = extractSignature(s.response.headers);
  if (signature === undefined) {
    // `extractSignature` collapses every failure into one
    // `undefined`; re-read the raw header only to name the
    // missing-vs-malformed split in the failure detail.
    const raw = s.response.headers.get(TAISTAMP_HEADER_SIGNATURE);
    return gate(
      STEP_LABELS.signatureHeader, false,
      raw === null ?
        `${TAISTAMP_HEADER_SIGNATURE} missing` :
        `malformed ${TAISTAMP_HEADER_SIGNATURE} value`,
    );
  }
  gate(
    STEP_LABELS.signatureHeader, true,
    `${signature.length} octets`,
  );
  return () => verifySignature({
    body: s.body, leap: s.leap, nonce: s.nonce,
    selector: s.selector, signature, verifier: s.verifier,
  });
};

// Validate: Ed25519 signature over the composed payload.
// Terminal state; consumes everything the probe carried.
const verifySignature = async (s: Verifiable): Promise<boolean> => {
  const payload = composeSignaturePayload(
    s.body, s.leap, s.selector, s.nonce,
  );
  try {
    const valid = await s.verifier.verify(s.signature, payload);
    return gate(
      STEP_LABELS.signatureVerified,
      valid,
      valid ?
        describeLabel(s.body, s.leap) :
        'verifier rejected the signature',
    );
  } catch (error) {
    return gate(
      STEP_LABELS.signatureVerified, false,
      error instanceof Error ? error.message : String(error),
    );
  }
};

/**
 * Probe a remote `/.well-known/taistamp` endpoint,
 * reporting each step via consola as it resolves. Every
 * probe gates on HTTP reachability and nonce echo. With a
 * `getVerifier` resolver the probe continues through
 * verifier resolution for the advertised selector,
 * response body shape, parseable TAI-Leap-Seconds and
 * TAI-Signature headers, and Ed25519 signature
 * verification under the resolved verifier. Without one
 * it reports the advertised selector and signature header
 * as informational and passes.
 *
 * @returns `true` when every gate passed
 */
export const probeEndpoint = async (
  options: ProbeOptions,
): Promise<boolean> => {
  // Trampoline: each state function reports its outcome,
  // then returns its successor bound to the state it
  // produced; calling from the loop instead of chaining
  // keeps the stack flat between steps.
  let next: ProbeNext = () => fetchEndpoint({
    fetchFn: options.fetchFn ?? globalThis.fetch,
    getVerifier: options.getVerifier,
    nonce: newNonce(),
    url: options.url,
  });
  while (typeof next === 'function') {
    next = await next();
  }
  return next;
};

/**
 * `taistamp probe <url>` — operator-side endpoint check.
 * Assembles a key bag from `--secret` and `--secret-env`,
 * sends one GET with a fresh nonce, prints per-step
 * verdicts via consola, and exits non-zero on any
 * failure.
 */
export const probe = defineCommand({
  meta: {
    name: 'probe',
    description: 'Probe a remote /.well-known/taistamp endpoint',
  },
  args: {
    ...ENV_FILE_ARG,
    url: {
      type: 'positional',
      description: 'origin or full endpoint URL (e.g. example.com); ' +
        'https is assumed when no scheme is given',
      required: true,
    },
    secret: {
      type: 'string',
      description: '`selector:base64` secret; repeatable',
    },
    secretEnv: {
      type: 'string',
      description: 'environment variable holding one or more secrets',
    },
  },
  async run({ args }) {
    try {
      const inline = asStringArray(args.secret);
      const envNames = asStringArray(args.secretEnv);
      const sources = collectSecretSources(inline, envNames);
      const keys = await buildKeyMap(sources, PROBE_CONTEXT);
      const url = resolveProbeURL(args.url);
      consola.info(`probing ${url}`);
      let getVerifier: GetVerifierFn | undefined;
      if (keys.size === 0) {
        consola.warn(
          'no --secret or --secret-env — signature verification skipped',
        );
      } else {
        consola.info(`trusted selectors: ${[...keys.keys()].join(', ')}`);
        getVerifier = (selector) => keys.get(selector)?.verifier;
      }
      const ok = await probeEndpoint({ getVerifier, url });
      if (!ok) process.exitCode = 1;
    } catch (error) {
      reportCommandError(error);
      process.exitCode = 1;
    }
  },
});
