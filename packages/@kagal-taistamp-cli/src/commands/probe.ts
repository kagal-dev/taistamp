import {
  type Bytes,
  decodeBase64,
  encodeBase64,
  getRandom,
  type KeyConfig,
  parseSecretsToKeys,
} from '@kagal/ed25519-secret';
import {
  asNonce,
  composeSignaturePayload,
  type LeapSeconds,
  type Nonce,
  readLabel,
  TAI64N_HEADER_KEY_SELECTOR,
  TAI64N_HEADER_LEAP_SECONDS,
  TAI64N_HEADER_NONCE,
  TAI64N_HEADER_SIGNATURE,
  TAISTAMP_PATH,
} from '@kagal/taistamp';
import { defineCommand } from 'citty';
import { consola } from 'consola';

import { reportCommandError } from './command-utils';

const NONCE_BYTE_LENGTH = 16;
const ED25519_SIGNATURE_BYTES = 64;
// Cap a single endpoint fetch so an unresponsive host
// fails the probe with a clear verdict instead of hanging
// the CLI indefinitely.
const PROBE_TIMEOUT_MS = 10_000;
// Standard or URL-safe base64 of exactly 64 octets:
// 86 alphabet chars with optional `==` padding. The
// decoder accepts both alphabets so the pattern follows
// suit.
const SIGNATURE_PATTERN = /^:([\d+/A-Za-z_-]{86}(?:==)?):$/;

/**
 * Coerce a CLI flag value (mri returns `string`,
 * `string[]`, or `undefined` for repeated string flags)
 * into a flat `string[]`.
 */
const asStringArray = (value: unknown): string[] => {
  if (value === undefined) return [];
  if (Array.isArray(value)) return value.map(String);
  return [String(value)];
};

/**
 * Resolve a CLI-supplied URL to the absolute taistamp
 * endpoint. The path is smart-appended only when the
 * input is a bare origin (`/`); an explicit path passes
 * through unchanged so operators can probe mounted
 * variants. The result is rebuilt from the input's
 * `origin` and pathname only — query strings, hash
 * fragments, and embedded userinfo are dropped because
 * the taistamp wire shape carries none of them.
 */
export const resolveProbeURL = (input: string): URL => {
  const source = new URL(input);
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
 * reachability-only probe or a misconfiguration.
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
  for (const keys of parsed) {
    for (const key of keys) {
      map.set(key.selector, key);
      consola.info(`loaded key: ${key.selector} ${key.publicJWK.x}`);
    }
  }
  return map;
};

/**
 * Discriminates a {@link ProbeStep}'s role in the
 * outcome. `gate` steps decide whether the probe passes
 * and short-circuit the run on failure; `info` steps are
 * informational (reachability-mode header reports) and
 * never affect `ProbeResult.ok`.
 */
export type ProbeStepKind = 'gate' | 'info';

/**
 * One labelled check inside a {@link probeEndpoint} run.
 * `detail` carries a human-readable note (status text,
 * mismatch reason, etc.) that the CLI surfaces alongside
 * the verdict.
 */
export interface ProbeStep {
  detail?: string
  kind: ProbeStepKind
  label: string
  ok: boolean
}

/**
 * Outcome of a {@link probeEndpoint} run. `ok` is the
 * conjunction of every gate step; `info` steps are
 * recorded but do not affect the verdict. The CLI prints
 * each step via consola and exits non-zero when `ok` is
 * `false`.
 */
export interface ProbeResult {
  ok: boolean
  steps: ProbeStep[]
}

interface BaseProbeOptions {
  fetchFn?: typeof fetch
  url: URL
}

/**
 * Reachability-only probe inputs: confirm HTTP
 * reachability and nonce echo, then report the
 * advertised TAI-Key-Selector and TAI-Signature
 * headers as informational. No verification is
 * performed.
 */
export interface ReachableProbeOptions extends BaseProbeOptions {
  mode: 'reachable'
}

/**
 * Strict-trust probe inputs: confirm HTTP reachability,
 * nonce echo, selector membership in `keys`, and
 * Ed25519 signature verification under the matched key.
 */
export interface VerifyProbeOptions extends BaseProbeOptions {
  keys: ReadonlyMap<string, KeyConfig>
  mode: 'verify'
}

/**
 * Inputs to {@link probeEndpoint}. `fetchFn` defaults to
 * the global `fetch`; tests inject a stub handler so the
 * probe runs in-process against a real `newTaistampHandler`.
 */
export type ProbeOptions = ReachableProbeOptions | VerifyProbeOptions;

interface NonceMaterial {
  brandedNonce: Nonce
  nonce: string
}

interface SelectedKey {
  match: KeyConfig
  selector: string
}

/**
 * Outcome of one probe helper. `step` is always recorded;
 * `next` carries data forward to the next helper when the
 * step passed, and is absent on failure.
 */
interface ProbeStepResult<T = true> {
  next?: T
  step: ProbeStep
}

const gateStep = (
  label: string,
  ok: boolean,
  detail?: string,
): ProbeStep => ({ detail, kind: 'gate', label, ok });

const infoStep = (label: string, detail?: string): ProbeStep => ({
  detail, kind: 'info', label, ok: true,
});

const prepareNonce = (): NonceMaterial => {
  const nonce = `:${encodeBase64(getRandom(NONCE_BYTE_LENGTH))}:`;
  const brandedNonce = asNonce(nonce);
  if (!brandedNonce) {
    throw new TypeError(
      `prepareNonce: generated nonce ${nonce} failed asNonce`,
    );
  }
  return { brandedNonce, nonce };
};

const describeFetchError = (error: unknown): string => {
  if (error instanceof Error) {
    return error.name === 'TimeoutError' ?
      `timed out after ${PROBE_TIMEOUT_MS} ms` :
      error.message;
  }
  return String(error);
};

const fetchEndpoint = async (
  fetchFn: typeof fetch,
  url: URL,
  nonce: string,
): Promise<ProbeStepResult<Response>> => {
  try {
    const response = await fetchFn(url, {
      method: 'GET',
      headers: { [TAI64N_HEADER_NONCE]: nonce },
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    const detail = `${response.status} ${response.statusText}`.trim();
    return {
      step: gateStep('fetch endpoint', response.ok, detail),
      next: response.ok ? response : undefined,
    };
  } catch (error) {
    return {
      step: gateStep('fetch endpoint', false, describeFetchError(error)),
    };
  }
};

const verifyNonceEcho = (
  response: Response,
  nonce: string,
): ProbeStepResult => {
  const echoed = response.headers.get(TAI64N_HEADER_NONCE);
  const ok = echoed === nonce;
  return {
    step: gateStep(
      'nonce echoed',
      ok,
      ok ? 'matched' : `expected ${nonce}, got ${echoed ?? '(missing)'}`,
    ),
    next: ok ? true : undefined,
  };
};

const reportAdvertised = (response: Response): ProbeStep[] => [
  infoStep(
    'selector advertised',
    response.headers.get(TAI64N_HEADER_KEY_SELECTOR) ?? '(missing)',
  ),
  infoStep(
    'signature advertised',
    response.headers.get(TAI64N_HEADER_SIGNATURE) ?? '(missing)',
  ),
];

const selectKey = (
  response: Response,
  keys: ReadonlyMap<string, KeyConfig>,
): ProbeStepResult<SelectedKey> => {
  const selector = response.headers.get(TAI64N_HEADER_KEY_SELECTOR);
  if (selector === null) {
    return {
      step: gateStep(
        'selector matched', false,
        `${TAI64N_HEADER_KEY_SELECTOR} missing`,
      ),
    };
  }
  const match = keys.get(selector);
  if (!match) {
    return {
      step: gateStep(
        'selector matched', false,
        `${selector} not in trusted bag`,
      ),
    };
  }
  return {
    step: gateStep('selector matched', true, selector),
    next: { match, selector },
  };
};

/**
 * Gate on the response body being a well-formed TAI64N
 * label, decoding it for the signature step. A malformed
 * body — wrong length or a non-ASCII octet — fails the
 * step with the reader's message.
 */
const verifyBodyShape = async (
  response: Response,
): Promise<ProbeStepResult<string>> => {
  let label: string;
  try {
    label = await readLabel(response);
  } catch (error) {
    return {
      step: gateStep(
        'body shape', false,
        error instanceof Error ? error.message : String(error),
      ),
    };
  }
  return {
    step: gateStep('body shape', true, `${label.length} octets`),
    next: label,
  };
};

const parseLeapHeader = (
  response: Response,
): ProbeStepResult<LeapSeconds> => {
  const header = response.headers.get(TAI64N_HEADER_LEAP_SECONDS);
  if (header === null) {
    return {
      step: gateStep(
        'leap-seconds header', false,
        `${TAI64N_HEADER_LEAP_SECONDS} missing`,
      ),
    };
  }
  // A digit-only run rejects the empty/whitespace value
  // `Number()` would otherwise coerce to a silent `0`,
  // alongside signs, decimals, and non-numerics.
  if (!/^\d+$/.test(header)) {
    return {
      step: gateStep(
        'leap-seconds header', false,
        `expected non-negative integer, got ${header || '(empty)'}`,
      ),
    };
  }
  return {
    step: gateStep('leap-seconds header', true, header),
    next: Number(header) as LeapSeconds,
  };
};

const parseSignatureHeader = (
  response: Response,
): ProbeStepResult<Bytes> => {
  const header = response.headers.get(TAI64N_HEADER_SIGNATURE);
  if (header === null) {
    return {
      step: gateStep(
        'signature header', false,
        `${TAI64N_HEADER_SIGNATURE} missing`,
      ),
    };
  }
  const matched = SIGNATURE_PATTERN.exec(header);
  if (!matched) {
    return {
      step: gateStep(
        'signature header', false,
        `malformed ${TAI64N_HEADER_SIGNATURE} value`,
      ),
    };
  }
  let signature: Bytes;
  try {
    signature = decodeBase64(matched[1]);
  } catch (error) {
    return {
      step: gateStep(
        'signature header', false,
        error instanceof Error ? error.message : String(error),
      ),
    };
  }
  if (signature.length !== ED25519_SIGNATURE_BYTES) {
    // Defence-in-depth: SIGNATURE_PATTERN already admits only
    // 86/88-char encodings of 64 bytes under the standard
    // alphabet, but a non-RFC-compliant decoder could still
    // surface a short buffer here.
    return {
      step: gateStep(
        'signature header', false,
        `expected ${ED25519_SIGNATURE_BYTES} octets, got ${signature.length}`,
      ),
    };
  }
  return {
    step: gateStep('signature header', true, `${signature.length} octets`),
    next: signature,
  };
};

const verifySignature = async (
  selected: SelectedKey,
  body: string,
  leap: LeapSeconds,
  signature: Bytes,
  brandedNonce: Nonce,
): Promise<ProbeStep> => {
  const payload = composeSignaturePayload(
    body, leap, selected.selector, brandedNonce,
  );
  try {
    const valid = await crypto.subtle.verify(
      'Ed25519', selected.match.publicKey, signature, payload,
    );
    return gateStep(
      'signature verified',
      valid,
      valid ? body : 'crypto.subtle.verify rejected the signature',
    );
  } catch (error) {
    return gateStep(
      'signature verified', false,
      error instanceof Error ? error.message : String(error),
    );
  }
};

/**
 * Probe a remote `/.well-known/taistamp` endpoint. In
 * `'verify'` mode the probe gates on HTTP reachability,
 * nonce echo, selector membership in `keys`, response
 * body shape, parseable TAI-Leap-Seconds and
 * TAI-Signature headers, and Ed25519 signature
 * verification under the matched public key. In
 * `'reachable'` mode the probe gates only on
 * reachability and nonce echo, then reports the
 * advertised selector and signature header as
 * informational.
 */
export const probeEndpoint = async (
  options: ProbeOptions,
): Promise<ProbeResult> => {
  const { url, fetchFn = globalThis.fetch } = options;
  const steps: ProbeStep[] = [];
  const finalise = (): ProbeResult => ({
    ok: steps.every((step) => step.kind === 'info' || step.ok),
    steps,
  });
  const push = <T>(result: ProbeStepResult<T>): T | undefined => {
    steps.push(result.step);
    return result.next;
  };

  const { brandedNonce, nonce } = prepareNonce();

  const response = push(await fetchEndpoint(fetchFn, url, nonce));
  if (!response) return finalise();
  if (!push(verifyNonceEcho(response, nonce))) return finalise();

  if (options.mode === 'reachable') {
    steps.push(...reportAdvertised(response));
    return finalise();
  }

  const selected = push(selectKey(response, options.keys));
  if (!selected) return finalise();

  const body = push(await verifyBodyShape(response));
  if (body === undefined) return finalise();

  const leap = push(parseLeapHeader(response));
  if (leap === undefined) return finalise();

  const signature = push(parseSignatureHeader(response));
  if (!signature) return finalise();

  steps.push(
    await verifySignature(selected, body, leap, signature, brandedNonce),
  );
  return finalise();
};

const printStep = (step: ProbeStep): void => {
  const message = step.detail ?
    `${step.label}: ${step.detail}` :
    step.label;
  if (step.kind === 'info') consola.info(message);
  else if (step.ok) consola.success(message);
  else consola.fail(message);
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
    url: {
      type: 'positional',
      description: 'origin or full endpoint URL (e.g. https://example.com)',
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
      const keys = await buildKeyMap(sources, 'taistamp probe');
      const url = resolveProbeURL(args.url);
      consola.info(`probing ${url}`);
      const options: ProbeOptions = keys.size === 0 ?
        { url, mode: 'reachable' } :
        { keys, mode: 'verify', url };
      if (options.mode === 'reachable') {
        consola.warn(
          'no --secret or --secret-env — signature verification skipped',
        );
      } else {
        consola.info(`trusted selectors: ${[...keys.keys()].join(', ')}`);
      }
      const result = await probeEndpoint(options);
      for (const step of result.steps) printStep(step);
      if (!result.ok) process.exitCode = 1;
    } catch (error) {
      reportCommandError(error);
      process.exitCode = 1;
    }
  },
});
