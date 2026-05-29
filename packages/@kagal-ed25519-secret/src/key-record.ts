// cSpell:words ALNUMPUNC VALCHAR tval tvals vars
import { decodeBase64, encodeKey } from './utils';
import { importVerifyKey, newVerifier, type Verifier } from './verifier';

/**
 * DKIM-style tag-list key record (RFC 6376 §3.2
 * syntax, §3.6.1 `p=` semantics) for publishing and
 * consuming public verification keys via DNS TXT
 * records.
 *
 * `P` tracks the form in use for the `p` field:
 * `Uint8Array` for raw key bytes (parse direction;
 * the shape a DNS-record decoder returns); `string`
 * for base64-encoded key bytes (publish direction;
 * the wire shape of `p=`); `CryptoKey` for the
 * verify-only key (post-import); `Verifier` for that
 * key wrapped as a verifier (post-wrap).
 *
 * Additional DKIM tags (e.g. `h`, `s`, `t`, `n`, `g`)
 * appear as own properties under their tag name and
 * are reached via the index signature. Consumers
 * needing typed access to a specific tag set extend
 * this interface — e.g. a parser produces
 * `interface DKIMKeyRecord extends KeyRecord<Uint8Array>`
 * with the declared tags, narrowing those keys to
 * `string` while arbitrary extras remain reachable
 * via the signature.
 *
 * Tag names and values are case-sensitive per
 * RFC 6376 §3.2. Empty values are distinct from
 * omitted tags: an absent `v=` leaves
 * `v === undefined`, an explicitly empty `v=` sets
 * `v === ''`. The `p=` material follows §3.6.1:
 * an empty value (`p: undefined` here) signals key
 * revocation; an absent `p=` is not a key record at
 * all and a parser rejects the input rather than
 * returning `undefined`.
 */
export interface KeyRecord<
  P = Uint8Array,
> {
  k?: string
  p: P | undefined
  v?: string

  [tag: string]: P | string | undefined
}

/**
 * Input for {@link makeKeyRecords}: a public
 * {@link CryptoKey} of a supported algorithm paired
 * with the DKIM-style selector under which it will be
 * published. Omitting
 * `publicKey` publishes a revocation record for the
 * selector instead of a key — empty `p=` per RFC 6376
 * §3.6.1. The selector doesn't appear in the produced
 * record — RFC 6376 §3.2 has no `s=` tag in the
 * key-record syntax (selectors live in the DNS owner
 * name, e.g. `<selector>._domainkey.<domain>`).
 */
export interface KeyRecordInput {
  publicKey?: CryptoKey
  selector: string
}

/**
 * Build {@link KeyRecord}s ready for
 * publication as `<selector>._keys.<domain>`
 * DNS TXT values, keyed by their selector. Returns a
 * frozen `{ [selector]: record }` object: `undefined`
 * or an empty array yields `{}`; a single
 * {@link KeyRecordInput} yields a single-entry
 * object; an array yields one entry per input
 * (insertion order matches input order; duplicate
 * selectors last-write-wins).
 *
 * `k=` is the public key's algorithm — its lowercase
 * WebCrypto name (`'ed25519'`); `p=` is the standard
 * base64 of the key's raw bytes (via
 * {@link encodeKey}, which rejects an unsupported or
 * non-extractable key). An input that omits `publicKey`
 * is a revocation record per RFC 6376 §3.6.1 —
 * `p: undefined` (empty `p=`) with `k=` omitted too,
 * since there's no key to name. `v=` and any
 * additional tags come from `template` (the latter via
 * its index signature); the function synthesises
 * nothing beyond `k=` and `p=`. The selector is the key in the
 * returned object — it isn't repeated as a tag on the
 * record (RFC 6376 §3.2 has no `s=` tag in the
 * key-record syntax). Selectors are passed through
 * verbatim; validate with {@link assertValidSelector}
 * at the caller if needed.
 *
 * `context` (default `'makeKeyRecords'`) prefixes any
 * thrown error. Array inputs get
 * `<context>: input N` to disambiguate which entry
 * failed; a single input throws under the bare
 * `<context>`.
 */
export const makeKeyRecords = async <K extends KeyRecordInput>(
  input: K | K[] | undefined,
  template: Partial<KeyRecord<string>> = {},
  context: string = 'makeKeyRecords',
): Promise<Readonly<Record<string, KeyRecord<string>>>> => {
  const wasArray = Array.isArray(input);
  const inputs: readonly K[] = input === undefined ? [] : (wasArray ? input : [input]);
  const contextFor: (i: number) => string = wasArray ? (i) => `${context}: input ${i}` : () => context;
  const entries = await Promise.all(
    inputs.map((entry, i) => buildEntry(entry, i, contextFor, template)),
  );
  return Object.freeze(Object.fromEntries(entries));
};

const buildEntry = async (
  input: KeyRecordInput,
  i: number,
  contextFor: (i: number) => string,
  template: Partial<KeyRecord<string>>,
): Promise<readonly [string, KeyRecord<string>]> => {
  const c = contextFor(i);
  // Strip `p` and `k` out of the template so a caller's
  // values can't override the synthesised `k=`/`p=` (and
  // so a template `k=` doesn't leak onto a revocation
  // record); `extraTags` carries the rest through.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { p: _p, k: _k, ...extraTags } = template;

  if (input.publicKey === undefined) {
    // No public key → revocation record: empty `p=`
    // (RFC 6376 §3.6.1), carried as `p: undefined`,
    // with `k=` omitted since there's no key to name.
    const record: KeyRecord<string> = { ...extraTags, p: undefined };
    return [input.selector, record] as const;
  }

  const p = await encodeKey(input.publicKey, c);
  const k = input.publicKey.algorithm.name.toLowerCase();
  const record: KeyRecord<string> = { ...extraTags, k, p };
  return [input.selector, record] as const;
};

/**
 * Parse a DNS TXT-record value as a single DKIM-style
 * key record (RFC 6376 §3.2 tag-list grammar; §3.6.1
 * `p=` semantics for the base64 key bytes and the
 * revoked-on-empty convention).
 *
 * Returns one record. RFC 6376 §3.6.2.2 mandates one
 * TXT RR per selector ("TXT RRs MUST be unique for a
 * particular selector name; that is, if there are
 * multiple records in an RRset, the results are
 * undefined"), so rotation is handled with a fresh
 * selector, not with multiple records under one name.
 *
 * Lenient on semantics: unknown tag names and
 * unknown `v`/`k` values pass through; missing
 * `v`/`k` is tolerated. Unknown tags land as own
 * properties on the returned record under their raw
 * tag name (RFC 6376 §3.2: "Unrecognized tags MUST
 * be ignored" — preserved here for inspection and
 * round-trip).
 *
 * Strict on syntax: malformed tag-list grammar,
 * malformed quoted character-strings, duplicate tag
 * names, missing `p=`, and undecodable `p=` base64 all
 * throw `TypeError`.
 *
 * Input shapes covered:
 *
 * - A raw string holding the tag-list:
 *   `'v=tai1; k=ed25519; p=...'`.
 * - A DoH-JSON-style string with one or more
 *   whitespace-separated quoted character-strings,
 *   concatenated with no intervening whitespace per
 *   RFC 1035 §3.3 and RFC 6376 §3.6.2.2:
 *   `'"v=tai1; ...; p=..."'` or
 *   `'"v=tai1; k=ed" "25519; p=..."'`.
 * - An array of pre-extracted character-strings (Node
 *   `dns.resolveTxt` inner array, DoH-wire parsers
 *   like `dns-packet`), concatenated with no
 *   intervening whitespace:
 *   `['v=tai1; k=ed', '25519; p=...']`.
 *
 * @param input - TXT record value: raw string,
 *   DoH-JSON-quoted string, or array of pre-extracted
 *   character-strings
 * @param context - optional prefix prepended to thrown
 *   error messages as `${context}: `
 */
export const parseKeyRecord = (
  input: readonly string[] | string,
  context?: string,
): KeyRecord<Uint8Array> => {
  const prefix = context ? `${context}: ` : '';
  const source = flatten(input, context);
  if (source === '') {
    throw new TypeError(`${prefix}empty input`);
  }
  const parts = splitTagSpecs(source);
  if (parts.length === 0) {
    throw new TypeError(`${prefix}empty tag-list`);
  }

  const record: Record<string, string | Uint8Array | undefined> = {};
  const seen = new Set<string>();
  let pSeen = false;

  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed === '') {
      throw new TypeError(`${prefix}empty tag-spec`);
    }
    const spec = parseTagSpec(part);
    if (spec === undefined) {
      throw new TypeError(`${prefix}invalid tag-spec: ${trimmed}`);
    }
    const { name, value } = spec;
    if (seen.has(name)) {
      throw new TypeError(`${prefix}duplicate tag: ${name}`);
    }
    seen.add(name);
    if (name === 'p') {
      pSeen = true;
      // RFC 6376 §3.6.1: empty `p=` signals revocation.
      const compact = value.replaceAll(/\s+/g, '');
      record.p = compact === '' ?
        undefined :
        decodeBase64(compact, `${prefix}p`);
    } else {
      record[name] = value;
    }
  }

  if (!pSeen) {
    throw new TypeError(`${prefix}missing tag: p`);
  }

  return record as KeyRecord<Uint8Array>;
};

/**
 * Parse a DNS TXT-record value into a {@link KeyRecord}
 * whose `p` field is the record's key bytes imported
 * into a verify-only {@link CryptoKey}.
 *
 * The algorithm comes from the record's `k=` tag,
 * defaulting to `rsa` when `k=` is absent (RFC 6376
 * §3.6.1); an unsupported algorithm — including that
 * `rsa` default — is rejected. A revoked record (empty
 * `p=`, RFC 6376 §3.6.1) carries through as
 * `p: undefined` with no key imported. `v`, `k`, and any
 * unknown tags pass through unchanged.
 *
 * @param input - TXT record value: raw string,
 *   DoH-JSON-quoted string, or array of pre-extracted
 *   character-strings (see {@link parseKeyRecord})
 * @param context - prefix prepended to thrown error
 *   messages; defaults to `'parseRecordToKey'`
 * @returns a {@link KeyRecord} carrying the verify-only
 *   `CryptoKey` in `p`, or `p: undefined` for a revoked
 *   record
 * @throws `TypeError` for malformed record syntax, an
 *   unsupported algorithm, or a wrong-length key
 */
export const parseRecordToKey = async (
  input: readonly string[] | string,
  context: string = 'parseRecordToKey',
): Promise<KeyRecord<CryptoKey>> => {
  const record = parseKeyRecord(input, context);
  const p = record.p === undefined ?
    undefined :
    await importVerifyKey(record.k ?? 'rsa', record.p, context);
  return { ...record, p } as KeyRecord<CryptoKey>;
};

/**
 * Parse a DNS TXT-record value into a {@link KeyRecord}
 * whose `p` field is a ready-to-use {@link Verifier} over
 * the record's published key.
 *
 * A revoked record (empty `p=`, RFC 6376 §3.6.1) carries
 * through as `p: undefined` with no verifier built. `v`,
 * `k`, and any unknown tags pass through unchanged.
 *
 * @param input - TXT record value: raw string,
 *   DoH-JSON-quoted string, or array of pre-extracted
 *   character-strings (see {@link parseKeyRecord})
 * @param context - prefix prepended to thrown error
 *   messages; defaults to `'parseRecordToVerifier'`
 * @returns a {@link KeyRecord} carrying the
 *   {@link Verifier} in `p`, or `p: undefined` for a
 *   revoked record
 * @throws `TypeError` for malformed record syntax, an
 *   unsupported algorithm, or a wrong-length key
 */
export const parseRecordToVerifier = async (
  input: readonly string[] | string,
  context: string = 'parseRecordToVerifier',
): Promise<KeyRecord<Verifier>> => {
  const record = await parseRecordToKey(input, context);
  const p = record.p === undefined ?
    undefined :
    newVerifier(record.p, context);
  return { ...record, p } as KeyRecord<Verifier>;
};

/**
 * Reduce the input to one tag-list source string,
 * concatenating multi-piece forms (quoted
 * character-strings or array elements) with no
 * intervening whitespace per RFC 1035 §3.3 and
 * RFC 6376 §3.6.2.2.
 */
const flatten = (
  input: readonly string[] | string,
  context: string | undefined,
): string => {
  if (Array.isArray(input)) return input.join('');
  const raw = input as string;
  const trimmed = raw.trim();
  if (trimmed === '') return '';
  if (!trimmed.startsWith('"')) return raw;
  return joinQuotedStrings(trimmed, context);
};

/**
 * Scan paired `"..."` runs separated by optional
 * whitespace and return the concatenation of their
 * contents with no whitespace inserted. Throws on
 * malformed quoting (stray characters outside a
 * quoted run, or an unclosed `"`).
 *
 * Does not decode backslash escapes; the resolvers we
 * target pre-resolve them.
 */
const joinQuotedStrings = (
  trimmed: string,
  context: string | undefined,
): string => {
  const prefix = context ? `${context}: ` : '';
  const pieces: string[] = [];
  let i = 0;
  while (i < trimmed.length) {
    if (trimmed[i] !== '"') {
      throw new TypeError(
        `${prefix}stray characters outside quoted character-string`,
      );
    }
    const close = trimmed.indexOf('"', i + 1);
    if (close === -1) {
      throw new TypeError(`${prefix}unclosed quoted character-string`);
    }
    pieces.push(trimmed.slice(i + 1, close));
    i = close + 1;
    while (i < trimmed.length && /\s/.test(trimmed[i] ?? '')) i++;
  }
  return pieces.join('');
};

/**
 * Split a tag-list into raw tag-spec fragments on
 * unquoted `;`. RFC 6376 §3.2 does not define quoting
 * inside tag-values, so a plain split is correct.
 * Trailing `;` is permitted by the grammar; the empty
 * fragment it produces is dropped.
 */
const splitTagSpecs = (tagList: string): string[] => {
  const parts = tagList.split(';');
  while (parts.length > 0 && (parts.at(-1) ?? '').trim() === '') {
    parts.pop();
  }
  return parts;
};

const TAG_SPEC_PATTERN = /^\s*([A-Za-z][\dA-Za-z_]*)\s*=\s*([\S\s]*?)\s*$/;
const TVAL_RUN_PATTERN = /^[!-:<-~]+(?:[ \t]+[!-:<-~]+)*$/;

/**
 * Match a single tag-spec per RFC 6376 §3.2:
 *
 *   tag-spec  = [FWS] tag-name [FWS] "=" [FWS] tag-value [FWS]
 *   tag-name  = ALPHA *ALNUMPUNC           ; ALNUMPUNC = ALPHA / DIGIT / "_"
 *   tag-value = [ tval *( 1*(WSP / FWS) tval ) ]
 *   tval      = 1*VALCHAR                  ; VALCHAR = %x21-3A / %x3C-7E
 *
 * Returns `undefined` when the fragment does not match.
 * Whitespace around `=` and around the value is folded
 * away; whitespace between tvals is left as-is in the
 * stored value (RFC 6376 §3.2: "Whitespace within a
 * value MUST be retained unless explicitly excluded by
 * the specific tag description" — `p=` is the
 * exception per RFC 6376 §3.6.1).
 */
const parseTagSpec = (
  fragment: string,
): undefined | { name: string; value: string } => {
  const match = TAG_SPEC_PATTERN.exec(fragment);
  if (!match) return undefined;
  const [, name, value] = match;
  if (value !== '' && !TVAL_RUN_PATTERN.test(value)) return undefined;
  return { name, value };
};
