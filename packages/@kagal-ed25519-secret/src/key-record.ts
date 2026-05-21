// cSpell:words vars
import { encodeKey } from './utils';

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
 * verify-only key (post-import).
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
