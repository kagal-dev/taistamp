// cspell:words AAEC
import type { Bytes as IndexBytes } from '../index';
import { asBytes, type Bytes, decodeBase64, getRandom } from '../utils';

/**
 * Compile-time type-check fixtures for `utils.ts`.
 * Picked up by `tsconfig.tests.json`; never run.
 *
 * Pin three layers of the `Bytes` contract — a
 * regression in any of them fails type-check:
 * 1. `Bytes` is assignable to `BufferSource` (what
 *    every `crypto.subtle.*` byte parameter expects).
 * 2. The `Bytes` re-export from `../index` is the
 *    same type, not a divergent alias.
 * 3. Each byte helper's return flows into
 *    `crypto.subtle.*` without casting at the call
 *    site — catches widening regressions in the
 *    helpers themselves.
 */

// Errors if `U` doesn't extend `T`. Pure compile-time.
type _AssertExtends<T, U extends T> = U;

// 1. WebCrypto contract.
export type _BytesIsBufferSource = _AssertExtends<BufferSource, Bytes>;

// 2. Index re-export is the same type — both directions
//    to catch a divergent alias.
export type _IndexBytesExtendsBytes =
  _AssertExtends<Bytes, IndexBytes>;
export type _BytesExtendsIndexBytes =
  _AssertExtends<IndexBytes, Bytes>;

// 3. Call-site flow — never called; type-check only.
//    Exercises each helper's return flowing into a
//    `crypto.subtle.*` `BufferSource` parameter without
//    casting at the call site.
export const _bytesFlowIntoWebCrypto = (key: CryptoKey) => [
  crypto.subtle.verify(
    'Ed25519', key, decodeBase64('AAEC'), getRandom(32),
  ),
  crypto.subtle.importKey(
    'raw', asBytes('AAEC'), { name: 'Ed25519' }, true, ['verify'],
  ),
  crypto.subtle.sign('Ed25519', key, decodeBase64('AAEC')),
];
