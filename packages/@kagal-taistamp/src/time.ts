import { TAI64_EPOCH_HI, TAI64N_LABEL_PATTERN } from './const';
import { type LeapSeconds, TAI_LEAP_SECONDS } from './leap-seconds';

type timestamp = {
  nano: number
  sec: number

  offset?: number
};

/**
 * Convert a UTC timestamp in milliseconds (the
 * `Date.now()` shape) to TAI seconds and nanoseconds,
 * applying the current `TAI_LEAP_SECONDS` offset. The
 * package deals in the current time: the offset tracks
 * the present, and anything before the unix epoch is
 * out of scope.
 */
export const fromUTC = (utc: number): timestamp => {
  // TODO: leap seconds table
  const sec = Math.floor(utc / 1000) + TAI_LEAP_SECONDS;
  const nano = (utc % 1000) * 1e6;
  return { sec, nano, offset: TAI_LEAP_SECONDS };
};

/**
 * The current TAI time as seconds and nanoseconds —
 * {@link fromUTC} applied to `Date.now()`.
 */
export const now = (): timestamp => {
  const utc = Date.now();
  return fromUTC(utc);
};

/**
 * Format a TAI timestamp as the 25-byte TAI64N label
 * served at `/.well-known/taistamp`: `@` followed by
 * 16 hex digits of TAI64 seconds (the 2^62 epoch
 * offset applied) and 8 hex digits of nanoseconds.
 * Defaults to {@link now} when no value is given.
 */
export const tai64nLabel = (value?: timestamp): string => {
  const { sec, nano } = value ?? now();

  const secHi = Math.trunc(sec / u32Range) + TAI64_EPOCH_HI;
  const secLo = sec % u32Range;

  const secHiHex = secHi.toString(16).padStart(8, '0');
  const secLoHex = secLo.toString(16).padStart(8, '0');
  const nanoHex = nano.toString(16).padStart(8, '0');

  return `@${secHiHex}${secLoHex}${nanoHex}`;
};

/**
 * The 25-byte TAI64N label for a UTC timestamp in
 * milliseconds — shorthand for
 * `tai64nLabel(fromUTC(utc))`.
 *
 * Labels are fixed-width hex, so they order
 * lexicographically: a verifier can bounds-check a
 * received label between the labels of
 * `Date.now() - skew` and `Date.now() + skew` without
 * decoding it.
 */
export const tai64nLabelFromUTC = (utc: number): string =>
  tai64nLabel(fromUTC(utc));

/**
 * Recover a UTC timestamp in milliseconds (the
 * `Date.now()` shape) from a TAI64N label — the inverse
 * of {@link tai64nLabelFromUTC}. A label minted from a
 * millisecond value round-trips back to it exactly; a
 * `Date` is one `new Date(ms)` away.
 *
 * Returns `undefined` for any value that is not `@`
 * followed by 24 hex digits (either case) — the
 * verify-side "malformed is absent" collapse shared with
 * `asSignature` and `asNonce`, so it drops straight into
 * a gate pipeline.
 *
 * `leapSeconds` is the TAI − UTC offset removed when
 * mapping TAI back to UTC; it defaults to the current
 * {@link TAI_LEAP_SECONDS}, mirroring {@link fromUTC}.
 * Pass a response's `extractLeapSeconds(headers)` to
 * honour a server that declared a different count — an
 * absent or malformed header yields `undefined` there
 * and falls through to the default, while a genuine `0`
 * is honoured.
 */
export const tai64nLabelToUTC = (
  label: string,
  leapSeconds: LeapSeconds = TAI_LEAP_SECONDS,
): number | undefined => {
  if (!TAI64N_LABEL_PATTERN.test(label)) return undefined;

  // The 64-bit seconds field must be read as two 32-bit
  // words: parsing all 16 hex digits at once yields
  // 2^62 + sec ≈ 4.6e18, whose float64 ULP (1024) has
  // already discarded sec's low bits before the epoch
  // base could be subtracted. Removing TAI64_EPOCH_HI on
  // the high word alone keeps every term exact.
  const secHi = Number.parseInt(label.slice(1, 9), 16) - TAI64_EPOCH_HI;
  const secLo = Number.parseInt(label.slice(9, 17), 16);
  const nano = Number.parseInt(label.slice(17, 25), 16);

  const sec = secHi * u32Range + secLo;
  return (sec - leapSeconds) * 1000 + nano / 1e6;
};

const u32Range = 0x1_00_00_00_00;
