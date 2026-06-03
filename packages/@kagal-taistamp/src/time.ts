import { TAI64_EPOCH_HI } from './const';
import { TAI_LEAP_SECONDS } from './leap-seconds';

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

const u32Range = 0x1_00_00_00_00;
