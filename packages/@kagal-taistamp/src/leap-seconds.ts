// cspell:words IERS

import { TAI64N_HEADER_LEAP_SECONDS } from './const';

/**
 * Upper bound for `leapSeconds` in the taistamp signed
 * payload. The framing encodes the value as a 4-byte
 * big-endian unsigned integer, so any input outside
 * `[0, 2^32-1]` cannot be represented. Verifiers MUST
 * treat an out-of-range `TAI-Leap-Seconds` response
 * header as unsigned, per spec §5.3.
 */
export const TAI_LEAP_SECONDS_MAX = 0xFF_FF_FF_FF;

declare const LeapSecondsBrand: unique symbol;

/**
 * `number` that has been confirmed to fit the
 * `[0, TAI_LEAP_SECONDS_MAX]` u32be range required by
 * the taistamp signed-payload framing. Construct only
 * via {@link extractLeapSeconds} or {@link asLeapSeconds};
 * the brand prevents an arbitrary number from reaching
 * the signing path.
 */
export type LeapSeconds = number & { readonly [LeapSecondsBrand]: never };

/**
 * Coerce a `number` to a {@link LeapSeconds}. Returns
 * `undefined` when `value` is non-integer, negative,
 * or exceeds {@link TAI_LEAP_SECONDS_MAX}.
 */
export const asLeapSeconds = (
  value: number,
): LeapSeconds | undefined => {
  if (
    !Number.isInteger(value) ||
    value < 0 ||
    value > TAI_LEAP_SECONDS_MAX
  ) return undefined;
  return value as LeapSeconds;
};

/**
 * Current TAI − UTC offset in whole seconds, used by
 * `fromUTC()` and emitted in the `TAI-Leap-Seconds`
 * response header. The value 37 has been in force
 * since 2017-01-01; update on the next IERS leap-second
 * announcement.
 *
 * @remarks
 * Stays a single `LeapSeconds` until a leap-seconds
 * table is added so the offset can be computed for any
 * TAI second; this constant becomes redundant then.
 */
export const TAI_LEAP_SECONDS: LeapSeconds = 37 as LeapSeconds;

/**
 * Strict decimal integer: a single `0` or a non-zero
 * leading digit followed by digits. Rejects hex
 * (`0x25`), float-style integers (`37.0`), signs,
 * whitespace, exponential notation, and leading zeros
 * — every input `Number()` would silently coerce to
 * an integer despite not being a canonical decimal.
 */
const DECIMAL_INTEGER = /^(?:0|[1-9]\d*)$/;

/**
 * Extract a usable leap-seconds count from response
 * headers. Returns `undefined` when the
 * `TAI-Leap-Seconds` field is missing, empty,
 * non-numeric, non-integer, negative, or out-of-range
 * — every "treat as unsigned" case in spec §5.3
 * collapsed into one verdict.
 */
export const extractLeapSeconds = (
  headers: Headers,
): LeapSeconds | undefined => {
  const raw = headers.get(TAI64N_HEADER_LEAP_SECONDS);
  if (!raw || !DECIMAL_INTEGER.test(raw)) return undefined;
  return asLeapSeconds(Number(raw));
};
