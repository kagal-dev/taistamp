//
// tai64n format
//
// Constants describing the TAI64N label itself, surfaced on
// the `@kagal/taistamp/utils` subpath.
//

/** `@` followed by 24 hex digits — the TAI64N label wire form. */
export const TAI64N_LABEL_PATTERN = /^@[\da-fA-F]{24}$/;

/** Byte length of a TAI64N label: `@` + 16 sec + 8 nano hex digits. */
export const TAI64N_LABEL_LENGTH = 1 + 16 + 8;

/** Media type of a TAI64N label body. */
export const TAI64N_CONTENT_TYPE = 'application/tai64n';

/** High 32 bits of the TAI64 second count at the unix epoch. */
export const TAI64N_EPOCH_HI = 0x40_00_00_00;

/** @deprecated Renamed to {@link TAI64N_EPOCH_HI}. */
export const TAI64_EPOCH_HI = TAI64N_EPOCH_HI;

//
// taistamp protocol
//
// Constants describing the taistamp HTTP exchange, surfaced
// on the main entry point.
//

export const TAISTAMP_PATH = '/.well-known/taistamp';

/** The taistamp response `Content-Type`. */
export const TAISTAMP_CONTENT_TYPE = TAI64N_CONTENT_TYPE;

/** The taistamp response `Content-Length`. */
export const TAISTAMP_CONTENT_LENGTH = TAI64N_LABEL_LENGTH;

export const TAISTAMP_HEADER_KEY_SELECTOR = 'TAI-Key-Selector';
export const TAISTAMP_HEADER_LEAP_SECONDS = 'TAI-Leap-Seconds';
export const TAISTAMP_HEADER_NONCE = 'TAI-Nonce';
export const TAISTAMP_HEADER_SIGNATURE = 'TAI-Signature';

//
// Back-compat aliases for the released TAI64N_-prefixed
// protocol names, surfaced on the /utils subpath.
//

/** @deprecated Renamed to {@link TAISTAMP_PATH}. */
export const TAI64N_PATH = TAISTAMP_PATH;

/** @deprecated Renamed to {@link TAISTAMP_CONTENT_LENGTH}. */
export const TAI64N_CONTENT_LENGTH = TAISTAMP_CONTENT_LENGTH;

/** @deprecated Renamed to {@link TAISTAMP_HEADER_KEY_SELECTOR}. */
export const TAI64N_HEADER_KEY_SELECTOR = TAISTAMP_HEADER_KEY_SELECTOR;

/** @deprecated Renamed to {@link TAISTAMP_HEADER_LEAP_SECONDS}. */
export const TAI64N_HEADER_LEAP_SECONDS = TAISTAMP_HEADER_LEAP_SECONDS;

/** @deprecated Renamed to {@link TAISTAMP_HEADER_NONCE}. */
export const TAI64N_HEADER_NONCE = TAISTAMP_HEADER_NONCE;

/** @deprecated Renamed to {@link TAISTAMP_HEADER_SIGNATURE}. */
export const TAI64N_HEADER_SIGNATURE = TAISTAMP_HEADER_SIGNATURE;
