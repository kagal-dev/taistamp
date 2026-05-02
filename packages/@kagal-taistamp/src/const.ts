export const TAI_OFFSET: number = 37;

export const TAI64N_PATH = '/.well-known/taistamp';

export const TAI64N_CONTENT_TYPE = 'application/tai64n';
export const TAI64N_CONTENT_LENGTH = 1 + 16 + 8; // '@' + sec (16 hex chars) + nano (8 hex chars)

export const TAI64N_HEADER_KEY_SELECTOR = 'TAI-Key-Selector';
export const TAI64N_HEADER_LEAP_SECONDS = 'TAI-Leap-Seconds';
export const TAI64N_HEADER_NONCE = 'TAI-Nonce';
export const TAI64N_HEADER_SIGNATURE = 'TAI-Signature';

export const TAI64_EPOCH_HI = 0x40_00_00_00;
