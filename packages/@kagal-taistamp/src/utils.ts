/**
 * Entry point for the `@kagal/taistamp/utils` subpath:
 * additional related exports kept out of the
 * protocol-shaped main surface.
 */

export {
  TAI64_EPOCH_HI,
  TAI64N_CONTENT_LENGTH,
  TAI64N_CONTENT_TYPE,
  TAI64N_EPOCH_HI,
  TAI64N_HEADER_KEY_SELECTOR,
  TAI64N_HEADER_LEAP_SECONDS,
  TAI64N_HEADER_NONCE,
  TAI64N_HEADER_SIGNATURE,
  TAI64N_LABEL_LENGTH,
  TAI64N_LABEL_PATTERN,
  TAI64N_PATH,
} from './const';

export {
  decodeSFBinary,
  encodeSFBinary,
  SF_BINARY_PATTERN,
} from './sf-binary';

export {
  fromUTC,
  now,
  tai64nLabel,
  tai64nLabelFromUTC,
  tai64nLabelToUTC,
} from './time';
