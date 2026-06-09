/**
 * Entry point for the `@kagal/taistamp/utils` subpath:
 * additional related exports kept out of the
 * protocol-shaped main surface.
 */

export { TAI64_EPOCH_HI, TAI64N_LABEL_PATTERN } from './const';

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
