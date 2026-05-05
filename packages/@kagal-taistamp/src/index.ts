import pkg from '../package.json' with { type: 'json' };

/** Package version from package.json. */
export const VERSION: string = pkg.version;

export * from './const';
export {
  composeSignaturePayload,
  newTaistampHandler,
  type TaistampHandlerConfig,
} from './handler';
export {
  asLeapSeconds,
  extractLeapSeconds,
  type LeapSeconds,
  TAI_LEAP_SECONDS,
  TAI_LEAP_SECONDS_MAX,
} from './leap-seconds';
export {
  asNonce,
  type Nonce,
} from './nonce';
export {
  newEd25519Signer,
  type Signer,
} from './signer';
export {
  fromUTC,
  now,
  tai64nLabel,
  tai64nLabelFromUTC,
} from './utils';
