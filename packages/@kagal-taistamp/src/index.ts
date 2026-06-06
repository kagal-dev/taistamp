import pkg from '../package.json' with { type: 'json' };

/** Package version from package.json. */
export const VERSION: string = pkg.version;

export {
  type KeyConfig,
  type KeyRecord,
  newSigner as newEd25519Signer,
  parseRecordToVerifier,
  parseSecretsToKeys,
  parseSecretToKey,
  type Signer,
  type Verifier,
} from '@kagal/ed25519-secret';

export { readASCII, readLabel } from './body';
export {
  TAI64N_CONTENT_LENGTH,
  TAI64N_CONTENT_TYPE,
  TAI64N_HEADER_KEY_SELECTOR,
  TAI64N_HEADER_LEAP_SECONDS,
  TAI64N_HEADER_NONCE,
  TAI64N_HEADER_SIGNATURE,
  TAI64N_PATH,
  TAISTAMP_PATH,
} from './const';
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
  newNonce,
  type Nonce,
} from './nonce';
export { asSignature, extractSignature } from './signature';
export { tai64nLabelFromUTC } from './time';
