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
  TAISTAMP_CONTENT_LENGTH,
  TAISTAMP_CONTENT_TYPE,
  TAISTAMP_HEADER_KEY_SELECTOR,
  TAISTAMP_HEADER_LEAP_SECONDS,
  TAISTAMP_HEADER_NONCE,
  TAISTAMP_HEADER_SIGNATURE,
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
  extractNonce,
  newNonce,
  type Nonce,
} from './nonce';
export { asSignature, extractSignature } from './signature';
export { tai64nLabelFromUTC, tai64nLabelToUTC } from './time';
