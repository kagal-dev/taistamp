import pkg from '../package.json' with { type: 'json' };

/** Package version from package.json. */
export const VERSION: string = pkg.version;

export {
  type Ed25519JWKSet,
  makeJWKS,
} from './jwks';
export {
  asEd25519Seed,
  type Ed25519PublicJWK,
  type Ed25519Seed,
  type KeyContext,
  type KeyPair,
  newKeyPair,
  newKeys,
} from './key';
export {
  type KeyConfig,
  parseSecretsToKeys,
  parseSecretToKey,
} from './secret';
export {
  assertValidSelector,
  isValidSelector,
  SELECTOR_PATTERN,
} from './selector';
export {
  newSigner,
  type Signer,
} from './signer';
export {
  asBytes,
  type Bytes,
  decodeBase64,
  encodeBase64,
  encodeKey,
  getRandom,
  splitFirst,
  splitLast,
} from './utils';
