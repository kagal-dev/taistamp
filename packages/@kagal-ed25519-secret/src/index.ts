import pkg from '../package.json' with { type: 'json' };

/** Package version from package.json. */
export const VERSION: string = pkg.version;

export {
  asEd25519Seed,
  type Ed25519Seed,
  type KeyPair,
  newKeyPair,
} from './key';
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
  decodeBase64,
  encodeBase64,
} from './utils';
