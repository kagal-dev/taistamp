import pkg from '../package.json' with { type: 'json' };

/** Package version from package.json. */
export const VERSION: string = pkg.version;

export {
  assertValidSelector,
  isValidSelector,
  SELECTOR_PATTERN,
} from './selector';
export {
  newSigner,
  type Signer,
} from './signer';
