import pkg from '../package.json' with { type: 'json' };

/** Package version from package.json. */
export const VERSION: string = pkg.version;

export * from './const';
export {
  newTaistampHandler,
  type TaistampHandlerConfig,
  taistampSignedPayload,
} from './handler';
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
