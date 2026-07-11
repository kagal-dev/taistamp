import { encodeKey, type KeyConfig } from '@kagal/ed25519-secret';

/**
 * Default selector for the seed command's optional
 * selector positional. Picked to look obviously
 * placeholder-y so operators don't ship it as their
 * production selector; RFC 6376 leaves selectors entirely
 * to operator choice, so the dummy default is purely a
 * usability cue. `@kagal/ed25519-secret`'s `newSecret`
 * carries no default of its own — the cli supplies this
 * at the call site.
 */
export const DEFAULT_SELECTOR = 'default';

/**
 * Render the DNS TXT key-record value publishing a key's
 * public half — `"v=tai1; k=<algorithm>; p=<base64>"`,
 * quoted like a zone-file character-string.
 */
export const makeKeyRecordTXT = async (
  key: KeyConfig,
  context?: string,
): Promise<string> => {
  const k = key.publicKey.algorithm.name.toLowerCase();
  const p = await encodeKey(key.publicKey, context);
  return `"v=tai1; k=${k}; p=${p}"`;
};
