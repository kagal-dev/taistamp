/**
 * Standalone compatibility smoke test — no test framework
 * required. Confirms the built dist loads on the current
 * Node version and that the public exports resolve to the
 * expected shapes. Behavioural coverage lives in the vitest
 * suite; this file's job is "did the dist boot at all".
 */

/* global console, process */
/* eslint unicorn/no-process-exit: "off" */

import {
  asBytes,
  asEd25519Seed,
  assertValidSelector,
  decodeBase64,
  encodeBase64,
  encodeKey,
  getRandom,
  isValidSelector,
  newKeyPair,
  newKeys,
  newSigner,
  parseSecretsToKeys,
  parseSecretToKey,
  SELECTOR_PATTERN,
  splitFirst,
  splitLast,
  VERSION,
} from '../../dist/index.mjs';

let failures = 0;

function pass(name, detail) {
  console.log(`  ok ${name}${detail ? ' ' + detail : ''}`);
}

function fail(name, reason) {
  console.error(`  FAIL ${name}: ${reason}`);
  failures++;
}

function checkFunction(name, value) {
  if (typeof value === 'function') {
    pass(name);
  } else {
    fail(name, `expected function, got ${typeof value}`);
  }
}

function checkString(name, value, expected) {
  if (typeof value !== 'string') {
    fail(name, `expected string, got ${typeof value}`);
    return;
  }
  if (expected !== undefined && value !== expected) {
    fail(name, `expected '${expected}', got '${value}'`);
    return;
  }
  pass(name, `= '${value}'`);
}

function checkInstance(name, value, ctor) {
  if (!(value instanceof ctor)) {
    const got = value?.constructor?.name ?? typeof value;
    fail(name, `expected ${ctor.name}, got ${got}`);
    return;
  }
  pass(name);
}

console.log(`Node ${process.version}`);
console.log(`@kagal/ed25519-secret v${VERSION}`);

checkString('VERSION', VERSION);
checkFunction('newKeyPair', newKeyPair);
checkFunction('newKeys', newKeys);
checkFunction('asEd25519Seed', asEd25519Seed);
checkFunction('parseSecretToKey', parseSecretToKey);
checkFunction('parseSecretsToKeys', parseSecretsToKeys);
checkFunction('newSigner', newSigner);
checkFunction('assertValidSelector', assertValidSelector);
checkFunction('isValidSelector', isValidSelector);
checkFunction('encodeBase64', encodeBase64);
checkFunction('encodeKey', encodeKey);
checkFunction('decodeBase64', decodeBase64);
checkFunction('getRandom', getRandom);
checkFunction('asBytes', asBytes);
checkFunction('splitFirst', splitFirst);
checkFunction('splitLast', splitLast);
checkInstance('SELECTOR_PATTERN', SELECTOR_PATTERN, RegExp);

if (failures > 0) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
} else {
  console.log(`\nok ${process.version} — all checks passed`);
}
