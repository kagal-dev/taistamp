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
  asLeapSeconds,
  asNonce,
  composeSignaturePayload,
  extractLeapSeconds,
  extractNonce,
  newEd25519Signer,
  newTaistampHandler,
  parseRecordToVerifier,
  parseSecretsToKeys,
  parseSecretToKey,
  TAI64N_CONTENT_LENGTH,
  TAI64N_CONTENT_TYPE,
  TAI64N_HEADER_KEY_SELECTOR,
  TAI64N_HEADER_LEAP_SECONDS,
  TAI64N_HEADER_NONCE,
  TAI64N_HEADER_SIGNATURE,
  TAI64N_PATH,
  tai64nLabelFromUTC as tai64nLabelFromUTCMain,
  TAI_LEAP_SECONDS,
  TAI_LEAP_SECONDS_MAX,
  TAISTAMP_PATH,
  VERSION,
} from '../../dist/index.mjs';
import {
  decodeSFBinary,
  encodeSFBinary,
  fromUTC,
  now,
  SF_BINARY_PATTERN,
  TAI64_EPOCH_HI,
  tai64nLabel,
  tai64nLabelFromUTC,
} from '../../dist/utils.mjs';

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

function checkNumber(name, value, expected) {
  if (typeof value !== 'number') {
    fail(name, `expected number, got ${typeof value}`);
    return;
  }
  if (expected !== undefined && value !== expected) {
    fail(name, `expected ${expected}, got ${value}`);
    return;
  }
  pass(name, `= ${value}`);
}

console.log(`Node ${process.version}`);
console.log(`@kagal/taistamp v${VERSION}`);

checkString('VERSION', VERSION);

// Constants
checkString('TAISTAMP_PATH', TAISTAMP_PATH, '/.well-known/taistamp');
checkString('TAI64N_PATH', TAI64N_PATH, '/.well-known/taistamp');
checkString('TAI64N_CONTENT_TYPE', TAI64N_CONTENT_TYPE, 'application/tai64n');
checkNumber('TAI64N_CONTENT_LENGTH', TAI64N_CONTENT_LENGTH, 25);
checkNumber('TAI_LEAP_SECONDS', TAI_LEAP_SECONDS, 37);
checkNumber('TAI_LEAP_SECONDS_MAX', TAI_LEAP_SECONDS_MAX, 0xFF_FF_FF_FF);
checkString(
  'TAI64N_HEADER_KEY_SELECTOR',
  TAI64N_HEADER_KEY_SELECTOR,
  'TAI-Key-Selector',
);
checkString(
  'TAI64N_HEADER_LEAP_SECONDS',
  TAI64N_HEADER_LEAP_SECONDS,
  'TAI-Leap-Seconds',
);
checkString('TAI64N_HEADER_NONCE', TAI64N_HEADER_NONCE, 'TAI-Nonce');
checkString('TAI64N_HEADER_SIGNATURE', TAI64N_HEADER_SIGNATURE, 'TAI-Signature');

// Functions
checkFunction('newTaistampHandler', newTaistampHandler);
checkFunction('newEd25519Signer', newEd25519Signer);
checkFunction('parseRecordToVerifier', parseRecordToVerifier);
checkFunction('parseSecretsToKeys', parseSecretsToKeys);
checkFunction('parseSecretToKey', parseSecretToKey);
checkFunction('composeSignaturePayload', composeSignaturePayload);
checkFunction('asLeapSeconds', asLeapSeconds);
checkFunction('asNonce', asNonce);
checkFunction('extractLeapSeconds', extractLeapSeconds);
checkFunction('extractNonce', extractNonce);
checkFunction('tai64nLabelFromUTC (main)', tai64nLabelFromUTCMain);

// /utils subpath
checkNumber('TAI64_EPOCH_HI', TAI64_EPOCH_HI, 0x40_00_00_00);
checkInstance('SF_BINARY_PATTERN', SF_BINARY_PATTERN, RegExp);
checkFunction('encodeSFBinary', encodeSFBinary);
checkFunction('decodeSFBinary', decodeSFBinary);
checkFunction('fromUTC', fromUTC);
checkFunction('now', now);
checkFunction('tai64nLabel', tai64nLabel);
checkFunction('tai64nLabelFromUTC', tai64nLabelFromUTC);

if (failures > 0) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
} else {
  console.log(`\nok ${process.version} — all checks passed`);
}
