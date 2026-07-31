/**
 * Standalone compatibility smoke test — no test framework
 * required. Confirms the built `dist/bin.mjs` boots on the
 * current Node version: shebang preserved, `--help` exits
 * cleanly, `seed new` mints a secret and rejects malformed
 * selectors, and `probe` rejects a missing required
 * positional. The `--env-file` missing-file contract is
 * behavioural, not a boot check — it lives in the vitest
 * suite (`cli.test.ts`), which exercises it directly and so
 * stays clear of node's own `--env-file` argv pre-scan.
 * Behavioural coverage lives in the vitest suite; this
 * file's job is "did the bin boot at all".
 */

/* global console, process, URL */
/* eslint unicorn/no-process-exit: "off" */

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const BIN = fileURLToPath(new URL('../../dist/bin.mjs', import.meta.url));

let failures = 0;

function pass(name, detail) {
  console.log(`  ok ${name}${detail ? ' ' + detail : ''}`);
}

function fail(name, reason) {
  console.error(`  FAIL ${name}: ${reason}`);
  failures++;
}

function checkShebang() {
  const head = readFileSync(BIN, 'utf8').slice(0, 19);
  if (head === '#!/usr/bin/env node') {
    pass('shebang', `= '${head}'`);
  } else {
    fail('shebang', `expected '#!/usr/bin/env node', got '${head}'`);
  }
}

function checkExit(name, arguments_, expected) {
  const result = spawnSync(process.execPath, [BIN, ...arguments_], {
    stdio: 'pipe',
    encoding: 'utf8',
  });
  if (result.status === expected) {
    pass(name, `exit=${result.status}`);
  } else {
    fail(name,
      `expected exit ${expected}, got ${result.status}` +
      (result.stderr ? `\n  stderr: ${result.stderr.trim()}` : ''));
  }
}

console.log(`Node ${process.version}`);
console.log(`bin: ${BIN}`);

checkShebang();
checkExit('--help', ['--help'], 0);
checkExit('seed new (default)', ['seed', 'new'], 0);
checkExit('seed new s1', ['seed', 'new', 's1'], 0);
checkExit('seed new 1bad', ['seed', 'new', '1bad'], 1);
checkExit('probe (missing url)', ['probe'], 1);

if (failures > 0) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
} else {
  console.log(`\nok ${process.version} — all checks passed`);
}
