#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, writeFileSync } from 'node:fs';

const mode = process.argv[2];
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
/** @type {Record<string, unknown>} */
const base = {
  '@version': 'AEB-1-REFEREE-RUNNER-RESULT-v1',
  case_id: input.case_id,
  native_verification: 'VERIFIED',
  rp_acceptance: 'ACCEPTED',
  action_relation: 'EXACT_MATCH',
  status: 'CURRENT',
  replay: 'FRESH',
  admission: 'ADMIT',
  custody: 'RESERVED',
  provider_commitment: 'NOT_INVOKED',
  observed_effect: 'NOT_OBSERVED',
  retry: 'NOT_APPLICABLE',
  reconciliation: 'NOT_APPLICABLE',
  reason_codes: [],
};

if (mode === 'timeout') {
  await new Promise((resolve) => setTimeout(resolve, 10_000));
} else if (mode === 'oversize') {
  process.stdout.write('x'.repeat(32_768));
} else if (mode === 'stderr-oversize') {
  process.stderr.write('x'.repeat(8_192));
} else if (mode === 'duplicate') {
  const raw = JSON.stringify(base);
  process.stdout.write(raw.replace('"case_id":', `"case_id":"${input.case_id}","case_id":`));
} else if (mode === 'trailing') {
  process.stdout.write(`${JSON.stringify(base)}\nnot-json\n`);
} else if (mode === 'crash') {
  process.stderr.write('fixture crash\n');
  process.exitCode = 7;
} else if (mode === 'nondeterministic') {
  const counterPath = process.argv[3];
  let count = 0;
  try {
    count = Number(readFileSync(counterPath, 'utf8'));
  } catch {
    // The first invocation creates the test-local counter.
  }
  writeFileSync(counterPath, String(count + 1), 'utf8');
  base.reason_codes = count === 0 ? ['provider_timeout'] : ['provider_crash', 'provider_timeout'];
  process.stdout.write(`${JSON.stringify(base)}\n`);
} else {
  process.stderr.write('unknown fixture mode\n');
  process.exitCode = 2;
}
