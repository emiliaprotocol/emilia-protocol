#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runPinnedFixture } from './adapter.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const invoked = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invoked) {
  const report = await runPinnedFixture();
  if (process.argv.includes('--check')) {
    const lock = JSON.parse(readFileSync(resolve(HERE, 'result-lock.json'), 'utf8'));
    const matches = report.outcome_binding.valid === lock.expected.valid
      && report.outcome_binding.lifecycle_state === lock.expected.lifecycle_state
      && report.outcome_binding.outcome === lock.expected.outcome
      && report.outcome_binding.result_digest === lock.outcome_binding_result_digest
      && report.report_digest === lock.report_digest;
    if (!matches) {
      console.error(`result drift: expected ${lock.outcome_binding_result_digest} / ${lock.report_digest}, got ${report.outcome_binding.result_digest} / ${report.report_digest}`);
      process.exitCode = 1;
    } else {
      console.log(JSON.stringify({
        profile: report.profile,
        outcome: report.outcome_binding.outcome,
        outcome_binding_result_digest: report.outcome_binding.result_digest,
        report_digest: report.report_digest,
        result_lock_match: true,
      }, null, 2));
    }
  } else {
    console.log(JSON.stringify(report, null, 2));
  }
}

export { runPinnedFixture };
