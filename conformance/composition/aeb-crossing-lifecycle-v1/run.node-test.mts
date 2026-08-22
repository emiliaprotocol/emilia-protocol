// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { buildReferenceReport, PROFILE, runProfile } from './run.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

test('both native authority systems traverse one consequence-boundary lifecycle contract', async () => {
  const report = await runProfile();
  const reference = JSON.parse(readFileSync(resolve(HERE, 'report.reference.json'), 'utf8'));
  assert.equal(report.profile, PROFILE);
  assert.equal(report.passed, true, JSON.stringify(report, null, 2));
  assert.equal(report.cases.length, 10);
  assert.equal(report.results_digest, reference.results_digest);
  assert.deepEqual(await buildReferenceReport(), reference);

  const byId = Object.fromEntries(report.cases.map((entry) => [entry.id, entry]));
  assert.equal(byId['OAUTH-ISSUED-ARTIFACT-THROUGH'].observed.native_system, 'oauth-transaction-challenge');
  assert.equal(byId['HUMAN-AUTHORIZATION-THROUGH'].observed.native_system, 'oasnt');
  assert.notEqual(
    byId['OAUTH-ISSUED-ARTIFACT-THROUGH'].observed.replay_unit,
    byId['HUMAN-AUTHORIZATION-THROUGH'].observed.replay_unit,
  );
});

test('provider entry remains at-most-once and uncertainty never becomes retry authority', async () => {
  const report = await runProfile();
  const byId = Object.fromEntries(report.cases.map((entry) => [entry.id, entry]));
  for (const id of [
    'WRAPPER-INDEPENDENT-REPLAY',
    'CONCURRENT-ADMISSION-AT-MOST-ONE',
    'LOST-RESPONSE-INDETERMINATE',
    'BLIND-RETRY-REFUSED',
    'AUTHENTICATED-RECONCILIATION-NO-REEXECUTION',
  ]) assert.equal(byId[id].passed, true, id);
  assert.equal(byId['LOST-RESPONSE-INDETERMINATE'].observed.retry_allowed, false);
  assert.equal(byId['AUTHENTICATED-RECONCILIATION-NO-REEXECUTION'].observed.provider_calls, 1);
});

test('executor observation and the nonauthorizing crossing-record boundary are explicit', async () => {
  const report = await runProfile();
  const byId = Object.fromEntries(report.cases.map((entry) => [entry.id, entry]));
  assert.equal(byId['EXECUTOR-OBSERVED-SUBSTITUTION-REFUSED'].observed.provider_calls, 0);
  assert.equal(byId['CROSSING-RECORD-NONAUTHORIZING'].observed.provider_calls, 0);
  assert.equal(byId['CROSSING-RECORD-NONAUTHORIZING'].observed.crossing_record_valid, true);
});
