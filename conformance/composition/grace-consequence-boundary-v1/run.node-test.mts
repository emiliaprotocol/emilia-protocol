// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { buildReferenceReport, PROFILE, runProfile } from './run.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

test('GRACE runs through the exact-action boundary under aggregate capacity', async () => {
  const report = await runProfile();
  const reference = JSON.parse(readFileSync(resolve(HERE, 'report.reference.json'), 'utf8'));
  assert.equal(report.profile, PROFILE);
  assert.equal(report.passed, true, JSON.stringify(report, null, 2));
  assert.equal(report.cases.length, 6);
  assert.equal(report.results_digest, reference.results_digest);
  assert.deepEqual(await buildReferenceReport(), reference);
});

test('uncertainty, replay, substitution, and aggregate oversubscription fail closed', async () => {
  const report = await runProfile();
  const byId = Object.fromEntries(report.cases.map((entry) => [entry.id, entry]));
  for (const id of [
    'AGGREGATE-ENVELOPE-REFUSES-SECOND-EVENT',
    'CURTAILMENT-SUBSTITUTION-REFUSED',
    'LOST-RESPONSE-KEEPS-CAPACITY-UNAVAILABLE',
    'AUTHENTICATED-RECONCILIATION-DOES-NOT-REEXECUTE',
    'TELEMETRY-CANNOT-MINT-CAPACITY',
  ]) assert.equal(byId[id].passed, true, id);
  assert.equal(byId['LOST-RESPONSE-KEEPS-CAPACITY-UNAVAILABLE'].observed.provider_calls, 1);
});

test('the report refuses to convert synthetic evidence into physical truth', async () => {
  const report = await runProfile();
  assert.match(report.known_limits.join(' '), /no physical grid event is claimed/i);
  assert.match(report.known_limits.join(' '), /does not prove delivered power/i);
});
