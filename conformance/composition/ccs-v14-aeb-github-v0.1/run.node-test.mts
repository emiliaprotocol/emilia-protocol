// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildReferenceReport, buildReferenceVectors } from './run.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

test('CCS v1.4 to AEB GitHub consequence profile passes every boundary case', async () => {
  const report = await buildReferenceReport() as any;
  assert.equal(report.passed, true, JSON.stringify(report, null, 2));
  assert.equal(report.cases.length, 8);
  assert.equal(report.cases.every((entry: any) => entry.passed), true);
  assert.equal(report.cases.find((entry: any) => entry.id === 'CCS-ALLOW-PLUS-EMILIA-AUTHORITY')?.observed.provider_calls, 1);
  for (const id of [
    'CCS-TAMPER-REFUSED', 'WRONG-RELYING-PARTY-REFUSED', 'STALE-STATUS-REFUSED',
    'ACTION-SUBSTITUTION-REFUSED', 'MISSING-EMILIA-AUTHORITY-REFUSED',
  ]) {
    assert.equal(report.cases.find((entry: any) => entry.id === id)?.observed.provider_calls, 0);
  }
  assert.equal(report.cases.find((entry: any) => entry.id === 'INDETERMINATE-BLOCKS-BLIND-RETRY')?.observed.provider_calls, 1);
});

test('checked-in report and vectors are deterministic', async () => {
  assert.equal(
    readFileSync(resolve(HERE, 'report.reference.json'), 'utf8'),
    `${JSON.stringify(await buildReferenceReport(), null, 2)}\n`,
  );
  assert.equal(
    readFileSync(resolve(HERE, 'vectors.reference.json'), 'utf8'),
    `${JSON.stringify(buildReferenceVectors(), null, 2)}\n`,
  );
});
