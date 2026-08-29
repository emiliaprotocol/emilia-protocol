// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { buildReferenceReport, PROFILE, runProfile } from './run.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

test('one P-256 signing input can have two valid exact envelopes', () => {
  const report = runProfile();
  const byId = Object.fromEntries(report.cases.map((entry) => [entry.id, entry]));
  assert.equal(report.profile, PROFILE);
  assert.equal(report.passed, true, JSON.stringify(report, null, 2));
  assert.equal(byId['P256-SIGNATURE-A-VERIFIES'].passed, true);
  assert.equal(byId['P256-SIGNATURE-B-VERIFIES'].passed, true);
  assert.equal(byId['EXACT-ENTRY-IDENTITY-SEPARATES-ENVELOPES'].passed, true);
  assert.equal(byId['SIGNING-INPUT-IDENTITY-IS-STABLE'].passed, true);
  assert.equal(byId['P256-RFC9943-CWT-CLAIMS-PRESENT'].passed, true);
});

test('substitutions fail while a valid re-encoding gets the correct reason', () => {
  const report = runProfile();
  const byId = Object.fromEntries(report.cases.map((entry) => [entry.id, entry]));
  assert.equal(byId['PAYLOAD-SUBSTITUTION-CHANGES-SIGNING-INPUT'].passed, true);
  assert.equal(byId['PROTECTED-HEADER-SUBSTITUTION-CHANGES-SIGNING-INPUT'].passed, true);
  assert.equal(byId['FALSE-TAMPERING-REASON-REFUSED'].observed.classification,
    'same_signing_input_different_envelope');
});

test('EP authorization identity remains separate and the report is pinned', () => {
  const report = runProfile();
  const byId = Object.fromEntries(report.cases.map((entry) => [entry.id, entry]));
  assert.equal(byId['EP-AUTHORIZATION-PAYLOAD-IDENTITY-VERIFIES'].passed, true);
  assert.equal(byId['ENTRY-DIGEST-CANNOT-SUBSTITUTE-FOR-AUTHORIZATION'].passed, true);
  const reference = JSON.parse(readFileSync(resolve(HERE, 'report.reference.json'), 'utf8'));
  assert.deepEqual(buildReferenceReport(), reference);
});

test('the SCITT identity composition runner is mandatory in CI', () => {
  const workflow = readFileSync(resolve(HERE, '../../../.github/workflows/ci.yml'), 'utf8');
  const packageJson = JSON.parse(readFileSync(resolve(HERE, '../../../package.json'), 'utf8'));
  assert.match(workflow, /npm run conformance:composition:scitt-statement-identity/);
  assert.match(workflow, /npm run conformance:composition:scitt-capsule-seam/);
  assert.match(
    packageJson.scripts['conformance:composition:scitt-statement-identity'],
    /npm run check:scitt-statement-identity-standalone/,
  );
});
