// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { runSuite, sampleReceiptSet } from './run.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

test('CCS-09 compatibility and optional mapping checks pass without upgrading historical evidence', () => {
  const report = runSuite();
  assert.equal(report.passed, true, JSON.stringify(report, null, 2));
  assert.equal(report.target.draft, 'draft-correctover-ccs-09');
  assert.equal(report.claim_scope.full_ccs09_conformance, false);
  assert.equal(report.claim_scope.external_operator_run, false);
  assert.equal(report.claim_scope.pre_effect_enforcement, false);
  assert.equal(report.mapping_policy, 'OPTIONAL');
  assert.equal(report.pins.adapter_id, 'native:ccs-05-v1.3-ed25519');
  assert.equal(report.pins.adapter_source_lock, 'draft-correctover-ccs-05-v1.3-c91f0fa31b1b9e5');
  assert.equal(report.checks.length, 26);
  assert.equal(report.checks.every((entry) => entry.passed), true);
});

test('every receipt field is authenticated, including the legacy HMAC field', () => {
  const report = runSuite();
  assert.equal(report.field_mutations.length, 22);
  assert.equal(new Set(report.field_mutations.map((entry) => entry.field)).size, 22);
  assert.equal(report.field_mutations.every((entry) => !entry.signature_valid && entry.native_verification === 'FAILED'), true);
  assert.equal(report.field_mutations.some((entry) => entry.field === 'receipt'), true);
});

test('the sample is locally generated test evidence with exactly 22 receipt fields', () => {
  const sample = sampleReceiptSet();
  assert.equal(sample.provenance, 'emilia-generated-deterministic-test-fixtures');
  for (const entry of sample.receipts) assert.equal(Object.keys(entry.receipt).length, 22);
  assert.equal(sample.receipts.length, 3);
  assert.equal('receipt_version' in sample.receipts[0].receipt, false);
});

test('the report target matches the separately byte-verified source lock', () => {
  const lock = JSON.parse(readFileSync(resolve(HERE, 'source-lock.json'), 'utf8'));
  const report = runSuite();
  assert.deepEqual({ name: report.target.draft, url: report.target.url,
    sha256: report.target.sha256, bytes: report.target.bytes }, lock.draft);
});

test('the CLI refuses an unknown flag instead of silently skipping verification', () => {
  const result = spawnSync(process.execPath, [resolve(HERE, 'run.mjs'), '--chek'], { encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unsupported argument/);
});

test('reference report and fixture bytes are deterministic', () => {
  assert.equal(readFileSync(resolve(HERE, 'report.reference.json'), 'utf8'), `${JSON.stringify(runSuite(), null, 2)}\n`);
  assert.equal(readFileSync(resolve(HERE, 'sample-receipts.reference.json'), 'utf8'), `${JSON.stringify(sampleReceiptSet(), null, 2)}\n`);
});
