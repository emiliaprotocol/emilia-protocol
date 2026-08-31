// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  createEquipmentEligibilityGuard,
  createFixture,
  runProfile,
  PROFILE_VERSION,
} from './run.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

test('the policy source lock identifies the exact public-inspection bytes', () => {
  const sourceLock = JSON.parse(readFileSync(resolve(HERE, 'source-lock.json'), 'utf8'));
  assert.equal(sourceLock.primary_source.citation, 'FR Doc. 2026-17843');
  assert.equal(sourceLock.primary_source.content_length, 175772);
  assert.equal(
    sourceLock.primary_source.sha256,
    'c40bd9077cc8182f0e6612adb0b7e1769256161d53fd167dd6b33b1554400995',
  );
  assert.equal(sourceLock.revalidation_required, true);
});

test('the reference profile reports every implemented case as passing', async () => {
  const report = await runProfile();
  assert.equal(report.profile, PROFILE_VERSION);
  assert.equal(report.passed, true, JSON.stringify(report, null, 2));
  assert.equal(report.cases.length, 24);
  for (const entry of report.cases) assert.equal(entry.passed, true, entry.id);
});

test('a slow status resolver cannot admit an action that expires while awaiting status', async () => {
  const base = Date.parse('2026-08-30T20:00:00.000Z');
  let clock = base;
  const artifactDigest = `sha256:${'11'.repeat(32)}`;
  const configurationDigest = `sha256:${'22'.repeat(32)}`;
  const firmwareDigest = `sha256:${'33'.repeat(32)}`;
  const action = {
    asset_id: 'asset:test-plc',
    operation: 'write_single_register',
    external_status_digest: artifactDigest,
    configuration_digest: configurationDigest,
    firmware_digest: firmwareDigest,
    valid_from: new Date(base - 1_000).toISOString(),
    expires_at: new Date(base + 10).toISOString(),
  };
  const guard = createEquipmentEligibilityGuard({
    now: () => clock,
    maxAgeMs: 60_000,
    resolveStatus: async () => {
      clock = base + 20;
      return {
        subject_type: 'equipment',
        subject_id: action.asset_id,
        status: 'ACTIVE',
        source_id: 'source:reference-equipment-status',
        source_version: 'test-1',
        source_artifact_digest: artifactDigest,
        issuer_key_id: 'key:reference-equipment-status:1',
        effective_at: new Date(base - 1_000).toISOString(),
        observed_at: new Date(base).toISOString(),
        expires_at: new Date(base + 10_000).toISOString(),
        applicable_asset_ids: [action.asset_id],
        applicable_operation_types: [action.operation],
        configuration_digest: configurationDigest,
        firmware_digest: firmwareDigest,
        authenticated: true,
        claim_boundary: 'synthetic test assertion',
      };
    },
  });

  const verdict = await guard({
    authorization: {},
    selector: {},
    observed_action: action,
    capability: null,
    checked_at: new Date(base).toISOString(),
  });
  assert.equal(verdict.ok, false);
  assert.equal(verdict.reason, 'action_expired');
  assert.equal(verdict.reservation, 'burn');
  assert.equal(verdict.evidence?.checked_at, new Date(base + 20).toISOString());
});

test('provider-entry status evidence reaches the effect and hash-chained execution detail', async () => {
  const fixture = await createFixture();
  let effectEvidence: any = null;
  const result = await fixture.attempt({
    effect: async (_action, operation) => {
      effectEvidence = operation.providerEntryEvidence;
      return { acknowledged: true };
    },
  });

  assert.equal(result.ok, true, result.reason);
  assert.equal(effectEvidence.guards.some((entry: any) => entry.kind === 'equipment_status'), true);
  assert.equal(effectEvidence.guards.some((entry: any) => entry.kind === 'organization_status'), true);
  assert.equal(
    result.provider_entry_evidence.guards.some((entry: any) => entry.kind === 'equipment_status'),
    true,
  );
  assert.deepEqual(
    result.raw.execution.detail.provider_entry_evidence,
    result.provider_entry_evidence,
  );
});

test('equipment status age policy accepts only bounded safe integers', () => {
  const resolveStatus = async () => { throw new Error('not called'); };
  assert.throws(
    () => createEquipmentEligibilityGuard({ resolveStatus, maxAgeMs: -1 }),
    /maxAgeMs must be a safe integer from 0 through 60000/,
  );
  assert.throws(
    () => createEquipmentEligibilityGuard({ resolveStatus, maxAgeMs: 60_001 }),
    /maxAgeMs must be a safe integer from 0 through 60000/,
  );
  for (const invalid of [Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(
      () => createEquipmentEligibilityGuard({ resolveStatus, maxAgeMs: invalid }),
      /maxAgeMs must be a safe integer from 0 through 60000/,
    );
  }
  assert.doesNotThrow(
    () => createEquipmentEligibilityGuard({ resolveStatus, maxAgeMs: 60_000 }),
  );
});

test('post-entry uncertainty cannot reopen the authority', async () => {
  const fixture = await createFixture();
  const first = await fixture.attempt({
    effect: async () => { throw new Error('response lost'); },
  });
  const retry = await fixture.attempt();

  assert.equal(first.terminal_outcome, 'indeterminate');
  assert.equal(first.operation.outcome, 'indeterminate');
  assert.equal(retry.ok, false);
  assert.equal(fixture.providerEntries, 1);
});
