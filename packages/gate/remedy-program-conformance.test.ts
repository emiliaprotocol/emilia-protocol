// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  REMEDY_PROGRAM_VERSION,
  createRemedyMemoryStore,
  createRemedyProgramKernel,
} from './remedy-program.js';

type DataRecord = Record<string, any>;

interface CatalogStep {
  op: string;
  fixture: string;
  patch?: DataRecord;
  expect: DataRecord;
}

interface CatalogVector {
  id: string;
  description: string;
  covers: string[];
  verifier_policy?: {
    reject_authorization_evidence_ids: string[];
  };
  steps: CatalogStep[];
}

interface Catalog {
  profile: string;
  vectors_version: string;
  visibility: string;
  vector_count: number;
  description: string;
  claim_boundary: string;
  verifier_model: string;
  materialization: DataRecord;
  required_coverage: string[];
  fixtures: Record<string, DataRecord>;
  vectors: CatalogVector[];
}

const NOW = Date.parse('2026-07-21T18:30:00.000Z');
const CATALOG_URL = new URL('../../conformance/vectors/remedy-program.v1.json', import.meta.url);
const catalog = JSON.parse(readFileSync(CATALOG_URL, 'utf8')) as Catalog;

const CATALOG_KEYS = new Set([
  'profile', 'vectors_version', 'visibility', 'vector_count', 'description',
  'claim_boundary', 'verifier_model', 'materialization', 'required_coverage',
  'fixtures', 'vectors',
]);
const VECTOR_KEYS = new Set([
  'id', 'description', 'covers', 'verifier_policy', 'steps',
]);
const STEP_KEYS = new Set(['op', 'fixture', 'patch', 'expect']);
const POLICY_KEYS = new Set(['reject_authorization_evidence_ids']);
const OPERATIONS = new Set([
  'create', 'status', 'recordRevocation', 'openDispute', 'authorizeRemedy',
  'claimRemedy', 'finalizeRemedy', 'reconcileOriginalEffect',
  'reconcileRemedy', 'resolveDispute',
]);

function isRecord(value: unknown): value is DataRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function assertExactKeys(value: DataRecord, expected: Set<string>, label: string) {
  const actual = Object.keys(value).sort();
  assert.deepEqual(actual, [...expected].sort(), `${label} has unhandled keys`);
}

function isMaterializationToken(value: unknown): value is DataRecord {
  if (!isRecord(value)) return false;
  const keys = Object.keys(value);
  return keys.length === 1 && ['$digest', '$sha256', '$caid'].includes(keys[0]);
}

function deepMerge(base: unknown, patch: unknown): unknown {
  if (patch === undefined) return structuredClone(base);
  if (!isRecord(base) || !isRecord(patch)
      || isMaterializationToken(base) || isMaterializationToken(patch)) {
    return structuredClone(patch);
  }
  const result = structuredClone(base) as DataRecord;
  for (const [key, value] of Object.entries(patch)) {
    result[key] = Object.hasOwn(result, key)
      ? deepMerge(result[key], value)
      : structuredClone(value);
  }
  return result;
}

function materialize(value: unknown, label: string): any {
  if (Array.isArray(value)) return value.map((entry, index) => materialize(entry, `${label}[${index}]`));
  if (!isRecord(value)) return value;
  if (isMaterializationToken(value)) {
    if (Object.hasOwn(value, '$digest')) {
      assert.match(value.$digest, /^[0-9a-f]$/, `${label} has invalid $digest token`);
      return `sha256:${value.$digest.repeat(64)}`;
    }
    if (Object.hasOwn(value, '$sha256')) {
      assert.equal(typeof value.$sha256, 'string', `${label} has invalid $sha256 token`);
      return `sha256:${createHash('sha256').update(value.$sha256).digest('hex')}`;
    }
    assert.match(value.$caid, /^[A-Za-z0-9_-]$/, `${label} has invalid $caid token`);
    return `caid:1:payments.refund.1:jcs-sha256:${value.$caid.repeat(43)}`;
  }
  for (const key of Object.keys(value)) {
    assert.equal(key.startsWith('$'), false, `${label}.${key} is an unhandled materialization token`);
  }
  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [key, materialize(entry, `${label}.${key}`)]),
  );
}

function valueAtPath(value: unknown, path: string): unknown {
  let current: any = value;
  for (const segment of path.split('.')) {
    assert.notEqual(current, null, `expectation path ${path} stopped before ${segment}`);
    assert.equal(typeof current, 'object', `expectation path ${path} stopped before ${segment}`);
    assert.equal(Object.hasOwn(current, segment), true, `expectation path ${path} is unhandled`);
    current = current[segment];
  }
  return current;
}

function assertExpectations(result: unknown, expectations: DataRecord, label: string) {
  assert.equal(isRecord(expectations), true, `${label} expectation must be an object`);
  assert.ok(Object.keys(expectations).length > 0, `${label} must explicitly validate its result`);
  for (const [path, expected] of Object.entries(expectations)) {
    assert.deepEqual(
      valueAtPath(result, path),
      materialize(expected, `${label}.expect.${path}`),
      `${label} expectation failed at ${path}`,
    );
  }
}

function verifiedOriginal(input: DataRecord) {
  return {
    ok: true,
    ...input.original,
    evidence_digest: input.original.terminal_evidence_digest,
  };
}

function verifiedRevocation(input: DataRecord) {
  return {
    ok: true,
    evidence_id: input.evidence.id,
    evidence_digest: input.evidence.digest,
    target_operation_id: input.expected.original.operation_id,
    action_digest: input.expected.original.action_digest,
    authority_id: 'deterministic-revocation-authority',
    revoked_at: '2026-07-21T18:15:00.000Z',
  };
}

function verifiedDispute(input: DataRecord) {
  return {
    ok: true,
    ...input.dispute,
    original_operation_id: input.expected.original.operation_id,
    original_action_digest: input.expected.original.action_digest,
  };
}

function verifiedAuthorization(input: DataRecord) {
  return {
    ok: true,
    ...input.authorization,
    dispute_id: input.expected.dispute.dispute_id,
    original_operation_id: input.expected.original.operation_id,
    destination_binding_digest: input.expected.destination_binding_digest,
    unit: input.expected.unit,
  };
}

function verifiedOutcome(input: DataRecord) {
  return {
    ok: true,
    evidence_id: input.evidence.evidence_id,
    evidence_digest: input.evidence.evidence_digest,
    remedy_operation_id: input.expected.remedy_operation_id,
    remedy_action_digest: input.expected.remedy_action_digest,
    destination_binding_digest: input.expected.destination_binding_digest,
    units: input.expected.units,
    unit: input.expected.unit,
    outcome: input.outcome,
    observed_at: input.evidence.observed_at,
  };
}

function verifiedOriginalReconciliation(input: DataRecord) {
  return {
    ok: true,
    evidence_id: input.evidence.evidence_id,
    evidence_digest: input.evidence.evidence_digest,
    original_operation_id: input.expected.original.operation_id,
    original_action_digest: input.expected.original.action_digest,
    terminal_evidence_digest: input.expected.original.terminal_evidence_digest,
    outcome: input.outcome,
    observed_at: input.evidence.observed_at,
  };
}

function verifiedResolution(input: DataRecord) {
  return {
    ok: true,
    dispute_id: input.expected.dispute.dispute_id,
    ...input.resolution,
  };
}

function kernelFor(vector: CatalogVector) {
  const rejectedAuthorizationEvidence = new Set(
    vector.verifier_policy?.reject_authorization_evidence_ids ?? [],
  );
  return createRemedyProgramKernel({
    store: createRemedyMemoryStore(),
    verifyOriginalEffect: verifiedOriginal,
    verifyRevocation: verifiedRevocation,
    verifyDispute: verifiedDispute,
    verifyRemedyAuthorization: (input: DataRecord) => (
      rejectedAuthorizationEvidence.has(input.authorization.evidence_id)
        ? { ok: false, reason: 'deterministic_trigger_only_refusal' }
        : verifiedAuthorization(input)
    ),
    verifyRemedyOutcome: verifiedOutcome,
    verifyOriginalReconciliation: verifiedOriginalReconciliation,
    verifyResolution: verifiedResolution,
    now: () => NOW,
  });
}

async function dispatch(subject: ReturnType<typeof createRemedyProgramKernel>, op: string, input: unknown) {
  switch (op) {
    case 'create': return subject.create(input);
    case 'status': return subject.status(input);
    case 'recordRevocation': return subject.recordRevocation(input);
    case 'openDispute': return subject.openDispute(input);
    case 'authorizeRemedy': return subject.authorizeRemedy(input);
    case 'claimRemedy': return subject.claimRemedy(input);
    case 'finalizeRemedy': return subject.finalizeRemedy(input);
    case 'reconcileOriginalEffect': return subject.reconcileOriginalEffect(input);
    case 'reconcileRemedy': return subject.reconcileRemedy(input);
    case 'resolveDispute': return subject.resolveDispute(input);
    default: assert.fail(`unhandled Remedy Program vector operation: ${op}`);
  }
}

function validateCatalog() {
  assert.equal(isRecord(catalog), true, 'catalog must be an object');
  assertExactKeys(catalog as unknown as DataRecord, CATALOG_KEYS, 'catalog');
  assert.equal(catalog.profile, REMEDY_PROGRAM_VERSION);
  assert.equal(catalog.vectors_version, '1.0.0');
  assert.equal(catalog.visibility, 'public-experimental');
  assert.equal(catalog.vector_count, catalog.vectors.length, 'declared vector count is stale');
  assert.match(catalog.claim_boundary, /deterministic verifier doubles/);
  assert.match(catalog.claim_boundary, /orchestration-only/);
  assert.match(catalog.claim_boundary, /not independent verification or cryptographic proof/);
  assert.deepEqual(Object.keys(catalog.materialization).sort(), ['$caid', '$digest', '$sha256']);
  assert.equal(isRecord(catalog.fixtures), true);
  assert.ok(Object.keys(catalog.fixtures).length > 0);
  assert.ok(Array.isArray(catalog.vectors));
  assert.ok(catalog.vectors.length > 0);

  const vectorIds = new Set<string>();
  const coverage = new Set<string>();
  const usedFixtures = new Set<string>();
  for (const [index, vector] of catalog.vectors.entries()) {
    assert.equal(isRecord(vector), true, `vector ${index} must be an object`);
    const expectedKeys = new Set(VECTOR_KEYS);
    if (vector.verifier_policy === undefined) expectedKeys.delete('verifier_policy');
    assertExactKeys(vector as unknown as DataRecord, expectedKeys, `vector ${index}`);
    assert.match(vector.id, /^[a-z0-9][a-z0-9_]*$/);
    assert.equal(vectorIds.has(vector.id), false, `duplicate vector id ${vector.id}`);
    vectorIds.add(vector.id);
    assert.ok(vector.description.length > 0, `${vector.id} needs a description`);
    assert.ok(Array.isArray(vector.covers) && vector.covers.length > 0, `${vector.id} needs coverage`);
    vector.covers.forEach((entry) => coverage.add(entry));
    assert.ok(Array.isArray(vector.steps) && vector.steps.length > 0, `${vector.id} needs steps`);
    if (vector.verifier_policy !== undefined) {
      assert.equal(isRecord(vector.verifier_policy), true);
      assertExactKeys(vector.verifier_policy as unknown as DataRecord, POLICY_KEYS, `${vector.id} verifier policy`);
      assert.ok(Array.isArray(vector.verifier_policy.reject_authorization_evidence_ids));
      assert.ok(vector.verifier_policy.reject_authorization_evidence_ids.every(
        (entry) => typeof entry === 'string' && entry.length > 0,
      ));
    }
    for (const [stepIndex, step] of vector.steps.entries()) {
      assert.equal(isRecord(step), true, `${vector.id} step ${stepIndex} must be an object`);
      const expectedStepKeys = new Set(STEP_KEYS);
      if (step.patch === undefined) expectedStepKeys.delete('patch');
      assertExactKeys(step as unknown as DataRecord, expectedStepKeys, `${vector.id} step ${stepIndex}`);
      assert.equal(OPERATIONS.has(step.op), true, `${vector.id} has unhandled operation ${step.op}`);
      assert.equal(Object.hasOwn(catalog.fixtures, step.fixture), true, `${vector.id} has unknown fixture ${step.fixture}`);
      usedFixtures.add(step.fixture);
      assert.equal(isRecord(step.expect), true, `${vector.id} step ${stepIndex} needs an expectation`);
      assert.ok(Object.keys(step.expect).length > 0, `${vector.id} step ${stepIndex} expectation is empty`);
    }
  }
  assert.deepEqual([...coverage].sort(), [...new Set(catalog.required_coverage)].sort(), 'coverage catalog is stale or unhandled');
  assert.deepEqual([...usedFixtures].sort(), Object.keys(catalog.fixtures).sort(), 'catalog has unused or unhandled fixtures');
}

test('Remedy Program catalog is public, exhaustive, and claim-bounded', () => {
  validateCatalog();
});

test('every Remedy Program semantic vector executes against the real kernel', async (t) => {
  validateCatalog();
  let handled = 0;
  for (const vector of catalog.vectors) {
    await t.test(vector.id, async () => {
      const subject = kernelFor(vector);
      for (const [index, step] of vector.steps.entries()) {
        const fixture = catalog.fixtures[step.fixture];
        const input = materialize(
          deepMerge(fixture, step.patch),
          `${vector.id}.steps[${index}].input`,
        );
        const result = await dispatch(subject, step.op, input);
        assertExpectations(result, step.expect, `${vector.id} step ${index} (${step.op})`);
      }
      handled += 1;
    });
  }
  assert.equal(handled, catalog.vector_count, 'one or more catalog vectors were not handled');
});
