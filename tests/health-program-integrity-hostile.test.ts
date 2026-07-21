// SPDX-License-Identifier: Apache-2.0
/**
 * Hostile contract for the Health Program Integrity engine.
 *
 * Expected public surface of lib/health/program-integrity.js:
 *   createProgramIntegrityEngine(config) -> {
 *     prepare({ action }),
 *     precheck({ action, authorization }),
 *     execute({ operation_id, action }),
 *     reconcile({ operation_id, evidence }),
 *     exportEvidence({ operation_id }),
 *   }
 *   verifyProgramIntegrityEvidencePacket(packet) -> { valid, reasons }
 *
 * The engine may expose additional fields, but these tests deliberately pin the
 * externally security-relevant state machine and refusal semantics.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { hashCanonicalAction } from '../lib/guard-policies.js';
import {
  createProgramIntegrityEngine,
  verifyProgramIntegrityEvidencePacket,
} from '../lib/health/program-integrity.js';

const NOW = '2026-07-23T21:30:00.000Z';
const MEMBER_REF = `member:sha256:${'1'.repeat(64)}`;
const FORM_DIGEST = `sha256:${'2'.repeat(64)}`;
const PROVIDER_SNAPSHOT_DIGEST = `sha256:${'3'.repeat(64)}`;
const AUTHORITY_SNAPSHOT_DIGEST = `sha256:${'4'.repeat(64)}`;
const EVIDENCE_DIGEST = `sha256:${'5'.repeat(64)}`;
const DESTINATION_DIGEST = `sha256:${'6'.repeat(64)}`;
const POLICY_HASH = `sha256:${'7'.repeat(64)}`;

const ACTION = Object.freeze({
  '@version': 'EP-HEALTH-PROGRAM-INTEGRITY-ACTION-v1',
  profile_id: 'medi-cal.hospice-integrity.v1',
  action_type: 'health.medi-cal.hospice-claim-payment.1',
  organization_id: 'org:ca-dhcs',
  provider_npi: '1234567890',
  member_ref: MEMBER_REF,
  service_period_start: '2026-07-01',
  service_period_end: '2026-07-15',
  authorization_form_digest: FORM_DIGEST,
  amount: '1250.00',
  currency: 'USD',
  payment_destination_digest: DESTINATION_DIGEST,
  reviewer_id: 'reviewer:integrity-17',
  authority_proof_digest: AUTHORITY_SNAPSHOT_DIGEST,
  policy_id: 'policy:dhcs-hospice-payment',
  policy_version: 1,
  policy_hash: POLICY_HASH,
});

const AUTHORITY = Object.freeze({
  valid: true,
  reviewer_id: 'reviewer:integrity-17',
  organization_id: ACTION.organization_id,
  authority_id: 'authority:dhcs-program-integrity',
  scope: [ACTION.action_type],
  valid_from: '2026-07-01T00:00:00.000Z',
  valid_until: '2026-08-01T00:00:00.000Z',
  revoked_at: null,
  snapshot_digest: AUTHORITY_SNAPSHOT_DIGEST,
});

function clone(value) {
  return structuredClone(value);
}

function rehashPacket(packet) {
  const unsigned = clone(packet);
  delete unsigned.packet_digest;
  packet.packet_digest = `sha256:${hashCanonicalAction(unsigned)}`;
}

function makeAuthorization(actionCaid, over = {}) {
  return {
    '@version': 'EP-HEALTH-PROGRAM-INTEGRITY-AUTHORIZATION-v1',
    reviewer_id: AUTHORITY.reviewer_id,
    authority_id: AUTHORITY.authority_id,
    organization_id: ACTION.organization_id,
    action_caid: actionCaid,
    issued_at: '2026-07-23T21:25:00.000Z',
    expires_at: '2026-07-23T21:35:00.000Z',
    authorization_evidence_digest: EVIDENCE_DIGEST,
    ...over,
  };
}

function makeProviderEvidence(operation, over = {}) {
  return {
    '@version': 'EP-HEALTH-PROGRAM-INTEGRITY-PROVIDER-EVIDENCE-v1',
    provider_id: 'medi-cal-claims-sandbox',
    environment: 'sandbox',
    operation_id: operation.operation_id,
    action_caid: operation.action_caid,
    idempotency_key: operation.idempotency_key,
    outcome: 'executed',
    provider_effect_reference: 'claim-effect-001',
    observed_at: '2026-07-23T21:31:00.000Z',
    signature: {
      algorithm: 'Ed25519',
      key_id: 'medi-cal-sandbox-2026-01',
      value: 'valid-test-signature',
    },
    ...over,
  };
}

function expectRefusal(result, reason) {
  expect(result).toMatchObject({
    ok: false,
    decision: 'REFUSED',
    reason,
  });
}

function makeHarness({
  authority = AUTHORITY,
  providerResult = { status: 'executed', effect_reference: 'claim-effect-001' },
  verifyEvidence,
  engineConfig = {},
} = {}) {
  const submit = vi.fn(async () => clone(providerResult));
  const resolveReviewerAuthority = vi.fn(async () => (
    authority instanceof Error ? Promise.reject(authority) : clone(authority)
  ));
  const verifyProviderEvidence = vi.fn(async ({ evidence }) => {
    if (verifyEvidence) return verifyEvidence(evidence);
    return evidence?.signature?.key_id === 'medi-cal-sandbox-2026-01'
      && evidence?.signature?.value === 'valid-test-signature';
  });
  const engine = createProgramIntegrityEngine({
    now: () => NOW,
    allow_ephemeral_state: true,
    provider_id: 'medi-cal-claims-sandbox',
    provider_environment: 'sandbox',
    provider_snapshot_digest: PROVIDER_SNAPSHOT_DIGEST,
    resolveReviewerAuthority,
    verifyProviderEvidence,
    submit,
    ...engineConfig,
  });
  return {
    engine,
    submit,
    resolveReviewerAuthority,
    verifyProviderEvidence,
  };
}

async function prepareReady(harness, action = ACTION, authorizationOver = {}) {
  const prepared = await harness.engine.prepare({ action: clone(action) });
  expect(prepared).toMatchObject({ ok: true });
  expect(prepared.action_caid).toMatch(/^caid:/);
  const authorization = makeAuthorization(prepared.action_caid, authorizationOver);
  const ready = await harness.engine.precheck({
    action: clone(action),
    authorization,
  });
  expect(ready).toMatchObject({
    ok: true,
    decision: 'READY',
    action_caid: prepared.action_caid,
  });
  expect(ready.operation_id).toEqual(expect.any(String));
  expect(ready.idempotency_key).toEqual(expect.any(String));
  return { prepared, authorization, ready };
}

describe('Health Program Integrity hostile contract', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('refuses caller-selected CAID and cross-profile CAID confusion', async () => {
    const harness = makeHarness();
    const prepared = await harness.engine.prepare({ action: clone(ACTION) });

    const selected = await harness.engine.precheck({
      action: { ...clone(ACTION), action_caid: `caid:${'a'.repeat(64)}` },
      authorization: makeAuthorization(prepared.action_caid),
    });
    expectRefusal(selected, 'caller_selected_caid_refused');

    const otherProfile = {
      ...clone(ACTION),
      profile_id: 'medicare.hospice-integrity.v1',
      action_type: 'health.medicare.hospice-claim-payment.1',
    };
    const confused = await harness.engine.precheck({
      action: otherProfile,
      authorization: makeAuthorization(prepared.action_caid),
    });
    expectRefusal(confused, 'action_caid_mismatch');
  });

  it('refuses the unversioned action type as an action-identity downgrade', async () => {
    const harness = makeHarness();
    const unversioned = {
      ...clone(ACTION),
      action_type: 'health.medi-cal.hospice-claim-payment',
    };

    const prepared = await harness.engine.prepare({ action: unversioned });

    expectRefusal(prepared, 'unsupported_action_type');
    expect(harness.submit).not.toHaveBeenCalled();
  });

  it.each([
    ['caller-selected CAID', (action) => { action.action_caid = `caid:${'a'.repeat(64)}`; }, 'caller_selected_caid_refused'],
    ['wrong envelope version', (action) => { action['@version'] = 'EP-HEALTH-PROGRAM-INTEGRITY-ACTION-v0'; }, 'unsupported_action_profile'],
    ['different versioned action type', (action) => { action.action_type = 'health.medicare.hospice-claim-payment.1'; }, 'unsupported_action_profile'],
    ['missing required string', (action) => { delete action.organization_id; }, 'invalid_action'],
    ['malformed NPI', (action) => { action.provider_npi = '123'; }, 'invalid_action'],
    ['malformed member reference', (action) => { action.member_ref = 'member:raw'; }, 'invalid_action'],
    ['malformed service start', (action) => { action.service_period_start = '2026-02-30'; }, 'invalid_action'],
    ['malformed service end', (action) => { action.service_period_end = 'not-a-date'; }, 'invalid_action'],
    ['reversed service period', (action) => {
      action.service_period_start = '2026-07-16';
      action.service_period_end = '2026-07-15';
    }, 'invalid_action'],
    ['malformed authorization digest', (action) => { action.authorization_form_digest = 'raw'; }, 'invalid_action'],
    ['fractional amount precision', (action) => { action.amount = '1250.001'; }, 'invalid_action'],
    ['zero amount', (action) => { action.amount = '0.00'; }, 'invalid_action'],
    ['wrong currency', (action) => { action.currency = 'EUR'; }, 'invalid_action'],
    ['malformed destination digest', (action) => { action.payment_destination_digest = 'raw'; }, 'invalid_action'],
    ['malformed reviewer ID', (action) => { action.reviewer_id = ' '; }, 'invalid_action'],
    ['malformed authority proof', (action) => { action.authority_proof_digest = 'raw'; }, 'invalid_action'],
    ['fractional policy version', (action) => { action.policy_version = 1.5; }, 'invalid_action'],
    ['non-positive policy version', (action) => { action.policy_version = 0; }, 'invalid_action'],
    ['malformed policy hash', (action) => { action.policy_hash = 'raw'; }, 'invalid_action'],
  ])('refuses malformed exact-action boundary: %s', async (_label, mutate, reason) => {
    const harness = makeHarness();
    const action = clone(ACTION);
    mutate(action);

    const result = await harness.engine.prepare({ action });

    expectRefusal(result, reason);
    expect(harness.submit).not.toHaveBeenCalled();
  });

  it.each([null, [], 'not-an-action'])('refuses a non-object exact action %#', async (action) => {
    const harness = makeHarness();
    const result = await harness.engine.prepare({ action });
    expectRefusal(result, 'invalid_action');
  });

  it.each([
    ['amount', (action) => { action.amount = '12500.00'; }],
    ['destination', (action) => { action.payment_destination_digest = `sha256:${'8'.repeat(64)}`; }],
    ['provider', (action) => { action.provider_npi = '1098765432'; }],
    ['member', (action) => { action.member_ref = `member:sha256:${'9'.repeat(64)}`; }],
    ['service-period start', (action) => { action.service_period_start = '2026-06-01'; }],
    ['service-period end', (action) => { action.service_period_end = '2026-07-31'; }],
  ])('refuses %s substitution after approval', async (_label, mutate) => {
    const harness = makeHarness();
    const { ready } = await prepareReady(harness);
    const changed = clone(ACTION);
    mutate(changed);

    const result = await harness.engine.execute({
      operation_id: ready.operation_id,
      action: changed,
    });

    expectRefusal(result, 'execution_action_mismatch');
    expect(harness.submit).not.toHaveBeenCalled();
  });

  it('refuses stale or expired authorization rather than extending its life', async () => {
    const harness = makeHarness();
    const prepared = await harness.engine.prepare({ action: clone(ACTION) });

    const expired = await harness.engine.precheck({
      action: clone(ACTION),
      authorization: makeAuthorization(prepared.action_caid, {
        issued_at: '2026-07-23T20:00:00.000Z',
        expires_at: '2026-07-23T21:29:59.999Z',
      }),
    });

    expectRefusal(expired, 'authorization_expired');
  });

  it.each([
    ['not found', null],
    ['wrong organization', { ...AUTHORITY, organization_id: 'org:other' }],
    ['wrong scope', { ...AUTHORITY, scope: ['medi-cal.provider.read'] }],
    ['revoked', { ...AUTHORITY, revoked_at: '2026-07-23T21:29:00.000Z' }],
    ['expired', { ...AUTHORITY, valid_until: '2026-07-23T21:29:59.999Z' }],
  ])('refuses missing reviewer authority: %s', async (_label, authority) => {
    const harness = makeHarness({ authority });
    const prepared = await harness.engine.prepare({ action: clone(ACTION) });
    const result = await harness.engine.precheck({
      action: clone(ACTION),
      authorization: makeAuthorization(prepared.action_caid),
    });

    expectRefusal(result, 'reviewer_authority_unsatisfied');
  });

  it('keeps a dispatched timeout indeterminate and refuses blind replay', async () => {
    const harness = makeHarness({
      providerResult: {
        status: 'indeterminate',
        dispatch_confirmed: true,
        provider_request_id: 'provider-request-001',
      },
    });
    const { ready } = await prepareReady(harness);

    const first = await harness.engine.execute({
      operation_id: ready.operation_id,
      action: clone(ACTION),
    });
    expect(first).toMatchObject({
      ok: false,
      decision: 'INDETERMINATE',
      reason: 'provider_outcome_indeterminate',
      operation_id: ready.operation_id,
    });
    expect(harness.submit).toHaveBeenCalledTimes(1);

    const replay = await harness.engine.execute({
      operation_id: ready.operation_id,
      action: clone(ACTION),
    });
    expectRefusal(replay, 'replay_refused');
    expect(harness.submit).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['untrusted key', (operation) => makeProviderEvidence(operation, {
      signature: {
        algorithm: 'Ed25519',
        key_id: 'attacker-key',
        value: 'forged',
      },
    })],
    ['wrong operation', (operation) => makeProviderEvidence(operation, {
      operation_id: 'health-op-attacker',
    })],
    ['wrong CAID', (operation) => makeProviderEvidence(operation, {
      action_caid: `caid:${'f'.repeat(64)}`,
    })],
    ['wrong idempotency key', (operation) => makeProviderEvidence(operation, {
      idempotency_key: 'health-idem-attacker',
    })],
    ['wrong provider', (operation) => makeProviderEvidence(operation, {
      provider_id: 'untrusted-provider',
    })],
    ['wrong environment', (operation) => makeProviderEvidence(operation, {
      environment: 'production',
    })],
  ])('refuses forged provider reconciliation: %s', async (_label, evidenceFor) => {
    const harness = makeHarness({
      providerResult: {
        status: 'indeterminate',
        dispatch_confirmed: true,
        provider_request_id: 'provider-request-002',
      },
    });
    const { ready } = await prepareReady(harness);
    const unknown = await harness.engine.execute({
      operation_id: ready.operation_id,
      action: clone(ACTION),
    });
    const evidence = evidenceFor(unknown);

    const reconciled = await harness.engine.reconcile({
      operation_id: ready.operation_id,
      evidence,
    });

    expectRefusal(reconciled, 'provider_evidence_invalid');
    expect(reconciled.previous_decision).toBe('INDETERMINATE');
  });

  it('makes reconciliation terminal: exact duplicate is idempotent and conflict refuses', async () => {
    const harness = makeHarness({
      providerResult: {
        status: 'indeterminate',
        dispatch_confirmed: true,
        provider_request_id: 'provider-request-003',
      },
    });
    const { ready } = await prepareReady(harness);
    const unknown = await harness.engine.execute({
      operation_id: ready.operation_id,
      action: clone(ACTION),
    });
    const evidence = makeProviderEvidence(unknown);

    const first = await harness.engine.reconcile({
      operation_id: ready.operation_id,
      evidence,
    });
    expect(first).toMatchObject({
      ok: true,
      decision: 'RECONCILED_EXECUTED',
      operation_id: ready.operation_id,
    });

    const duplicate = await harness.engine.reconcile({
      operation_id: ready.operation_id,
      evidence: clone(evidence),
    });
    expect(duplicate).toMatchObject({
      ok: true,
      decision: 'RECONCILED_EXECUTED',
      idempotent: true,
    });

    const conflict = await harness.engine.reconcile({
      operation_id: ready.operation_id,
      evidence: {
        ...clone(evidence),
        outcome: 'not_executed',
        provider_effect_reference: 'claim-effect-conflict',
      },
    });
    expectRefusal(conflict, 'reconciliation_conflict');
  });

  it('fails closed without durable state and uses a configured durable store idempotently', async () => {
    const unavailable = makeHarness({
      engineConfig: {
        allow_ephemeral_state: false,
      },
    });
    const prepared = await unavailable.engine.prepare({ action: clone(ACTION) });
    const refused = await unavailable.engine.precheck({
      action: clone(ACTION),
      authorization: makeAuthorization(prepared.action_caid),
    });
    expectRefusal(refused, 'state_storage_unavailable');

    const records = new Map();
    const stateStore = {
      get: vi.fn(async (operationId) => records.get(operationId) || null),
      set: vi.fn(async (operationId, operation) => {
        records.set(operationId, clone(operation));
      }),
    };
    const durable = makeHarness({
      engineConfig: {
        allow_ephemeral_state: false,
        state_store: stateStore,
      },
    });
    const first = await prepareReady(durable);
    const duplicate = await durable.engine.precheck({
      action: clone(ACTION),
      authorization: clone(first.authorization),
    });

    expect(duplicate).toMatchObject({
      ok: true,
      decision: 'READY',
      operation_id: first.ready.operation_id,
      idempotent: true,
    });
    expect(stateStore.get).toHaveBeenCalled();
    expect(stateStore.set).toHaveBeenCalledTimes(1);
  });

  it('fails closed for an incomplete durable store and refuses conflicting stored operations', async () => {
    const incomplete = makeHarness({
      engineConfig: {
        allow_ephemeral_state: false,
        state_store: {},
      },
    });
    const incompletePrepared = await incomplete.engine.prepare({ action: clone(ACTION) });
    const unavailable = await incomplete.engine.precheck({
      action: clone(ACTION),
      authorization: makeAuthorization(incompletePrepared.action_caid),
    });
    expectRefusal(unavailable, 'state_storage_unavailable');

    let stored;
    const collisionStore = {
      get: vi.fn(async () => stored),
      set: vi.fn(async () => undefined),
    };
    const collision = makeHarness({
      engineConfig: {
        allow_ephemeral_state: false,
        state_store: collisionStore,
      },
    });
    const collisionPrepared = await collision.engine.prepare({ action: clone(ACTION) });
    const authorization = makeAuthorization(collisionPrepared.action_caid);

    stored = {
      action_caid: `caid:1:health.medi-cal.hospice-claim-payment.1:jcs-sha256:${'A'.repeat(43)}`,
      decision: 'READY',
    };
    const mismatched = await collision.engine.precheck({
      action: clone(ACTION),
      authorization: clone(authorization),
    });
    expectRefusal(mismatched, 'operation_action_mismatch');

    stored = {
      action_caid: collisionPrepared.action_caid,
      decision: 'EXECUTED',
    };
    const replay = await collision.engine.precheck({
      action: clone(ACTION),
      authorization: clone(authorization),
    });
    expectRefusal(replay, 'replay_refused');
  });

  it('uses the default clock safely and refuses unknown operations on both terminal APIs', async () => {
    const defaultClockEngine = createProgramIntegrityEngine({
      allow_ephemeral_state: true,
    });
    const prepared = await defaultClockEngine.prepare({ action: clone(ACTION) });
    expect(prepared).toMatchObject({ ok: true });

    const harness = makeHarness();
    expectRefusal(await harness.engine.execute({
      operation_id: 'health-op-missing',
      action: clone(ACTION),
    }), 'operation_not_found');
    expectRefusal(await harness.engine.reconcile({
      operation_id: 'health-op-missing',
      evidence: {},
    }), 'operation_not_found');
  });

  it('exports a minimal executed packet when optional provider metadata and effect references are absent', async () => {
    const harness = makeHarness({
      providerResult: { status: 'executed' },
      engineConfig: {
        provider_id: undefined,
        provider_environment: undefined,
        provider_snapshot_digest: undefined,
      },
    });
    const { ready } = await prepareReady(harness);
    const executed = await harness.engine.execute({
      operation_id: ready.operation_id,
      action: clone(ACTION),
    });
    expect(executed).toMatchObject({ ok: true, decision: 'EXECUTED' });

    const packet = await harness.engine.exportEvidence({
      operation_id: ready.operation_id,
    });
    expect(packet.provider).toEqual({
      provider_id: null,
      environment: null,
      snapshot_digest: null,
    });
    expect(verifyProgramIntegrityEvidencePacket(packet)).toEqual({
      valid: true,
      reasons: [],
    });
  });

  it('fails closed when the provider adapter is absent, refuses an explicit provider denial, and blocks early export', async () => {
    const noAdapter = makeHarness({
      engineConfig: {
        submit: undefined,
      },
    });
    const missing = await prepareReady(noAdapter);
    const indeterminate = await noAdapter.engine.execute({
      operation_id: missing.ready.operation_id,
      action: clone(ACTION),
    });
    expect(indeterminate).toMatchObject({
      ok: false,
      decision: 'INDETERMINATE',
      reason: 'provider_outcome_indeterminate',
    });

    const denied = makeHarness({
      providerResult: { status: 'refused' },
    });
    const ready = await prepareReady(denied);
    const premature = await denied.engine.exportEvidence({
      operation_id: ready.ready.operation_id,
    });
    expectRefusal(premature, 'evidence_not_available');

    const refusal = await denied.engine.execute({
      operation_id: ready.ready.operation_id,
      action: clone(ACTION),
    });
    expectRefusal(refusal, 'provider_refused');

    const missingOperation = await denied.engine.exportEvidence({
      operation_id: 'health-op-missing',
    });
    expectRefusal(missingOperation, 'operation_not_found');
  });

  it('records an authenticated not-executed reconciliation as a terminal verifiable outcome', async () => {
    const harness = makeHarness({
      providerResult: {
        status: 'indeterminate',
        dispatch_confirmed: true,
      },
    });
    const { ready } = await prepareReady(harness);
    const unknown = await harness.engine.execute({
      operation_id: ready.operation_id,
      action: clone(ACTION),
    });
    const evidence = makeProviderEvidence(unknown, {
      outcome: 'not_executed',
      provider_effect_reference: null,
    });
    const reconciled = await harness.engine.reconcile({
      operation_id: ready.operation_id,
      evidence,
    });
    expect(reconciled).toMatchObject({
      ok: true,
      decision: 'RECONCILED_FAILED',
      authenticated_provider_evidence: true,
    });

    const packet = await harness.engine.exportEvidence({
      operation_id: ready.operation_id,
    });
    expect(verifyProgramIntegrityEvidencePacket(packet)).toEqual({
      valid: true,
      reasons: [],
    });
  });

  it('fails closed when provider-evidence verification throws and forbids reconciliation before an indeterminate outcome', async () => {
    const readyHarness = makeHarness();
    const ready = await prepareReady(readyHarness);
    const early = await readyHarness.engine.reconcile({
      operation_id: ready.ready.operation_id,
      evidence: makeProviderEvidence(ready.ready),
    });
    expectRefusal(early, 'reconciliation_not_allowed');

    const throwing = makeHarness({
      providerResult: {
        status: 'indeterminate',
        dispatch_confirmed: true,
      },
      verifyEvidence: () => {
        throw new Error('provider trust service unavailable');
      },
    });
    const prepared = await prepareReady(throwing);
    const unknown = await throwing.engine.execute({
      operation_id: prepared.ready.operation_id,
      action: clone(ACTION),
    });
    const refused = await throwing.engine.reconcile({
      operation_id: prepared.ready.operation_id,
      evidence: makeProviderEvidence(unknown),
    });
    expectRefusal(refused, 'provider_evidence_invalid');
  });

  it.each([
    ['runtime observe flag', { enforcement_mode: 'observe' }],
    ['caller allow flag', { fail_open: true }],
    ['unknown bypass field', { bypass_checks: true }],
  ])('refuses runtime fail-open downgrade: %s', async (_label, downgrade) => {
    const harness = makeHarness();
    const prepared = await harness.engine.prepare({ action: clone(ACTION) });
    const result = await harness.engine.precheck({
      action: { ...clone(ACTION), ...downgrade },
      authorization: makeAuthorization(prepared.action_caid),
    });

    expectRefusal(result, 'runtime_downgrade_refused');
    expect(harness.submit).not.toHaveBeenCalled();
  });

  it('fails closed when reviewer authority resolution throws', async () => {
    const harness = makeHarness({ authority: new Error('directory unavailable') });
    const prepared = await harness.engine.prepare({ action: clone(ACTION) });
    const result = await harness.engine.precheck({
      action: clone(ACTION),
      authorization: makeAuthorization(prepared.action_caid),
    });

    expectRefusal(result, 'reviewer_authority_unavailable');
  });

  it.each([
    ['member_name', 'Jane Example'],
    ['date_of_birth', '1950-01-01'],
    ['diagnosis', 'terminal condition'],
    ['clinical_note', 'raw clinical narrative'],
    ['authorization_form', 'raw form content'],
    ['medicare_beneficiary_identifier', '1EG4-TE5-MK73'],
  ])('refuses prohibited PHI field %s before it can enter evidence', async (field, value) => {
    const harness = makeHarness();
    const result = await harness.engine.prepare({
      action: { ...clone(ACTION), [field]: value },
    });

    expectRefusal(result, 'prohibited_phi');
  });

  it('refuses prohibited PHI carried in authorization before authority resolution', async () => {
    const harness = makeHarness();
    const prepared = await harness.engine.prepare({ action: clone(ACTION) });
    const result = await harness.engine.precheck({
      action: clone(ACTION),
      authorization: makeAuthorization(prepared.action_caid, {
        clinical_note: 'raw clinical narrative',
      }),
    });

    expectRefusal(result, 'prohibited_phi');
    expect(harness.resolveReviewerAuthority).not.toHaveBeenCalled();
    expect(harness.submit).not.toHaveBeenCalled();
  });

  it('refuses prohibited PHI in provider evidence before signature verification', async () => {
    const harness = makeHarness({
      providerResult: {
        status: 'indeterminate',
        dispatch_confirmed: true,
        provider_request_id: 'provider-request-phi',
      },
    });
    const { ready } = await prepareReady(harness);
    const unknown = await harness.engine.execute({
      operation_id: ready.operation_id,
      action: clone(ACTION),
    });
    harness.verifyProviderEvidence.mockClear();

    const result = await harness.engine.reconcile({
      operation_id: ready.operation_id,
      evidence: makeProviderEvidence(unknown, {
        authorization_form: 'raw authorization form',
      }),
    });

    expectRefusal(result, 'prohibited_phi');
    expect(result.previous_decision).toBe('INDETERMINATE');
    expect(harness.verifyProviderEvidence).not.toHaveBeenCalled();
  });

  it('exports a minimal unambiguous packet without raw PHI', async () => {
    const harness = makeHarness();
    const { ready } = await prepareReady(harness);
    const executed = await harness.engine.execute({
      operation_id: ready.operation_id,
      action: clone(ACTION),
    });
    expect(executed).toMatchObject({ ok: true, decision: 'EXECUTED' });

    const packet = await harness.engine.exportEvidence({
      operation_id: ready.operation_id,
    });
    const serialized = JSON.stringify(packet);

    expect(packet).toMatchObject({
      operation_id: ready.operation_id,
      action_caid: ready.action_caid,
      decision: 'EXECUTED',
      action: {
        provider_npi: ACTION.provider_npi,
        member_ref: ACTION.member_ref,
        service_period_start: ACTION.service_period_start,
        service_period_end: ACTION.service_period_end,
        authorization_form_digest: ACTION.authorization_form_digest,
        amount: ACTION.amount,
        currency: ACTION.currency,
        payment_destination_digest: ACTION.payment_destination_digest,
      },
    });
    expect(serialized).not.toContain('Jane Example');
    expect(serialized).not.toContain('1950-01-01');
    expect(serialized).not.toMatch(/member_name|date_of_birth|diagnosis|clinical_note|authorization_form":/);

    expect(verifyProgramIntegrityEvidencePacket(packet)).toMatchObject({
      valid: true,
      reasons: [],
    });
  });

  it.each([
    ['missing action CAID', (packet) => { delete packet.action_caid; }],
    ['missing operation ID', (packet) => { delete packet.operation_id; }],
    ['wrong packet version', (packet) => { packet['@version'] = 'EP-HEALTH-PROGRAM-INTEGRITY-EVIDENCE-v0'; }],
    ['empty operation ID', (packet) => { packet.operation_id = ''; }],
    ['non-string action CAID', (packet) => { packet.action_caid = 7; }],
    ['non-object action', (packet) => { packet.action = []; }],
    ['embedded raw authorization', (packet) => { packet.authorization = { form: 'raw' }; }],
    ['nested PHI in an array', (packet) => { packet.annotations = [{ clinical_note: 'raw' }]; }],
    ['malformed action digest', (packet) => { packet.action_digest = 'not-a-digest'; }],
    ['summary/action mismatch', (packet) => { packet.action.amount = '9999.00'; }],
    ['wrong exact-action CAID', (packet) => {
      packet.action_caid = packet.action_caid.replace(
        /jcs-sha256:[A-Za-z0-9_-]{43}$/,
        `jcs-sha256:${'A'.repeat(43)}`,
      );
    }],
    ['conflicting outcome', (packet) => { packet.outcome = 'not_executed'; }],
    ['unknown decision', (packet) => {
      packet.decision = 'READY';
      packet.outcome = 'ready';
    }],
    ['non-array operation records', (packet) => { packet.operations = {}; }],
    ['empty operation records', (packet) => { packet.operations = []; }],
    ['wrong operation record', (packet) => {
      packet.operations = [{
        operation_id: 'health-op-other',
        decision: packet.decision,
      }];
    }],
    ['wrong operation decision', (packet) => {
      packet.operations = [{
        operation_id: packet.operation_id,
        decision: 'REFUSED',
      }];
    }],
    ['duplicate operation records', (packet) => {
      packet.operations = [
        { operation_id: packet.operation_id, decision: 'EXECUTED' },
        { operation_id: packet.operation_id, decision: 'REFUSED' },
      ];
    }],
  ])('evidence verifier refuses ambiguity: %s', async (_label, mutate) => {
    const harness = makeHarness();
    const { ready } = await prepareReady(harness);
    await harness.engine.execute({
      operation_id: ready.operation_id,
      action: clone(ACTION),
    });
    const packet = clone(await harness.engine.exportEvidence({
      operation_id: ready.operation_id,
    }));
    mutate(packet);
    rehashPacket(packet);

    const verdict = verifyProgramIntegrityEvidencePacket(packet);

    expect(verdict.valid).toBe(false);
    expect(verdict.reasons).toContain('evidence_packet_ambiguous');
  });

  it('accepts an optional single operation record that exactly matches the packet', async () => {
    const harness = makeHarness();
    const { ready } = await prepareReady(harness);
    await harness.engine.execute({
      operation_id: ready.operation_id,
      action: clone(ACTION),
    });
    const packet = clone(await harness.engine.exportEvidence({
      operation_id: ready.operation_id,
    }));
    packet.operations = [{
      operation_id: packet.operation_id,
      decision: packet.decision,
    }];
    rehashPacket(packet);

    expect(verifyProgramIntegrityEvidencePacket(packet)).toEqual({
      valid: true,
      reasons: [],
    });
  });

  it.each([null, [], 'not-a-packet'])('refuses a non-object evidence packet %#', (packet) => {
    expect(verifyProgramIntegrityEvidencePacket(packet)).toEqual({
      valid: false,
      reasons: ['evidence_packet_ambiguous'],
    });
  });
});
