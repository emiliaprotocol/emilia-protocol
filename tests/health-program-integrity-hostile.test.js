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
  action_type: 'health.medi_cal.hospice_claim_payment.1',
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
      action_type: 'health.medicare.hospice_claim_payment.1',
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
      action_type: 'health.medi_cal.hospice_claim_payment',
    };

    const prepared = await harness.engine.prepare({ action: unversioned });

    expectRefusal(prepared, 'unsupported_action_type');
    expect(harness.submit).not.toHaveBeenCalled();
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
    ['summary/action mismatch', (packet) => { packet.action.amount = '9999.00'; }],
    ['conflicting outcome', (packet) => { packet.outcome = 'not_executed'; }],
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

    const verdict = verifyProgramIntegrityEvidencePacket(packet);

    expect(verdict.valid).toBe(false);
    expect(verdict.reasons).toContain('evidence_packet_ambiguous');
  });
});
