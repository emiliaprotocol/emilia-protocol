import { describe, expect, it } from 'vitest';

import {
  createSyntheticHospiceScenario,
  evaluateHospiceProgramIntegrity,
  reconcileHospiceProgramIntegrity,
} from '../lib/health/program-integrity.js';

const FORBIDDEN = /patient_name|date_of_birth|diagnosis_text|clinical_note|bank_account|raw_provider_evidence/i;

function clone(value) {
  return structuredClone(value);
}

function expectBlockedFor(mutator) {
  const scenario = createSyntheticHospiceScenario();
  mutator(scenario);
  const result = evaluateHospiceProgramIntegrity(scenario);
  expect(result.decision).toBe('blocked');
  expect(result.caid).toBeNull();
  expect(result.operation_id).toBe(scenario.operation_id);
}

describe('synthetic Medi-Cal hospice program integrity', () => {
  it('exports exactly the stable collaborator interfaces', async () => {
    const module = await import('../lib/health/program-integrity.js');
    expect(Object.keys(module).sort()).toEqual([
      'createSyntheticHospiceScenario',
      'evaluateHospiceProgramIntegrity',
      'reconcileHospiceProgramIntegrity',
    ]);
  });

  it('creates deterministic PHI-free input and approves the exact synthetic action', () => {
    const first = createSyntheticHospiceScenario();
    const second = createSyntheticHospiceScenario();
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));

    const result = evaluateHospiceProgramIntegrity(first);
    expect(result.decision).toBe('approved');
    expect(result.operation_id).toBe('hospice-op-001');
    expect(result.caid).toMatch(/^caid:1:[a-z0-9.-]+\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/);
    expect(result.requirements).toEqual([
      'provider_npi',
      'pairwise_member_ref',
      'service_period',
      'authorization_digest',
      'positive_usd_amount',
      'destination_digest',
      'provider_standing',
      'verified_authorization',
      'named_reviewer',
      'authority_proof',
      'policy',
      'trust_evidence',
    ]);
    expect(result.evidence_summary).toEqual({
      provider_npi: 'valid',
      member_ref: 'pairwise',
      service_period: 'valid',
      authorization: 'verified',
      amount: 'positive_usd',
      destination: 'digest_bound',
      provider_standing: 'in_good_standing',
      reviewer: 'named',
      authority: 'verified',
      policy: 'pinned',
      trust: 'verified',
      execution_binding: 'exact',
      capability: 'single_use_committed',
    });
    expect(result.replay_safe).toBe(true);
  });

  it.each([
    ['missing provider NPI', (scenario) => { delete scenario.provider.npi; }],
    ['malformed provider NPI', (scenario) => { scenario.provider.npi = 'not-an-npi'; }],
    ['missing pairwise member ref', (scenario) => { delete scenario.member_ref; }],
    ['non-pairwise member ref', (scenario) => { scenario.member_ref = 'member:raw-identifier'; }],
    ['malformed service period', (scenario) => { scenario.service_period.end = '2026-02-31'; }],
    ['missing authorization digest', (scenario) => { delete scenario.authorization.digest; }],
    ['malformed authorization digest', (scenario) => { scenario.authorization.digest = 'sha256:not-a-digest'; }],
    ['non-positive amount', (scenario) => { scenario.claim.amount_usd = 0; }],
    ['non-USD amount', (scenario) => { scenario.claim.currency = 'EUR'; }],
    ['missing destination digest', (scenario) => { delete scenario.claim.destination_digest; }],
    ['untrusted provider standing', (scenario) => { scenario.provider.standing = 'unknown'; }],
    ['unverified authorization', (scenario) => { scenario.authorization.verified = false; }],
    ['missing named reviewer', (scenario) => { scenario.authorization.reviewer = ''; }],
    ['malformed authority proof', (scenario) => { scenario.authority.proof_digest = 'raw-proof'; }],
    ['missing policy', (scenario) => { scenario.authority.policy = ''; }],
    ['malformed trust evidence', (scenario) => { scenario.authority.trust_evidence_digest = 'raw-trust'; }],
  ])('fails closed for %s', (_label, mutator) => {
    expectBlockedFor(mutator);
  });

  it('refuses exact-action substitution before reserving or executing', () => {
    const scenario = createSyntheticHospiceScenario();
    const substituted = clone(scenario);
    substituted.member_ref = 'pairwise:synthetic-member-attacker';

    const result = evaluateHospiceProgramIntegrity(substituted);
    expect(result.decision).toBe('blocked');
    expect(result.reason_codes).toContain('authorization_action_binding_failed');

    const observedSubstitution = createSyntheticHospiceScenario();
    const observed = clone(observedSubstitution);
    observed.claim.destination_digest = `sha256:${'d'.repeat(64)}`;
    const observedResult = evaluateHospiceProgramIntegrity(observedSubstitution, {
      observedAction: observed,
    });
    expect(observedResult.decision).toBe('blocked');
    expect(observedResult.reason_codes).toContain('execution_action_mismatch');
  });

  it('refuses duplicate use of an already committed operation', () => {
    const scenario = createSyntheticHospiceScenario();
    const first = evaluateHospiceProgramIntegrity(scenario);
    const second = evaluateHospiceProgramIntegrity(scenario);

    expect(first.decision).toBe('approved');
    expect(second.decision).toBe('blocked');
    expect(second.reason_codes).toContain('operation_already_committed');
    expect(second.caid).toBe(first.caid);
  });

  it('refuses a second caller while the same operation is reserved', () => {
    const scenario = createSyntheticHospiceScenario();
    const first = evaluateHospiceProgramIntegrity(scenario, { providerOutcome: 'pending' });
    const second = evaluateHospiceProgramIntegrity(scenario);

    expect(first.decision).toBe('blocked');
    expect(first.reason_codes).toContain('provider_operation_in_flight');
    expect(second.decision).toBe('blocked');
    expect(second.reason_codes).toContain('operation_in_flight');
  });

  it('consumes an indeterminate operation and refuses blind replay', () => {
    const scenario = createSyntheticHospiceScenario();
    const timeout = evaluateHospiceProgramIntegrity(scenario, { providerOutcome: 'response_lost' });
    const retry = evaluateHospiceProgramIntegrity(scenario);

    expect(timeout.decision).toBe('indeterminate');
    expect(timeout.replay_safe).toBe(false);
    expect(timeout.evidence_summary.capability).toBe('single_use_indeterminate');
    expect(retry.decision).toBe('blocked');
    expect(retry.reason_codes).toContain('blind_replay_refused');
    expect(retry.replay_safe).toBe(false);
  });

  it('reconciles only authenticated exact-operation and exact-CAID provider evidence', () => {
    const scenario = createSyntheticHospiceScenario();
    const indeterminate = evaluateHospiceProgramIntegrity(scenario, { providerOutcome: 'timeout' });
    const reconciled = reconcileHospiceProgramIntegrity(scenario, {
      providerEvidence: scenario.provider_evidence,
    });

    expect(indeterminate.decision).toBe('indeterminate');
    expect(reconciled.decision).toBe('reconciled');
    expect(reconciled.caid).toBe(indeterminate.caid);
    expect(reconciled.evidence_summary.provider_evidence).toBe('authenticated_exact_match');
    expect(reconciled.replay_safe).toBe(true);
    expect(reconciled).not.toHaveProperty('provider_evidence');
    expect(reconciled).not.toHaveProperty('raw_provider_evidence');

    const idempotent = reconcileHospiceProgramIntegrity(scenario, {
      providerEvidence: scenario.provider_evidence,
    });
    expect(idempotent.decision).toBe('reconciled');
    expect(idempotent.reason_codes).toContain('reconciliation_idempotent');
  });

  it.each([
    ['tampered signature body', (evidence) => { evidence.body.status = 'reversed'; }],
    ['wrong operation', (evidence) => { evidence.body.operation_id = 'hospice-op-attacker'; }],
    ['wrong CAID', (evidence) => {
      evidence.body.caid = evidence.body.caid.replace(/jcs-sha256:[A-Za-z0-9_-]{43}$/, `jcs-sha256:${'A'.repeat(43)}`);
    }],
  ])('keeps %s reconciliation indeterminate', (_label, tamper) => {
    const scenario = createSyntheticHospiceScenario();
    evaluateHospiceProgramIntegrity(scenario, { providerOutcome: 'response_lost' });
    const evidence = clone(scenario.provider_evidence);
    tamper(evidence);

    const result = reconcileHospiceProgramIntegrity(scenario, { providerEvidence: evidence });
    expect(result.decision).toBe('indeterminate');
    expect(result.replay_safe).toBe(false);
    expect(result.reason_codes).toContain('provider_evidence_rejected');
  });

  it('rejects provider evidence for another exact action even when it is authentic', () => {
    const first = createSyntheticHospiceScenario();
    const other = createSyntheticHospiceScenario({ operation_id: 'hospice-op-002' });
    evaluateHospiceProgramIntegrity(first, { providerOutcome: 'response_lost' });

    const result = reconcileHospiceProgramIntegrity(first, {
      providerEvidence: other.provider_evidence,
    });
    expect(result.decision).toBe('indeterminate');
    expect(result.reason_codes).toContain('provider_evidence_rejected');
  });

  it('does not leak PHI, raw provider evidence, or claim content in summaries', () => {
    const scenario = createSyntheticHospiceScenario();
    const approved = evaluateHospiceProgramIntegrity(scenario);
    const indeterminateScenario = createSyntheticHospiceScenario({ operation_id: 'hospice-op-003' });
    evaluateHospiceProgramIntegrity(indeterminateScenario, { providerOutcome: 'response_lost' });
    const indeterminate = reconcileHospiceProgramIntegrity(indeterminateScenario, {
      providerEvidence: indeterminateScenario.provider_evidence,
    });

    expect(JSON.stringify(approved)).not.toMatch(FORBIDDEN);
    expect(JSON.stringify(indeterminate)).not.toMatch(FORBIDDEN);
    expect(JSON.stringify(approved)).not.toMatch(/pairwise:|sha256:[0-9a-f]{64}/i);
    expect(JSON.stringify(indeterminate)).not.toMatch(/pairwise:|sha256:[0-9a-f]{64}/i);
  });
});
