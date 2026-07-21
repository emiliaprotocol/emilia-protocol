// SPDX-License-Identifier: Apache-2.0
//
// EP-ADMISSIBILITY vector — one heterogeneous evidence bundle, evaluated against
// several RELYING-PARTY-supplied evidence policies, yielding the classified
// verdict: admissible | missing_evidence | stale | conflicted | unverifiable.
//
// The point this vector makes concrete:
//   • sufficiency is RELATIVE to a reliance purpose — the SAME bundle is
//     `admissible` for audit and `missing_evidence` for money movement;
//   • the policy is supplied by the RELYING PARTY, never read from the bundle;
//   • the verdict is DETERMINISTIC — re-running with the same (policy, facts,
//     as_of) reproduces the same verdict and the same replay_digest.
//
// Run:  node examples/admissibility/admissibility-vector.mjs [--emit]
//
// The per-component `verified` flags here stand in for the output of the real
// type verifiers (EP-RECEIPT verify, the recourse verifier, permit/attestation
// verifiers). This module is about the POLICY decision over verified facts.

import assert from 'node:assert/strict';
import { SUBJECT_DIGEST, RECEIPT_PAYLOAD_DIGEST } from '../recourse/recourse-reference-vector.mjs';
import { evaluateAdmissibility } from '../../lib/evidence/admissibility.js';

// A fixed evaluation instant, so freshness is deterministic (no wall clock).
export const AS_OF = '2026-07-02T12:00:00Z';
const ACTION = SUBJECT_DIGEST; // all legs bind the same action

// ── The bundle: a well-formed, verified set of legs for one agent action ──────
// (authorization_receipt = the EMILIA WHO apex; policy_permit = CAN; the rest
//  are the surrounding legs a high-stakes reliance purpose may demand.)
export function baseComponents(): any[] {
  return [
    { type: 'agent_identity',         verified: true, action_digest: ACTION, issued_at: '2026-07-02T11:58:00Z', label: 'WIMSE/SPIFFE' },
    { type: 'policy_permit',          verified: true, action_digest: ACTION, issued_at: '2026-07-02T11:59:00Z', outcome: 'allow' },
    { type: 'authorization_receipt',  verified: true, action_digest: ACTION, issued_at: '2026-07-02T11:59:30Z', outcome: 'allow', label: 'named-human, EP-RECEIPT-v1' },
    { type: 'execution_attestation',  verified: true, action_digest: ACTION, issued_at: '2026-07-02T12:00:00Z' },
    { type: 'transparency',           verified: true, action_digest: ACTION, issued_at: '2026-07-02T12:00:05Z', label: 'SCITT inclusion' },
    { type: 'recourse_reference',     verified: true, action_digest: ACTION, issued_at: '2026-07-02T11:59:40Z', label: `bound to ${RECEIPT_PAYLOAD_DIGEST.slice(0, 14)}…` },
  ];
}

// ── Reliance-purpose evidence policies (RELYING-PARTY supplied) ───────────────
export const POLICIES = {
  // Audit just needs the human authorization + a transparency anchor.
  audit: {
    policy_id: 'ep:evpolicy:audit:v1',
    reliance_purpose: 'audit',
    requirement: 'authorization_receipt AND transparency',
  },
  // Money movement demands the full chain, tight freshness, and live recourse.
  money_movement: {
    policy_id: 'ep:evpolicy:money-movement:v1',
    reliance_purpose: 'money_movement',
    requirement: 'agent_identity AND policy_permit AND authorization_receipt AND execution_attestation AND recourse_reference',
    freshness_sec: { authorization_receipt: 900, policy_permit: 900 },
    revocation_required: ['recourse_reference'],
  },
  // Insurance claim: authorization + a recourse reference to bind who's on the hook.
  insurance_claim: {
    policy_id: 'ep:evpolicy:insurance:v1',
    reliance_purpose: 'insurance_claim',
    requirement: 'authorization_receipt AND recourse_reference',
    freshness_sec: { authorization_receipt: 3600 },
  },
};

function verdictOf(components, policy, opts = {}) {
  return evaluateAdmissibility({ action_digest: ACTION, components }, policy, { as_of: AS_OF, ...opts });
}

// ── Scenarios ─────────────────────────────────────────────────────────────────
export function run() {
  const results: Record<string, any> = {};

  // 1. admissible — full bundle vs money_movement policy.
  const admissible = verdictOf(baseComponents(), POLICIES.money_movement);
  assert.equal(admissible.verdict, 'admissible', admissible.reasons.join('; '));
  results.admissible = admissible;

  // 1b. same full bundle is trivially admissible for the lighter audit purpose.
  const auditOk = verdictOf(baseComponents(), POLICIES.audit);
  assert.equal(auditOk.verdict, 'admissible');
  results.audit_admissible = auditOk;

  // 2. missing_evidence — drop recourse + attestation, evaluate vs money_movement.
  //    Nothing present is broken; the requirement simply isn't met.
  const thin = baseComponents().filter((c) => !['recourse_reference', 'execution_attestation'].includes(c.type));
  const missing = verdictOf(thin, POLICIES.money_movement);
  assert.equal(missing.verdict, 'missing_evidence', missing.reasons.join('; '));
  // ...yet the SAME thin bundle is still admissible for audit — sufficiency is purpose-relative.
  assert.equal(verdictOf(thin, POLICIES.audit).verdict, 'admissible');
  results.missing_evidence = missing;

  // 3. stale — receipt older than the money_movement freshness bound.
  const staleComps = baseComponents().map((c) =>
    c.type === 'authorization_receipt' ? { ...c, issued_at: '2026-07-02T11:00:00Z' } : c); // 60 min > 900 s
  const stale = verdictOf(staleComps, POLICIES.money_movement);
  assert.equal(stale.verdict, 'stale', stale.reasons.join('; '));
  // the evidence EXISTS (would pass without the freshness bound) — that's why it's `stale`, not `missing`.
  assert.ok(stale.reasons.some((r) => /stale|revoked/.test(r)));
  results.stale = stale;

  // 3b. stale via revocation — recourse reference revoked, money_movement requires it live.
  const revokedComps = baseComponents().map((c) =>
    c.type === 'recourse_reference' ? { ...c, revoked: true } : c);
  const revoked = verdictOf(revokedComps, POLICIES.money_movement);
  assert.equal(revoked.verdict, 'stale', revoked.reasons.join('; '));
  results.stale_revoked = revoked;

  // 4. conflicted — a leg binds a DIFFERENT action than the rest.
  const forkComps = baseComponents().map((c) =>
    c.type === 'policy_permit' ? { ...c, action_digest: 'e'.repeat(64) } : c);
  const conflictedAction = verdictOf(forkComps, POLICIES.money_movement);
  assert.equal(conflictedAction.verdict, 'conflicted', conflictedAction.reasons.join('; '));
  results.conflicted_action = conflictedAction;

  // 4b. conflicted — a verified component is a DENIAL (the human refused).
  const denialComps = baseComponents().map((c) =>
    c.type === 'authorization_receipt' ? { ...c, outcome: 'deny' } : c);
  const conflictedDenial = verdictOf(denialComps, POLICIES.money_movement);
  assert.equal(conflictedDenial.verdict, 'conflicted', conflictedDenial.reasons.join('; '));
  assert.ok(conflictedDenial.reasons.some((r) => /refusal|denial/.test(r)));
  results.conflicted_denial = conflictedDenial;

  // 5. unverifiable — a required leg failed its OWN verification (bad signature).
  const brokenComps = baseComponents().map((c) =>
    c.type === 'authorization_receipt' ? { ...c, verified: false } : c);
  const unverifiable = verdictOf(brokenComps, POLICIES.money_movement);
  assert.equal(unverifiable.verdict, 'unverifiable', unverifiable.reasons.join('; '));
  results.unverifiable = unverifiable;

  // 5b. unverifiable — no relying-party policy supplied (sufficiency is never bundle-chosen).
  const noPolicy = evaluateAdmissibility({ action_digest: ACTION, components: baseComponents() }, {} as any, { as_of: AS_OF });
  assert.equal(noPolicy.verdict, 'unverifiable');
  results.no_policy = noPolicy;

  // ── Determinism / policy replay: same inputs => same verdict AND same digest ──
  const a = verdictOf(baseComponents(), POLICIES.money_movement);
  const b = verdictOf(baseComponents(), POLICIES.money_movement);
  assert.equal(a.replay_digest, b.replay_digest, 'replay digest must be deterministic');
  assert.equal(a.verdict, b.verdict);
  // a different policy over the same bundle => a different replay digest.
  assert.notEqual(a.replay_digest, verdictOf(baseComponents(), POLICIES.audit).replay_digest);

  return results;
}

export const results = run();

if (process.argv.includes('--emit')) {
  const rows = Object.entries(results).map(([k, v]: [string, any]) => ({
    scenario: k, purpose: v.reliance_purpose, verdict: v.verdict,
    satisfied_by: v.satisfied_by, replay_digest: v.replay_digest,
  }));
  console.log(JSON.stringify(rows, null, 2));
}
console.log('ADMISSIBILITY VECTOR OK —',
  Object.values(results).map((v: any) => `${v.reliance_purpose ?? 'none'}:${v.verdict}`).join('  '));
