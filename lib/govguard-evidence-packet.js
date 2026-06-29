// SPDX-License-Identifier: Apache-2.0
// GovGuard procurement evidence packet: the auditor/IG-facing summary of an
// observe-mode fire drill or pilot window.

export const GOVGUARD_EVIDENCE_PACKET_VERSION = 'GG-EVIDENCE-PACKET-v1';

export const GG1_CHECKS = Object.freeze([
  { id: 'missing_receipt_refused', title: 'Missing receipt refused before execution' },
  { id: 'wrong_org_refused', title: 'Receipt cannot be scoped to another organization' },
  { id: 'wrong_approver_refused', title: 'Only the signoff-bound approver can approve' },
  { id: 'self_approval_refused', title: 'Initiator cannot approve their own action' },
  { id: 'class_c_on_class_a_refused', title: 'Software/bearer approval cannot satisfy Class-A actions' },
  { id: 'replay_refused', title: 'Consumed receipt cannot be reused' },
  { id: 'tampered_action_refused', title: 'Tampered amount, destination, or recipient breaks the action binding' },
  { id: 'execution_mismatch_refused', title: 'System-of-record execution mismatch is refused' },
  { id: 'observe_evidence_exported', title: 'Observe-mode evidence exports what enforce mode would have done' },
]);

export function effectiveGovGuardDecision(after) {
  if (after?.enforcement_mode === 'observe') {
    return after.observed_decision || after.decision || 'allow';
  }
  return after?.decision || 'allow';
}

function bucket(rows) {
  const summary = {
    total_actions: rows.length,
    would_allow: 0,
    would_require_signoff: 0,
    would_deny: 0,
  };
  const byActionType = {};

  for (const ev of rows) {
    const a = ev.after_state || {};
    const decision = effectiveGovGuardDecision(a);
    const at = a.action_type || 'unknown';
    byActionType[at] = byActionType[at] || { total: 0, allow: 0, signoff: 0, deny: 0 };
    byActionType[at].total += 1;

    if (decision === 'deny') {
      summary.would_deny += 1;
      byActionType[at].deny += 1;
    } else if (decision === 'allow_with_signoff') {
      summary.would_require_signoff += 1;
      byActionType[at].signoff += 1;
    } else {
      summary.would_allow += 1;
      byActionType[at].allow += 1;
    }
  }

  return { summary, byActionType };
}

export function buildGovGuardEvidencePacket({
  pilotId,
  events = [],
  generatedAt = new Date().toISOString(),
  verifier = '@emilia-protocol/verify',
} = {}) {
  const rows = events || [];
  const { summary, byActionType } = bucket(rows);
  const gated = summary.would_require_signoff + summary.would_deny;
  const highRiskActions = [];

  for (const ev of rows) {
    const a = ev.after_state || {};
    const decision = effectiveGovGuardDecision(a);
    if (decision !== 'deny' && decision !== 'allow_with_signoff') continue;
    highRiskActions.push({
      receipt_id: ev.target_id || a.receipt_id || null,
      action_type: a.action_type || 'unknown',
      target_resource_id: a.target_resource_id || null,
      would_have: decision,
      enforcement_mode: a.enforcement_mode || null,
      signoff_tier: a.signoff_tier || null,
      required_assurance: a.required_assurance || null,
      policy_id: a.policy_id || null,
      policy_hash: a.policy_hash || null,
      action_hash: a.action_hash || null,
      execution_binding_hash: a.execution_binding?.field_hash || null,
      amount: a.amount ?? null,
      currency: a.currency ?? null,
      reasons: a.reasons || [],
      initiator_attestation: a.initiator_attestation || null,
      observed_at: ev.created_at || null,
    });
  }

  return {
    '@version': GOVGUARD_EVIDENCE_PACKET_VERSION,
    product: 'EMILIA GovGuard',
    pilot_id: pilotId || null,
    generated_at: generatedAt,
    headline: rows.length === 0
      ? 'No actions observed yet.'
      : `Of ${summary.total_actions} observed action(s), ${gated} would have been denied or held for named approval before execution.`,
    summary,
    by_action_type: byActionType,
    high_risk_actions: highRiskActions.slice(0, 50),
    verification: {
      verifier,
      offline_command: `npx ${verifier} receipt.json`,
      evidence_source: 'GovGuard audit_events projection plus signed EP-RECEIPT-v1 documents where available.',
      relying_party_note: 'Verify representative signed receipts offline and compare action_hash, policy_hash, required_assurance, and execution_binding_hash to this packet.',
    },
    gg1: {
      badge: 'GG-1 Enforced',
      statement: 'GovGuard conformance is earned by CI checks, not asserted in copy.',
      checks: GG1_CHECKS,
    },
    limitations: [
      'Observe mode reports what enforce mode would have done; it does not block production actions.',
      'The packet proves action-level authorization controls and evidence integrity; it does not decide whether the underlying benefit or payment decision was substantively correct.',
      'Identity enrollment, authority records, and source-of-record field observation remain deployment responsibilities.',
    ],
  };
}

const govGuardEvidencePacket = {
  GOVGUARD_EVIDENCE_PACKET_VERSION,
  GG1_CHECKS,
  effectiveGovGuardDecision,
  buildGovGuardEvidencePacket,
};

export default govGuardEvidencePacket;
