// SPDX-License-Identifier: Apache-2.0
// Auditor / insurer-facing reliance packet for an EMILIA Gate decision.

export const RELIANCE_PACKET_VERSION = 'EP-GATE-RELIANCE-PACKET-v1';

function evidenceStatus(evidence) {
  if (!evidence) return { ok: null, length: null, head: null };
  if (typeof evidence.verify === 'function') return evidence.verify();
  return evidence;
}

function check(id, ok, detail = null) {
  return { id, ok, ...(detail ? { detail } : {}) };
}

export function buildReliancePacket({
  decision,
  execution = null,
  evidence = null,
  manifest = null,
  binding = null,
  verifier = '@emilia-protocol/gate',
} = {}) {
  const evidenceCheck = evidenceStatus(evidence);
  const decisionHash = decision?.evidence?.hash || decision?.hash || null;
  const executionBound = !execution || (execution.kind === 'execution' && execution.authorizes_decision === decisionHash);
  const bindingCheck = binding || decision?.evidence?.execution_binding || decision?.execution_binding || null;
  const allowed = decision?.allow === true;
  const evidenceOk = evidenceCheck.ok !== false;
  const bindingOk = bindingCheck ? bindingCheck.ok === true : true;
  const verdict = allowed && executionBound && evidenceOk && bindingOk ? 'rely' : 'do_not_rely';

  return {
    '@version': RELIANCE_PACKET_VERSION,
    product: 'EMILIA Gate',
    verifier,
    verdict,
    summary: {
      action: decision?.action || null,
      receipt_id: decision?.evidence?.receipt_id || decision?.receipt_id || null,
      subject: decision?.evidence?.subject || null,
      required_tier: decision?.evidence?.required_tier || decision?.required_tier || null,
      observed_tier: decision?.evidence?.have_tier || decision?.have_tier || null,
      decision_hash: decisionHash,
      execution_hash: execution?.hash || null,
      evidence_head: evidenceCheck.head || null,
    },
    checks: [
      check('receipt_present_and_valid', allowed && !String(decision?.reason || '').startsWith('receipt_rejected'), decision?.reason || null),
      check('assurance_sufficient', allowed || decision?.reason !== 'assurance_too_low', decision?.reason === 'assurance_too_low' ? 'receipt tier below action requirement' : null),
      check('receipt_one_time_consumed', allowed || decision?.reason === 'replay_refused' ? decision?.reason !== 'replay_refused' : null),
      check('execution_fields_bound', bindingCheck ? bindingCheck.ok === true : null, bindingCheck ? { missing_observed_fields: bindingCheck.missing_observed_fields || [], mismatched_fields: bindingCheck.mismatched_fields || [] } : 'no material execution-field binding required by this action'),
      check('execution_attests_decision', execution ? executionBound : null, execution ? null : 'no execution record supplied'),
      check('evidence_log_intact', evidenceCheck.ok === undefined ? null : evidenceCheck.ok, evidenceCheck.reason || null),
    ],
    manifest_version: manifest?.['@version'] || null,
    limitations: [
      'The packet proves the gate verified a receipt and enforced its configured policy; it does not prove the human made a wise decision.',
      'Identity, authority enrollment, and key custody remain external trust roots that must be operated correctly.',
      'For execution-field binding, observedAction must come from the system of record, not from attacker-controlled request input.',
    ],
  };
}

export default { RELIANCE_PACKET_VERSION, buildReliancePacket };
