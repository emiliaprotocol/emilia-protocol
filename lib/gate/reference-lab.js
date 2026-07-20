// SPDX-License-Identifier: Apache-2.0
// Public reference lab for EMILIA Gate. Every check runs through the published
// Gate runtime with generated, throwaway keys. The lab never represents a real
// payment, deployment, export, clinical decision, or production mobile device.

import crypto from 'node:crypto';
import {
  createDefaultActionRiskManifest,
  createEg1Harness,
  createTrustedActionFirewall,
} from '@/packages/gate/index.js';

const REFERENCE_POLICY_ID = 'policy_eg1';
const REFERENCE_TENANT_ID = 'ep:org:eg1';
const REFERENCE_POLICY_HASH = `sha256:${crypto.createHash('sha256').update(JSON.stringify({
  id: REFERENCE_POLICY_ID,
  purpose: 'generated-reference-consequence-authorization',
  version: 1,
})).digest('hex')}`;
const CLASS_A_APPROVERS = Object.freeze([
  Object.freeze({ subject: 'ep:approver:eg1:cfo', role: 'cfo' }),
]);
const QUORUM_APPROVERS = Object.freeze([
  Object.freeze({ subject: 'ep:approver:eg1:cfo', role: 'cfo' }),
  Object.freeze({ subject: 'ep:approver:eg1:security-officer', role: 'security_officer' }),
]);

export const GATE_REFERENCE_PROFILES = Object.freeze({
  treasury: Object.freeze({
    id: 'treasury',
    label: 'Treasury',
    headline: 'Release $250,000',
    consequence: 'Funds leave the treasury account.',
    tier: 'class_a',
    policy: REFERENCE_POLICY_ID,
    policy_hash: REFERENCE_POLICY_HASH,
    tenant_id: REFERENCE_TENANT_ID,
    approvers: CLASS_A_APPROVERS,
    selector: Object.freeze({ protocol: 'mcp', tool: 'release_payment' }),
    action: Object.freeze({
      action_type: 'payment.release',
      amount_usd: 250000,
      currency: 'USD',
      payment_instruction_id: 'pi_reference_250000',
      beneficiary_account_hash: 'sha256:7d75d81f3f52f76f6e95a52b2b21f3b4',
    }),
    material: Object.freeze([
      ['Amount', '$250,000.00'],
      ['Beneficiary', 'Grid Restoration Services'],
      ['Destination', 'Account ending 1842'],
      ['Purpose', 'Emergency restoration equipment'],
    ]),
    effect: Object.freeze({ status: 'released', reference: 'wire_ref_1842' }),
    drift(action) { return { ...action, amount_usd: action.amount_usd + 1 }; },
    tamper: Object.freeze({ amount_usd: 9999999 }),
  }),
  production: Object.freeze({
    id: 'production',
    label: 'Production',
    headline: 'Deploy to production',
    consequence: 'A new artifact becomes live for customers.',
    tier: 'quorum',
    policy: REFERENCE_POLICY_ID,
    policy_hash: REFERENCE_POLICY_HASH,
    tenant_id: REFERENCE_TENANT_ID,
    approvers: QUORUM_APPROVERS,
    selector: Object.freeze({ protocol: 'mcp', tool: 'deploy_production' }),
    action: Object.freeze({
      action_type: 'deploy.production',
      repo: 'emilia/reference-service',
      commit_sha: '8f46c3f4b35d59cc87ad4e5fca4778130a734f12',
      environment: 'production',
      artifact_digest: 'sha256:8d7cf9e9f120fc76a6c84f9c274f141a',
    }),
    material: Object.freeze([
      ['Repository', 'emilia/reference-service'],
      ['Commit', '8f46c3f4b35d'],
      ['Environment', 'production'],
      ['Artifact', 'sha256:8d7cf9e9f120'],
    ]),
    effect: Object.freeze({ status: 'deployed', reference: 'deploy_ref_8f46c3f' }),
    drift(action) { return { ...action, commit_sha: 'ffffffffffffffffffffffffffffffffffffffff' }; },
    tamper: Object.freeze({ environment: 'break-glass-production' }),
  }),
  data: Object.freeze({
    id: 'data',
    label: 'Data',
    headline: 'Export 50,000 records',
    consequence: 'A sensitive dataset leaves its system of record.',
    tier: 'class_a',
    policy: REFERENCE_POLICY_ID,
    policy_hash: REFERENCE_POLICY_HASH,
    tenant_id: REFERENCE_TENANT_ID,
    approvers: CLASS_A_APPROVERS,
    selector: Object.freeze({ protocol: 'mcp', tool: 'export_customer_data' }),
    action: Object.freeze({
      action_type: 'data.export',
      dataset: 'claims-analytics-2026q2',
      recipient: 'research-enclave-04',
      purpose: 'approved outcomes study',
      row_count_max: 50000,
    }),
    material: Object.freeze([
      ['Dataset', 'claims-analytics-2026q2'],
      ['Recipient', 'research-enclave-04'],
      ['Purpose', 'Approved outcomes study'],
      ['Maximum rows', '50,000'],
    ]),
    effect: Object.freeze({ status: 'exported', reference: 'export_ref_2026q2' }),
    drift(action) { return { ...action, recipient: 'unapproved-external-bucket' }; },
    tamper: Object.freeze({ row_count_max: 5000000 }),
  }),
  healthcare: Object.freeze({
    id: 'healthcare',
    label: 'Healthcare',
    headline: 'Override a coverage decision',
    consequence: 'A regulated decision changes for one case.',
    tier: 'quorum',
    policy: REFERENCE_POLICY_ID,
    policy_hash: REFERENCE_POLICY_HASH,
    tenant_id: REFERENCE_TENANT_ID,
    approvers: QUORUM_APPROVERS,
    selector: Object.freeze({ protocol: 'mcp', tool: 'override_regulated_decision' }),
    action: Object.freeze({
      action_type: 'regulated.decision.override',
      case_id: 'rx-case-7F41',
      decision_id: 'coverage-decision-8841',
      subject_id: 'patient:pseudonymous:91b4',
      override_reason: 'documented continuity-of-care exception',
    }),
    material: Object.freeze([
      ['Case', 'RX-7F41'],
      ['Decision', 'coverage-decision-8841'],
      ['Subject', 'pseudonymous:91b4'],
      ['Basis', 'Continuity-of-care exception'],
    ]),
    effect: Object.freeze({ status: 'overridden', reference: 'decision_ref_8841' }),
    drift(action) { return { ...action, case_id: 'rx-case-OTHER' }; },
    tamper: Object.freeze({ override_reason: 'unreviewed agent recommendation' }),
  }),
});

function shortHash(value) {
  if (typeof value !== 'string') return null;
  return value.length > 28 ? `${value.slice(0, 14)}...${value.slice(-10)}` : value;
}

function participantSummary(receipt) {
  const quorum = receipt?.payload?.quorum;
  if (Array.isArray(quorum?.members)) {
    return quorum.members.map((member) => ({
      role: member.role,
      approver: member.signoff?.context?.approver || null,
      ceremony: 'WebAuthn P-256 / UV',
    }));
  }
  const signoff = receipt?.payload?.signoff;
  return signoff ? [{
    role: receipt.payload?.claim?.approver_role || 'accountable_approver',
    approver: signoff.context?.approver || receipt.payload?.claim?.approver || null,
    ceremony: 'WebAuthn P-256 / UV',
  }] : [];
}

function ceremonyPolicies(receipt) {
  const quorum = receipt?.payload?.quorum;
  if (Array.isArray(quorum?.members)) {
    return [...new Set(quorum.members.map((member) => member?.signoff?.context?.policy).filter(Boolean))];
  }
  const policy = receipt?.payload?.signoff?.context?.policy;
  return policy ? [policy] : [];
}

function makeGate(harness, profile, publicKey = harness.publicKey) {
  const manifest = createDefaultActionRiskManifest();
  const requirement = manifest.actions.find((entry) => entry.action_type === profile.action.action_type);
  if (!requirement) throw new Error(`reference_manifest_requirement_missing:${profile.action.action_type}`);
  requirement.business_authorization = {
    policy: { id: profile.policy, hash: profile.policy_hash },
    tenant_id: profile.tenant_id,
    allowed_approvers: profile.approvers.map((entry) => ({ ...entry })),
  };
  return createTrustedActionFirewall({
    manifest,
    trustedKeys: [publicKey],
    approverKeys: harness.approverKeys,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    quorumPolicy: profile.tier === 'quorum' ? harness.quorumPolicy : null,
    allowEphemeralStore: true,
    strictEvidence: true,
  });
}

function receiptBusinessAuthorization(profile) {
  return {
    policy_id: profile.policy,
    policy_hash: profile.policy_hash,
    tenant_id: profile.tenant_id,
    approver_role: profile.tier === 'quorum' ? 'cfo' : profile.approvers[0].role,
    approver_authorizations: profile.approvers.map((entry) => ({ ...entry })),
  };
}

function decisionView(result) {
  return {
    allowed: result?.allow === true,
    status: Number(result?.status) || null,
    reason: result?.reason || null,
    decision_hash: result?.evidence?.hash || null,
    required_tier: result?.evidence?.required_tier || result?.requirement?.assurance_class || null,
    observed_tier: result?.evidence?.have_tier || null,
    policy_id: result?.evidence?.evaluated_policy_id || null,
    policy_hash: result?.evidence?.evaluated_policy_hash || null,
    tenant_id: result?.evidence?.evaluated_tenant_id || null,
    approvers: result?.evidence?.evaluated_approvers || [],
  };
}

export function getGateReferenceProfile(profileId) {
  return GATE_REFERENCE_PROFILES[profileId] || GATE_REFERENCE_PROFILES.treasury;
}

export async function runGateReferenceLab(profileId = 'treasury') {
  const profile = getGateReferenceProfile(profileId);
  const harness = createEg1Harness({
    action: profile.action,
    idPrefix: `gate_${profile.id}`,
  });
  const gate = makeGate(harness, profile);

  const challengeDecision = await gate.check({
    selector: profile.selector,
    observedAction: profile.action,
  });

  const driftReceipt = harness.mint({
    outcome: 'allow_with_signoff',
    ...(profile.tier === 'quorum' ? { quorum: { threshold: 2 } } : {}),
    extra: receiptBusinessAuthorization(profile),
  });
  const driftDecision = await gate.check({
    selector: profile.selector,
    receipt: driftReceipt,
    observedAction: profile.drift(profile.action),
  });

  const tamperedReceipt = harness.mint({
    outcome: 'allow_with_signoff',
    ...(profile.tier === 'quorum' ? { quorum: { threshold: 2 } } : {}),
    extra: receiptBusinessAuthorization(profile),
    tamper: profile.tamper,
  });
  const tamperDecision = await gate.check({
    selector: profile.selector,
    receipt: tamperedReceipt,
    observedAction: profile.action,
  });

  const wrongHarness = createEg1Harness({ action: profile.action, idPrefix: 'gate_wrong_authority' });
  const wrongAuthorityGate = makeGate(harness, profile, wrongHarness.publicKey);
  const wrongAuthorityReceipt = harness.mint({
    outcome: 'allow_with_signoff',
    ...(profile.tier === 'quorum' ? { quorum: { threshold: 2 } } : {}),
    extra: receiptBusinessAuthorization(profile),
  });
  const wrongAuthorityDecision = await wrongAuthorityGate.check({
    selector: profile.selector,
    receipt: wrongAuthorityReceipt,
    observedAction: profile.action,
  });

  const validReceipt = harness.mint({
    outcome: 'allow_with_signoff',
    ...(profile.tier === 'quorum' ? { quorum: { threshold: 2 } } : {}),
    extra: receiptBusinessAuthorization(profile),
  });
  // gate.run()'s inferred param type comes from its `receipt = null` default
  // (packages/gate/index.js has no @param JSDoc on run(), unlike check()),
  // so TS narrows it to `null | undefined`. run() forwards this object
  // straight into check(), whose @param types receipt as `any` — the real
  // accepted type is a receipt object, this is a type-gap, not a bug.
  const execution = await gate.run(/** @type {any} */ ({
    selector: profile.selector,
    receipt: validReceipt,
    observedAction: profile.action,
  }), async () => ({ ...profile.effect, executed_at: new Date().toISOString() }));

  if (!execution?.ok || execution?.packet?.verdict !== 'rely') {
    throw new Error(`reference_execution_refused:${execution?.authorization?.reason || 'unknown'}`);
  }

  const replayDecision = await gate.check({
    selector: profile.selector,
    receipt: validReceipt,
    observedAction: profile.action,
  });
  const evidence = gate.evidence.verify();

  const participants = participantSummary(validReceipt);
  const authorization = decisionView(execution.authorization);
  return {
    ok: true,
    reference_only: true,
    physical_claim: false,
    generated_at: new Date().toISOString(),
    run_id: `gatelab_${crypto.randomBytes(8).toString('hex')}`,
    profile: {
      id: profile.id,
      label: profile.label,
      headline: profile.headline,
      consequence: profile.consequence,
      policy: profile.policy,
      policy_hash: profile.policy_hash,
      tenant_id: profile.tenant_id,
      tier: profile.tier,
      selector: profile.selector,
      material: profile.material,
    },
    action: profile.action,
    action_hash: harness.actionHash,
    challenge: {
      status: challengeDecision.status,
      reason: challengeDecision.reason,
      header: challengeDecision.header || null,
      body: challengeDecision.challenge || null,
    },
    ceremony: {
      assurance: profile.tier,
      threshold: profile.tier === 'quorum' ? 2 : 1,
      participants,
      action_hash: harness.actionHash,
      policy: profile.policy,
      context_policies: ceremonyPolicies(validReceipt),
      origin: harness.allowedOrigins[0],
    },
    authorization,
    execution: {
      effect: execution.result,
      authorizes_decision: execution.execution?.authorizes_decision || null,
      execution_hash: execution.execution?.hash || null,
      bound: execution.execution?.authorizes_decision === authorization.decision_hash,
    },
    reliance: {
      verdict: execution.packet.verdict,
      checks: execution.packet.checks,
      summary: execution.packet.summary,
    },
    evidence: {
      ok: evidence.ok,
      length: evidence.length,
      head: evidence.head,
      head_short: shortHash(evidence.head),
    },
    attacks: [
      { id: 'missing', label: 'Missing receipt', refused: challengeDecision.allow === false, status: challengeDecision.status, reason: challengeDecision.reason },
      { id: 'drift', label: 'Execution drift', refused: driftDecision.allow === false, status: driftDecision.status, reason: driftDecision.reason },
      { id: 'tamper', label: 'Tampered receipt', refused: tamperDecision.allow === false, status: tamperDecision.status, reason: tamperDecision.reason },
      { id: 'authority', label: 'Wrong authority', refused: wrongAuthorityDecision.allow === false, status: wrongAuthorityDecision.status, reason: wrongAuthorityDecision.reason },
      { id: 'replay', label: 'Receipt replay', refused: replayDecision.allow === false, status: replayDecision.status, reason: replayDecision.reason },
    ],
    limitations: [
      'Generated keys and effects are reference-only; no production system is mutated.',
      'The lab proves authorization enforcement and evidence integrity, not that the authorized decision was wise.',
      'Executor-observed fields and durable, shared storage remain mandatory production trust boundaries.',
    ],
  };
}

export default runGateReferenceLab;
