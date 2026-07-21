// SPDX-License-Identifier: Apache-2.0
// JS conformance runner: emits exact typed result rows. argv[2] = vectors path.
// Polymorphic: receipt (document) | signoff | quorum.
import { verifyReceipt, verifyWebAuthnSignoff, verifyQuorum, verifyRevocation, verifyTimeAttestation, verifyTrustReceipt, verifyProvenanceOffline, verifyEvidenceRecord, canonicalize, isCanonicalizable, evaluateCurrency, validateInitiatorAttestation, verifyConsumptionProof, requireWitnessQuorum, verifyOutcomeBinding, trustReceiptDigest } from '../../packages/verify/index.js';
import { evaluatePredictedEffects } from '../../packages/verify/effect-predicates.js';
import { verifyTimestampProof } from '../../packages/verify/timestamp-proof.js';
import { verifyAuthorityProofViaDocument } from '../../lib/authority/document-proof-join.js';
import { artifactDigest, EVIDENCE_GRAPH_VERSION, evaluateEvidenceGraph } from '../../lib/evidence/evidence-graph.js';
import { verifyAuthorizationChain } from '../../packages/verify/evidence-chain.js';
import { verifyResolutionReceipt } from '../../packages/verify/resolution.js';
import { strictParseGate } from './strict-json.mjs';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
const corpusText = new TextDecoder('utf-8', { fatal: true }).decode(readFileSync(process.argv[2]));
const corpus = JSON.parse(corpusText);
const corpusGate = strictParseGate(corpusText);
if (!corpusGate.ok) throw new Error(`strict corpus JSON refused: ${corpusGate.reason}`);
const { vectors } = corpus;
if (!Array.isArray(vectors)) throw new Error('conformance corpus must contain a vectors array');
const common = corpus.common && typeof corpus.common === 'object' && !Array.isArray(corpus.common)
  ? corpus.common
  : {};

// EP-CANONICALIZATION-v1 differential branch. Contract (see the suite profile):
// standard parse, then the strict-parse gate (duplicate member names, unpaired
// surrogate escapes, depth > 64 — see strict-json.mjs), then the EP I-JSON
// profile predicate, then SHA-256 over the UTF-8 canonical bytes compared to the
// pinned digest. Fail-closed at every step.
function runCanonicalization(c) {
  if (typeof c?.input_json !== 'string') return false;
  let value;
  try { value = JSON.parse(c.input_json); } catch { return false; }
  if (!strictParseGate(c.input_json).ok) return false;
  if (!isCanonicalizable(value)) return false;
  return createHash('sha256').update(canonicalize(value), 'utf8').digest('hex') === c.expected_digest;
}

const digest = (value) => `sha256:${createHash('sha256')
  .update(canonicalize(value), 'utf8').digest('hex')}`;
const validResult = (valid) => ({ valid: Boolean(valid) });

function exactAuthorityResult(v: any) {
  const result = verifyAuthorityProofViaDocument(v.proof, v.docs, v.opts);
  const machineResult = { ...result } as Record<string, any>;
  delete (machineResult as any).limitations;
  const exact = {
    ...machineResult,
    proof_input_digest: digest(v.proof),
    document_chain_digest: digest(v.docs),
  };
  return { ...exact, result_digest: digest(exact) };
}

function exactRevocationResult(v) {
  const result = verifyRevocation(v.target, v.revocation, {
    revokerKeys: v.revoker_keys,
    maxAgeSeconds: v.max_age_seconds,
    now: v.now,
  });
  const exact = {
    valid: result.valid,
    checks: result.checks,
    reasons: Object.entries(result.checks)
      .filter(([, passed]) => !passed)
      .map(([check]) => check),
    target_digest: digest(v.target),
    revocation_digest: digest(v.revocation),
  };
  return { ...exact, result_digest: digest(exact) };
}

function exactOutcomeResult(v) {
  const outcomeOpts = {
    receiptOptions: common.receipt_options,
    executorKeys: v.executor_keys ?? common.executor_keys,
    now: common.now,
    ...(Object.hasOwn(v, 'policy_predicted_effects')
      ? { policyPredictedEffects: v.policy_predicted_effects }
      : {}),
  };
  const result = verifyOutcomeBinding(common.receipt, v.attestation, outcomeOpts);
  return {
    outcome: result.outcome_binding.outcome,
    valid: result.valid,
    checks: result.checks,
    reasons: result.outcome_binding.reasons,
    receipt_digest: trustReceiptDigest(common.receipt),
    attestation_digest: digest(v.attestation),
    result_digest: result.result_digest,
  };
}

const GRAPH_ACTION = `sha256:${'a'.repeat(64)}`;
function outcomeGraphResult(v) {
  const attestation = {
    typ: 'effect_attestation',
    action: GRAPH_ACTION,
    receipt_id: 'tr_outcome_1',
    issued_at: '2026-07-08T00:00:00Z',
    ...v.attestation,
  };
  const document = {
    '@version': EVIDENCE_GRAPH_VERSION,
    action_digest: GRAPH_ACTION,
    nodes: [{
      id: artifactDigest(attestation),
      type: 'effect_attestation',
      artifact: attestation,
    }],
    edges: [],
  };
  const verifiers = {
    effect_attestation: (artifact) => ({
      valid: true,
      action_digest: artifact.action,
      issued_at: artifact.issued_at,
      receipt_id: artifact.receipt_id,
      observed_effect_digest: artifact.observed_effect_digest,
      observed_effects: artifact.observed_effects,
    }),
  };
  const policy = {
    policy_id: 'ep:test:outcome-binding',
    reliance_purpose: 'regulated_execution',
    requirement: 'effect_attestation',
    ...(v.policy || {}),
  };
  const resolveApprovedEffect = v.approved
    ? (receiptId) => ({
      valid: receiptId === attestation.receipt_id,
      receipt_id: attestation.receipt_id,
      action_digest: GRAPH_ACTION,
      ...v.approved,
    })
    : undefined;
  const result = evaluateEvidenceGraph(document, policy, {
    verifiers,
    resolveApprovedEffect,
    as_of: '2026-07-08T00:02:00Z',
  });
  return {
    verdict: result.verdict,
    ...(v.expect.reason_contains ? { reasons: result.reasons } : {}),
  };
}

const out = vectors.map((v) => {
  if (v.proof && Array.isArray(v.docs) && v.opts) {
    return { id: v.id, ...exactAuthorityResult(v) };
  }
  if (v.kind === 'predicate' && Object.hasOwn(v, 'predicted_effects')) {
    const result = evaluatePredictedEffects(v.predicted_effects, v.observed_effects);
    return {
      id: v.id,
      outcome: result.outcome,
      ...(v.expect.reason_contains ? { reasons: result.reasons } : {}),
    };
  }
  if (v.kind === 'graph') return { id: v.id, ...outcomeGraphResult(v) };
  if (v.attestation && common.receipt) return { id: v.id, ...exactOutcomeResult(v) };
  if (v.document) return { id: v.id, ...validResult(verifyReceipt(v.document, v.public_key).valid) };
  if (v.resolution_receipt !== undefined || v.resolution_authorization !== undefined) {
    const receipt = v.resolution_receipt ?? v.resolution_authorization;
    const result = verifyResolutionReceipt(receipt, {
      bindingMoment: v.binding_moment,
      expectedActionHash: v.expected_action_hash,
      expectedSelectedOption: v.expected_selected_option,
      expectedNonce: v.expected_nonce,
      expectedInitiator: v.expected_initiator,
      evaluationTime: v.evaluation_time,
      principalKeys: v.principal_keys,
      rpId: v.rp_id,
      allowedOrigins: v.allowed_origins,
    });
    return { id: v.id, ...validResult(v.resolution_authorization !== undefined ? result.valid && result.authorizes_action : result.valid) };
  }
  if (v.signoff) return { id: v.id, ...validResult(verifyWebAuthnSignoff(v.signoff, v.approver_public_key, { rpId: v.rp_id, allowedOrigins: v.allowed_origins }).valid) };
  if (v.quorum) return { id: v.id, ...validResult(verifyQuorum(v.quorum, { rpId: 'emiliaprotocol.ai', allowedOrigins: ['https://www.emiliaprotocol.ai'] }).valid) };
  if (v.revocation) {
    return Object.hasOwn(v.expect || {}, 'result_digest')
      ? { id: v.id, ...exactRevocationResult(v) }
      : { id: v.id, ...validResult(verifyRevocation(v.target, v.revocation, {
        revokerKeys: v.revoker_keys,
        maxAgeSeconds: v.max_age_seconds,
        now: v.now,
      }).valid) };
  }
  if (v.time_attestation) return { id: v.id, ...validResult(verifyTimeAttestation(v.time_attestation, { tsaKeys: v.tsa_keys, expectedHash: v.expected_hash, notBefore: v.not_before, notAfter: v.not_after }).valid) };
  if (v.trust_receipt) return { id: v.id, ...validResult(verifyTrustReceipt(v.trust_receipt, { approverKeys: v.verification.approver_keys, logPublicKey: v.verification.log_public_key, ...(v.verify_opts || {}) }).valid) };
  if (v.provenance_chain) return { id: v.id, ...validResult(verifyProvenanceOffline(v.provenance_chain, { delegationKeys: v.delegation_keys, rootVerification: v.root_verification, actionVerification: v.action_verification, now: v.now_ms }).valid) };
  if (v.evidence_record) return { id: v.id, ...validResult(verifyEvidenceRecord(v.evidence_record, { tsaKeys: v.tsa_keys, protectedHash: v.protected_hash }).valid) };
  if (v.canonicalization) return { id: v.id, ...validResult(runCanonicalization(v.canonicalization)) };
  // EP-CURRENCY-v1: valid iff the two-valued currency status equals expect_status.
  if (v.currency) return { id: v.id, ...validResult(evaluateCurrency(v.currency.args).currency_at_T.status === v.currency.expect_status) };
  // EP-INITIATOR-ATTESTATION-v1: valid iff the attestation validates (fail-closed).
  if (v.initiator_attestation) return { id: v.id, ...validResult(validateInitiatorAttestation(v.initiator_attestation).ok) };
  // EP-SMT-CONSUME-v1: valid iff the sparse-Merkle absent→present transition verifies.
  if (v.consumption_proof) return { id: v.id, ...validResult(verifyConsumptionProof(v.consumption_proof).valid) };
  // EP-WITNESS-v1: valid iff k distinct pinned witnesses validly cosigned the head.
  if (v.witness_quorum) { const w = v.witness_quorum; return { id: v.id, ...validResult(requireWitnessQuorum(w.checkpoint, w.cosignatures, w.pinned, w.k).ok) }; }
  // EP-TIMESTAMP-PROOF-v1 (RFC 3161): valid iff the pinned TSA's TimeStampToken
  // verifies over the expected digest (fail-closed on any refusal).
  if (v.timestamp_proof !== undefined) return { id: v.id, ...validResult(verifyTimestampProof(v.timestamp_proof, v.expected_digest, v.pinned_tsa_keys).verified) };
  // EP-AEC-ROLE-v1: valid iff the evidence requirement is SATISFIED, with the built-in
  // ep-receipt using role-scoped pins (keys_by_type) and a permissive stub for
  // each stub_type. Exercises real signatures, role scoping, and signed binding.
  if (v.aec_chain) {
    const stub = (ev) => ({ valid: ev?.valid !== false, action_digest: ev?.action_digest });
    const verifiers = {};
    for (const t of (v.stub_types || [])) verifiers[t] = stub;
    return { id: v.id, ...validResult(verifyAuthorizationChain(v.aec_chain, { keysByType: v.keys_by_type, policiesByType: v.policies_by_type, verifiers, requirement: v.requirement, expectedActionDigest: v.expected_action_digest, verificationTime: v.verification_time }).satisfied) };
  }
  return { id: v.id, ...validResult(false) };
});
process.stdout.write(JSON.stringify(out));
