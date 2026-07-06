// SPDX-License-Identifier: Apache-2.0
// JS conformance runner: emits [{id, valid}] per vector. argv[2] = vectors path.
// Polymorphic: receipt (document) | signoff | quorum.
import { verifyReceipt, verifyWebAuthnSignoff, verifyQuorum, verifyRevocation, verifyTimeAttestation, verifyTrustReceipt, verifyProvenanceOffline, verifyEvidenceRecord, canonicalize, isCanonicalizable, evaluateCurrency, validateInitiatorAttestation, verifyConsumptionProof, requireWitnessQuorum } from '../../packages/verify/index.js';
import { verifyTimestampProof } from '../../packages/verify/timestamp-proof.js';
import { strictParseGate } from './strict-json.mjs';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
const { vectors } = JSON.parse(readFileSync(process.argv[2], 'utf8'));

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
const out = vectors.map((v) => {
  if (v.document) return { id: v.id, valid: verifyReceipt(v.document, v.public_key).valid };
  if (v.signoff) return { id: v.id, valid: verifyWebAuthnSignoff(v.signoff, v.approver_public_key, { rpId: v.rp_id }).valid };
  if (v.quorum) return { id: v.id, valid: verifyQuorum(v.quorum, { rpId: 'emiliaprotocol.ai' }).valid };
  if (v.revocation) return { id: v.id, valid: verifyRevocation(v.target, v.revocation, { revokerKeys: v.revoker_keys, maxAgeSeconds: v.max_age_seconds, now: v.now }).valid };
  if (v.time_attestation) return { id: v.id, valid: verifyTimeAttestation(v.time_attestation, { tsaKeys: v.tsa_keys, expectedHash: v.expected_hash, notBefore: v.not_before, notAfter: v.not_after }).valid };
  if (v.trust_receipt) return { id: v.id, valid: verifyTrustReceipt(v.trust_receipt, { approverKeys: v.verification.approver_keys, logPublicKey: v.verification.log_public_key, ...(v.verify_opts || {}) }).valid };
  if (v.provenance_chain) return { id: v.id, valid: verifyProvenanceOffline(v.provenance_chain, { delegationKeys: v.delegation_keys, now: v.now_ms }).valid };
  if (v.evidence_record) return { id: v.id, valid: verifyEvidenceRecord(v.evidence_record, { tsaKeys: v.tsa_keys, protectedHash: v.protected_hash }).valid };
  if (v.canonicalization) return { id: v.id, valid: runCanonicalization(v.canonicalization) };
  // EP-CURRENCY-v1: valid iff the two-valued currency status equals expect_status.
  if (v.currency) return { id: v.id, valid: evaluateCurrency(v.currency.args).currency_at_T.status === v.currency.expect_status };
  // EP-INITIATOR-ATTESTATION-v1: valid iff the attestation validates (fail-closed).
  if (v.initiator_attestation) return { id: v.id, valid: validateInitiatorAttestation(v.initiator_attestation).ok };
  // EP-SMT-CONSUME-v1: valid iff the sparse-Merkle absent→present transition verifies.
  if (v.consumption_proof) return { id: v.id, valid: verifyConsumptionProof(v.consumption_proof).valid };
  // EP-WITNESS-v1: valid iff k distinct pinned witnesses validly cosigned the head.
  if (v.witness_quorum) { const w = v.witness_quorum; return { id: v.id, valid: requireWitnessQuorum(w.checkpoint, w.cosignatures, w.pinned, w.k).ok }; }
  // EP-TIMESTAMP-PROOF-v1 (RFC 3161): valid iff the pinned TSA's TimeStampToken
  // verifies over the expected digest (fail-closed on any refusal).
  if (v.timestamp_proof !== undefined) return { id: v.id, valid: verifyTimestampProof(v.timestamp_proof, v.expected_digest, v.pinned_tsa_keys).verified };
  return { id: v.id, valid: false };
});
process.stdout.write(JSON.stringify(out));
