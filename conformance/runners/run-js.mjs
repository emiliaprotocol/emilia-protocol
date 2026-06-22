// SPDX-License-Identifier: Apache-2.0
// JS conformance runner: emits [{id, valid}] per vector. argv[2] = vectors path.
// Polymorphic: receipt (document) | signoff | quorum.
import { verifyReceipt, verifyWebAuthnSignoff, verifyQuorum, verifyRevocation, verifyTimeAttestation, verifyTrustReceipt, verifyProvenanceOffline } from '../../packages/verify/index.js';
import { readFileSync } from 'node:fs';
const { vectors } = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const out = vectors.map((v) => {
  if (v.document) return { id: v.id, valid: verifyReceipt(v.document, v.public_key).valid };
  if (v.signoff) return { id: v.id, valid: verifyWebAuthnSignoff(v.signoff, v.approver_public_key, { rpId: v.rp_id }).valid };
  if (v.quorum) return { id: v.id, valid: verifyQuorum(v.quorum, { rpId: 'emiliaprotocol.ai' }).valid };
  if (v.revocation) return { id: v.id, valid: verifyRevocation(v.target, v.revocation, { revokerKeys: v.revoker_keys, maxAgeSeconds: v.max_age_seconds, now: v.now }).valid };
  if (v.time_attestation) return { id: v.id, valid: verifyTimeAttestation(v.time_attestation, { tsaKeys: v.tsa_keys, expectedHash: v.expected_hash, notBefore: v.not_before, notAfter: v.not_after }).valid };
  if (v.trust_receipt) return { id: v.id, valid: verifyTrustReceipt(v.trust_receipt, { approverKeys: v.verification.approver_keys, logPublicKey: v.verification.log_public_key }).valid };
  if (v.provenance_chain) return { id: v.id, valid: verifyProvenanceOffline(v.provenance_chain, { delegationKeys: v.delegation_keys, now: v.now_ms }).valid };
  return { id: v.id, valid: false };
});
process.stdout.write(JSON.stringify(out));
