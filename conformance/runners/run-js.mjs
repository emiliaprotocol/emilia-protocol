// SPDX-License-Identifier: Apache-2.0
// JS conformance runner: emits [{id, valid}] per vector. argv[2] = vectors path.
// Polymorphic: receipt (document) | signoff | quorum.
import { verifyReceipt, verifyWebAuthnSignoff, verifyQuorum } from '../../packages/verify/index.js';
import { readFileSync } from 'node:fs';
const { vectors } = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const out = vectors.map((v) => {
  if (v.document) return { id: v.id, valid: verifyReceipt(v.document, v.public_key).valid };
  if (v.signoff) return { id: v.id, valid: verifyWebAuthnSignoff(v.signoff, v.approver_public_key, { rpId: v.rp_id }).valid };
  if (v.quorum) return { id: v.id, valid: verifyQuorum(v.quorum, { rpId: 'emiliaprotocol.ai' }).valid };
  return { id: v.id, valid: false };
});
process.stdout.write(JSON.stringify(out));
