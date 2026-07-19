#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Human-authorization binding vector — B1..B5 from
// draft-schrock-human-authorization-binding, deterministic.
// Run: node examples/binding/human-authorization-binding-vector.mjs
import crypto from 'node:crypto';
import { canonicalize } from '../../packages/verify/index.js';

const canon = (o) => Buffer.from(canonicalize(o), 'utf8');
const digest = (o) => 'sha256:' + crypto.createHash('sha256').update(canon(o)).digest('hex');
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const seed = crypto.createHash('sha256').update('ep:binding-vector:v1').digest();
const key = crypto.createPrivateKey({ key: Buffer.concat([PKCS8, seed]), format: 'der', type: 'pkcs8' });
const pub = crypto.createPublicKey(/** @type {any} */ (key)).export({ type: 'spki', format: 'der' }).toString('base64url');

const ACTION_DIGEST = 'sha256:' + 'a'.repeat(64);

// The authorization artifact (stand-in for an EP receipt; verifies under its own rules)
const payload = { typ: 'authorization_receipt', action_digest: ACTION_DIGEST, approver: 'ops-lead@example.com' };
const artifact = { payload, sig: crypto.sign(null, canon(payload), key).toString('base64url'), approver_key: pub };
const ARTIFACT_DIGEST = digest(artifact);

// A host record (capsule/permit-shaped) binding it BY REFERENCE
export const host = {
  typ: 'agent-action-capsule', action_digest: ACTION_DIGEST, outcome: 'executed',
  human_authorization_ref: { digest: ARTIFACT_DIGEST, format: 'ep-receipt' },
};

export function verifyBinding(hostRec, art, pinnedIssuerKeys = []) {
  const checks = { b1_digest: false, artifact_sig: false, b2_action: false, b3_accepted: false };
  const ref = hostRec?.human_authorization_ref;
  if (!ref?.digest || !art) return { verified: false, accepted: false, checks }; // B4: absence fails closed
  checks.b1_digest = digest(art) === ref.digest;
  try {
    const k = crypto.createPublicKey({ key: Buffer.from(art.approver_key, 'base64url'), type: 'spki', format: 'der' });
    checks.artifact_sig = crypto.verify(null, canon(art.payload), k, Buffer.from(art.sig, 'base64url'));
  } catch { checks.artifact_sig = false; }
  checks.b2_action = art.payload?.action_digest === hostRec.action_digest;
  checks.b3_accepted = pinnedIssuerKeys.includes(art.approver_key);
  const verified = checks.b1_digest && checks.artifact_sig && checks.b2_action;
  return { verified, accepted: verified && checks.b3_accepted, checks };
}

// Positive: verified + accepted with pinned issuer
const pos = verifyBinding(host, artifact, [pub]);
if (!pos.accepted) throw new Error('positive failed: ' + JSON.stringify(pos.checks));
// B1: tampered artifact no longer hashes to the reference
const tampered = { ...artifact, payload: { ...payload, approver: 'mallory' } };
if (verifyBinding(host, tampered, [pub]).verified) throw new Error('B1 not enforced');
// B2: genuine artifact for a DIFFERENT action is invalid, not weak
const otherPayload = { ...payload, action_digest: 'sha256:' + 'b'.repeat(64) };
const other = { payload: otherPayload, sig: crypto.sign(null, canon(otherPayload), key).toString('base64url'), approver_key: pub };
const hostOther = { ...host, human_authorization_ref: { digest: digest(other), format: 'ep-receipt' } };
if (verifyBinding(hostOther, other, [pub]).verified) throw new Error('B2 not enforced');
// B3: unpinned issuer verifies but is never accepted
const un = verifyBinding(host, artifact, []);
if (!un.verified || un.accepted) throw new Error('B3 not enforced');
// B4: absent binding is absence of evidence
if (verifyBinding({ ...host, human_authorization_ref: undefined }, artifact, [pub]).verified) throw new Error('B4 not enforced');
console.error('BINDING VECTOR OK — B1 digest, B2 action, B3 verified!=accepted, B4 fail-closed absence all enforced');
