// SPDX-License-Identifier: Apache-2.0
//
// Parity test: the ported offline provenance verifier in the PUBLISHED package
// (packages/verify/provenance.js) must return byte-identical verdicts to the
// reference verifier (lib/provenance/chain.js) on real, live-minted bundles —
// a valid one, a scope-containment violation, and a tampered delegation proof.
// This proves the port (which the verify CLI now auto-detects) added no drift.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { assembleProvenance, verifyProvenanceOffline as libVerify } from '../lib/provenance/chain.js';
import { verifyProvenanceOffline as pkgVerify } from '../packages/verify/provenance.js';
import {
  canonicalize, buildContexts, collectSignoffs, assembleAuthorizationReceipt,
  policyHash as computePolicyHash, generateEd25519KeyPair,
} from '../packages/issue/index.js';

const NOW = Date.parse('2026-06-13T12:00:00.000Z');
const ISSUED_AT = '2026-06-13T11:00:00.000Z';
const EXPIRES_AT = '2026-06-13T18:00:00.000Z';
const FLAG_UP = 0x01; const FLAG_UV = 0x04;

function newP256() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { privateKey, publicKey, publicKeyB64u: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
function classASigner({ approverKeyId, privateKey, signedAt }) {
  return {
    approverKeyId, keyClass: 'A', signedAt,
    signWebAuthn: (digest) => {
      const clientData = { type: 'webauthn.get', challenge: Buffer.from(digest).toString('base64url'), origin: 'https://test.emilia', crossOrigin: false };
      const cdj = Buffer.from(JSON.stringify(clientData), 'utf8');
      const authData = Buffer.concat([crypto.createHash('sha256').update('rp').digest(), Buffer.from([FLAG_UP | FLAG_UV]), Buffer.from([0, 0, 0, 1])]);
      const signed = Buffer.concat([authData, crypto.createHash('sha256').update(cdj).digest()]);
      return { authenticator_data: authData.toString('base64url'), client_data_json: cdj.toString('base64url'), signature: crypto.sign('sha256', signed, privateKey).toString('base64url') };
    },
  };
}
async function mintReceipt({ action, approver = 'ep:approver:human', approverKeyId = 'ep:key:human#1' }) {
  const kp = newP256(); const logKp = generateEd25519KeyPair();
  const pHash = computePolicyHash({ policy_id: action.policy_id });
  const contexts = buildContexts({ action, policyHash: pHash, approvers: [approver], requiredApprovals: 1, issuedAt: ISSUED_AT, expiresAt: EXPIRES_AT });
  const signoffs = await collectSignoffs(contexts, [classASigner({ approverKeyId, signedAt: ISSUED_AT, privateKey: kp.privateKey })]);
  const receipt = assembleAuthorizationReceipt({ receiptId: `ep:receipt:${crypto.randomBytes(8).toString('base64url')}`, action, contexts, signoffs, committedAt: '2026-06-13T11:30:00.000Z', log: { privateKey: logKp.privateKey, logKeyId: 'ep:log:test#1' } });
  const verification = { approver_keys: { [approverKeyId]: { approver_id: approver, public_key: kp.publicKeyB64u, key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2036-01-01T00:00:00Z' } }, log_public_key: logKp.publicKeyB64u, rp_id: 'rp', allowed_origins: ['https://test.emilia'] };
  return { receipt, verification, approver, approverKeyId };
}
const PROOF_FIELDS = ['delegation_id', 'delegator', 'delegatee', 'scope', 'max_value_usd', 'expires_at', 'constraints'];
function signedLink(link, delegatorKp) {
  const subset = {}; for (const f of PROOF_FIELDS) subset[f] = link[f] ?? null;
  const payload = Buffer.from(canonicalize(subset), 'utf8');
  return { ...link, proof: { algorithm: 'Ed25519', signed_payload_b64u: payload.toString('base64url'), signature_b64u: crypto.sign(null, payload, delegatorKp.privateKey).toString('base64url'), public_key: delegatorKp.publicKeyB64u } };
}
const action = (action_type) => ({ action_type, policy_id: 'pol:test', initiator: 'ep:agent:1', params: { amount: 100 } });

async function buildValid() {
  const root = await mintReceipt({ action: action('payment.release'), approver: 'ep:approver:dir', approverKeyId: 'ep:key:dir#1' });
  const approval = await mintReceipt({ action: action('payment.release'), approver: 'ep:approver:dir', approverKeyId: 'ep:key:dir#1' });
  const delegatorKp = generateEd25519KeyPair();
  const link = signedLink({ delegation_id: 'dlg:1', parent_ref: 'ep:approver:dir', delegator: 'ep:approver:dir', delegatee: 'ep:agent:1', scope: ['payment.release'], max_value_usd: 1000, expires_at: EXPIRES_AT, constraints: {} }, delegatorKp);
  const doc = assembleProvenance({ rootSignoff: root, delegationChain: [link], actionApproval: approval, execution: { action_hash: approval.receipt.action_hash, irreversible: true, executed_at: ISSUED_AT } });
  const opts = {
    now: NOW,
    delegationKeys: { 'ep:approver:dir': { public_key: delegatorKp.publicKeyB64u } },
    rootVerification: root.verification,
    actionVerification: approval.verification,
  };
  return { doc, opts };
}

const sameVerdict = (a, b) => { expect(a.valid).toBe(b.valid); expect(a.checks).toEqual(b.checks); };

describe('packages/verify provenance port — parity with lib/provenance/chain.js', () => {
  it('agrees on a valid bundle (and it is valid)', async () => {
    const { doc, opts } = await buildValid();
    const lib = libVerify(doc, opts); const pkg = pkgVerify(doc, opts);
    expect(lib.valid).toBe(true);
    sameVerdict(lib, pkg);
  });

  it('agrees on a scope-containment violation (both invalid, same checks)', async () => {
    const { doc, opts } = await buildValid();
    doc.delegation_chain[0].scope = ['treasury.wire']; // exceeds root scope payment.release
    const lib = libVerify(doc, opts); const pkg = pkgVerify(doc, opts);
    expect(lib.valid).toBe(false);
    sameVerdict(lib, pkg);
  });

  it('agrees on a tampered delegation proof (both invalid, same checks)', async () => {
    const { doc, opts } = await buildValid();
    doc.delegation_chain[0].max_value_usd = 999999; // mutate a proof-covered field after signing
    const lib = libVerify(doc, opts); const pkg = pkgVerify(doc, opts);
    expect(lib.valid).toBe(false);
    sameVerdict(lib, pkg);
  });

  it('agrees on a malformed document', () => {
    sameVerdict(libVerify({ '@version': 'nope' }), pkgVerify({ '@version': 'nope' }));
  });
});
