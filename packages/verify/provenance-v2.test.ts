// SPDX-License-Identifier: Apache-2.0
//
// EP-PROVENANCE-CHAIN-v2 hybrid delegation-link-proof test: the reference
// hybrid migration for the surface this file owns directly (the delegation
// link's detached proof). Root/action receipt verification stays whatever
// EP-RECEIPT-v1/v2 the receipt-issuance workstream ships (composed
// unchanged, per the module header), so the hostile matrix here targets
// verifyDelegationProofSetV2 -- the actual signed artifact -- plus the
// document-level version guard on verifyProvenanceOfflineV2.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  PROVENANCE_VERSION,
  PROVENANCE_V2_VERSION,
  PROVENANCE_V2_REQUIRED_ALGORITHMS,
  delegationProofV2Bytes,
  verifyDelegationProofSetV2,
  verifyProvenanceOffline,
  verifyProvenanceOfflineV2,
} from './provenance.js';
import { signAgileSet } from './pq-signature-agility.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const pqSecretB64u = Buffer.from(pq.secretKey).toString('base64url');

const LINK = {
  delegation_id: 'd1', delegator: 'root', delegatee: 'agent1',
  scope: ['wire.release'], max_value_usd: 100, expires_at: '2027-01-01T00:00:00Z', constraints: {},
};
const PIN = { public_key: edPubB64u, pq_public_key: pqPubB64u };

async function signLink(link: any = LINK) {
  const bytes = delegationProofV2Bytes(link);
  const signatures = await signAgileSet(new Uint8Array(bytes), [
    { alg: 'Ed25519', private_key: ed.privateKey },
    { alg: 'ML-DSA-65', private_key: pqSecretB64u },
  ]);
  return { ...link, proof_set: { required_algorithms: [...PROVENANCE_V2_REQUIRED_ALGORITHMS], signatures } };
}

test('real ML-DSA-65 backend is available for this suite', () => {
  assert.ok(typeof ml_dsa65?.sign === 'function');
});

test('a real hybrid delegation-link proof_set verifies under both pinned keys', async () => {
  const link = await signLink();
  assert.equal(await verifyDelegationProofSetV2(link, PIN), true);
});

test('LEG STRIPPING: removing the ML-DSA leg refuses', async () => {
  const link: any = await signLink();
  link.proof_set.signatures = link.proof_set.signatures.filter((s: any) => s.alg === 'Ed25519');
  assert.equal(await verifyDelegationProofSetV2(link, PIN), false);
});

test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
  const link: any = await signLink();
  link.proof_set.signatures = link.proof_set.signatures.filter((s: any) => s.alg === 'ML-DSA-65');
  assert.equal(await verifyDelegationProofSetV2(link, PIN), false);
});

test('SET NARROWING: a narrowed required_algorithms fails structurally', async () => {
  const link: any = await signLink();
  link.proof_set.required_algorithms = ['Ed25519'];
  assert.equal(await verifyDelegationProofSetV2(link, PIN), false);
});

test('delegationProofV2Bytes refuses to build bytes for a non-registered algorithm set (no narrowing escape hatch)', () => {
  assert.throws(() => delegationProofV2Bytes(LINK, ['Ed25519']));
});

test('WRONG-LENGTH SIGNATURE: a truncated leg refuses', async () => {
  const link: any = await signLink();
  const edSig = link.proof_set.signatures.find((s: any) => s.alg === 'Ed25519');
  edSig.sig = edSig.sig.slice(0, -4);
  assert.equal(await verifyDelegationProofSetV2(link, PIN), false);
});

test('ED448 MASQUERADE: an Ed448 key pinned as the Ed25519 half refuses', async () => {
  const link = await signLink();
  const ed448 = crypto.generateKeyPairSync('ed448');
  const ed448PubB64u = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
  assert.equal(await verifyDelegationProofSetV2(link, { public_key: ed448PubB64u, pq_public_key: pqPubB64u }), false);
});

test('an unpinned delegator confers nothing', async () => {
  const link = await signLink();
  assert.equal(await verifyDelegationProofSetV2(link, undefined), false);
  assert.equal(await verifyDelegationProofSetV2(link, { public_key: edPubB64u }), false);
});

test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
  const link = await signLink();
  assert.equal(await verifyDelegationProofSetV2(link, PIN, { mldsaBackendLoader: async () => null }), false);
});

test('TAMPERED AFTER SIGNING: editing max_value_usd breaks the proof', async () => {
  const link: any = await signLink();
  link.max_value_usd = 999;
  assert.equal(await verifyDelegationProofSetV2(link, PIN), false);
});

// ── document-level version guard (verifyProvenanceOfflineV2) ──────────────

test('the v1 chain verifier refuses a v2 document on the version marker, without crashing', () => {
  const res = verifyProvenanceOffline({ '@version': PROVENANCE_V2_VERSION });
  assert.equal(res.valid, false);
  assert.ok(res.errors.some((e: string) => e.includes(PROVENANCE_V2_VERSION)));
});

test('the v2 chain verifier refuses a v1 document on the version marker, without crashing', async () => {
  const res = await verifyProvenanceOfflineV2({ '@version': PROVENANCE_VERSION });
  assert.equal(res.valid, false);
  assert.ok(res.errors.some((e: string) => e.includes(PROVENANCE_VERSION)));
});

test('the v2 chain verifier refuses malformed input without throwing', async () => {
  for (const junk of [null, undefined, 'x', 42, []]) {
    const res = await verifyProvenanceOfflineV2(junk as any);
    assert.equal(res.valid, false);
  }
});

test('the registered required algorithm set is fixed and Ed25519-first', () => {
  assert.deepEqual([...PROVENANCE_V2_REQUIRED_ALGORITHMS], ['Ed25519', 'ML-DSA-65']);
});
