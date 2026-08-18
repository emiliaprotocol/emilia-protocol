// SPDX-License-Identifier: Apache-2.0
//
// EP-AUTHORITY-DOC-v2 hostile matrix: the hybrid (Ed25519 + ML-DSA-65)
// authority document chain + endorsements. The PQ leg runs for real.
import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';

import {
  AUTHORITY_DOC_V2_VERSION,
  AUTHORITY_DOC_V2_REQUIRED_ALGORITHMS,
  authorityIssuerKeyIdV2,
  createAuthorityDocV2,
  verifyAuthorityChainV2,
  endorseAuthorityDocV2,
  verifyEndorsementV2,
  verifyAuthorityChain,
} from './authority-doc';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

function edKeyPair() { return crypto.generateKeyPairSync('ed25519'); }
function pqKeyPair() {
  const pair = ml_dsa65.keygen(crypto.randomBytes(32));
  return { publicKey: Buffer.from(pair.publicKey).toString('base64url'), secretKey: Buffer.from(pair.secretKey).toString('base64url') };
}

const root = edKeyPair();
const rootPq = pqKeyPair();
const ROOT_SIGNER = { privateKey: root.privateKey, pqPrivateKey: rootPq.secretKey, pqPublicKey: rootPq.publicKey };

const issuer = edKeyPair();
const issuerPub = crypto.createPublicKey(issuer.privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
const issuerPq = pqKeyPair();

async function buildRootDoc() {
  return createAuthorityDocV2({
    org: { domain: 'example.org', id: 'org:example' },
    issuer_keys: [{
      key: issuerPub,
      pq_key: issuerPq.publicKey,
      usages: ['receipt_signing'],
      valid_from: '2026-01-01T00:00:00.000Z',
      valid_to: '2027-01-01T00:00:00.000Z',
    }],
    issued_at: '2026-01-01T00:00:00.000Z',
  }, ROOT_SIGNER, null);
}

describe('EP-AUTHORITY-DOC-v2 hostile matrix', () => {
  it('real ML-DSA-65 backend is available for this suite', () => {
    expect(typeof ml_dsa65?.sign).toBe('function');
  });

  it('a real hybrid single-document chain verifies under both root keys', async () => {
    const doc = await buildRootDoc();
    const res = await verifyAuthorityChainV2([doc]);
    expect(res.verified).toBe(true);
    expect(res.breaks).toEqual([]);
  });

  it('the registered algorithm set is Ed25519 then ML-DSA-65', () => {
    expect(AUTHORITY_DOC_V2_REQUIRED_ALGORITHMS).toEqual(['Ed25519', 'ML-DSA-65']);
  });

  it('issuer key ids are bound to BOTH halves together', () => {
    const kid = authorityIssuerKeyIdV2(issuerPub, issuerPq.publicKey);
    expect(kid).toMatch(/^ep:authority-issuer-key:v2:sha256:[0-9a-f]{64}$/);
    expect(authorityIssuerKeyIdV2(issuerPub, rootPq.publicKey)).not.toBe(kid);
  });

  it('LEG STRIPPING: removing the self-signature ML-DSA leg refuses', async () => {
    const doc: any = await buildRootDoc();
    doc.proof.signatures = doc.proof.signatures.filter((s: any) => s.alg === 'Ed25519');
    const res = await verifyAuthorityChainV2([doc]);
    expect(res.verified).toBe(false);
    expect(res.reasons.some((r: string) => r.includes('self-signature invalid'))).toBe(true);
  });

  it('LEG STRIPPING: removing the self-signature Ed25519 leg refuses too', async () => {
    const doc: any = await buildRootDoc();
    doc.proof.signatures = doc.proof.signatures.filter((s: any) => s.alg === 'ML-DSA-65');
    const res = await verifyAuthorityChainV2([doc]);
    expect(res.verified).toBe(false);
  });

  it('NARROWED SET: required_algorithms trimmed refuses structurally', async () => {
    const doc: any = await buildRootDoc();
    doc.proof.required_algorithms = ['Ed25519'];
    const res = await verifyAuthorityChainV2([doc]);
    expect(res.verified).toBe(false);
  });

  it('WRONG-LENGTH SIGNATURE: a truncated self-signature leg refuses without throwing', async () => {
    const doc: any = await buildRootDoc();
    doc.proof.signatures = doc.proof.signatures.map((s: any) => (
      s.alg === 'Ed25519' ? { ...s, sig: Buffer.from(s.sig, 'base64url').subarray(0, 5).toString('base64url') } : s
    ));
    const res = await verifyAuthorityChainV2([doc]);
    expect(res.verified).toBe(false);
  });

  it('ED448 MASQUERADE: an Ed448 SPKI as root_key refuses (curve-pinned)', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const doc: any = await buildRootDoc();
    doc.root_key = ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const res = await verifyAuthorityChainV2([doc]);
    expect(res.verified).toBe(false);
    expect(res.reasons.some((r: string) => r.includes('root_key/root_pq_key'))).toBe(true);
  });

  it('ED448 MASQUERADE: an Ed448 SPKI as an issuer key refuses', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const doc: any = await buildRootDoc();
    doc.issuer_keys[0].key = ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const res = await verifyAuthorityChainV2([doc]);
    expect(res.verified).toBe(false);
  });

  it('V1 REFUSES V2: verifyAuthorityChain (v1, sync) refuses a v2 document cleanly, without throwing', async () => {
    const doc = await buildRootDoc();
    const res = verifyAuthorityChain([doc]);
    expect(res.verified).toBe(false);
    expect(res.reasons[0]).toMatch(/bad version/);
  });

  it('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const doc = await buildRootDoc();
    const res = await verifyAuthorityChainV2([doc], { mldsaBackendLoader: async () => null });
    expect(res.verified).toBe(false);
  });

  it('malformed input refuses without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}, [null]]) {
      const res = await verifyAuthorityChainV2(junk as any);
      expect(res.verified).toBe(false);
    }
  });

  it('refuses malformed authority metadata before trusting a valid-looking signature set', async () => {
    const base: any = await buildRootDoc();
    const cases: Array<[string, (doc: any) => void, RegExp]> = [
      ['organization', (doc) => { doc.org.domain = 'not a stable domain'; }, /organization identifier/],
      ['issued-at', (doc) => { doc.issued_at = 'not-an-instant'; }, /issued_at/],
      ['issuer-array', (doc) => { doc.issuer_keys = null; }, /issuer_keys is not an array/],
      ['duplicate-kid', (doc) => { doc.issuer_keys.push(structuredClone(doc.issuer_keys[0])); }, /non-empty and unique/],
      ['window', (doc) => { doc.issuer_keys[0].valid_to = '2025-01-01T00:00:00.000Z'; }, /invalid time window/],
      ['key-id', (doc) => { doc.issuer_keys[0].kid = 'ep:authority-issuer-key:v2:sha256:' + '0'.repeat(64); }, /full hybrid public-key digest/],
      ['registry-id', (doc) => { doc.issuer_keys[0].registry_issuer_id = 'not stable'; }, /unstable registry issuer/],
      ['usages', (doc) => { doc.issuer_keys[0].usages = ['receipt_signing', 'receipt_signing']; }, /invalid usages/],
    ];
    for (const [name, mutate, reason] of cases) {
      const doc = structuredClone(base);
      mutate(doc);
      const result = await verifyAuthorityChainV2([doc]);
      expect(result.verified, name).toBe(false);
      expect(result.reasons.join(' '), name).toMatch(reason);
    }

    await expect(verifyAuthorityChainV2([{ impossible: 1n }] as any))
      .resolves.toMatchObject({
        verified: false,
        reasons: ['authority chain contains non-canonical JSON state'],
      });
  });

  describe('rotation continuity', () => {
    it('a properly-continued rotation verifies with no breaks', async () => {
      const docA = await buildRootDoc();
      const newRoot = edKeyPair();
      const newRootPq = pqKeyPair();
      const docB = await createAuthorityDocV2({
        org: { domain: 'example.org', id: 'org:example' },
        issuer_keys: [{
          key: issuerPub, pq_key: issuerPq.publicKey, usages: ['receipt_signing'],
          valid_from: '2026-01-01T00:00:00.000Z', valid_to: '2027-01-01T00:00:00.000Z',
        }],
        issued_at: '2026-02-01T00:00:00.000Z',
      }, { privateKey: newRoot.privateKey, pqPrivateKey: newRootPq.secretKey, pqPublicKey: newRootPq.publicKey },
      { doc: docA, continuitySigner: ROOT_SIGNER });
      const res = await verifyAuthorityChainV2([docA, docB]);
      expect(res.verified).toBe(true);
      expect(res.breaks).toEqual([]);
    });

    it('LEG STRIPPING on the continuity signature flags a break (compromise-recovery path), never throws', async () => {
      const docA = await buildRootDoc();
      const newRoot = edKeyPair();
      const newRootPq = pqKeyPair();
      const docB: any = await createAuthorityDocV2({
        org: { domain: 'example.org', id: 'org:example' },
        issuer_keys: [{
          key: issuerPub, pq_key: issuerPq.publicKey, usages: ['receipt_signing'],
          valid_from: '2026-01-01T00:00:00.000Z', valid_to: '2027-01-01T00:00:00.000Z',
        }],
        issued_at: '2026-02-01T00:00:00.000Z',
      }, { privateKey: newRoot.privateKey, pqPrivateKey: newRootPq.secretKey, pqPublicKey: newRootPq.publicKey },
      { doc: docA, continuitySigner: ROOT_SIGNER });
      docB.continuity_proof.signatures = docB.continuity_proof.signatures.filter((s: any) => s.alg === 'Ed25519');
      const res = await verifyAuthorityChainV2([docA, docB]);
      expect(res.verified).toBe(true); // structurally sound chain
      expect(res.breaks).toEqual([1]);
    });
  });

  describe('endorsements', () => {
    it('a real hybrid endorsement verifies', async () => {
      const doc = await buildRootDoc();
      const endorser = edKeyPair();
      const endorserPq = pqKeyPair();
      const endorsement = await endorseAuthorityDocV2(doc, 'endorser.example', {
        privateKey: endorser.privateKey, pqPrivateKey: endorserPq.secretKey, pqPublicKey: endorserPq.publicKey,
      });
      expect(await verifyEndorsementV2(endorsement, doc)).toBe(true);
    });

    it('LEG STRIPPING on an endorsement refuses', async () => {
      const doc = await buildRootDoc();
      const endorser = edKeyPair();
      const endorserPq = pqKeyPair();
      const endorsement: any = await endorseAuthorityDocV2(doc, 'endorser.example', {
        privateKey: endorser.privateKey, pqPrivateKey: endorserPq.secretKey, pqPublicKey: endorserPq.publicKey,
      });
      endorsement.proof.signatures = endorsement.proof.signatures.filter((s: any) => s.alg === 'ML-DSA-65');
      expect(await verifyEndorsementV2(endorsement, doc)).toBe(false);
    });

    it('an endorsement bound to a different document digest refuses', async () => {
      const docA = await buildRootDoc();
      const docB: any = await createAuthorityDocV2({
        org: { domain: 'other.example', id: 'org:other' },
        issuer_keys: [{
          key: issuerPub, pq_key: issuerPq.publicKey, usages: ['receipt_signing'],
          valid_from: '2026-01-01T00:00:00.000Z', valid_to: '2027-01-01T00:00:00.000Z',
        }],
        issued_at: '2026-01-01T00:00:00.000Z',
      }, ROOT_SIGNER, null);
      const endorser = edKeyPair();
      const endorserPq = pqKeyPair();
      const endorsement = await endorseAuthorityDocV2(docA, 'endorser.example', {
        privateKey: endorser.privateKey, pqPrivateKey: endorserPq.secretKey, pqPublicKey: endorserPq.publicKey,
      });
      expect(await verifyEndorsementV2(endorsement, docB)).toBe(false);
    });
  });
});
