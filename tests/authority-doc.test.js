// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  AUTHORITY_DOC_VERSION, createAuthorityDoc, endorseAuthorityDoc,
  verifyAuthorityChain, resolveIssuerKeyAt, verifyEndorsement,
  evaluateIntroduction, docCoreDigest,
} from '../lib/authority/authority-doc.js';

const kp = () => crypto.generateKeyPairSync('ed25519');
const pub = (k) => crypto.createPublicKey(k).export({ type: 'spki', format: 'der' }).toString('base64url');

const root0 = kp(), root1 = kp(), issuerA = kp(), issuerB = kp(), endorser = kp(), mallory = kp();

function buildChain() {
  const doc0 = createAuthorityDoc({
    org: { name: 'Acme Payments', domain: 'acme.example' },
    issuer_keys: [{ key: pub(issuerA.privateKey), custody_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' }],
    issued_at: '2026-01-01T00:00:00Z',
  }, root0.privateKey);
  // rotation: new root, new issuer key; continuity signed by OLD root
  const doc1 = createAuthorityDoc({
    org: { name: 'Acme Payments', domain: 'acme.example' },
    issuer_keys: [
      { key: pub(issuerA.privateKey), custody_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
      { key: pub(issuerB.privateKey), custody_class: 'A', valid_from: '2026-06-01T00:00:00Z', valid_to: '2027-06-01T00:00:00Z' },
    ],
    issued_at: '2026-06-01T00:00:00Z',
  }, root1.privateKey, { doc: doc0, continuityPrivateKey: root0.privateKey });
  return [doc0, doc1];
}

describe('EP-AUTHORITY-DOC — chain, rotation, compromise', () => {
  it('a well-formed rotated chain verifies with no continuity breaks', () => {
    const r = verifyAuthorityChain(buildChain());
    expect(r.verified).toBe(true);
    expect(r.breaks).toEqual([]);
  });

  it('a rotation without continuity is FLAGGED, never silently accepted', () => {
    const [doc0] = buildChain();
    const orphan = createAuthorityDoc({
      org: { name: 'Acme Payments', domain: 'acme.example' },
      issuer_keys: [{ key: pub(mallory.privateKey), custody_class: 'A', valid_from: '2026-06-01T00:00:00Z', valid_to: '2027-06-01T00:00:00Z' }],
      issued_at: '2026-06-01T00:00:00Z',
    }, mallory.privateKey, { doc: doc0, continuityPrivateKey: mallory.privateKey });
    const r = verifyAuthorityChain([doc0, orphan]);
    expect(r.breaks).toEqual([1]);
    expect(r.reasons.join(' ')).toContain('NO valid continuity');
  });

  it('a forked prev-digest (equivocation) fails the chain outright', () => {
    const [doc0, doc1] = buildChain();
    const forged = { ...doc1, prev_doc_digest: 'sha256:' + 'f'.repeat(64) };
    // re-sign the forged core so only the CHAIN check can catch it
    const { sig, continuity_sig, endorsements, ...core } = forged;
    forged.sig = crypto.sign(null, Buffer.from(JSON.stringify(core).length ? cCanon(core) : '', 'utf8'), root1.privateKey).toString('base64url');
    function cCanon(v) {
      if (v === null || typeof v !== 'object') return JSON.stringify(v);
      if (Array.isArray(v)) return `[${v.map(cCanon).join(',')}]`;
      return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${cCanon(v[k])}`).join(',')}}`;
    }
    const r = verifyAuthorityChain([doc0, forged]);
    expect(r.verified).toBe(false);
    expect(r.reasons.join(' ')).toContain('fork/equivocation');
  });

  it('time-of-issuance: rotation never breaks old artifacts; revocation voids only the future', () => {
    const [doc0, doc1] = buildChain();
    const kidA = doc0.issuer_keys[0].kid;
    // key A resolvable at an old timestamp even after rotation
    expect(resolveIssuerKeyAt([doc0, doc1], kidA, '2026-03-01T00:00:00Z')?.key).toBe(pub(issuerA.privateKey));
    // revoke A as of July in a doc2
    const doc2 = createAuthorityDoc({
      org: { name: 'Acme Payments', domain: 'acme.example' },
      issuer_keys: [
        { key: pub(issuerA.privateKey), custody_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z', revoked_at: '2026-07-01T00:00:00Z' },
        { key: pub(issuerB.privateKey), custody_class: 'A', valid_from: '2026-06-01T00:00:00Z', valid_to: '2027-06-01T00:00:00Z' },
      ],
      issued_at: '2026-07-01T00:00:00Z',
    }, root1.privateKey, { doc: doc1, continuityPrivateKey: root1.privateKey });
    const chain = [doc0, doc1, doc2];
    expect(resolveIssuerKeyAt(chain, kidA, '2026-03-01T00:00:00Z')).not.toBeNull(); // honest history survives
    expect(resolveIssuerKeyAt(chain, kidA, '2026-08-01T00:00:00Z')).toBeNull();     // future is voided
  });

  it('endorsements verify against the exact doc digest and nothing else', () => {
    const [, doc1] = buildChain();
    const e = endorseAuthorityDoc(doc1, 'Meridian Audit LLP', endorser.privateKey);
    expect(verifyEndorsement(e, doc1)).toBe(true);
    const tampered = { ...doc1, org: { ...doc1.org, name: 'Acme Totally Real' } };
    expect(verifyEndorsement(e, tampered)).toBe(false);
  });
});

describe('introduction as evidence — graded, replayable acceptance', () => {
  const LOW = {
    policy_id: 'ep:intro:low-value:v1', reliance_purpose: 'introduction',
    requirement: 'authority_chain AND domain_binding',
  };
  const HIGH = {
    policy_id: 'ep:intro:money-movement:v1', reliance_purpose: 'introduction',
    requirement: 'authority_chain AND domain_binding AND log_inclusion AND endorsement_pinned',
    freshness_sec: {},
  };
  const obsYoung = { domain_binding: { verified: true, observed_at: '2026-07-01T00:00:00Z' } };

  it('a young, unendorsed issuer: admissible for low-value, missing_evidence for money movement', () => {
    const docs = buildChain();
    const low = evaluateIntroduction(docs, obsYoung, LOW, { as_of: '2026-07-01T01:00:00Z' });
    const high = evaluateIntroduction(docs, obsYoung, HIGH, { as_of: '2026-07-01T01:00:00Z' });
    expect(low.verdict).toBe('admissible');
    expect(high.verdict).toBe('missing_evidence');
  });

  it('history + a pinned endorsement widen acceptance mechanically — no reconfiguration', () => {
    const docs = buildChain();
    docs[1] = { ...docs[1], endorsements: [endorseAuthorityDoc(docs[1], 'Meridian Audit LLP', endorser.privateKey)] };
    const obs = { ...obsYoung, log_inclusion: { verified: true, first_logged_at: '2026-06-01T00:00:00Z' } };
    const high = evaluateIntroduction(docs, obs, HIGH, { anchors: [pub(endorser.privateKey)], as_of: '2026-07-01T00:00:00Z' });
    expect(high.verdict).toBe('admissible');
  });

  it('an endorsement from an UNPINNED party never satisfies endorsement_pinned', () => {
    const docs = buildChain();
    docs[1] = { ...docs[1], endorsements: [endorseAuthorityDoc(docs[1], 'Randos Inc', mallory.privateKey)] };
    const obs = { ...obsYoung, log_inclusion: { verified: true, first_logged_at: '2026-06-01T00:00:00Z' } };
    const high = evaluateIntroduction(docs, obs, HIGH, { anchors: [pub(endorser.privateKey)], as_of: '2026-07-01T00:00:00Z' });
    expect(high.verdict).toBe('missing_evidence');
  });

  it('a continuity break degrades the chain fact — the compromise path is policy, not default', () => {
    const [doc0] = buildChain();
    const orphan = createAuthorityDoc({
      org: { name: 'Acme Payments', domain: 'acme.example' },
      issuer_keys: [{ key: pub(mallory.privateKey), custody_class: 'A', valid_from: '2026-06-01T00:00:00Z', valid_to: '2027-06-01T00:00:00Z' }],
      issued_at: '2026-06-01T00:00:00Z',
    }, mallory.privateKey, { doc: doc0, continuityPrivateKey: mallory.privateKey });
    const r = evaluateIntroduction([doc0, orphan], obsYoung, LOW, { as_of: '2026-07-01T00:00:00Z' });
    expect(r.verdict).not.toBe('admissible');
    expect(r.authority.continuity_breaks).toEqual([1]);
  });

  it('replay: same chain + same observations + same policy -> same verdict and digest', () => {
    const docs = buildChain();
    const a = evaluateIntroduction(docs, obsYoung, LOW, { as_of: '2026-07-01T00:00:00Z' });
    const b = evaluateIntroduction(JSON.parse(JSON.stringify(docs)), obsYoung, LOW, { as_of: '2026-07-01T00:00:00Z' });
    expect(a.verdict).toBe(b.verdict);
    expect(a.replay_digest).toBe(b.replay_digest);
  });

  it('doc version and structure are fail-closed', () => {
    const docs = buildChain();
    docs[0] = { ...docs[0], '@version': 'EP-AUTHORITY-DOC-v0' };
    const r = evaluateIntroduction(docs, obsYoung, LOW, {});
    expect(r.verdict).not.toBe('admissible');
    expect(AUTHORITY_DOC_VERSION).toBe('EP-AUTHORITY-DOC-v1');
    expect(docCoreDigest(buildChain()[0]).startsWith('sha256:')).toBe(true);
  });
});
