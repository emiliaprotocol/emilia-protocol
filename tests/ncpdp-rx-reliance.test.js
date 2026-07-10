// SPDX-License-Identifier: Apache-2.0
// EP-NCPDP-RX-RELIANCE-PROFILE-v1 — conformance + unit tests.
//
// Assembles a fully-valid Rx reliance packet (a valid trust receipt with a
// Class-A prescriber signoff + a scoped prescriber authority proof + signed
// consent / clinical / benefit legs) against a payer challenge, then drives
// conformance/vectors/ncpdp-rx-reliance.v1.json: each vector names a `break`
// applied to the base packet and asserts the closed rx verdict. Signatures live.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import {
  buildRxAppealBundle,
  commitRxEvidence,
  derivePairwisePatientRef,
  evaluateRxReliance,
  RX_VERDICTS,
  signRxArtifact,
  verifyRxArtifact,
} from '../lib/ncpdp/rx-reliance.js';
import { signAuthorityProof } from '../lib/authority/proof.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SUITE = JSON.parse(readFileSync(resolve(HERE, '../conformance/vectors/ncpdp-rx-reliance.v1.json'), 'utf8'));

const canon = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));
const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const leafV2 = (p) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0]), Buffer.from(p, 'utf8')])).digest('hex');
const pairV2 = (l, r) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([1]), Buffer.from(l, 'utf8'), Buffer.from(r, 'utf8')])).digest('hex');
const ed = () => { const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519'); return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') }; };
const p256 = () => { const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }); return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') }; };

const logKey = ed(); const intake = ed(); const prescriber = p256();
const registryKey = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from('a7'.repeat(32), 'hex')]), format: 'der', type: 'pkcs8' });
const registryPub = crypto.createPublicKey(registryKey).export({ type: 'spki', format: 'der' }).toString('base64url');
const consentKey = ed(); const clinicalKey = ed(); const payerKey = ed();
const privacyKey = Buffer.from('51'.repeat(32), 'hex');
const privacyKeyId = 'test-rx-privacy-2026-01';
const patientRef = derivePairwisePatientRef({ patientIdentifier: 'test-member-1', relyingPartyId: 'payer.test', privacyKeyId, sectorSecret: privacyKey });
const BENEFIT_POLICY_HASH = 'sha256:' + sha('payer:formulary:specialty-tier4:planX@v7');
const NOW = Date.parse('2026-07-08T14:05:00.000Z');

function signA(digestHex) {
  const challenge = Buffer.from(digestHex, 'hex').toString('base64url');
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://www.emiliaprotocol.ai' }), 'utf8');
  const authData = Buffer.concat([crypto.createHash('sha256').update('www.emiliaprotocol.ai').digest(), Buffer.from([0x05]), Buffer.from([0, 0, 0, 0])]);
  const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
  return { authenticator_data: authData.toString('base64url'), client_data_json: clientDataJSON.toString('base64url'), signature: crypto.sign('sha256', signedData, prescriber.privateKey).toString('base64url') };
}
function buildReceipt() {
  const action = { ep_version: '1.0', action_type: 'rx.prior_auth.approve', organization_id: 'clinicX', target: { system: 'pbm', resource: 'pa/1' }, parameters: { drug: 'SYN' }, initiator: 'ep:entity:pa-intake-agent', policy_id: 'ep:policy:x', requested_at: '2026-07-08T14:00:00Z' };
  const action_hash = `sha256:${sha(canon(action))}`;
  const base = { ep_version: '1.0', context_type: 'ep.signoff.v1', action_hash, policy_id: 'ep:policy:x', policy_hash: BENEFIT_POLICY_HASH, initiator: action.initiator, required_approvals: 2, issued_at: '2026-07-08T14:00:05Z', expires_at: '2026-07-08T14:15:05Z' };
  const ctx1 = { ...base, approver: 'ep:approver:intake-agent', approver_index: 1, nonce: 'n-1' };
  const ctx2 = { ...base, approver: 'ep:approver:prescriber', approver_index: 2, nonce: 'n-2' };
  const d1 = sha(canon(ctx1)); const d2 = sha(canon(ctx2));
  const signoffs = [
    { context_hash: `sha256:${d1}`, signature: crypto.sign(null, Buffer.from(d1, 'hex'), intake.privateKey).toString('base64url'), key_class: 'B', approver_key_id: 'ep:key:intake#1', signed_at: '2026-07-08T14:03:40Z' },
    { context_hash: `sha256:${d2}`, signature: 'unused', key_class: 'A', approver_key_id: 'ep:key:prescriber#1', signed_at: '2026-07-08T14:04:01Z', webauthn: signA(d2) },
  ];
  const receipt = { receipt_id: 'ep:receipt:1', action, action_hash, contexts: [ctx1, ctx2], signoffs, consumption: { nonce: 'n', state: 'COMMITTED', committed_at: '2026-07-08T14:04:02Z' } };
  const leaf = leafV2(canon(receipt));
  const root = pairV2(pairV2(leaf, sha('s1')), sha('s2'));
  const checkpoint = { tree_size: 4, root_hash: `sha256:${root}`, log_key_id: 'ep:log:1', merkle_alg: 'EP-MERKLE-v2' };
  const log_signature = crypto.sign(null, crypto.createHash('sha256').update(canon(checkpoint), 'utf8').digest(), logKey.privateKey).toString('base64url');
  receipt.log_proof = { alg: 'EP-MERKLE-v2', leaf_hash: `sha256:${leaf}`, leaf_index: 0, inclusion_path: [{ hash: sha('s1'), position: 'right' }, { hash: sha('s2'), position: 'right' }], checkpoint: { ...checkpoint, log_signature } };
  return receipt;
}

const receipt = buildReceipt();
const ACTION = { action_type: 'rx.prior_auth.approve', organization_id: 'clinicX', policy_hash: BENEFIT_POLICY_HASH, action_hash: receipt.action_hash };
const KEYS = {
  'ep:key:intake#1': { approver_id: 'ep:approver:intake-agent', public_key: intake.pub, key_class: 'B', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
  'ep:key:prescriber#1': { approver_id: 'ep:approver:prescriber', public_key: prescriber.pub, key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
};
const OPTS = { approverKeys: KEYS, logPublicKey: logKey.pub, rpId: 'www.emiliaprotocol.ai' };
const CHALLENGE = {
  '@type': 'EP-RX-EVIDENCE-CHALLENGE-v1', transaction: 'ncpdp.epa', required_assurance: 'class_a',
  required: { prescriber_authority: true, patient_consent: true, clinical_evidence: true, benefit_policy_hash: BENEFIT_POLICY_HASH, benefit_freshness_sec: 3600, revocation_freshness_sec: 3600, signed_denial_required: true },
  accepted_registry_keys: [{ issuer_id: 'auth_prescriber', organization_id: 'clinicX', public_key: registryPub, min_epoch: 9, registry_head: 'sha256:' + '22'.repeat(32) }],
  accepted_issuer_keys: [logKey.pub], accepted_consent_keys: [consentKey.pub], accepted_clinical_keys: [clinicalKey.pub], accepted_payer_keys: [payerKey.pub],
};

const authority = (scope = ['rx.prior_auth.approve']) => signAuthorityProof({ authority_id: 'auth_prescriber', subject: 'ep:approver:prescriber', organization_id: 'clinicX', role: 'prescriber', scope, limits: {}, validity: { from: '2026-01-01T00:00:00.000Z', to: '2027-01-01T00:00:00.000Z' }, revocation: { status: 'not_revoked', checked_at: '2026-07-08T13:59:00.000Z' }, registry_head: 'sha256:' + '22'.repeat(32), registry_epoch: 9, policy_hash: BENEFIT_POLICY_HASH, issued_at: '2026-07-08T13:59:00.000Z' }, registryKey);
const consent = () => signRxArtifact({ '@type': 'EP-RX-CONSENT-v1', action_hash: receipt.action_hash, privacy_key_id: privacyKeyId, subject_ref: patientRef, consent_digest: commitRxEvidence({ evidenceType: 'consent', record: { test: 'c' }, privacyKeyId, sectorSecret: privacyKey }), issued_at: '2026-07-08T13:50:00.000Z' }, consentKey.privateKey);
const clinical = () => signRxArtifact({ '@type': 'EP-RX-CLINICAL-v1', action_hash: receipt.action_hash, privacy_key_id: privacyKeyId, evidence_digest: commitRxEvidence({ evidenceType: 'clinical', record: { test: 'e' }, privacyKeyId, sectorSecret: privacyKey }), criteria: 'met', issued_at: '2026-07-08T13:52:00.000Z' }, clinicalKey.privateKey);
const denial = () => signRxArtifact({ '@type': 'EP-RX-DENIAL-v1', action_hash: receipt.action_hash, privacy_key_id: privacyKeyId, reason_code: 'x', reason_digest: commitRxEvidence({ evidenceType: 'denial', record: { test: 'r' }, privacyKeyId, sectorSecret: privacyKey }), appeal_url: 'https://p.example/appeals', issued_at: '2026-07-08T14:04:30.000Z' }, payerKey.privateKey);

function base() {
  return { '@type': 'EP-RX-RELIANCE-PACKET-v1', action: ACTION, receipt, authority_proof: authority(), patient_consent: consent(), clinical_evidence: clinical(), benefit_check: { checked_at: '2026-07-08T14:00:00.000Z', policy_hash: BENEFIT_POLICY_HASH }, revocation_state: { checked_at: '2026-07-08T14:00:00.000Z' }, determination: 'approve' };
}
function applyBreak(brk) {
  const p = base();
  switch (brk) {
    case 'none': return p;
    case 'signed_deny': return { ...p, determination: 'deny', signed_denial: denial() };
    case 'authority_wrong_scope': return { ...p, authority_proof: authority(['rx.refill.approve']) };
    case 'no_consent': return { ...p, patient_consent: undefined };
    case 'no_clinical': return { ...p, clinical_evidence: undefined };
    case 'wrong_formulary_policy': return { ...p, benefit_check: { ...p.benefit_check, policy_hash: 'sha256:' + sha('wrong') } };
    case 'stale_benefit': return { ...p, benefit_check: { checked_at: '2026-07-01T00:00:00.000Z', policy_hash: BENEFIT_POLICY_HASH } };
    case 'deny_unsigned': return { ...p, determination: 'deny', signed_denial: undefined };
    default: throw new Error(`unknown break ${brk}`);
  }
}

describe('EP-NCPDP-RX-RELIANCE-PROFILE-v1 conformance suite', () => {
  for (const v of SUITE.vectors) {
    it(`${v.id} -> ${v.expect.verdict}`, () => {
      const r = evaluateRxReliance({ challenge: CHALLENGE, packet: applyBreak(v.break), now: NOW }, OPTS);
      expect(RX_VERDICTS).toContain(r.verdict);
      expect(r.verdict).toBe(v.expect.verdict);
      expect(r.rely).toBe(v.expect.valid);
    });
  }
  it('covers every closed rx verdict at least once', () => {
    const covered = new Set(SUITE.vectors.map((v) => v.expect.verdict));
    for (const verdict of RX_VERDICTS) expect(covered.has(verdict)).toBe(true);
  });
});

describe('EP-NCPDP-RX-RELIANCE unit invariants', () => {
  it('rx_rely covers both a dispensable approve and a signed appeal-ready deny', () => {
    expect(evaluateRxReliance({ challenge: CHALLENGE, packet: applyBreak('none'), now: NOW }, OPTS).determination).toBe('approve');
    const d = evaluateRxReliance({ challenge: CHALLENGE, packet: applyBreak('signed_deny'), now: NOW }, OPTS);
    expect(d.verdict).toBe('rx_rely');
    expect(d.determination).toBe('deny');
  });
  it('the appeal bundle is content-addressed and re-verifiable', () => {
    const p = applyBreak('none');
    const r = evaluateRxReliance({ challenge: CHALLENGE, packet: p, now: NOW }, OPTS);
    const bundle = buildRxAppealBundle({ challenge: CHALLENGE, packet: p, result: r, now: '2026-07-08T14:05:00.000Z', privacyKey, privacyKeyId });
    expect(bundle['@type']).toBe('EP-RX-RELIANCE-BUNDLE-v2');
    expect(bundle.bundle_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(bundle.verdict).toBe('rx_rely');
  });
  it('no pinned challenge fails closed', () => {
    const r = evaluateRxReliance({ challenge: {}, packet: applyBreak('none'), now: NOW }, OPTS);
    expect(r.rely).toBe(false);
  });
});

describe('EP-NCPDP-RX-RELIANCE branch coverage', () => {
  it('verifyRxArtifact: an artifact older than the staleness bound is verified-but-not-accepted', () => {
    const old = signRxArtifact({ '@type': 'EP-RX-CONSENT-v1', action_hash: receipt.action_hash, privacy_key_id: privacyKeyId, subject_ref: patientRef, consent_digest: commitRxEvidence({ evidenceType: 'consent', record: { test: 'old' }, privacyKeyId, sectorSecret: privacyKey }), issued_at: '2026-01-01T00:00:00.000Z' }, consentKey.privateKey);
    const r = verifyRxArtifact(old, { expectType: 'EP-RX-CONSENT-v1', pinnedKeys: [consentKey.pub], now: NOW, maxStalenessSec: 3600 });
    expect(r.verified).toBe(true);
    expect(r.accepted).toBe(false);
    expect(r.reason).toBe('stale');
  });
  it('verifyRxArtifact: a valid signature under an unpinned key is verified, not accepted', () => {
    const r = verifyRxArtifact(consent(), { expectType: 'EP-RX-CONSENT-v1', pinnedKeys: [clinicalKey.pub] });
    expect(r.verified).toBe(true);
    expect(r.accepted).toBe(false);
    expect(r.reason).toBe('issuer_key_not_pinned');
  });
  it('toMs accepts an ISO string, an omitted, and an unparseable now', () => {
    expect(evaluateRxReliance({ challenge: CHALLENGE, packet: applyBreak('none'), now: '2026-07-08T14:05:00.000Z' }, OPTS).verdict).toBe('rx_rely');
    // omitted now -> Date.now(); unparseable now -> Date.now(); both clock-dependent, so only assert closed-set membership.
    expect(RX_VERDICTS).toContain(evaluateRxReliance({ challenge: CHALLENGE, packet: applyBreak('none') }, OPTS).verdict);
    expect(RX_VERDICTS).toContain(evaluateRxReliance({ challenge: CHALLENGE, packet: applyBreak('none'), now: 'not-a-date' }, OPTS).verdict);
  });
  it('a benefit check citing a different formulary policy is policy_mismatch', () => {
    const p = { ...base(), benefit_check: { checked_at: '2026-07-08T14:00:00.000Z', policy_hash: 'sha256:' + sha('other-formulary') } };
    expect(evaluateRxReliance({ challenge: CHALLENGE, packet: p, now: NOW }, OPTS).verdict).toBe('rx_do_not_rely_policy_mismatch');
  });
  it('a deny with signed_denial_required:false relies without a denial artifact', () => {
    const ch = { ...CHALLENGE, required: { ...CHALLENGE.required, signed_denial_required: false } };
    const r = evaluateRxReliance({ challenge: ch, packet: { ...base(), determination: 'deny' }, now: NOW }, OPTS);
    expect(r.verdict).toBe('rx_rely');
    expect(r.determination).toBe('deny');
  });
  it('a malformed or absent packet fails closed', () => {
    expect(evaluateRxReliance({ challenge: CHALLENGE, packet: { '@type': 'wrong' }, now: NOW }, OPTS).rely).toBe(false);
    expect(evaluateRxReliance({ challenge: CHALLENGE, packet: null, now: NOW }, OPTS).rely).toBe(false);
  });
  it('signRxArtifact rejects a body without an @type', () => {
    expect(() => signRxArtifact({ action_hash: receipt.action_hash }, consentKey.privateKey)).toThrow(/@type/);
  });
  it('verifyRxArtifact fails closed on a malformed signature envelope', () => {
    const r = verifyRxArtifact({ '@type': 'EP-RX-CONSENT-v1', signature: { algorithm: 'RSA' } });
    expect(r.verified).toBe(false);
    expect(r.reason).toBe('signature_malformed');
  });
  it('verifyRxArtifact fails closed when the signing key is unparseable (verify throws)', () => {
    const a = consent();
    a.signature = { ...a.signature, public_key: 'not-valid-der-key-data' }; // body/digest unchanged; createPublicKey throws
    const r = verifyRxArtifact(a, { expectType: 'EP-RX-CONSENT-v1' });
    expect(r.verified).toBe(false);
    expect(r.reason).toBe('signature_invalid');
  });
  it('buildRxAppealBundle refuses incomplete input instead of exporting an ambiguous record', () => {
    expect(() => buildRxAppealBundle({ privacyKey })).toThrow(/challenge/);
  });
  it('evaluateRxReliance without prescriber_authority required skips the authority leg', () => {
    const ch = { ...CHALLENGE, required: { ...CHALLENGE.required, prescriber_authority: false, revocation_freshness_sec: undefined } };
    const p = { ...base(), authority_proof: undefined, revocation_state: undefined };
    const r = evaluateRxReliance({ challenge: ch, packet: p, now: NOW }, OPTS);
    expect(RX_VERDICTS).toContain(r.verdict);
  });
});
