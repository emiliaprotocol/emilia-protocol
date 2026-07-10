// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';

import {
  buildRxAppealBundle,
  commitRxEvidence,
  derivePairwisePatientRef,
  signRxArtifact,
  verifyRxArtifact,
} from '../lib/ncpdp/rx-reliance.js';

const privacyKey = Buffer.from('71'.repeat(32), 'hex');
const otherPrivacyKey = Buffer.from('72'.repeat(32), 'hex');
const privacyKeyId = 'payer-a-rx-privacy-2026-01';
const actionHash = `sha256:${'ab'.repeat(32)}`;
const policyHash = `sha256:${'cd'.repeat(32)}`;
const ed = () => crypto.generateKeyPairSync('ed25519');
const issuer = ed();
const issuerPublic = issuer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

function artifacts() {
  const subject_ref = derivePairwisePatientRef({ patientIdentifier: 'MEMBER-448193', relyingPartyId: 'payer-a.example', privacyKeyId, sectorSecret: privacyKey });
  return {
    consent: signRxArtifact({
      '@type': 'EP-RX-CONSENT-v1', action_hash: actionHash, privacy_key_id: privacyKeyId, subject_ref,
      consent_digest: commitRxEvidence({ evidenceType: 'consent', record: { member: 'MEMBER-448193', scope: 'pa' }, privacyKeyId, sectorSecret: privacyKey }),
      issued_at: '2026-07-10T10:00:00.000Z',
    }, issuer.privateKey),
    clinical: signRxArtifact({
      '@type': 'EP-RX-CLINICAL-v1', action_hash: actionHash, privacy_key_id: privacyKeyId,
      evidence_digest: commitRxEvidence({ evidenceType: 'clinical', record: { diagnosis: 'SENSITIVE-DX', lab: 'SENSITIVE-LAB' }, privacyKeyId, sectorSecret: privacyKey }),
      criteria: 'step-therapy-met', issued_at: '2026-07-10T10:01:00.000Z',
    }, issuer.privateKey),
  };
}

describe('EP-NCPDP-RX-PRIVACY-PROFILE-v1', () => {
  it('derives stable references within one relying party and unlinkable references across parties', () => {
    const input = { patientIdentifier: 'MEMBER-448193', relyingPartyId: 'payer-a.example', privacyKeyId, sectorSecret: privacyKey };
    const a = derivePairwisePatientRef(input);
    expect(derivePairwisePatientRef(input)).toBe(a);
    expect(derivePairwisePatientRef({ ...input, relyingPartyId: 'payer-b.example' })).not.toBe(a);
    expect(derivePairwisePatientRef({ ...input, sectorSecret: otherPrivacyKey })).not.toBe(a);
    expect(a).not.toContain('MEMBER-448193');
  });

  it('requires a 256-bit privacy key for references and commitments', () => {
    expect(() => derivePairwisePatientRef({ patientIdentifier: 'x', relyingPartyId: 'rp', privacyKeyId, sectorSecret: Buffer.alloc(16) })).toThrow(/32 bytes/);
    expect(() => commitRxEvidence({ evidenceType: 'clinical', record: {}, privacyKeyId, sectorSecret: Buffer.alloc(0) })).toThrow(/32 bytes/);
  });

  it('uses keyed, domain-separated commitments for low-entropy records', () => {
    const record = { diagnosis: 'A' };
    const clinical = commitRxEvidence({ evidenceType: 'clinical', record, privacyKeyId, sectorSecret: privacyKey });
    const consent = commitRxEvidence({ evidenceType: 'consent', record, privacyKeyId, sectorSecret: privacyKey });
    expect(clinical).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);
    expect(clinical).not.toBe(consent);
    expect(clinical).not.toBe(commitRxEvidence({ evidenceType: 'clinical', record, privacyKeyId, sectorSecret: otherPrivacyKey }));
  });

  it.each([
    ['direct patient field', { patient_name: 'Ada' }],
    ['member identifier', { member_id: 'MEMBER-448193' }],
    ['nested clinical record', { raw: { diagnosis: 'SENSITIVE-DX' } }],
  ])('refuses %s before signing', (_label, extra) => {
    const body = {
      '@type': 'EP-RX-CONSENT-v1', action_hash: actionHash, privacy_key_id: privacyKeyId,
      subject_ref: derivePairwisePatientRef({ patientIdentifier: 'x', relyingPartyId: 'rp', privacyKeyId, sectorSecret: privacyKey }),
      consent_digest: commitRxEvidence({ evidenceType: 'consent', record: {}, privacyKeyId, sectorSecret: privacyKey }),
      issued_at: '2026-07-10T10:00:00.000Z', ...extra,
    };
    expect(() => signRxArtifact(body, issuer.privateKey)).toThrow(/forbids artifact field/);
  });

  it('refuses direct identifiers, bare hashes, free text, and instance-specific appeal URLs', () => {
    const digest = commitRxEvidence({ evidenceType: 'consent', record: {}, privacyKeyId, sectorSecret: privacyKey });
    expect(() => signRxArtifact({ '@type': 'EP-RX-CONSENT-v1', action_hash: actionHash, privacy_key_id: privacyKeyId, subject_ref: 'ep:patient:123', consent_digest: digest, issued_at: '2026-07-10T10:00:00.000Z' }, issuer.privateKey)).toThrow(/pairwise/);
    expect(() => signRxArtifact({ '@type': 'EP-RX-CLINICAL-v1', action_hash: actionHash, privacy_key_id: privacyKeyId, evidence_digest: `sha256:${'00'.repeat(32)}`, criteria: 'met', issued_at: '2026-07-10T10:00:00.000Z' }, issuer.privateKey)).toThrow(/keyed commitment/);
    expect(() => signRxArtifact({ '@type': 'EP-RX-CLINICAL-v1', action_hash: actionHash, privacy_key_id: privacyKeyId, evidence_digest: digest, criteria: 'patient has a sensitive diagnosis', issued_at: '2026-07-10T10:00:00.000Z' }, issuer.privateKey)).toThrow(/coded token/);
    expect(() => signRxArtifact({ '@type': 'EP-RX-DENIAL-v1', action_hash: actionHash, privacy_key_id: privacyKeyId, reason_code: 'not-covered', reason_digest: digest, appeal_url: 'https://payer.example/appeals/MEMBER-448193?name=Ada', issued_at: '2026-07-10T10:00:00.000Z' }, issuer.privateKey)).toThrow(/generic HTTPS route/);
  });

  it('does not accept a signed artifact unless the relying party pins its issuer', () => {
    const artifact = artifacts().consent;
    expect(verifyRxArtifact(artifact, { expectType: 'EP-RX-CONSENT-v1', expectActionHash: actionHash }).reason).toBe('issuer_key_not_pinned');
    expect(verifyRxArtifact(artifact, { expectType: 'EP-RX-CONSENT-v1', expectActionHash: actionHash, pinnedKeys: [issuerPublic] }).accepted).toBe(true);
  });

  it('refuses future-dated artifacts at a freshness boundary', () => {
    const artifact = artifacts().consent;
    const result = verifyRxArtifact(artifact, {
      expectType: 'EP-RX-CONSENT-v1', expectActionHash: actionHash, pinnedKeys: [issuerPublic],
      now: Date.parse('2026-07-10T09:59:59.000Z'), maxStalenessSec: 3600,
    });
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe('stale');
  });

  it('projects an appeal bundle without recursively copying planted PHI', () => {
    const signed = artifacts();
    const secretValues = ['MEMBER-448193', 'Ada Patient', 'SENSITIVE-DX', 'SENSITIVE-LAB'];
    const challenge = {
      '@type': 'EP-RX-EVIDENCE-CHALLENGE-v1', transaction: 'ncpdp.epa', required_assurance: 'class_a',
      required: { patient_consent: true, clinical_evidence: true, benefit_policy_hash: policyHash, benefit_freshness_sec: 3600 },
      accepted_issuer_keys: [issuerPublic], internal_note: 'Ada Patient',
    };
    const packet = {
      '@type': 'EP-RX-RELIANCE-PACKET-v1',
      action: { action_type: 'rx.prior_auth.approve', action_hash: actionHash, policy_hash: policyHash, patient_name: 'Ada Patient' },
      receipt: { receipt_id: 'MEMBER-448193', diagnosis: 'SENSITIVE-DX' },
      authority_proof: { note: 'SENSITIVE-LAB' },
      patient_consent: signed.consent, clinical_evidence: signed.clinical, determination: 'approve',
    };
    const bundle = buildRxAppealBundle({
      challenge, packet,
      result: { verdict: 'rx_rely', determination: 'approve', checks: { patient_consent: true, clinical_evidence: true } },
      now: '2026-07-10T10:05:00.000Z', privacyKey, privacyKeyId, retentionDays: 7,
    });
    const serialized = JSON.stringify(bundle);
    for (const value of secretValues) expect(serialized).not.toContain(value);
    expect(bundle['@type']).toBe('EP-RX-RELIANCE-BUNDLE-v2');
    expect(bundle.projection_key_id).toBe(privacyKeyId);
    expect(bundle.purge_after).toBe('2026-07-17T10:05:00.000Z');
    expect(bundle.evidence_refs.packet).toMatch(/^hmac-sha256:/);
    expect(bundle.bundle_digest).toMatch(/^sha256:/);
  });

  it('refuses unknown fields in the signature envelope before export', () => {
    const signed = artifacts();
    signed.consent.signature.patient_name = 'Ada Patient';
    expect(() => buildRxAppealBundle({
      challenge: { '@type': 'EP-RX-EVIDENCE-CHALLENGE-v1', transaction: 'ncpdp.epa', required: {} },
      packet: { action: { action_type: 'rx.prior_auth.approve', action_hash: actionHash }, patient_consent: signed.consent },
      result: { verdict: 'rx_rely', determination: 'approve', checks: {} },
      privacyKey, privacyKeyId,
    })).toThrow(/forbids artifact field/);
  });
});
