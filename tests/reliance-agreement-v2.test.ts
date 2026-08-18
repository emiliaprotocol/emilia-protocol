// SPDX-License-Identifier: Apache-2.0
//
// EP-RELIANCE-AGREEMENT-v2 / EP-RELIANCE-EVENT-v2 hybrid test: the reference
// hybrid migration (packages/verify/src/revocation.ts's EP-REVOCATION-v2
// pattern) applied to the reliance agreement + event pair.
//
// Builds REAL Ed25519 + ML-DSA-65 signed v2 agreements/events (two distinct
// PQ keypairs, one per required party), then asserts the fail-closed
// predicate. The hostile half is the point: a stripped per-party leg, a
// narrowed required_algorithms set, a wrong-length ML-DSA-65 signature, an
// Ed448 key masquerading as a party's Ed25519 pin, key substitution across
// parties, a PQ-key mismatch on the event's relying_party signature, and a
// v1 verifier handed a v2 object (and vice versa).
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import { canonicalize } from '../packages/verify/src/index.ts';
import {
  RELIANCE_AGREEMENT_VERSION,
  RELIANCE_EVENT_VERSION,
  signRelianceAgreement,
  signRelianceEvent,
  verifyRelianceAgreement,
  verifyRelianceEvent,
  relianceResultDigest,
  RELIANCE_AGREEMENT_V2_VERSION,
  RELIANCE_EVENT_V2_VERSION,
  RELIANCE_AGREEMENT_V2_REQUIRED_ALGORITHMS,
  RELIANCE_EVENT_V2_REQUIRED_ALGORITHMS,
  signRelianceAgreementV2,
  signRelianceEventV2,
  verifyRelianceAgreementV2,
  verifyRelianceEventV2,
  verifyRelianceAgreementStatement,
  verifyRelianceEventStatement,
  relianceAgreementV2Digest,
  agreementV2SigningBytes,
  eventV2SigningBytes,
} from '../packages/verify/src/reliance-agreement.ts';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

// -- two distinct parties, each with a REAL Ed25519 + ML-DSA-65 keypair --
const issuerEd = crypto.generateKeyPairSync('ed25519');
const rpEd = crypto.generateKeyPairSync('ed25519');
const pubOf = (kp: crypto.KeyPairKeyObjectResult) => kp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

const issuerPq = ml_dsa65.keygen(crypto.randomBytes(32));
const rpPq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = (pq: { publicKey: Uint8Array }) => Buffer.from(pq.publicKey).toString('base64url');

const ISSUER_KEY_ID = 'ep:key:issuer-1';
const RP_KEY_ID = 'ep:key:rp-1';

const PINS = Object.freeze({
  [ISSUER_KEY_ID]: { public_key: pubOf(issuerEd), pq_public_key: pqPubB64u(issuerPq) },
  [RP_KEY_ID]: { public_key: pubOf(rpEd), pq_public_key: pqPubB64u(rpPq) },
});

const ISSUER_SIGNER = { party: 'issuer', privateKey: issuerEd.privateKey, pqSecretKey: issuerPq.secretKey, pqPublicKeyB64u: issuerPq.publicKey };
const RP_SIGNER = { party: 'relying_party', privateKey: rpEd.privateKey, pqSecretKey: rpPq.secretKey, pqPublicKeyB64u: rpPq.publicKey };

// The evidence condition: a reliance profile pinned BY DIGEST (same shape as
// the v1 conformance fixture in tests/reliance-agreement.test.ts).
const PROFILE = {
  '@type': 'EP-RELIANCE-PROFILE-v1',
  required_assurance: 'class_a',
  required_authority: true,
  required_evidence: ['authority_proof', 'revocation_freshness'],
  max_revocation_staleness_sec: 300,
};
const PROFILE_DIGEST = `sha256:${crypto.createHash('sha256').update(canonicalize(PROFILE), 'utf8').digest('hex')}`;
const ACTION_DIGEST = `sha256:${'4e'.repeat(32)}`;
const NOW = '2026-08-17T12:00:00.000Z';

function sharedFields() {
  return {
    parties: {
      issuer: { id: 'ep:org:example-issuer', key_id: ISSUER_KEY_ID },
      relying_party: { id: 'ep:org:example-bank', key_id: RP_KEY_ID },
    },
    required_signers: ['issuer', 'relying_party'],
    scope: {
      action_families: ['wire_transfer', 'ach_credit'],
      jurisdictions: ['US-NY'],
      validity: { not_before: '2026-01-01T00:00:00.000Z', not_after: '2027-01-01T00:00:00.000Z' },
    },
    condition: { reliance_profile_digest: PROFILE_DIGEST, min_assurance_class: 'V', max_staleness_sec: 300 },
    terms: {
      mode: 'indemnity',
      cap_amount: '1000000.00',
      currency: 'USD',
      per_action_cap: '250000.00',
      aggregate_cap: '1000000.00',
      deductible: '10000.00',
    },
    recourse_ref: 'https://example.com/master-agreement#annex-b',
  };
}

function basePayloadV2(overrides: Record<string, any> = {}) {
  return {
    version: RELIANCE_AGREEMENT_V2_VERSION,
    agreement_id: 'ra:v2-example:2026-001',
    ...sharedFields(),
    ...overrides,
  };
}

const ALL_SIGNERS_V2 = () => [ISSUER_SIGNER, RP_SIGNER];

async function baseAgreementV2(overrides: Record<string, any> = {}) {
  return signRelianceAgreementV2(basePayloadV2(overrides), ALL_SIGNERS_V2());
}

function baseResult(overrides: Record<string, any> = {}) {
  return {
    '@type': 'EP-RELIANCE-RESULT-v1',
    action_digest: ACTION_DIGEST,
    action_family: 'wire_transfer',
    verdict: 'rely',
    profile_digest: PROFILE_DIGEST,
    ...overrides,
  };
}

async function baseEventV2(
  agreement: Record<string, any>,
  result: Record<string, any>,
  { relied_at = '2026-08-17T11:59:00.000Z', signer = RP_SIGNER as any } = {},
) {
  return signRelianceEventV2({
    version: RELIANCE_EVENT_V2_VERSION,
    event_id: 'rev:v2-example:2026-08-17:0001',
    agreement_digest: relianceAgreementV2Digest(agreement),
    action_digest: result.action_digest,
    reliance_result_digest: relianceResultDigest(result),
    relied_at,
  }, signer);
}

// v1 fixtures, built independently (Ed25519 only), to prove v1 stays untouched.
function basePayloadV1(overrides: Record<string, any> = {}) {
  return {
    version: RELIANCE_AGREEMENT_VERSION,
    agreement_id: 'ra:v1-example:2026-001',
    ...sharedFields(),
    ...overrides,
  };
}
const ALL_SIGNERS_V1 = () => [
  { party: 'issuer', privateKey: issuerEd.privateKey },
  { party: 'relying_party', privateKey: rpEd.privateKey },
];
const V1_PINS = Object.freeze({ [ISSUER_KEY_ID]: pubOf(issuerEd), [RP_KEY_ID]: pubOf(rpEd) });

describe('EP-RELIANCE-AGREEMENT-v2 / EP-RELIANCE-EVENT-v2 hybrid', () => {
  it('a. valid v2 agreement: both required parties sign Ed25519 + ML-DSA-65, verifies', async () => {
    const agreement = await baseAgreementV2();
    expect(agreement.version).toBe(RELIANCE_AGREEMENT_V2_VERSION);
    expect(agreement.required_algorithms).toEqual([...RELIANCE_AGREEMENT_V2_REQUIRED_ALGORITHMS]);
    expect(agreement.signatures).toHaveLength(2);
    for (const entry of agreement.signatures) {
      expect(entry.signatures.map((s: any) => s.alg)).toEqual([...RELIANCE_AGREEMENT_V2_REQUIRED_ALGORITHMS]);
    }
    const r = await verifyRelianceAgreementV2(agreement, { trustedKeys: PINS, now: NOW });
    expect(r.valid).toBe(true);
    expect(r.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(r.required_signers).toEqual(['issuer', 'relying_party']);
  });

  it('b. valid v2 event bound to a v2 agreement verifies', async () => {
    const agreement = await baseAgreementV2();
    const result = baseResult();
    const event = await baseEventV2(agreement, result);
    expect(event.version).toBe(RELIANCE_EVENT_V2_VERSION);
    expect(event.signature.party).toBe('relying_party');
    expect(event.signature.signatures.map((s: any) => s.alg)).toEqual([...RELIANCE_EVENT_V2_REQUIRED_ALGORITHMS]);
    const r = await verifyRelianceEventV2(event, { agreement, relianceResult: result, trustedKeys: PINS, now: NOW });
    expect(r.valid).toBe(true);
    expect(r.agreement_digest).toBe(relianceAgreementV2Digest(agreement));
    expect(r.event_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('c1. the v1 agreement verifier refuses a v2 agreement cleanly on the version marker, no throw', async () => {
    const agreementV2 = await baseAgreementV2();
    let r: any;
    expect(() => { r = verifyRelianceAgreement(agreementV2, { trustedKeys: V1_PINS, now: NOW }); }).not.toThrow();
    expect(r.valid).toBe(false);
    expect(r.reasons.join(' ')).toContain(RELIANCE_AGREEMENT_VERSION);
  });

  it('c2. the v1 event verifier refuses a v2 event cleanly on the version marker, no throw', async () => {
    const agreementV2 = await baseAgreementV2();
    const result = baseResult();
    const eventV2 = await baseEventV2(agreementV2, result);
    let r: any;
    expect(() => { r = verifyRelianceEvent(eventV2, { agreement: agreementV2, relianceResult: result, trustedKeys: V1_PINS, now: NOW }); }).not.toThrow();
    expect(r.valid).toBe(false);
    expect(r.reasons.join(' ')).toContain(RELIANCE_EVENT_VERSION);
  });

  it('c3. the v2 agreement verifier refuses a v1 agreement cleanly on the version marker, no throw', async () => {
    const agreementV1 = signRelianceAgreement(basePayloadV1(), ALL_SIGNERS_V1());
    const r = await verifyRelianceAgreementV2(agreementV1, { trustedKeys: PINS, now: NOW });
    expect(r.valid).toBe(false);
    expect(r.reasons.join(' ')).toContain(RELIANCE_AGREEMENT_V2_VERSION);
  });

  it('c4. the v2 event verifier refuses a v1 event cleanly on the version marker, no throw', async () => {
    const agreementV1 = signRelianceAgreement(basePayloadV1(), ALL_SIGNERS_V1());
    const result = baseResult();
    const eventV1 = signRelianceEvent({
      version: RELIANCE_EVENT_VERSION,
      event_id: 'rev:v1-example:2026-08-17:0001',
      agreement_digest: `sha256:${'11'.repeat(32)}`, // irrelevant -- refused before binding checks
      action_digest: result.action_digest,
      reliance_result_digest: relianceResultDigest(result),
      relied_at: '2026-08-17T11:59:00.000Z',
    }, rpEd.privateKey);
    const r = await verifyRelianceEventV2(eventV1, { agreement: agreementV1, relianceResult: result, trustedKeys: PINS, now: NOW });
    expect(r.valid).toBe(false);
    expect(r.reasons.join(' ')).toContain(RELIANCE_EVENT_V2_VERSION);
  });

  it('c5. v1 agreements and events still round-trip UNCHANGED through the v1 verifiers', () => {
    const agreement = signRelianceAgreement(basePayloadV1(), ALL_SIGNERS_V1());
    const ra = verifyRelianceAgreement(agreement, { trustedKeys: V1_PINS, now: NOW });
    expect(ra.valid).toBe(true);

    const result = baseResult();
    const event = signRelianceEvent({
      version: RELIANCE_EVENT_VERSION,
      event_id: 'rev:v1-example:2026-08-17:0002',
      agreement_digest: ra.digest,
      action_digest: result.action_digest,
      reliance_result_digest: relianceResultDigest(result),
      relied_at: '2026-08-17T11:59:00.000Z',
    }, rpEd.privateKey);
    const re = verifyRelianceEvent(event, { agreement, relianceResult: result, trustedKeys: V1_PINS, now: NOW });
    expect(re.valid).toBe(true);
  });

  it('the version routers dispatch a mixed bag to the right verifier', async () => {
    const agreementV1 = signRelianceAgreement(basePayloadV1(), ALL_SIGNERS_V1());
    const agreementV2 = await baseAgreementV2();
    expect((await verifyRelianceAgreementStatement(agreementV1, { trustedKeys: V1_PINS, now: NOW })).valid).toBe(true);
    expect((await verifyRelianceAgreementStatement(agreementV2, { trustedKeys: PINS, now: NOW })).valid).toBe(true);

    const result = baseResult();
    const eventV2 = await baseEventV2(agreementV2, result);
    const eventV1 = signRelianceEvent({
      version: RELIANCE_EVENT_VERSION,
      event_id: 'rev:v1-example:2026-08-17:0003',
      agreement_digest: verifyRelianceAgreement(agreementV1, { trustedKeys: V1_PINS, now: NOW }).digest,
      action_digest: result.action_digest,
      reliance_result_digest: relianceResultDigest(result),
      relied_at: '2026-08-17T11:59:00.000Z',
    }, rpEd.privateKey);
    expect((await verifyRelianceEventStatement(eventV1, { agreement: agreementV1, relianceResult: result, trustedKeys: V1_PINS, now: NOW })).valid).toBe(true);
    expect((await verifyRelianceEventStatement(eventV2, { agreement: agreementV2, relianceResult: result, trustedKeys: PINS, now: NOW })).valid).toBe(true);
  });

  it('d. a stripped ML-DSA-65 leg for ONE party refuses, naming that party', async () => {
    const agreement = await baseAgreementV2();
    const rpEntry = agreement.signatures.find((s: any) => s.party === 'relying_party');
    rpEntry.signatures = rpEntry.signatures.filter((s: any) => s.alg !== 'ML-DSA-65');
    const r = await verifyRelianceAgreementV2(agreement, { trustedKeys: PINS, now: NOW });
    expect(r.valid).toBe(false);
    expect(r.reasons.join(' ')).toContain('relying_party');
    expect(r.reasons.join(' ')).toContain('ML-DSA-65');
  });

  it('e. narrowed required_algorithms (structural field trimmed, signatures untouched) refuses', async () => {
    const agreement = await baseAgreementV2();
    agreement.required_algorithms = ['Ed25519'];
    const r = await verifyRelianceAgreementV2(agreement, { trustedKeys: PINS, now: NOW });
    expect(r.valid).toBe(false);
    expect(r.reasons.join(' ')).toContain('required_algorithms');
  });

  it('e2. agreementV2SigningBytes/eventV2SigningBytes refuse any non-registered algorithm set (anti-stripping guard)', () => {
    expect(() => agreementV2SigningBytes({}, ['Ed25519'])).toThrow(/registered/);
    expect(() => eventV2SigningBytes({}, ['ML-DSA-65', 'Ed25519'])).toThrow(/registered/);
  });

  it('f. a wrong-length ML-DSA-65 signature refuses, never throws', async () => {
    const agreement = await baseAgreementV2();
    const rpEntry = agreement.signatures.find((s: any) => s.party === 'relying_party');
    const pqSig = rpEntry.signatures.find((s: any) => s.alg === 'ML-DSA-65');
    pqSig.sig = Buffer.from('00'.repeat(100), 'hex').toString('base64url'); // not 3309 bytes
    const r = await verifyRelianceAgreementV2(agreement, { trustedKeys: PINS, now: NOW });
    expect(r.valid).toBe(false);
  });

  it('g. an Ed448 key masquerading as a party Ed25519 pin is refused by the curve pin', async () => {
    const agreement = await baseAgreementV2();
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448PubB64u = ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const pins = { ...PINS, [RP_KEY_ID]: { ...PINS[RP_KEY_ID], public_key: ed448PubB64u } };
    const r = await verifyRelianceAgreementV2(agreement, { trustedKeys: pins, now: NOW });
    expect(r.valid).toBe(false);
  });

  it('h. key substitution: pinning a different partys keys than the ones that actually signed refuses', async () => {
    const agreement = await baseAgreementV2();
    const swappedPins = {
      [ISSUER_KEY_ID]: PINS[RP_KEY_ID],
      [RP_KEY_ID]: PINS[ISSUER_KEY_ID],
    };
    const r = await verifyRelianceAgreementV2(agreement, { trustedKeys: swappedPins, now: NOW });
    expect(r.valid).toBe(false);
  });

  it('i. an event signed with a PQ key that does not match the pinned relying_party PQ key refuses', async () => {
    const agreement = await baseAgreementV2();
    const result = baseResult();
    const rogueSigner = { party: 'relying_party', privateKey: rpEd.privateKey, pqSecretKey: ml_dsa65.keygen(crypto.randomBytes(32)).secretKey, pqPublicKeyB64u: rpPq.publicKey };
    const event = await baseEventV2(agreement, result, { signer: rogueSigner });
    const r = await verifyRelianceEventV2(event, { agreement, relianceResult: result, trustedKeys: PINS, now: NOW });
    expect(r.valid).toBe(false);
  });

  it('missing PQ pin for a required party refuses by name (agreement side)', async () => {
    const agreement = await baseAgreementV2();
    const pins = { ...PINS, [RP_KEY_ID]: { public_key: PINS[RP_KEY_ID].public_key } };
    const r = await verifyRelianceAgreementV2(agreement, { trustedKeys: pins, now: NOW });
    expect(r.valid).toBe(false);
    expect(r.reasons.join(' ')).toContain('relying_party');
  });

  it('missing PQ pin for the events relying_party refuses (event binds through the same pin set)', async () => {
    const agreement = await baseAgreementV2();
    const result = baseResult();
    const event = await baseEventV2(agreement, result);
    const pins = { ...PINS, [RP_KEY_ID]: { public_key: PINS[RP_KEY_ID].public_key } };
    const r = await verifyRelianceEventV2(event, { agreement, relianceResult: result, trustedKeys: pins, now: NOW });
    expect(r.valid).toBe(false);
  });

  it('duplicate algorithm entries within one partys signature set refuse', async () => {
    const agreement = await baseAgreementV2();
    const issuerEntry = agreement.signatures.find((s: any) => s.party === 'issuer');
    issuerEntry.signatures.push({ ...issuerEntry.signatures[0] });
    const r = await verifyRelianceAgreementV2(agreement, { trustedKeys: PINS, now: NOW });
    expect(r.valid).toBe(false);
    expect(r.reasons.join(' ')).toContain('duplicate');
  });

  it('an unavailable ML-DSA backend is a named refusal, never a silent pass', async () => {
    const agreement = await baseAgreementV2();
    const r = await verifyRelianceAgreementV2(agreement, { trustedKeys: PINS, now: NOW, mldsaBackendLoader: () => null });
    expect(r.valid).toBe(false);
    expect(r.reasons.join(' ')).toContain('pq_backend_unavailable');
  });

  it('malformed inputs fail closed with a reason, never throw (v2 agreement + event)', async () => {
    for (const junk of [null, undefined, 42, 'x', [], { version: 'nope' }]) {
      const a = await verifyRelianceAgreementV2(junk as any, { trustedKeys: PINS, now: NOW });
      expect(a.valid).toBe(false);
      expect(a.reasons.length).toBeGreaterThan(0);

      const e = await verifyRelianceEventV2(junk as any, {
        agreement: await baseAgreementV2(), relianceResult: baseResult(), trustedKeys: PINS, now: NOW,
      });
      expect(e.valid).toBe(false);
      expect(e.reasons.length).toBeGreaterThan(0);
    }
  });

  it('signRelianceAgreementV2/signRelianceEventV2 refuse to emit a half-hybrid artifact', async () => {
    await expect(signRelianceAgreementV2(basePayloadV2(), [
      { party: 'issuer', privateKey: issuerEd.privateKey, pqSecretKey: issuerPq.secretKey, pqPublicKeyB64u: issuerPq.publicKey },
      { party: 'relying_party', privateKey: rpEd.privateKey } as any, // missing pqSecretKey/pqPublicKeyB64u
    ])).rejects.toThrow(/half-hybrid/);

    await expect(signRelianceEventV2({
      version: RELIANCE_EVENT_V2_VERSION,
      event_id: 'x',
      agreement_digest: `sha256:${'11'.repeat(32)}`,
      action_digest: ACTION_DIGEST,
      reliance_result_digest: `sha256:${'22'.repeat(32)}`,
      relied_at: NOW,
    }, { privateKey: rpEd.privateKey } as any)).rejects.toThrow(/half-hybrid/);
  });
});
