// SPDX-License-Identifier: Apache-2.0
//
// EP-IDENTIFIED-RECEIPT-SUBMISSION-v2 (lib/signatures.ts): the hybrid
// submission-signature profile behind the identified_signed provenance tier,
// plus the regression that the untouched v1 path still behaves exactly as it
// did.
//
// The v1 path's whole weakness is the point of the v2 profile and is asserted
// here rather than asserted about: a v1 signature covers 32 bytes of receipt
// hash with nowhere to commit an algorithm set, so a set of v1-style signatures
// can be stripped leg by leg and each survivor still verifies. v2 signs bytes
// that CONTAIN the set, and the test proves narrowing breaks the survivor.
//
// The PQ leg runs for real. These tests FAIL LOUDLY if @noble/post-quantum is
// missing rather than silently skipping.

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import {
  buildIdentifiedSubmissionDigest,
  IDENTIFIED_SUBMISSION_V2_PROFILE,
  IDENTIFIED_SUBMISSION_V2_REQUIRED_ALGORITHMS,
  identifiedSubmissionV2SignedBytes,
  resolveProvenanceTier,
  resolveProvenanceTierV2,
  verifyIdentifiedSubmissionV2,
  verifyReceiptSignature,
} from '../lib/signatures.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const RECEIPT_HASH = crypto.createHash('sha256').update('a receipt').digest('hex');
const OTHER_HASH = crypto.createHash('sha256').update('another receipt').digest('hex');

const ed = crypto.generateKeyPairSync('ed25519');
const edSpkiB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(new Uint8Array(crypto.createHash('sha256').update('identified-v2/seed').digest()));
const pqPublicB64u = Buffer.from(pq.publicKey).toString('base64url');

const KEYS = {
  ed25519PublicKey: edSpkiB64u,
  ed25519KeyId: 'ep:key:submitter-ed#1',
  mldsaPublicKey: pqPublicB64u,
  mldsaKeyId: 'ep:key:submitter-pq#1',
};

/** Mint a REAL v2 submission; overrides let a test tamper AFTER signing. */
function buildV2({
  receiptHash = RECEIPT_HASH,
  requiredAlgorithms = [...IDENTIFIED_SUBMISSION_V2_REQUIRED_ALGORITHMS],
} = {}) {
  const bytes = identifiedSubmissionV2SignedBytes(receiptHash, requiredAlgorithms as any);
  return {
    '@version': IDENTIFIED_SUBMISSION_V2_PROFILE,
    required_algorithms: [...requiredAlgorithms],
    signatures: [
      {
        alg: 'Ed25519',
        sig: crypto.sign(null, bytes, ed.privateKey).toString('base64url'),
        key_id: KEYS.ed25519KeyId,
      },
      {
        alg: 'ML-DSA-65',
        sig: Buffer.from(ml_dsa65.sign(new Uint8Array(bytes), pq.secretKey)).toString('base64url'),
        key_id: KEYS.mldsaKeyId,
      },
    ],
  };
}

describe('the v1 submission signature path is untouched', () => {
  const v1Signature = crypto
    .sign(null, Buffer.from(RECEIPT_HASH, 'hex'), ed.privateKey)
    .toString('base64url');

  it('still verifies a v1 signature over the raw receipt-hash bytes', () => {
    expect(verifyReceiptSignature(RECEIPT_HASH, v1Signature, edSpkiB64u).valid).toBe(true);
    expect(verifyReceiptSignature(OTHER_HASH, v1Signature, edSpkiB64u).valid).toBe(false);
  });

  it('still resolves and downgrades the identified_signed tier synchronously', () => {
    expect(resolveProvenanceTier('identified_signed', RECEIPT_HASH, { signature: v1Signature }, edSpkiB64u))
      .toEqual({ tier: 'identified_signed' });
    expect(resolveProvenanceTier('identified_signed', RECEIPT_HASH, {}, edSpkiB64u).tier)
      .toBe('self_attested');
    expect(resolveProvenanceTier('self_attested', RECEIPT_HASH, {}, edSpkiB64u))
      .toEqual({ tier: 'self_attested' });
  });

  it('WHY v2 EXISTS: a v1 signature carries no commitment to an algorithm set', () => {
    // Two v1-style signatures over the SAME 32 bytes. Delete either and the
    // survivor still verifies, because nothing in those 32 bytes says a second
    // algorithm was ever required. This is the property v2 fixes.
    const pqOverSameBytes = ml_dsa65.sign(new Uint8Array(Buffer.from(RECEIPT_HASH, 'hex')), pq.secretKey);
    expect(ml_dsa65.verify(pqOverSameBytes, new Uint8Array(Buffer.from(RECEIPT_HASH, 'hex')), pq.publicKey)).toBe(true);
    expect(verifyReceiptSignature(RECEIPT_HASH, v1Signature, edSpkiB64u).valid).toBe(true);
  });

  it('NON-CIRCULARITY: a v2 proof in evidence does not enter the v1 signature input', () => {
    const withoutV2 = buildIdentifiedSubmissionDigest({
      targetEntityRef: 'ent_1',
      evidence: { note: 'kept' },
    });
    const withV2 = buildIdentifiedSubmissionDigest({
      targetEntityRef: 'ent_1',
      evidence: { note: 'kept', signature_v2: buildV2() },
    });
    expect(withV2.digest).toBe(withoutV2.digest);
    expect(withV2.payload.evidence).toEqual({ note: 'kept' });
  });

  it('REGRESSION: excluding signature_v2 changes nothing for a submission that lacks it', () => {
    const digest = buildIdentifiedSubmissionDigest({
      targetEntityRef: 'ent_1',
      transactionRef: 'txn_1',
      evidence: { public_key: 'ignored', signature: 'ignored', note: 'kept' },
    });
    expect(digest.payload.evidence).toEqual({ note: 'kept' });
    expect(digest.canonical).toContain('"evidence":{"note":"kept"}');
  });

  it('a v2 proof object presented in the v1 `signature` slot fails closed', () => {
    const tier = resolveProvenanceTier(
      'identified_signed', RECEIPT_HASH, { signature: buildV2() as any }, edSpkiB64u,
    );
    expect(tier.tier).toBe('self_attested');
  });
});

describe('EP-IDENTIFIED-RECEIPT-SUBMISSION-v2 signed bytes', () => {
  it('commits the profile marker, the receipt hash, and the required set', () => {
    const bytes = identifiedSubmissionV2SignedBytes(RECEIPT_HASH);
    expect(JSON.parse(bytes.toString('utf8'))).toEqual({
      '@version': 'EP-IDENTIFIED-RECEIPT-SUBMISSION-v2',
      receipt_hash: RECEIPT_HASH,
      required_algorithms: ['Ed25519', 'ML-DSA-65'],
    });
    // Canonical JSON: keys sorted, no whitespace.
    expect(bytes.toString('utf8')).toBe(
      `{"@version":"EP-IDENTIFIED-RECEIPT-SUBMISSION-v2","receipt_hash":"${RECEIPT_HASH}","required_algorithms":["Ed25519","ML-DSA-65"]}`,
    );
  });

  it('refuses a malformed hash or a non-registered set', () => {
    expect(() => identifiedSubmissionV2SignedBytes('not-a-hash')).toThrow(/lowercase SHA-256 hex/);
    expect(() => identifiedSubmissionV2SignedBytes(RECEIPT_HASH.toUpperCase())).toThrow();
    expect(() => identifiedSubmissionV2SignedBytes(RECEIPT_HASH, ['Ed25519'])).toThrow(/registered/);
    expect(() => identifiedSubmissionV2SignedBytes(RECEIPT_HASH, ['ML-DSA-65', 'Ed25519'])).toThrow(/registered/);
  });
});

describe('EP-IDENTIFIED-RECEIPT-SUBMISSION-v2 verification', () => {
  it('accepts a well-formed submission under both pinned keys', async () => {
    const result = await verifyIdentifiedSubmissionV2(RECEIPT_HASH, buildV2(), KEYS);
    expect(result.reason).toBeNull();
    expect(result.valid).toBe(true);
    expect(result.checks).toEqual({ algorithm_set: true, legs_present: true, signatures_valid: true });
  });

  it('refuses a submission bound to a DIFFERENT receipt hash', async () => {
    const result = await verifyIdentifiedSubmissionV2(OTHER_HASH, buildV2(), KEYS);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('signature_invalid');
  });

  it('STRIPPED LEG: dropping the ML-DSA signature is refused', async () => {
    const submission = buildV2();
    submission.signatures = submission.signatures.filter((s) => s.alg === 'Ed25519');
    const result = await verifyIdentifiedSubmissionV2(RECEIPT_HASH, submission, KEYS);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('hybrid_leg_missing');
    expect(result.failed_algorithm).toBe('ML-DSA-65');
  });

  it('NARROWED SET: dropping the leg and narrowing the set is refused', async () => {
    const submission = buildV2();
    submission.signatures = submission.signatures.filter((s) => s.alg === 'Ed25519');
    submission.required_algorithms = ['Ed25519'];
    const result = await verifyIdentifiedSubmissionV2(RECEIPT_HASH, submission, KEYS);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('algorithm_set_mismatch');
  });

  it('ANTI-STRIPPING IS CRYPTOGRAPHIC: the surviving Ed25519 leg does not verify over the narrowed bytes', () => {
    const full = buildV2();
    const edLeg = full.signatures.find((s) => s.alg === 'Ed25519')!;
    const narrowedBytes = Buffer.from(
      `{"@version":"EP-IDENTIFIED-RECEIPT-SUBMISSION-v2","receipt_hash":"${RECEIPT_HASH}","required_algorithms":["Ed25519"]}`,
      'utf8',
    );
    expect(crypto.verify(null, narrowedBytes, ed.publicKey, Buffer.from(edLeg.sig, 'base64url'))).toBe(false);
    // The same signature over the FULL set still verifies, so the failure above
    // is attributable to the narrowing and nothing else.
    expect(crypto.verify(
      null, identifiedSubmissionV2SignedBytes(RECEIPT_HASH), ed.publicKey, Buffer.from(edLeg.sig, 'base64url'),
    )).toBe(true);
  });

  it('WRONG-LENGTH SIGNATURE: a truncated ML-DSA leg is refused, never skipped', async () => {
    const submission = buildV2();
    const pqLeg = submission.signatures.find((s) => s.alg === 'ML-DSA-65')!;
    pqLeg.sig = Buffer.from(pqLeg.sig, 'base64url').subarray(0, 3308).toString('base64url');
    const result = await verifyIdentifiedSubmissionV2(RECEIPT_HASH, submission, KEYS);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('signature_invalid');
    expect(result.failed_algorithm).toBe('ML-DSA-65');
  });

  it('ED448 MASQUERADE: an Ed448 key pinned as the Ed25519 half is refused', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const result = await verifyIdentifiedSubmissionV2(RECEIPT_HASH, buildV2(), {
      ...KEYS,
      ed25519PublicKey: ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
    });
    expect(result.valid).toBe(false);
    // ed25519PublicKey() curve-pins before the agility module is even reached.
    expect(result.reason).toBe('missing_key');
    expect(result.failed_algorithm).toBe('Ed25519');
  });

  it('DUPLICATE and UNEXPECTED algorithms are refused', async () => {
    const dup = buildV2();
    dup.signatures = [dup.signatures[0], { ...dup.signatures[0] }, dup.signatures[1]];
    expect((await verifyIdentifiedSubmissionV2(RECEIPT_HASH, dup, KEYS)).reason).toBe('duplicate_algorithm');

    const extra = buildV2();
    extra.signatures = [...extra.signatures, { alg: 'RSA-PSS', sig: 'AAAA', key_id: 'x' }];
    const result = await verifyIdentifiedSubmissionV2(RECEIPT_HASH, extra, KEYS);
    expect(result.reason).toBe('unexpected_algorithm');
    expect(result.failed_algorithm).toBe('RSA-PSS');
  });

  it('V1 PROFILE REFUSED: a submission without the v2 marker is refused', async () => {
    const submission: any = buildV2();
    submission['@version'] = 'EP-IDENTIFIED-RECEIPT-SUBMISSION-v1';
    expect((await verifyIdentifiedSubmissionV2(RECEIPT_HASH, submission, KEYS)).reason).toBe('unknown_profile');
  });

  it('MISSING KEY: half a pin is a refusal, never a structural pass', async () => {
    for (const keys of [null, undefined, {}, { ed25519PublicKey: edSpkiB64u }, { mldsaPublicKey: pqPublicB64u }]) {
      const result = await verifyIdentifiedSubmissionV2(RECEIPT_HASH, buildV2(), keys as any);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('missing_key');
    }
  });

  it('NO PQ BACKEND: an absent ML-DSA backend refuses; it never passes on the classical leg', async () => {
    const result = await verifyIdentifiedSubmissionV2(RECEIPT_HASH, buildV2(), KEYS, {
      mldsaBackendLoader: () => null,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('pq_backend_unavailable');
    expect(result.failed_algorithm).toBe('ML-DSA-65');
  });

  it('NOTHING THROWS on hostile caller input', async () => {
    const hostile = [null, undefined, 0, '', [], { '@version': 1 }, buildV2().signatures,
      { '@version': IDENTIFIED_SUBMISSION_V2_PROFILE },
      { '@version': IDENTIFIED_SUBMISSION_V2_PROFILE, required_algorithms: ['Ed25519', 'ML-DSA-65'], signatures: [{}] }];
    for (const submission of hostile) {
      const result = await verifyIdentifiedSubmissionV2(RECEIPT_HASH, submission, KEYS);
      expect(result.valid).toBe(false);
      expect(typeof result.reason).toBe('string');
    }
    const badHash = await verifyIdentifiedSubmissionV2('nope' as any, buildV2(), KEYS);
    expect(badHash.reason).toBe('malformed_receipt_hash');
  });
});

describe('resolveProvenanceTierV2', () => {
  it('keeps the identified_signed tier for a verifying v2 proof', async () => {
    const tier = await resolveProvenanceTierV2(
      'identified_signed', RECEIPT_HASH, { signature_v2: buildV2() }, KEYS,
    );
    expect(tier).toEqual({ tier: 'identified_signed' });
  });

  it('passes non-identified tiers through unchanged', async () => {
    expect(await resolveProvenanceTierV2('self_attested', RECEIPT_HASH, {}, KEYS))
      .toEqual({ tier: 'self_attested' });
  });

  it('downgrades when the proof is absent, half-pinned, or stripped', async () => {
    const noProof = await resolveProvenanceTierV2('identified_signed', RECEIPT_HASH, {}, KEYS);
    expect(noProof.tier).toBe('self_attested');
    expect(noProof.warning).toMatch(/no EP-IDENTIFIED-RECEIPT-SUBMISSION-v2 proof/);

    const halfPinned = await resolveProvenanceTierV2(
      'identified_signed', RECEIPT_HASH, { signature_v2: buildV2() }, { ed25519PublicKey: edSpkiB64u },
    );
    expect(halfPinned.tier).toBe('self_attested');
    expect(halfPinned.warning).toMatch(/Ed25519 \+ ML-DSA-65 submitter key pair/);

    const stripped = buildV2();
    stripped.signatures = stripped.signatures.filter((s) => s.alg === 'Ed25519');
    const downgraded = await resolveProvenanceTierV2(
      'identified_signed', RECEIPT_HASH, { signature_v2: stripped }, KEYS,
    );
    expect(downgraded.tier).toBe('self_attested');
    expect(downgraded.warning).toMatch(/hybrid_leg_missing/);
  });

  it('downgrades rather than passes when the ML-DSA backend is unavailable', async () => {
    const tier = await resolveProvenanceTierV2(
      'identified_signed', RECEIPT_HASH, { signature_v2: buildV2() }, KEYS,
      { mldsaBackendLoader: () => null },
    );
    expect(tier.tier).toBe('self_attested');
    expect(tier.warning).toMatch(/pq_backend_unavailable/);
  });
});
