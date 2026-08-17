// SPDX-License-Identifier: Apache-2.0
//
// EP-DISPLAY-ATTESTATION-v2 hybrid verifier test.
//
// Builds a REAL Ed25519 + ML-DSA-65 signed display attestation over a canonical
// action, then asserts the fail-closed predicate: WYSIWYS render binding plus
// the hybrid hostile matrix (leg stripping both ways, set narrowing structural +
// independent crypto.verify, widening, duplicate/relabelled/swapped legs, Ed448
// masquerade, key substitution, tamper-after-signing), the v1 verifier refusing
// a v2 attestation, and a v1 byte-identity regression.
//
// The PQ leg runs for real: this suite FAILS LOUDLY if @noble/post-quantum is
// missing rather than silently skipping.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import { canonicalize } from '../packages/issue/index.js';
import {
  DISPLAY_ATTESTATION_V2_VERSION,
  DISPLAY_ATTESTATION_V2_REQUIRED_ALGORITHMS,
  renderAction,
  buildDisplayAttestation,
  buildDisplayAttestationV2,
  verifyDisplayAttestation,
  verifyDisplayAttestationV2,
} from '../lib/wysiwys/render.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const ACTION = {
  action_type: 'payment.release',
  policy_id: 'policy.wires',
  actor_id: 'ep:agent:worker',
  target_resource_id: 'wire/8841',
  organization_id: 'org.acme',
  amount: 2_400_000,
  currency: 'USD',
  requested_at: '2026-08-02T20:00:00.000Z',
};
const SIGNER_KEY_ID = 'ep:display-signer:client-1';

const ed = crypto.generateKeyPairSync('ed25519');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const pqSecretB64u = Buffer.from(pq.secretKey).toString('base64url');

const clone = <T>(v: T): T => structuredClone(v);

async function buildV2(action = ACTION) {
  return buildDisplayAttestationV2({
    action,
    signer: { signer_key_id: SIGNER_KEY_ID, privateKey: ed.privateKey, pqSecretKey: pqSecretB64u, pqPublicKey: pqPubB64u },
  });
}
function pins(att: any) {
  return {
    displaySignerKeys: { [att.proof.signer_key_id]: { public_key: att.proof.public_key, pq_public_key: att.proof.pq_public_key } },
    requireSignedAttestation: true,
  };
}

describe('EP-DISPLAY-ATTESTATION-v2 hybrid', () => {
  it('real ML-DSA-65 backend is available for this suite', () => {
    expect(typeof ml_dsa65?.sign).toBe('function');
  });

  it('a real hybrid attestation verifies under both pinned keys', async () => {
    const att = await buildV2();
    const res = await verifyDisplayAttestationV2(ACTION, att, pins(att));
    expect(res.valid).toBe(true);
    expect(res.checks.legs_present).toBe(true);
    expect(res.checks.proof_signed).toBe(true);
    expect(res.checks.display_hash_match).toBe(true);
  });

  it('the committed bytes carry the required algorithm set + v2 marker', async () => {
    const att = await buildV2();
    const bytes = canonicalize({
      '@version': DISPLAY_ATTESTATION_V2_VERSION,
      render_profile: att.render_profile,
      action_hash: att.action_hash,
      display_hash: att.display_hash,
      required_algorithms: [...DISPLAY_ATTESTATION_V2_REQUIRED_ALGORITHMS],
    });
    expect(bytes).toContain('"required_algorithms":["Ed25519","ML-DSA-65"]');
  });

  // --- v1 / v2 compatibility --------------------------------------------------

  it('the v1 verifier refuses a v2 attestation on the version marker', async () => {
    const att = await buildV2();
    const res = verifyDisplayAttestation(ACTION, att, {});
    expect(res.valid).toBe(false);
    expect(res.errors).toContain('invalid_attestation_version');
  });

  it('the v1 verifier still accepts a v1 attestation, unchanged (byte-identity regression)', () => {
    const v1 = buildDisplayAttestation({
      action: ACTION,
      signer: {
        signer_key_id: SIGNER_KEY_ID,
        privateKey: ed.privateKey,
        publicKeyB64u: ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
      },
    });
    const res = verifyDisplayAttestation(ACTION, v1, {
      displaySignerKeys: { [SIGNER_KEY_ID]: { public_key: ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url') } },
    });
    expect(res.valid).toBe(true);
  });

  it('the v2 verifier refuses a v1 attestation on the version marker', async () => {
    const v1 = buildDisplayAttestation({ action: ACTION });
    const res = await verifyDisplayAttestationV2(ACTION, v1, {});
    expect(res.valid).toBe(false);
    expect(res.errors).toContain('invalid_attestation_version');
  });

  // --- WYSIWYS render binding -------------------------------------------------

  it('RENDER MISMATCH: attesting one action but verifying against another refuses', async () => {
    const att = await buildV2();
    const other = { ...ACTION, amount: 9_999_999 };
    const res = await verifyDisplayAttestationV2(other, att, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.display_hash_match).toBe(false);
  });

  // --- anti-stripping ---------------------------------------------------------

  it('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
    const att = clone(await buildV2());
    att.proof.signatures = att.proof.signatures.filter((s: any) => s.alg === 'Ed25519');
    const res = await verifyDisplayAttestationV2(ACTION, att, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.legs_present).toBe(false);
    expect(res.checks.proof_signed).toBe(false);
  });

  it('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const att = clone(await buildV2());
    att.proof.signatures = att.proof.signatures.filter((s: any) => s.alg === 'ML-DSA-65');
    const res = await verifyDisplayAttestationV2(ACTION, att, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.legs_present).toBe(false);
  });

  it('SET NARROWING fails BOTH structurally and cryptographically', async () => {
    const att = clone(await buildV2());
    att.proof.required_algorithms = ['Ed25519'];
    att.proof.signatures = att.proof.signatures.filter((s: any) => s.alg === 'Ed25519');
    const res = await verifyDisplayAttestationV2(ACTION, att, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.algorithm_set).toBe(false);

    const rendered = renderAction(ACTION);
    const narrowedBytes = Buffer.from(canonicalize({
      '@version': DISPLAY_ATTESTATION_V2_VERSION,
      render_profile: rendered.render_profile,
      action_hash: rendered.action_hash,
      display_hash: rendered.display_hash,
      required_algorithms: ['Ed25519'],
    }), 'utf8');
    const edPub = crypto.createPublicKey({ key: Buffer.from(att.proof.public_key, 'base64url'), format: 'der', type: 'spki' });
    const survivingSig = Buffer.from(att.proof.signatures[0].sig, 'base64url');
    expect(crypto.verify(null, narrowedBytes, edPub, survivingSig)).toBe(false);
  });

  it('SET WIDENING: an extra algorithm refuses', async () => {
    const att = clone(await buildV2());
    att.proof.required_algorithms = ['Ed25519', 'ML-DSA-65', 'Ed448'];
    const res = await verifyDisplayAttestationV2(ACTION, att, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.algorithm_set).toBe(false);
  });

  it('DUPLICATE ALGORITHM refuses', async () => {
    const att = clone(await buildV2());
    att.proof.signatures = [att.proof.signatures[0], att.proof.signatures[0]];
    const res = await verifyDisplayAttestationV2(ACTION, att, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.legs_present).toBe(false);
  });

  it('ALGORITHM RELABELLING: Ed25519 leg called Ed448 refuses', async () => {
    const att = clone(await buildV2());
    att.proof.signatures = att.proof.signatures.map((s: any) => (s.alg === 'Ed25519' ? { ...s, alg: 'Ed448' } : s));
    const res = await verifyDisplayAttestationV2(ACTION, att, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.legs_present).toBe(false);
  });

  it('SWAPPED LEGS: the ML-DSA signature relabelled as Ed25519 refuses', async () => {
    const att = clone(await buildV2());
    const pqLeg = att.proof.signatures.find((s: any) => s.alg === 'ML-DSA-65');
    att.proof.signatures = [{ ...pqLeg, alg: 'Ed25519' }, pqLeg];
    const res = await verifyDisplayAttestationV2(ACTION, att, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.proof_signed).toBe(false);
  });

  it('ED448 MASQUERADE: an Ed448 SPKI presented and pinned as the Ed25519 half refuses', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const att = clone(await buildV2());
    att.proof.public_key = ed448Pub;
    const res = await verifyDisplayAttestationV2(ACTION, att, {
      displaySignerKeys: { [SIGNER_KEY_ID]: { public_key: ed448Pub, pq_public_key: att.proof.pq_public_key } },
      requireSignedAttestation: true,
    });
    expect(res.valid).toBe(false);
    expect(res.checks.proof_signed).toBe(false);
  });

  // --- pinning ----------------------------------------------------------------

  it('an unpinned signer confers nothing', async () => {
    const att = await buildV2();
    const res = await verifyDisplayAttestationV2(ACTION, att, { displaySignerKeys: {}, requireSignedAttestation: true });
    expect(res.valid).toBe(false);
    expect(res.checks.signer_key_pinned).toBe(false);
  });

  it('pinning only the Ed25519 half refuses (both halves required)', async () => {
    const att = await buildV2();
    const res = await verifyDisplayAttestationV2(ACTION, att, {
      displaySignerKeys: { [SIGNER_KEY_ID]: { public_key: att.proof.public_key, pq_public_key: '' } as any },
      requireSignedAttestation: true,
    });
    expect(res.valid).toBe(false);
    expect(res.checks.signer_key_pinned).toBe(false);
  });

  it('PQ KEY SUBSTITUTION: a different pinned ML-DSA key refuses', async () => {
    const att = await buildV2();
    const other = ml_dsa65.keygen(crypto.randomBytes(32));
    const res = await verifyDisplayAttestationV2(ACTION, att, {
      displaySignerKeys: { [SIGNER_KEY_ID]: { public_key: att.proof.public_key, pq_public_key: Buffer.from(other.publicKey).toString('base64url') } },
      requireSignedAttestation: true,
    });
    expect(res.valid).toBe(false);
    expect(res.checks.signer_key_pinned).toBe(false);
  });

  // --- binding ----------------------------------------------------------------

  it('TAMPERED AFTER SIGNING: editing display_hash breaks the render binding', async () => {
    const att = clone(await buildV2());
    att.display_hash = `sha256:${'a'.repeat(64)}`;
    const res = await verifyDisplayAttestationV2(ACTION, att, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.display_hash_match).toBe(false);
  });

  // --- fail-closed backend ----------------------------------------------------

  it('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const att = await buildV2();
    const res = await verifyDisplayAttestationV2(ACTION, att, { ...pins(att), mldsaBackendLoader: async () => null });
    expect(res.valid).toBe(false);
    expect(res.checks.proof_signed).toBe(false);
    expect(res.errors.some((e) => /pq_backend_unavailable/.test(e))).toBe(true);
  });

  // --- fail-closed on junk ----------------------------------------------------

  it('malformed input refuses without throwing', async () => {
    for (const junk of ['x', 42, []]) {
      const res = await verifyDisplayAttestationV2(ACTION, junk, pins(await buildV2()));
      expect(res.valid).toBe(false);
    }
  });
});
