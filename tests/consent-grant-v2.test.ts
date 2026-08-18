// SPDX-License-Identifier: Apache-2.0
//
// EP-CONSENT-GRANT-v2 hybrid grant test: the reference hybrid migration
// applied to the standing-consent grant, following the same pattern as
// packages/verify/revocation-v2.test.ts.
//
// Builds a REAL Ed25519 + ML-DSA-65 signed v2 grant, then asserts the
// fail-closed predicate. The hostile half is the point: leg stripping,
// required_algorithms narrowing, an Ed448 key masquerading as the Ed25519
// half, key substitution, a wrong-length signature, and a v1 verifier
// handed a v2 grant (and vice versa).
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import {
  CONSENT_GRANT_VERSION,
  buildConsentGrant,
  verifyConsentGrant,
  CONSENT_GRANT_V2_VERSION,
  CONSENT_GRANT_V2_REQUIRED_ALGORITHMS,
  computeGrantHashV2,
  buildConsentGrantV2,
  verifyConsentGrantV2,
  verifyConsentGrantStatement,
} from '../packages/verify/src/consent-grant.ts';
import { canonicalize } from '../packages/verify/src/index.ts';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const GRANT_ID = 'grant_v2_test_1';
const PRINCIPAL = 'principal:alice';
const ASSET = 'asset:acct-123';
const VERB = 'control:transfer';
const ISSUED_AT = '2026-06-01T00:00:00.000Z';
const EXPIRES_AT = '2026-12-01T00:00:00.000Z';
const NOW = '2026-08-17T12:00:00.000Z';

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');

const SIGNER = { privateKey: ed.privateKey, pqSecretKey: pq.secretKey, pqPublicKeyB64u: pq.publicKey };
const PINS = { public_key: edPubB64u, pq_public_key: pqPubB64u };

const SPEC = {
  grant_id: GRANT_ID,
  principal: PRINCIPAL,
  asset: ASSET,
  control_verb: VERB,
  issued_at: ISSUED_AT,
  expires_at: EXPIRES_AT,
};

const build = (specOverrides = {}, signer = SIGNER) => buildConsentGrantV2({ ...SPEC, ...specOverrides }, signer);

/** A real, valid EP-REVOCATION-v1 statement over the grant's grant_hash, built
 * without importing the revocation module -- same shape the offline verifier
 * (composed inside consent-grant.ts) accepts. */
function buildV1RevocationFor(grant: any, revokerKeyPair: crypto.KeyPairSyncResult<string, string> | crypto.KeyPairKeyObjectResult, revokerId: string) {
  const revokerPubB64u = revokerKeyPair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
  const fields = {
    '@version': 'EP-REVOCATION-v1',
    target_type: 'commit',
    target_id: grant.grant_id,
    action_hash: grant.grant_hash,
    revoker_id: revokerId,
    revoked_at: '2026-07-01T00:00:00.000Z',
    reason: 'authority withdrawn',
  };
  const sig = crypto.sign(null, Buffer.from(canonicalize(fields), 'utf8'), revokerKeyPair.privateKey).toString('base64url');
  return {
    ...fields,
    proof: {
      algorithm: 'Ed25519',
      revoker_key_id: `ep:revoker-key:sha256:${crypto.createHash('sha256')
        .update(Buffer.from(revokerPubB64u, 'base64url')).digest('hex')}`,
      signature_b64u: sig,
      public_key: revokerPubB64u,
    },
  };
}

// --- honesty gate: the PQ leg must actually run -------------------------------

it('real ML-DSA-65 backend is available for this suite', () => {
  expect(typeof ml_dsa65?.sign).toBe('function');
});

// --- (a) happy path -------------------------------------------------------------

describe('valid v2 roundtrip', () => {
  it('builds then verifies clean, with the registered algorithm set in order', async () => {
    const grant = await build();
    expect(grant.profile).toBe(CONSENT_GRANT_V2_VERSION);
    expect(grant.required_algorithms).toEqual([...CONSENT_GRANT_V2_REQUIRED_ALGORITHMS]);
    expect(grant.signatures.map((s: any) => s.alg)).toEqual([...CONSENT_GRANT_V2_REQUIRED_ALGORITHMS]);
    expect(computeGrantHashV2(grant)).toBe(grant.grant_hash);

    const res = await verifyConsentGrantV2(grant, PINS, { now: NOW });
    expect(res.valid).toBe(true);
    expect(res.errors).toEqual([]);
    expect(res.checks.signature_set_valid).toBe(true);
  });

  it('both legs sign the SAME bytes, and those bytes carry the algorithm set', async () => {
    const grant = await build();
    const { grant_hash, signatures, ...rest } = grant;
    const bytes = Buffer.from(canonicalize({ ...rest, required_algorithms: grant.required_algorithms }), 'utf8');
    expect(bytes.toString('utf8')).toContain('"required_algorithms":["Ed25519","ML-DSA-65"]');
    const edLeg = signatures.find((s: any) => s.alg === 'Ed25519');
    const pqLeg = signatures.find((s: any) => s.alg === 'ML-DSA-65');
    expect(crypto.verify(null, bytes, ed.publicKey, Buffer.from(edLeg.sig, 'base64url'))).toBe(true);
    expect(ml_dsa65.verify(
      new Uint8Array(Buffer.from(pqLeg.sig, 'base64url')), new Uint8Array(bytes), pq.publicKey,
    )).toBe(true);
  });
});

// --- (b) v1 / v2 coexistence -----------------------------------------------------

describe('v1 / v2 coexistence', () => {
  it('the v1 verifier refuses a v2 grant CLEANLY on the profile marker (no throw)', async () => {
    const grant = await build();
    let res: any;
    expect(() => { res = verifyConsentGrant(grant, edPubB64u, { now: NOW }); }).not.toThrow();
    expect(res.valid).toBe(false);
    expect(res.reason).toMatch(/unsupported profile/);
    // v1's early guard returns before touching any v2-only field, so it never
    // reaches a signature check on the (v2-shaped) signatures array.
    expect(res.checks).toEqual({ hash: false, signature: false, within_window: false });
  });

  it('a v1 grant still round-trips unchanged through the unmodified v1 builder + verifier', () => {
    const v1Grant = buildConsentGrant(SPEC, ed.privateKey);
    expect(v1Grant.profile).toBe(CONSENT_GRANT_VERSION);
    expect(typeof v1Grant.signature).toBe('string');
    const res = verifyConsentGrant(v1Grant, edPubB64u, { now: NOW });
    expect(res.valid).toBe(true);
  });

  it('the v2 verifier refuses a v1 grant on the version marker', async () => {
    const v1Grant = buildConsentGrant(SPEC, ed.privateKey);
    const res = await verifyConsentGrantV2(v1Grant, PINS, { now: NOW });
    expect(res.valid).toBe(false);
    expect(res.checks.version).toBe(false);
    expect(res.errors.some((e) => /unsupported profile/.test(e))).toBe(true);
  });

  it('verifyConsentGrantStatement routes each profile to its own verifier', async () => {
    const v2Grant = await build();
    const v1Grant = buildConsentGrant(SPEC, ed.privateKey);
    expect((await verifyConsentGrantStatement(v2Grant, PINS, { now: NOW })).valid).toBe(true);
    expect((await verifyConsentGrantStatement(v1Grant, edPubB64u, { now: NOW })).valid).toBe(true);
  });
});

// --- (c) stripped leg + narrowed set (attacker tries to look self-consistent) ---

describe('anti-stripping', () => {
  it('LEG STRIPPING + SET NARROWING TOGETHER: refuses on algorithm_set, legs_present, hash, and signature_set_valid', async () => {
    const grant = await build();
    const tampered = {
      ...grant,
      required_algorithms: ['Ed25519'],
      signatures: grant.signatures.filter((s: any) => s.alg === 'Ed25519'),
    };
    const res = await verifyConsentGrantV2(tampered, PINS, { now: NOW });
    expect(res.valid).toBe(false);
    expect(res.checks.algorithm_set).toBe(false);
    expect(res.checks.legs_present).toBe(false);
    expect(res.checks.hash).toBe(false);
    expect(res.checks.signature_set_valid).toBe(false);
  });

  it('LEG STRIPPING alone (set left intact) refuses structurally on legs_present', async () => {
    const grant = await build();
    const tampered = { ...grant, signatures: grant.signatures.filter((s: any) => s.alg === 'Ed25519') };
    const res = await verifyConsentGrantV2(tampered, PINS, { now: NOW });
    expect(res.valid).toBe(false);
    expect(res.checks.legs_present).toBe(false);
    expect(res.checks.algorithm_set).toBe(true);
  });

  it('SET NARROWING alone (signatures untouched) refuses structurally, and bytes can never be recomputed to match', async () => {
    const grant = await build();
    const tampered = { ...grant, required_algorithms: ['Ed25519'] };
    const res = await verifyConsentGrantV2(tampered, PINS, { now: NOW });
    expect(res.valid).toBe(false);
    expect(res.checks.algorithm_set).toBe(false);
    expect(res.checks.hash).toBe(false);
    expect(res.checks.signature_set_valid).toBe(false);

    // Illustrative cryptographic proof, independent of the verifier: the
    // genuine Ed25519 signature was made over bytes committing to the FULL
    // registered set. It does not verify over bytes recomputed with the
    // narrowed set either -- there is no honest way to make the narrowed
    // presentation look self-consistent.
    const { grant_hash: _gh, signatures: _sigs, ...rest } = grant;
    const narrowedBytes = Buffer.from(canonicalize({ ...rest, required_algorithms: ['Ed25519'] }), 'utf8');
    const edLeg = grant.signatures.find((s: any) => s.alg === 'Ed25519');
    expect(crypto.verify(null, narrowedBytes, ed.publicKey, Buffer.from(edLeg.sig, 'base64url'))).toBe(false);
  });

  it('SET WIDENING refuses on algorithm_set', async () => {
    const grant = await build();
    const tampered = { ...grant, required_algorithms: ['Ed25519', 'ML-DSA-65', 'Ed448'] };
    const res = await verifyConsentGrantV2(tampered, PINS, { now: NOW });
    expect(res.valid).toBe(false);
    expect(res.checks.algorithm_set).toBe(false);
  });

  it('DUPLICATE ALGORITHM entries refuse on legs_present', async () => {
    const grant = await build();
    const tampered = { ...grant, signatures: [grant.signatures[0], grant.signatures[0]] };
    const res = await verifyConsentGrantV2(tampered, PINS, { now: NOW });
    expect(res.valid).toBe(false);
    expect(res.checks.legs_present).toBe(false);
    expect(res.errors.some((e) => /duplicate signature/.test(e))).toBe(true);
  });
});

// --- (e) wrong-length signature ---------------------------------------------------

it('WRONG-LENGTH SIGNATURE: a truncated ML-DSA-65 sig refuses via malformed_signature, never throws', async () => {
  const grant = await build();
  const tampered = {
    ...grant,
    signatures: grant.signatures.map((s: any) => (s.alg === 'ML-DSA-65'
      ? { ...s, sig: Buffer.from(s.sig, 'base64url').subarray(0, 100).toString('base64url') }
      : s)),
  };
  const res = await verifyConsentGrantV2(tampered, PINS, { now: NOW });
  expect(res.valid).toBe(false);
  expect(res.checks.signature_set_valid).toBe(false);
  expect(res.errors.some((e) => /malformed_signature/.test(e))).toBe(true);
});

// --- (f) Ed448 masquerade ---------------------------------------------------------

it('ED448 MASQUERADE: an Ed448 SPKI pinned as the Ed25519 half refuses, never silently accepted', async () => {
  const ed448 = crypto.generateKeyPairSync('ed448');
  const ed448PubB64u = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
  const grant = await build();
  const res = await verifyConsentGrantV2(grant, { public_key: ed448PubB64u, pq_public_key: pqPubB64u }, { now: NOW });
  expect(res.valid).toBe(false);
  expect(res.checks.signature_set_valid).toBe(false);
  expect(res.errors.some((e) => /malformed_key|algorithm_key_mismatch/.test(e))).toBe(true);
});

// --- (g) key substitution ---------------------------------------------------------

describe('key substitution / pinning', () => {
  it('pinning a different principal (both halves swapped) refuses', async () => {
    const grant = await build();
    const otherEd = crypto.generateKeyPairSync('ed25519');
    const otherEdPubB64u = otherEd.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const otherPq = ml_dsa65.keygen(crypto.randomBytes(32));
    const otherPqPubB64u = Buffer.from(otherPq.publicKey).toString('base64url');
    const res = await verifyConsentGrantV2(
      grant, { public_key: otherEdPubB64u, pq_public_key: otherPqPubB64u }, { now: NOW },
    );
    expect(res.valid).toBe(false);
    expect(res.checks.signature_set_valid).toBe(false);
  });

  it('an unpinned principal (no keys at all) refuses on key_pinned', async () => {
    const grant = await build();
    const res = await verifyConsentGrantV2(grant, undefined, { now: NOW });
    expect(res.valid).toBe(false);
    expect(res.checks.key_pinned).toBe(false);
  });

  it('pinning only the Ed25519 half (PQ half missing) refuses (both halves required)', async () => {
    const grant = await build();
    const res = await verifyConsentGrantV2(grant, { public_key: edPubB64u }, { now: NOW });
    expect(res.valid).toBe(false);
    expect(res.checks.key_pinned).toBe(false);
  });

  it('PQ KEY SUBSTITUTION alone: a different pinned ML-DSA key refuses', async () => {
    const grant = await build();
    const other = ml_dsa65.keygen(crypto.randomBytes(32));
    const res = await verifyConsentGrantV2(
      grant, { public_key: edPubB64u, pq_public_key: Buffer.from(other.publicKey).toString('base64url') }, { now: NOW },
    );
    expect(res.valid).toBe(false);
    expect(res.checks.signature_set_valid).toBe(false);
  });
});

// --- window + revocation composition ----------------------------------------------

describe('window and revocation', () => {
  it('an expired v2 grant refuses on within_window', async () => {
    const grant = await build();
    const res = await verifyConsentGrantV2(grant, PINS, { now: '2027-01-01T00:00:00.000Z' });
    expect(res.valid).toBe(false);
    expect(res.checks.within_window).toBe(false);
  });

  it('a v2 grant not yet valid refuses on within_window', async () => {
    const grant = await build();
    const res = await verifyConsentGrantV2(grant, PINS, { now: '2026-01-01T00:00:00.000Z' });
    expect(res.valid).toBe(false);
    expect(res.checks.within_window).toBe(false);
  });

  it('a valid v1 revocation statement against the grant_hash makes the v2 grant refuse as revoked (v1 revocation stays valid evidence against a v2 grant)', async () => {
    const grant = await build();
    const revokerEd = crypto.generateKeyPairSync('ed25519');
    const revokerPubB64u = revokerEd.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const revocation = buildV1RevocationFor(grant, revokerEd, 'ep:revoker:consent_v2_test');
    const res = await verifyConsentGrantV2(grant, PINS, {
      now: NOW,
      revocation,
      revokerKeys: { 'ep:revoker:consent_v2_test': { public_key: revokerPubB64u } },
    });
    expect(res.valid).toBe(false);
    expect(res.checks.revocation).toBe(false);
    expect(res.errors).toContain('grant_revoked');
  });

  it('a malformed / unpinned revocation statement refuses as revocation_invalid, not silently ignored', async () => {
    const grant = await build();
    const res = await verifyConsentGrantV2(grant, PINS, {
      now: NOW,
      revocation: { '@version': 'EP-REVOCATION-v1', junk: true },
      revokerKeys: {},
    });
    expect(res.valid).toBe(false);
    expect(res.checks.revocation).toBe(false);
    expect(res.errors).toContain('revocation_invalid');
  });
});

// --- fail-closed backend + junk ----------------------------------------------------

describe('fail-closed backend and malformed input', () => {
  it('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const grant = await build();
    const res = await verifyConsentGrantV2(grant, PINS, { now: NOW, mldsaBackendLoader: async () => null });
    expect(res.valid).toBe(false);
    expect(res.checks.signature_set_valid).toBe(false);
    expect(res.errors.some((e) => /pq_backend_unavailable/.test(e))).toBe(true);
  });

  it('malformed grant input refuses without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
      const res = await verifyConsentGrantV2(junk as any, PINS, { now: NOW });
      expect(res.valid).toBe(false);
    }
  });
});

// --- builder honesty gate ----------------------------------------------------------

describe('buildConsentGrantV2 honesty gate', () => {
  it('refuses a signer missing either PQ half', async () => {
    await expect(build({}, { privateKey: ed.privateKey } as any)).rejects.toThrow(/pqSecretKey/);
    await expect(build({}, { ...SIGNER, pqPublicKeyB64u: new Uint8Array(10) } as any)).rejects.toThrow(/1952/);
    await expect(build({}, { ...SIGNER, pqSecretKey: new Uint8Array(10) } as any)).rejects.toThrow(/4032/);
  });

  it('refuses a malformed grant (missing asset/control_verb, or a bad window)', async () => {
    await expect(build({ asset: undefined } as any)).rejects.toThrow(/asset/);
    await expect(build({ issued_at: 'not-a-date' } as any)).rejects.toThrow(/RFC-3339/);
    await expect(build({ issued_at: EXPIRES_AT, expires_at: ISSUED_AT } as any)).rejects.toThrow(/empty validity window/);
  });
});
