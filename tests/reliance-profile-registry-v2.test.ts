// SPDX-License-Identifier: Apache-2.0
//
// EP-RELIANCE-PROFILE-REGISTRY-v2 hybrid registry-entry test: the reference
// hybrid migration applied to the reliance profile registry.
//
// Mints a REAL Ed25519 + ML-DSA-65 signed registry entry, then asserts the
// fail-closed predicate. The hostile half is the point: leg stripping, set
// narrowing, an Ed448 key masquerading as the Ed25519 half, a wrong-length
// signature, entry_digest tampering, and a v1 verifier handed a v2 entry.
//
// The PQ leg runs for real. This suite fails loudly if @noble/post-quantum is
// missing rather than silently skipping, so a green run means ML-DSA-65
// actually verified.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  PROFILE_REGISTRY_VERSION,
  signRelianceProfileEntry,
  verifyRelianceProfileEntry,
  PROFILE_REGISTRY_V2_VERSION,
  PROFILE_REGISTRY_V2_REQUIRED_ALGORITHMS,
  entrySigningBytesV2,
  profileRegistryEntryDigestV2,
  signRelianceProfileEntryV2,
  verifyRelianceProfileEntryV2,
  verifyRelianceProfileEntryStatement,
} from '../packages/verify/src/reliance-profile-registry.ts';
import { canonicalize } from '../packages/verify/src/index.ts';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

// Minimal EP-RELIANCE-PROFILE-v1 that passes validateRelianceProfile (same
// shape as public/schemas/reliance-profiles/ncpdp-specialty-pa.v1.json).
const PROFILE = {
  '@type': 'EP-RELIANCE-PROFILE-v1',
  required_assurance: 'class_a',
  required_authority: true,
  max_revocation_staleness_sec: 3600,
  accepted_registry_keys: [],
  accepted_issuer_keys: [],
  accepted_policy_hashes: [],
  required_evidence: ['receipt', 'class_a_or_quorum', 'authority_proof', 'revocation_freshness', 'consumption_proof'],
};

const REGISTRY_ID = 'emilia-registrar';

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');

const SIGNER = {
  privateKey: ed.privateKey,
  pqSecretKey: pq.secretKey,
  pqPublicKeyB64u: pq.publicKey,
};

const PIN = { registry_id: REGISTRY_ID, public_key: edPubB64u, pq_public_key: pqPubB64u };
const PINNED = () => ({ pinnedRegistryKeys: [PIN] });

const build = (overrides: Record<string, unknown> = {}) => signRelianceProfileEntryV2({
  registry_id: REGISTRY_ID,
  profile_id: 'ncpdp.specialty-pa.v1',
  profile: PROFILE,
  registry_epoch: 3,
  issued_at: '2026-07-07T00:00:00.000Z',
  ...overrides,
}, SIGNER);

// --- honesty gate: the PQ leg must actually run ------------------------------

describe('honesty gate', () => {
  it('a real ML-DSA-65 backend is available for this suite', () => {
    expect(typeof ml_dsa65?.sign).toBe('function');
  });
});

// --- (a) happy path: valid v2 roundtrip --------------------------------------

describe('valid v2 roundtrip', () => {
  it('verifies and accepts when both key halves are pinned for the registry_id', async () => {
    const entry = await build();
    expect(entry['@type']).toBe(PROFILE_REGISTRY_V2_VERSION);
    expect(entry.proof.required_algorithms).toEqual([...PROFILE_REGISTRY_V2_REQUIRED_ALGORITHMS]);
    expect(entry.proof.signatures.map((s: { alg: string }) => s.alg)).toEqual([...PROFILE_REGISTRY_V2_REQUIRED_ALGORITHMS]);

    const res = await verifyRelianceProfileEntryV2(entry, PINNED());
    expect(res.verified).toBe(true);
    expect(res.accepted).toBe(true);
    expect(res.checks.algorithm_set).toBe(true);
    expect(res.checks.legs_present).toBe(true);
    expect(res.checks.signature_set_valid).toBe(true);
    expect(res.checks.pinned_registry_key).toBe(true);
    expect(res.entry_digest).toBe(profileRegistryEntryDigestV2(entry));
    expect(res.profile['@type']).toBe('EP-RELIANCE-PROFILE-v1');
    expect(Object.isFrozen(res.profile)).toBe(true);
  });

  it('both legs sign the SAME bytes, and those bytes carry the committed algorithm set (entrySigningBytesV2 exercised directly)', async () => {
    const entry = await build();
    expect(profileRegistryEntryDigestV2(entry)).toBe(entry.proof.entry_digest);

    const { proof: _proof, ...unsignedBody } = entry;
    const bytes = entrySigningBytesV2(unsignedBody);
    expect(bytes.toString('utf8')).toContain('"required_algorithms":["Ed25519","ML-DSA-65"]');
    expect(bytes.toString('utf8').startsWith('EP-RELIANCE-PROFILE-REGISTRY-v2\0')).toBe(true);

    const [edLeg, pqLeg] = entry.proof.signatures;
    expect(crypto.verify(null, bytes, ed.publicKey, Buffer.from(edLeg.sig, 'base64url'))).toBe(true);
    expect(ml_dsa65.verify(
      new Uint8Array(Buffer.from(pqLeg.sig, 'base64url')), new Uint8Array(bytes), pq.publicKey,
    )).toBe(true);
  });
});

// --- (b) v1/v2 non-interference ----------------------------------------------

describe('v1 / v2 non-interference', () => {
  it('the v1 verifier refuses a v2 entry CLEANLY, no throw', async () => {
    const entry = await build();
    let res: any;
    expect(() => { res = verifyRelianceProfileEntry(entry as any, PINNED() as any); }).not.toThrow();
    expect(res.verified).toBe(false);
    expect(res.accepted).toBe(false);
    expect(res.reason).toBe('unsupported_version');
  });

  it('a v1 entry still round-trips through the unmodified v1 verifier', () => {
    const registrarKey = crypto.generateKeyPairSync('ed25519').privateKey;
    const registrarPub = crypto.createPublicKey(registrarKey).export({ type: 'spki', format: 'der' }).toString('base64url');
    const entry = signRelianceProfileEntry({
      registry_id: REGISTRY_ID, profile_id: 'ncpdp.specialty-pa.v1', profile: PROFILE, registry_epoch: 3,
    }, registrarKey);
    expect(entry['@type']).toBe(PROFILE_REGISTRY_VERSION);
    const res = verifyRelianceProfileEntry(entry, { pinnedRegistryKeys: [{ registry_id: REGISTRY_ID, public_key: registrarPub }] });
    expect(res.verified).toBe(true);
    expect(res.accepted).toBe(true);
  });

  it('the v2 verifier refuses a v1 entry on the version marker', async () => {
    const registrarKey = crypto.generateKeyPairSync('ed25519').privateKey;
    const entry = signRelianceProfileEntry({
      registry_id: REGISTRY_ID, profile_id: 'ncpdp.specialty-pa.v1', profile: PROFILE, registry_epoch: 3,
    }, registrarKey);
    const res = await verifyRelianceProfileEntryV2(entry as any, PINNED());
    expect(res.verified).toBe(false);
    expect(res.reason).toBe('unsupported_version');
  });

  it('verifyRelianceProfileEntryStatement routes each version to its own verifier', async () => {
    const v2 = await build();
    const registrarKey = crypto.generateKeyPairSync('ed25519').privateKey;
    const registrarPub = crypto.createPublicKey(registrarKey).export({ type: 'spki', format: 'der' }).toString('base64url');
    const v1 = signRelianceProfileEntry({
      registry_id: REGISTRY_ID, profile_id: 'ncpdp.specialty-pa.v1', profile: PROFILE, registry_epoch: 3,
    }, registrarKey);
    expect((await verifyRelianceProfileEntryStatement(v2, PINNED())).accepted).toBe(true);
    expect((await verifyRelianceProfileEntryStatement(v1, { pinnedRegistryKeys: [{ registry_id: REGISTRY_ID, public_key: registrarPub }] })).accepted).toBe(true);
  });
});

// --- (c) stripped leg ---------------------------------------------------------

describe('leg stripping', () => {
  it('removing the ML-DSA-65 leg (set intact) refuses structurally', async () => {
    const entry = await build();
    entry.proof.signatures = entry.proof.signatures.filter((s: { alg: string }) => s.alg === 'Ed25519');
    const res = await verifyRelianceProfileEntryV2(entry, PINNED());
    expect(res.verified).toBe(false);
    expect(res.checks.legs_present).toBe(false);
  });

  it('removing the Ed25519 leg refuses too (neither leg alone suffices)', async () => {
    const entry = await build();
    entry.proof.signatures = entry.proof.signatures.filter((s: { alg: string }) => s.alg === 'ML-DSA-65');
    const res = await verifyRelianceProfileEntryV2(entry, PINNED());
    expect(res.verified).toBe(false);
    expect(res.checks.legs_present).toBe(false);
  });
});

// --- (d) narrowed set ----------------------------------------------------------

describe('set narrowing', () => {
  it('trimming required_algorithms (signatures left in place) refuses structurally, and the surviving Ed25519 signature no longer verifies', async () => {
    const entry = await build();
    const edSig = entry.proof.signatures.find((s: { alg: string }) => s.alg === 'Ed25519');

    entry.proof.required_algorithms = ['Ed25519'];
    const res = await verifyRelianceProfileEntryV2(entry, PINNED());
    expect(res.verified).toBe(false);
    expect(res.checks.algorithm_set).toBe(false);

    // Cryptographic half, proved independently: the surviving Ed25519
    // signature was made over bytes committing to the FULL set, so it cannot
    // verify over bytes rebuilt with the narrowed set.
    const narrowedBytes = Buffer.from(
      'EP-RELIANCE-PROFILE-REGISTRY-v2\0' + canonicalize({
        '@type': PROFILE_REGISTRY_V2_VERSION,
        registry_id: entry.registry_id,
        profile_id: entry.profile_id,
        registry_epoch: entry.registry_epoch,
        profile: entry.profile,
        profile_hash: entry.profile_hash,
        issued_at: entry.issued_at,
        required_algorithms: ['Ed25519'],
      }),
      'utf8',
    );
    expect(crypto.verify(null, narrowedBytes, ed.publicKey, Buffer.from(edSig.sig, 'base64url'))).toBe(false);
  });

  it('entrySigningBytesV2 itself refuses to build bytes over a non-registered set', () => {
    expect(() => entrySigningBytesV2({}, ['Ed25519'])).toThrow(/registered/);
  });
});

// --- (e) wrong-length signature ------------------------------------------------

describe('malformed signature', () => {
  it('a wrong-length Ed25519 signature refuses, no throw', async () => {
    const entry = await build();
    entry.proof.signatures = entry.proof.signatures.map((s: { alg: string; sig: string }) => (
      s.alg === 'Ed25519' ? { ...s, sig: Buffer.from('00'.repeat(10), 'hex').toString('base64url') } : s
    ));
    const res = await verifyRelianceProfileEntryV2(entry, PINNED());
    expect(res.verified).toBe(false);
    expect(res.checks.signature_set_valid).toBe(false);
  });
});

// --- (f) Ed448 masquerade ------------------------------------------------------

describe('curve masquerade', () => {
  it('an Ed448 key presented and pinned as the Ed25519 half is refused by the curve pin', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const entry = await build();
    entry.proof.public_key = ed448Pub;
    // key_id would now mismatch too (a second, independent refusal reason),
    // but the point of this test is the curve pin inside signature verification.
    const res = await verifyRelianceProfileEntryV2(entry, {
      pinnedRegistryKeys: [{ registry_id: REGISTRY_ID, public_key: ed448Pub, pq_public_key: pqPubB64u }],
    });
    expect(res.verified).toBe(false);
    expect(res.checks.signature_set_valid).toBe(false);
  });
});

// --- (g) verified but not accepted ---------------------------------------------

describe('verified but not accepted', () => {
  it('both signatures hold but the registrar key is not pinned at all', async () => {
    const entry = await build();
    const res = await verifyRelianceProfileEntryV2(entry, { pinnedRegistryKeys: [] });
    expect(res.verified).toBe(true);
    expect(res.accepted).toBe(false);
    expect(res.reason).toBe('registry_key_not_pinned');
  });

  it('both signatures hold but the pin is registered for a different registry_id', async () => {
    const entry = await build();
    const res = await verifyRelianceProfileEntryV2(entry, {
      pinnedRegistryKeys: [{ registry_id: 'attacker-registry', public_key: edPubB64u, pq_public_key: pqPubB64u }],
    });
    expect(res.verified).toBe(true);
    expect(res.accepted).toBe(false);
    expect(res.reason).toBe('pin_missing_or_mismatched_registry_id');
  });
});

// --- (h) entry_digest mismatch --------------------------------------------------

describe('entry_digest tampering', () => {
  it('a field edited after signing (entry_digest left stale) refuses', async () => {
    const entry = await build();
    entry.issued_at = '2099-01-01T00:00:00.000Z'; // tampered after signing
    const res = await verifyRelianceProfileEntryV2(entry, PINNED());
    expect(res.verified).toBe(false);
    expect(res.reason).toBe('entry_digest_mismatch');
  });

  it('an entry_digest hand-edited to a bogus value also refuses', async () => {
    const entry = await build();
    entry.proof.entry_digest = `sha256:${'0'.repeat(64)}`;
    const res = await verifyRelianceProfileEntryV2(entry, PINNED());
    expect(res.verified).toBe(false);
    expect(res.reason).toBe('entry_digest_mismatch');
  });
});

// --- fail-closed on junk / missing backend --------------------------------------

describe('fail-closed on junk input', () => {
  it('malformed entries refuse without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
      const res = await verifyRelianceProfileEntryV2(junk as any, PINNED());
      expect(res.verified).toBe(false);
    }
  });

  it('a missing pq_public_key refuses cleanly', async () => {
    const entry = await build();
    delete (entry.proof as any).pq_public_key;
    const res = await verifyRelianceProfileEntryV2(entry, PINNED());
    expect(res.verified).toBe(false);
  });
});

describe('no ML-DSA backend', () => {
  it('an unavailable ML-DSA backend is a refusal, never a pass on the Ed25519 leg', async () => {
    const entry = await build();
    const res = await verifyRelianceProfileEntryV2(entry, { ...PINNED(), mldsaBackendLoader: async () => null });
    expect(res.verified).toBe(false);
    expect(res.checks.signature_set_valid).toBe(false);
  });
});

// --- issuer-side honesty gate ---------------------------------------------------

describe('signRelianceProfileEntryV2 honesty gate', () => {
  it('refuses an invalid inner profile', async () => {
    await expect(signRelianceProfileEntryV2({
      registry_id: REGISTRY_ID, profile_id: 'x', profile: { '@type': 'nope' }, registry_epoch: 1,
    }, SIGNER)).rejects.toThrow(/invalid inner profile/);
  });

  it('refuses a missing registry_id / profile_id', async () => {
    await expect(signRelianceProfileEntryV2({
      registry_id: '', profile_id: 'x', profile: PROFILE, registry_epoch: 1,
    }, SIGNER)).rejects.toThrow(/registry_id/);
    await expect(signRelianceProfileEntryV2({
      registry_id: REGISTRY_ID, profile_id: '', profile: PROFILE, registry_epoch: 1,
    }, SIGNER)).rejects.toThrow(/profile_id/);
  });

  it('refuses a signer missing PQ key material rather than emit a half-hybrid entry', async () => {
    await expect(signRelianceProfileEntryV2({
      registry_id: REGISTRY_ID, profile_id: 'x', profile: PROFILE, registry_epoch: 1,
    }, { privateKey: ed.privateKey } as any)).rejects.toThrow(/pqSecretKey/);
  });

  it('refuses PQ key material of the wrong length', async () => {
    await expect(signRelianceProfileEntryV2({
      registry_id: REGISTRY_ID, profile_id: 'x', profile: PROFILE, registry_epoch: 1,
    }, { ...SIGNER, pqPublicKeyB64u: new Uint8Array(10) })).rejects.toThrow(/1952/);
  });
});
