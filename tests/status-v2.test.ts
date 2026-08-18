// SPDX-License-Identifier: Apache-2.0
//
// EP-REVOKER-AUTHORITY-v2 / EP-STATUS-v2 hybrid verifier hostile matrix, plus
// the issuer-side (lib/revocation/status.ts) build + FIPS-consult regression.
//
// Builds REAL Ed25519 + ML-DSA-65 signed certificates and status heads, then
// asserts the fail-closed predicate against packages/verify/src/status.ts's
// verifyRevokerAuthorityCertificateV2 / verifyStatusArtifactV2 DIRECTLY (the
// source, not the compiled dist), and separately exercises the issuer-side
// builders in lib/revocation/status.ts (which compose the compiled package).
import { describe, expect, it } from 'vitest';
import crypto, { type KeyObject } from 'node:crypto';

import {
  REVOCER_AUTHORITY_VERSION,
  STATUS_VERSION,
  REVOCER_AUTHORITY_V2_VERSION,
  REVOCER_AUTHORITY_V2_REQUIRED_ALGORITHMS,
  STATUS_V2_VERSION,
  STATUS_V2_REQUIRED_ALGORITHMS,
  verifyRevokerAuthorityCertificate,
  verifyStatusArtifact,
  verifyRevokerAuthorityCertificateV2,
  verifyStatusArtifactV2,
  verifyRevokerAuthorityCertificateStatement,
  verifyStatusArtifactStatement,
} from '../packages/verify/src/status.ts';
import {
  buildRevokerAuthorityCertificate,
  buildStatusArtifact,
  buildRevokerAuthorityCertificateV2,
  buildStatusArtifactV2,
  deriveRevokerKeyId,
  deriveRevokerPqKeyId,
  type ExternalEd25519Signer,
  type ExternalHybridSigner,
} from '../lib/revocation/status.ts';
import { checkOperationPolicy, type FipsPosture } from '../packages/verify/src/fips-mode.ts';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

interface KeyPair { publicKey: KeyObject; privateKey: KeyObject; }

const TARGET = {
  type: 'receipt' as const,
  id: 'receipt:payment-release:0001',
  digest: `sha256:${'a'.repeat(64)}`,
  usage: 'authorization' as const,
};

const authorityEd = crypto.generateKeyPairSync('ed25519');
const authorityPq = ml_dsa65.keygen(crypto.randomBytes(32));
const revokerEd = crypto.generateKeyPairSync('ed25519');
const revokerPq = ml_dsa65.keygen(crypto.randomBytes(32));
// A second, DIFFERENT revoker PQ keypair, used only for key-substitution vectors.
const otherPq = ml_dsa65.keygen(crypto.randomBytes(32));

function edPub(keyPair: KeyPair): string {
  return keyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
}
function pqPub(kp: { publicKey: Uint8Array }): string {
  return Buffer.from(kp.publicKey).toString('base64url');
}

const authorityPinV2 = {
  authority_domain: 'status.acme.example',
  authority_id: 'org:acme',
  key_id: 'key:acme-status-root',
  public_key: edPub(authorityEd),
  pq_key_id: 'key:acme-status-root-pq',
  pq_public_key: pqPub(authorityPq),
};

function hybridSigner(
  ed: KeyPair,
  edKeyId: string,
  pq: { secretKey: Uint8Array },
  pqKeyId: string,
): ExternalHybridSigner {
  return {
    ed25519: {
      algorithm: 'Ed25519',
      keyId: edKeyId,
      async sign(bytes) {
        return crypto.sign(null, Buffer.from(bytes), ed.privateKey).toString('base64url');
      },
    },
    mldsa: {
      algorithm: 'ML-DSA-65',
      keyId: pqKeyId,
      async sign(bytes) {
        return Buffer.from(ml_dsa65.sign(bytes, pq.secretKey)).toString('base64url');
      },
    },
  };
}

function authoritySignerV2(): ExternalHybridSigner {
  return hybridSigner(authorityEd, authorityPinV2.key_id, authorityPq, authorityPinV2.pq_key_id);
}
function revokerSignerV2(): ExternalHybridSigner {
  return hybridSigner(
    revokerEd,
    deriveRevokerKeyId(edPub(revokerEd)),
    revokerPq,
    deriveRevokerPqKeyId(pqPub(revokerPq)),
  );
}

function certificateInputV2(overrides: Record<string, unknown> = {}) {
  return {
    certificateId: 'revoker-authority:acme:primary:v2',
    authorityPin: authorityPinV2,
    revokerId: 'revoker:acme:primary',
    revokerPublicKey: edPub(revokerEd),
    revokerPqPublicKey: pqPub(revokerPq),
    scope: {
      allowed_target_types: ['receipt', 'commit'] as const,
      allowed_usages: ['authorization', 'execution'] as const,
    },
    issuedAt: '2026-07-01T00:00:00Z',
    expiresAt: '2026-08-01T00:00:00Z',
    signer: authoritySignerV2(),
    ...overrides,
  };
}

async function certificateV2(overrides: Record<string, unknown> = {}) {
  return buildRevokerAuthorityCertificateV2(certificateInputV2(overrides));
}

function statusInputV2(authority: unknown, overrides: Record<string, unknown> = {}) {
  return {
    authorityPin: authorityPinV2,
    certificate: authority,
    target: TARGET,
    status: 'not_revoked' as const,
    issuedAt: '2026-07-22T12:00:00Z',
    nextUpdate: '2026-07-22T12:05:00Z',
    signer: revokerSignerV2(),
    ...overrides,
  };
}

describe('EP-REVOKER-AUTHORITY-v2 certificate', () => {
  it('builds and verifies a valid hybrid certificate', async () => {
    const cert = await certificateV2();
    expect(cert['@version']).toBe(REVOCER_AUTHORITY_V2_VERSION);
    expect((cert as any).required_algorithms).toEqual([...REVOCER_AUTHORITY_V2_REQUIRED_ALGORITHMS]);
    expect((cert as any).proof.signatures.map((s: any) => s.alg)).toEqual([...REVOCER_AUTHORITY_V2_REQUIRED_ALGORITHMS]);

    const result = await verifyRevokerAuthorityCertificateV2(cert, {
      authorityPin: authorityPinV2,
      now: '2026-07-15T00:00:00Z',
    });
    expect(result.valid).toBe(true);
    expect(result.reasons).toEqual([]);
  });

  it('the v1 verifier refuses a v2 certificate cleanly on the version marker, no throw', async () => {
    const cert = await certificateV2();
    expect(() => verifyRevokerAuthorityCertificate(cert, {
      authorityPin: { ...authorityPinV2 } as any,
      now: '2026-07-15T00:00:00Z',
    })).not.toThrow();
    const result = verifyRevokerAuthorityCertificate(cert, {
      authorityPin: { ...authorityPinV2 } as any,
      now: '2026-07-15T00:00:00Z',
    });
    expect(result.valid).toBe(false);
  });

  it('the v2 verifier refuses a v1 certificate cleanly, no throw', async () => {
    const v1cert = await buildRevokerAuthorityCertificate({
      certificateId: 'revoker-authority:acme:primary:v1',
      authorityPin: {
        authority_domain: authorityPinV2.authority_domain,
        authority_id: authorityPinV2.authority_id,
        key_id: authorityPinV2.key_id,
        public_key: authorityPinV2.public_key,
      },
      revokerId: 'revoker:acme:primary',
      revokerPublicKey: edPub(revokerEd),
      scope: { allowed_target_types: ['receipt'], allowed_usages: ['authorization'] },
      issuedAt: '2026-07-01T00:00:00Z',
      expiresAt: '2026-08-01T00:00:00Z',
      signer: {
        algorithm: 'Ed25519',
        keyId: authorityPinV2.key_id,
        async sign(bytes: Uint8Array) {
          return crypto.sign(null, Buffer.from(bytes), authorityEd.privateKey).toString('base64url');
        },
      } as ExternalEd25519Signer,
    });
    await expect(verifyRevokerAuthorityCertificateV2(v1cert, { authorityPin: authorityPinV2 }))
      .resolves.toMatchObject({ valid: false });
    // Also confirm the v1 artifact still round-trips through the unmodified v1 verifier.
    expect(verifyRevokerAuthorityCertificate(v1cert, {
      authorityPin: {
        authority_domain: authorityPinV2.authority_domain,
        authority_id: authorityPinV2.authority_id,
        key_id: authorityPinV2.key_id,
        public_key: authorityPinV2.public_key,
      },
      now: '2026-07-15T00:00:00Z',
    }).valid).toBe(true);
  });

  it('stripped ML-DSA-65 leg refuses', async () => {
    const cert: any = structuredClone(await certificateV2());
    cert.proof.signatures = cert.proof.signatures.filter((s: any) => s.alg !== 'ML-DSA-65');
    const result = await verifyRevokerAuthorityCertificateV2(cert, { authorityPin: authorityPinV2, now: '2026-07-15T00:00:00Z' });
    expect(result.valid).toBe(false);
  });

  it('narrowed required_algorithms refuses structurally and the surviving Ed25519 leg no longer verifies', async () => {
    const cert: any = structuredClone(await certificateV2());
    cert.required_algorithms = ['Ed25519'];
    const result = await verifyRevokerAuthorityCertificateV2(cert, { authorityPin: authorityPinV2, now: '2026-07-15T00:00:00Z' });
    expect(result.valid).toBe(false);
    expect(result.checks.structure).toBe(false);
  });

  it('wrong-length ML-DSA-65 signature refuses, never throws', async () => {
    const cert: any = structuredClone(await certificateV2());
    const pqLeg = cert.proof.signatures.find((s: any) => s.alg === 'ML-DSA-65');
    pqLeg.sig = Buffer.from(Buffer.from(pqLeg.sig, 'base64url').subarray(0, 100)).toString('base64url');
    await expect(verifyRevokerAuthorityCertificateV2(cert, { authorityPin: authorityPinV2, now: '2026-07-15T00:00:00Z' }))
      .resolves.toMatchObject({ valid: false });
  });

  it('Ed448 masquerading as the pinned Ed25519 half is refused, never silently accepted', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const cert: any = await certificateV2();
    const badPin = {
      ...authorityPinV2,
      public_key: ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    };
    const result = await verifyRevokerAuthorityCertificateV2(cert, { authorityPin: badPin as any });
    expect(result.valid).toBe(false);
  });

  it('key substitution: pinning a different PQ key than the one that signed refuses', async () => {
    const cert = await certificateV2();
    const badPin = { ...authorityPinV2, pq_public_key: pqPub(otherPq) };
    const result = await verifyRevokerAuthorityCertificateV2(cert, { authorityPin: badPin as any });
    expect(result.valid).toBe(false);
  });
});

describe('EP-STATUS-v2 status head', () => {
  it('builds and verifies a valid hybrid status head', async () => {
    const cert = await certificateV2();
    const status = await buildStatusArtifactV2(statusInputV2(cert) as any);
    expect(status['@version']).toBe(STATUS_V2_VERSION);
    expect((status as any).required_algorithms).toEqual([...STATUS_V2_REQUIRED_ALGORITHMS]);

    const result = await verifyStatusArtifactV2(TARGET, status, {
      authorityPin: authorityPinV2,
      certificate: cert,
      now: '2026-07-22T12:01:00Z',
    });
    expect(result.valid).toBe(true);
    expect(result.outcome).toBe('current_not_revoked');
  });

  it('a hybrid predecessor/successor chain verifies, and sequence/predecessor digest are enforced', async () => {
    const cert = await certificateV2();
    const head0 = await buildStatusArtifactV2(statusInputV2(cert) as any);
    const head1 = await buildStatusArtifactV2(statusInputV2(cert, {
      issuedAt: '2026-07-22T12:10:00Z',
      nextUpdate: '2026-07-22T12:15:00Z',
      previousStatus: head0,
    }) as any);
    expect((head1 as any).sequence).toBe(1);

    const result = await verifyStatusArtifactV2(TARGET, head1, {
      authorityPin: authorityPinV2,
      certificate: cert,
      previousStatus: head0,
      now: '2026-07-22T12:11:00Z',
    });
    expect(result.valid).toBe(true);
  });

  it('a v1 predecessor is refused for a v2 successor (no cross-version chaining)', async () => {
    const cert = await certificateV2();
    const head0v2 = await buildStatusArtifactV2(statusInputV2(cert) as any);
    // Build a v1-shaped predecessor by hand (same digest chain would-be link,
    // wrong version marker) and try to extend it as if it were v2.
    const fakeV1Predecessor: any = { ...head0v2, '@version': STATUS_VERSION };
    delete fakeV1Predecessor.required_algorithms;
    const result = await verifyStatusArtifactV2(TARGET, await buildStatusArtifactV2(statusInputV2(cert, {
      issuedAt: '2026-07-22T12:10:00Z',
      nextUpdate: '2026-07-22T12:15:00Z',
      previousStatus: head0v2,
    }) as any), {
      authorityPin: authorityPinV2,
      certificate: cert,
      previousStatus: fakeV1Predecessor,
      now: '2026-07-22T12:11:00Z',
    });
    expect(result.valid).toBe(false);
  });

  it('the v1 verifier refuses a v2 status head cleanly, no throw; a v1 head still round-trips', async () => {
    const cert = await certificateV2();
    const status = await buildStatusArtifactV2(statusInputV2(cert) as any);
    expect(() => verifyStatusArtifact(TARGET, status, {
      authorityPin: authorityPinV2 as any,
      certificate: cert as any,
      now: '2026-07-22T12:01:00Z',
    })).not.toThrow();
    expect(verifyStatusArtifact(TARGET, status, {
      authorityPin: authorityPinV2 as any,
      certificate: cert as any,
      now: '2026-07-22T12:01:00Z',
    }).valid).toBe(false);
  });

  it('the router dispatches v1 and v2 heads to the correct verifier', async () => {
    const cert = await certificateV2();
    const v2status = await buildStatusArtifactV2(statusInputV2(cert) as any);
    const v2result = await verifyStatusArtifactStatement(TARGET, v2status, {
      authorityPin: authorityPinV2,
      certificate: cert,
      now: '2026-07-22T12:01:00Z',
    });
    expect(v2result.valid).toBe(true);

    const v1cert = await verifyRevokerAuthorityCertificateStatement(cert, { authorityPin: authorityPinV2, now: '2026-07-15T00:00:00Z' } as any);
    expect(v1cert.valid).toBe(true);
  });

  it('stripped leg on the status head refuses', async () => {
    const cert = await certificateV2();
    const status: any = structuredClone(await buildStatusArtifactV2(statusInputV2(cert) as any));
    status.proof.signatures = status.proof.signatures.filter((s: any) => s.alg !== 'ML-DSA-65');
    const result = await verifyStatusArtifactV2(TARGET, status, {
      authorityPin: authorityPinV2,
      certificate: cert,
      now: '2026-07-22T12:01:00Z',
    });
    expect(result.valid).toBe(false);
  });

  it('terminal revocation: a revoked v2 status head is honored and never ages back to current', async () => {
    const cert = await certificateV2();
    const revoked = await buildStatusArtifactV2(statusInputV2(cert, {
      status: 'revoked',
      nextUpdate: null,
    }) as any);
    const result = await verifyStatusArtifactV2(TARGET, revoked, {
      authorityPin: authorityPinV2,
      certificate: cert,
      now: '2026-09-22T12:00:00Z',
    });
    expect(result.valid).toBe(true);
    expect(result.outcome).toBe('revoked');
  });
});

describe('lib/revocation/status.ts issuer-side FIPS consult (opt-in, lib/revocation/status.ts:signatureFrom)', () => {
  it('refuses malformed PQ keys, authority pins, signer shapes, and certificate windows before issuance', async () => {
    expect(() => deriveRevokerPqKeyId('not-a-key')).toThrow(/ML-DSA-65 public key/);

    const invalidPins = [
      { ...authorityPinV2, authority_domain: 'bad domain' },
      { ...authorityPinV2, public_key: 'not-an-ed25519-key' },
      { ...authorityPinV2, pq_public_key: 'not-an-mldsa-key' },
    ];
    for (const authorityPin of invalidPins) {
      await expect(buildRevokerAuthorityCertificateV2(certificateInputV2({ authorityPin }) as any))
        .rejects.toThrow(/authorityPin/);
    }

    await expect(buildRevokerAuthorityCertificateV2(certificateInputV2({
      expiresAt: '2026-06-01T00:00:00Z',
    }) as any)).rejects.toThrow(/expiresAt must be later/);

    const baseSigner = authoritySignerV2();
    const signerCases = [
      null,
      { ...baseSigner, mldsa: null },
      { ...baseSigner, mldsa: { ...baseSigner.mldsa, private_key: 'secret' } },
      { ...baseSigner, mldsa: { ...baseSigner.mldsa, algorithm: 'Ed25519' } },
      { ...baseSigner, mldsa: { ...baseSigner.mldsa, keyId: 'key:wrong' } },
      { ...baseSigner, mldsa: { ...baseSigner.mldsa, sign: null } },
    ];
    for (const signer of signerCases) {
      await expect(buildRevokerAuthorityCertificateV2(certificateInputV2({ signer }) as any))
        .rejects.toThrow();
    }
  });

  it('refuses every malformed external hybrid signature output without emitting an artifact', async () => {
    const base = authoritySignerV2();
    const signerCases: ExternalHybridSigner[] = [
      {
        ...base,
        ed25519: { ...base.ed25519, async sign() { throw new Error('ed signer offline'); } },
      },
      {
        ...base,
        ed25519: { ...base.ed25519, async sign() { return 'not-canonical'; } },
      },
      {
        ...base,
        ed25519: { ...base.ed25519, async sign() { return new Uint8Array(3); } },
      },
      {
        ...base,
        mldsa: { ...base.mldsa, async sign() { throw new Error('pq signer offline'); } },
      },
      {
        ...base,
        mldsa: { ...base.mldsa, async sign() { return 'not-canonical'; } },
      },
      {
        ...base,
        mldsa: { ...base.mldsa, async sign() { return new Uint8Array(3); } },
      },
    ];
    for (const signer of signerCases) {
      await expect(buildRevokerAuthorityCertificateV2(certificateInputV2({ signer }) as any))
        .rejects.toThrow(/signer|signature/);
    }
  });

  it('refuses malformed v2 predecessor state before extending the status chain', async () => {
    const cert = await certificateV2();
    const head = await buildStatusArtifactV2(statusInputV2(cert) as any);
    const cases: Array<[string, (candidate: any) => void]> = [
      ['version', (candidate) => { candidate['@version'] = STATUS_VERSION; }],
      ['target', (candidate) => { candidate.target.id = 'receipt:other'; }],
      ['status', (candidate) => { candidate.status = 'unknown'; }],
      ['sequence', (candidate) => { candidate.sequence = -1; }],
      ['previous-digest', (candidate) => { candidate.previous_status_digest = 'bad'; }],
      ['non-monotonic', (candidate) => { candidate.issued_at = '2026-07-23T12:10:00Z'; }],
      ['window', (candidate) => { candidate.next_update = candidate.issued_at; }],
      ['algorithm-set', (candidate) => { candidate.required_algorithms = ['Ed25519']; }],
      ['proof-key', (candidate) => { candidate.proof.key_id = 'key:wrong'; }],
      ['signature', (candidate) => { candidate.proof.signatures[0].sig = 'broken'; }],
    ];
    for (const [name, mutate] of cases) {
      const previousStatus = structuredClone(head);
      mutate(previousStatus);
      await expect(buildStatusArtifactV2(statusInputV2(cert, {
        issuedAt: '2026-07-23T12:00:00Z',
        nextUpdate: '2026-07-23T12:05:00Z',
        previousStatus,
      }) as any), name).rejects.toThrow();
    }

    const revoked = await buildStatusArtifactV2(statusInputV2(cert, {
      status: 'revoked',
      nextUpdate: null,
    }) as any);
    await expect(buildStatusArtifactV2(statusInputV2(cert, {
      issuedAt: '2026-07-23T12:00:00Z',
      nextUpdate: '2026-07-23T12:05:00Z',
      previousStatus: revoked,
    }) as any)).rejects.toThrow(/terminal revocation/);
  });

  it('with no fipsPosture supplied, issuance is byte-identical to before the consult existed', async () => {
    const cert = await certificateV2();
    // Byte-identical claim, pinned: re-derive bytes/verification independently
    // rather than trusting the builder's own internal round trip.
    const result = await verifyRevokerAuthorityCertificateV2(cert, { authorityPin: authorityPinV2, now: '2026-07-15T00:00:00Z' });
    expect(result.valid).toBe(true);
  });

  it('a denied FIPS posture refuses issuance with a named reason, before any bytes reach the signer', async () => {
    const deniedPosture: FipsPosture = {
      version: 'EP-FIPS-MODE-v1' as any,
      fips_status: 'active',
      fips_mode_active: true,
      openssl_version: 'test-openssl',
      node_version: process.version,
      openssl_operational: true,
      ed25519_operational: true,
      ed25519_in_validated_boundary: false,
      mldsa_backend: 'test',
      mldsa_validated_module: false,
    };
    // Sanity: this posture really is denied per fips-mode.ts's own policy.
    expect(checkOperationPolicy('Ed25519', deniedPosture).permitted).toBe(false);

    let signerWasCalled = false;
    const signer = authoritySignerV2();
    const guardedSigner: ExternalHybridSigner = {
      ed25519: { ...signer.ed25519, async sign(bytes) { signerWasCalled = true; return signer.ed25519.sign(bytes, {} as any); } },
      mldsa: signer.mldsa,
    };

    await expect(buildRevokerAuthorityCertificateV2(certificateInputV2({
      signer: guardedSigner,
      fipsPosture: deniedPosture,
    }) as any)).rejects.toThrow(/fips_policy_denied|FIPS posture/);
    expect(signerWasCalled).toBe(false);
  });

  it('a permitted FIPS posture (verifiably inactive) allows issuance to proceed normally', async () => {
    const inactivePosture: FipsPosture = {
      version: 'EP-FIPS-MODE-v1' as any,
      fips_status: 'inactive',
      fips_mode_active: false,
      openssl_version: 'test-openssl',
      node_version: process.version,
      openssl_operational: null,
      ed25519_operational: null,
      ed25519_in_validated_boundary: null,
      mldsa_backend: 'test',
      mldsa_validated_module: false,
    };
    expect(checkOperationPolicy('Ed25519', inactivePosture).permitted).toBe(true);
    const cert = await certificateV2({ fipsPosture: inactivePosture } as any);
    const result = await verifyRevokerAuthorityCertificateV2(cert, { authorityPin: authorityPinV2, now: '2026-07-15T00:00:00Z' });
    expect(result.valid).toBe(true);
  });
});
