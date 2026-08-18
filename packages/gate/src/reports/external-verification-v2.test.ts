// SPDX-License-Identifier: Apache-2.0
//
// EP-EXTERNAL-VERIFICATION-STATEMENT-v2 -- hostile matrix for the hybrid
// external-verifier statement. New file under src/reports/ so vitest
// exercises this package's TS source directly; the dist-backed
// packages/gate/reports/external-verification.test.js keeps covering v1.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import {
  EXTERNAL_VERIFICATION_STATEMENT_V2_VERSION,
  EXTERNAL_VERIFICATION_V2_REQUIRED_ALGORITHMS,
  signExternalVerificationStatement,
  signExternalVerificationStatementV2,
  verifyExternalVerificationStatement,
  verifyExternalVerificationStatementV2,
  verifyExternalVerificationStatementAnyVersion,
} from './external-verification.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

function verifierFixture() {
  const ed = crypto.generateKeyPairSync('ed25519');
  const edPubB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const pq = ml_dsa65.keygen(crypto.randomBytes(32));
  const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
  return {
    keys: {
      ed: { privateKey: ed.privateKey },
      pq: { secretKey: pq.secretKey, publicKeyB64u: pqPubB64u },
    },
    edPrivateKey: ed.privateKey,
    edPubB64u,
    pqPubB64u,
  };
}

function args(overrides: Record<string, unknown> = {}) {
  return {
    generated_at: '2026-08-17T12:00:00.000Z',
    verifier: { id: 'ext:auditor:hybrid-alpha', name: 'Hybrid Alpha External Verification' },
    subject: { kind: 'gate_evidence_log', evidence_head: `sha256:${'a'.repeat(64)}` },
    procedure: { id: 'ep-gate-reperformance', version: 'EP-GATE-REPERFORMANCE-v1' },
    inputs: { entries_digest: `sha256:${'b'.repeat(64)}` },
    result: { status: 'verified', checks: [{ id: 'chain_reperformed', ok: true }] },
    ...overrides,
  };
}

describe('EP-EXTERNAL-VERIFICATION-STATEMENT-v2 hybrid statement', () => {
  it('valid v2 roundtrip: verifies under a pin carrying both halves', async () => {
    const verifier = verifierFixture();
    const stmt = await signExternalVerificationStatementV2(args(), verifier.keys);
    expect(stmt['@version']).toBe(EXTERNAL_VERIFICATION_STATEMENT_V2_VERSION);
    expect(stmt.signature.required_algorithms).toEqual([...EXTERNAL_VERIFICATION_V2_REQUIRED_ALGORITHMS]);
    expect(stmt.signature.signatures.map((s) => s.alg)).toEqual([...EXTERNAL_VERIFICATION_V2_REQUIRED_ALGORITHMS]);

    const result = await verifyExternalVerificationStatementV2(stmt, {
      pinnedVerifierKeys: [{
        verifier_id: 'ext:auditor:hybrid-alpha', public_key: verifier.edPubB64u, pq_public_key: verifier.pqPubB64u,
      }],
    });
    expect(result.verified).toBe(true);
    expect(result.accepted).toBe(true);
  });

  it('the router accepts a v1 statement unchanged, and a v2 one via the hybrid path', async () => {
    const classical = crypto.generateKeyPairSync('ed25519');
    const classicalPub = classical.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const v1 = signExternalVerificationStatement(args({ verifier: { id: 'ext:auditor:v1' } }), classical.privateKey);
    const v1Result = await verifyExternalVerificationStatementAnyVersion(v1, {
      pinnedVerifierKeys: [{ verifier_id: 'ext:auditor:v1', public_key: classicalPub }],
    });
    expect(v1Result.verified).toBe(true);

    const verifier = verifierFixture();
    const v2 = await signExternalVerificationStatementV2(args(), verifier.keys);
    const v2Result = await verifyExternalVerificationStatementAnyVersion(v2, {
      pinnedVerifierKeys: [{
        verifier_id: 'ext:auditor:hybrid-alpha', public_key: verifier.edPubB64u, pq_public_key: verifier.pqPubB64u,
      }],
    });
    expect(v2Result.verified).toBe(true);
  });

  it('v1-refuses-v2: the existing SYNC verifier refuses a v2 statement cleanly on the version marker', async () => {
    const verifier = verifierFixture();
    const stmt = await signExternalVerificationStatementV2(args(), verifier.keys);
    // No await: verifyExternalVerificationStatement remains synchronous.
    const result = verifyExternalVerificationStatement(stmt as any, { pinnedVerifierKeys: [] });
    expect(result.verified).toBe(false);
    expect(result.reason).toBe('unsupported_version');
  });

  it('a v2 statement from a verifier pinned WITHOUT the ML-DSA half refuses (never partial credit)', async () => {
    const verifier = verifierFixture();
    const stmt = await signExternalVerificationStatementV2(args(), verifier.keys);
    const result = await verifyExternalVerificationStatementV2(stmt, {
      pinnedVerifierKeys: [{ verifier_id: 'ext:auditor:hybrid-alpha', public_key: verifier.edPubB64u } as any],
    });
    expect(result.verified).toBe(false);
    expect(result.reason).toBe('verifier_key_not_pinned');
  });

  it('stripped leg: dropping the ML-DSA signature refuses, never a classical-only pass', async () => {
    const verifier = verifierFixture();
    const stmt = await signExternalVerificationStatementV2(args(), verifier.keys);
    const stripped = {
      ...stmt,
      signature: { ...stmt.signature, signatures: stmt.signature.signatures.filter((s) => s.alg !== 'ML-DSA-65') },
    };
    const result = await verifyExternalVerificationStatementV2(stripped, {
      pinnedVerifierKeys: [{
        verifier_id: 'ext:auditor:hybrid-alpha', public_key: verifier.edPubB64u, pq_public_key: verifier.pqPubB64u,
      }],
    });
    expect(result.verified).toBe(false);
  });

  it('narrowed set: claiming required_algorithms=["Ed25519"] only is refused structurally', async () => {
    const verifier = verifierFixture();
    const stmt = await signExternalVerificationStatementV2(args(), verifier.keys);
    const narrowed = {
      ...stmt,
      required_algorithms: ['Ed25519'],
      signature: {
        ...stmt.signature,
        required_algorithms: ['Ed25519'],
        signatures: stmt.signature.signatures.filter((s) => s.alg === 'Ed25519'),
      },
    };
    const result = await verifyExternalVerificationStatementV2(narrowed, {
      pinnedVerifierKeys: [{
        verifier_id: 'ext:auditor:hybrid-alpha', public_key: verifier.edPubB64u, pq_public_key: verifier.pqPubB64u,
      }],
    });
    expect(result.verified).toBe(false);
    expect(result.reason).toBe('unsupported_algorithm_set');
  });

  it('wrong-length signature on the ML-DSA leg refuses, never crashes', async () => {
    const verifier = verifierFixture();
    const stmt = await signExternalVerificationStatementV2(args(), verifier.keys);
    const tampered = {
      ...stmt,
      signature: {
        ...stmt.signature,
        signatures: stmt.signature.signatures.map((s) => (
          s.alg === 'ML-DSA-65' ? { ...s, sig: Buffer.from(crypto.randomBytes(16)).toString('base64url') } : s
        )),
      },
    };
    await expect(verifyExternalVerificationStatementV2(tampered, {
      pinnedVerifierKeys: [{
        verifier_id: 'ext:auditor:hybrid-alpha', public_key: verifier.edPubB64u, pq_public_key: verifier.pqPubB64u,
      }],
    })).resolves.toMatchObject({ verified: false });
  });

  it('Ed448-masquerade: a non-Ed25519 SPKI presented as the classical half refuses, never verified under the wrong curve', async () => {
    const verifier = verifierFixture();
    const stmt = await signExternalVerificationStatementV2(args(), verifier.keys);
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448PubB64u = ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const masqueraded = { ...stmt, signature: { ...stmt.signature, public_key: ed448PubB64u } };
    const result = await verifyExternalVerificationStatementV2(masqueraded, {
      pinnedVerifierKeys: [{
        verifier_id: 'ext:auditor:hybrid-alpha', public_key: ed448PubB64u, pq_public_key: verifier.pqPubB64u,
      }],
    });
    expect(result.verified).toBe(false);
  });

  it('never throws on hostile input (absent statement, tampered digest, prototype-bearing document)', async () => {
    for (const bad of [null, undefined, {}, { '@version': EXTERNAL_VERIFICATION_STATEMENT_V2_VERSION }]) {
      await expect(verifyExternalVerificationStatementV2(bad as any, { pinnedVerifierKeys: [] }))
        .resolves.toMatchObject({ verified: false });
    }
    const verifier = verifierFixture();
    const stmt = await signExternalVerificationStatementV2(args(), verifier.keys);
    const tamperedDigest = { ...stmt, signature: { ...stmt.signature, statement_digest: `sha256:${'0'.repeat(64)}` } };
    await expect(verifyExternalVerificationStatementV2(tamperedDigest, {
      pinnedVerifierKeys: [{
        verifier_id: 'ext:auditor:hybrid-alpha', public_key: verifier.edPubB64u, pq_public_key: verifier.pqPubB64u,
      }],
    })).resolves.toMatchObject({ verified: false, reason: 'statement_digest_mismatch' });
  });
});
