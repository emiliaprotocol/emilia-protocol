// SPDX-License-Identifier: Apache-2.0
//
// EP-MEMORY-PROJECTION-PQ-COSIGNATURE-v1: the additive, DETACHED hybrid leg
// beside an UNCHANGED MEMORY-PROJECTION-RECORD-v1.
//
// The first suite is the one that matters most: it proves the joint wire of
// draft-ferro-schrock-memory-projection-record-00 was not touched. The rest is
// the hostile matrix for the EP-owned co-signature. The PQ leg runs for real.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import {
  MEMORY_PROJECTION_RECORD_VERSION,
  MEMORY_PROJECTION_PQ_COSIGNATURE_VERSION,
  MEMORY_PROJECTION_PQ_REQUIRED_ALGORITHMS,
  createMemoryProjectionRecordV1,
  verifyMemoryProjectionRecordV1Envelope,
  memoryProjectionPqCosignatureBody,
  memoryProjectionPqCosignatureSigningBytes,
  signMemoryProjectionPqCosignature,
  verifyMemoryProjectionPqCosignature,
} from '../packages/verify/src/memory-projection.ts';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const adapter = crypto.generateKeyPairSync('ed25519');
const adapterPub = adapter.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const cosigner = crypto.generateKeyPairSync('ed25519');
const cosignerPub = cosigner.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');

const KEY_ID = 'adapter-key-1';
const CO_KEY_ID = 'ep-cosigner-1';
const CO_PQ_KEY_ID = 'ep-cosigner-pq-1';

const PIN = {
  key_id: CO_KEY_ID,
  public_key: cosignerPub,
  pq_key_id: CO_PQ_KEY_ID,
  pq_public_key: pqPubB64u,
};

const SIGNER = {
  key_id: CO_KEY_ID,
  private_key: cosigner.privateKey,
  public_key: cosignerPub,
  pq_key_id: CO_PQ_KEY_ID,
  pq_secret_key: pq.secretKey,
  pq_public_key: pqPubB64u,
};

const enc = new TextEncoder();

function makeRecord(projectionId = 'urn:ep:projection:1') {
  return createMemoryProjectionRecordV1({
    sourceProfile: 'apertomemory/sealed-object/v1',
    projectionId,
    createdAt: '2026-08-17T10:00:00Z',
    adapter: { id: 'urn:ep:adapter:apertomemory', keyId: KEY_ID },
    selectionContext: {
      recallRequestBytes: enc.encode('recall'),
      selectionPolicyBytes: enc.encode('policy'),
      trustSnapshotBytes: enc.encode('trust'),
      trustEvaluatedAt: '2026-08-17T09:59:00Z',
      contextFrameProfile: 'frame/v1',
    },
    delivered: [{
      formatVersion: 1,
      sealedObjectBytes: enc.encode('sealed'),
      contextFragmentBytes: enc.encode('fragment'),
      derivedTrust: 'trusted',
      authorship: 'signed',
      authorKeyIdB64u: 'YXV0aG9yLWtleS0x',
      custodyPresent: true,
    }],
    exclusions: {
      authenticationFailed: 0, schemaInvalid: 0, policyFiltered: 0, contextLimit: 0,
    },
    privateKey: adapter.privateKey,
  }).record;
}

const POLICY = {
  adapterKeys: {
    [KEY_ID]: {
      public_key_spki_b64u: adapterPub,
      status: 'active' as const,
      valid_from: '2026-01-01T00:00:00Z',
      valid_to: '2027-01-01T00:00:00Z',
      revoked_at: null,
    },
  },
  verificationTime: '2026-08-17T10:05:00Z',
  maxProjectionAgeSec: 86_400,
  maxTrustAgeSec: 86_400,
};

describe('the co-authored joint wire is untouched', () => {
  it('the record produced alongside a co-signature is a plain, unchanged v1 record', async () => {
    const record = makeRecord();
    expect(record['@version']).toBe(MEMORY_PROJECTION_RECORD_VERSION);
    expect(Object.keys(record.proof).sort()).toEqual(['alg', 'key_id', 'signature_b64u']);
    expect(record.proof.alg).toBe('Ed25519');
    expect(Buffer.from(record.proof.signature_b64u, 'base64url').length).toBe(64);
    // Signing a detached co-signature does not mutate the record in any way.
    const before = JSON.stringify(record);
    await signMemoryProjectionPqCosignature(record, SIGNER);
    expect(JSON.stringify(record)).toBe(before);
    // And the unchanged v1 envelope verifier still accepts it.
    const envelope = verifyMemoryProjectionRecordV1Envelope(record, POLICY);
    expect(envelope.projection_id).toBe('urn:ep:projection:1');
  });

  it('the co-signature lives entirely outside the record (never a record member)', async () => {
    const record = makeRecord();
    const cosig = await signMemoryProjectionPqCosignature(record, SIGNER);
    expect(cosig['@version']).toBe(MEMORY_PROJECTION_PQ_COSIGNATURE_VERSION);
    expect(cosig.record_version).toBe(MEMORY_PROJECTION_RECORD_VERSION);
    expect(Object.keys(record)).not.toContain('pq_proof');
    expect(Object.keys(record)).not.toContain('required_algorithms');
  });
});

describe('EP-MEMORY-PROJECTION-PQ-COSIGNATURE-v1 happy path', () => {
  it('the real ML-DSA-65 backend is present (never a silent skip)', () => {
    expect(pq.publicKey.length).toBe(1952);
  });

  it('round-trips under both pinned keys and binds the exact record', async () => {
    const record = makeRecord();
    const cosig = await signMemoryProjectionPqCosignature(record, SIGNER);
    expect(cosig.proof.signatures.map((s) => s.alg)).toEqual(['Ed25519', 'ML-DSA-65']);
    expect(Buffer.from(cosig.proof.signatures[1].sig, 'base64url').length).toBe(3309);
    const result = await verifyMemoryProjectionPqCosignature(record, cosig, PIN);
    expect(result.errors).toEqual([]);
    expect(result.valid).toBe(true);
  });

  it('the ML-DSA-65 leg really checks out standalone over the recomputed bytes', async () => {
    const record = makeRecord();
    const cosig = await signMemoryProjectionPqCosignature(record, SIGNER);
    const bytes = memoryProjectionPqCosignatureSigningBytes(memoryProjectionPqCosignatureBody(record));
    const sig = Buffer.from(cosig.proof.signatures[1].sig, 'base64url');
    expect(ml_dsa65.verify(new Uint8Array(sig), new Uint8Array(bytes), pq.publicKey)).toBe(true);
  });
});

describe('EP-MEMORY-PROJECTION-PQ-COSIGNATURE-v1 hostile matrix', () => {
  const build = async () => {
    const record = makeRecord();
    const cosig = await signMemoryProjectionPqCosignature(record, SIGNER);
    return { record, cosig: JSON.parse(JSON.stringify(cosig)) };
  };

  it('refuses a stripped ML-DSA leg with the set left intact', async () => {
    const { record, cosig } = await build();
    cosig.proof.signatures = cosig.proof.signatures.filter((s: any) => s.alg !== 'ML-DSA-65');
    const result = await verifyMemoryProjectionPqCosignature(record, cosig, PIN);
    expect(result.valid).toBe(false);
    expect(result.checks.legs_present).toBe(false);
  });

  it('refuses a narrowed required_algorithms set', async () => {
    const { record, cosig } = await build();
    cosig.proof.signatures = cosig.proof.signatures.filter((s: any) => s.alg !== 'ML-DSA-65');
    cosig.proof.required_algorithms = ['Ed25519'];
    const result = await verifyMemoryProjectionPqCosignature(record, cosig, PIN);
    expect(result.valid).toBe(false);
    expect(result.checks.algorithm_set).toBe(false);
    expect(result.checks.legs_present).toBe(false);
  });

  it('refuses a widened algorithm set', async () => {
    const { record, cosig } = await build();
    cosig.proof.required_algorithms = ['Ed25519', 'ML-DSA-65', 'Ed448'];
    const result = await verifyMemoryProjectionPqCosignature(record, cosig, PIN);
    expect(result.valid).toBe(false);
    expect(result.checks.algorithm_set).toBe(false);
  });

  it('refuses a wrong-length Ed25519 signature', async () => {
    const { record, cosig } = await build();
    cosig.proof.signatures[0].sig = Buffer.alloc(63).toString('base64url');
    const result = await verifyMemoryProjectionPqCosignature(record, cosig, PIN);
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toContain('malformed_signature');
  });

  it('refuses a wrong-length ML-DSA-65 signature', async () => {
    const { record, cosig } = await build();
    cosig.proof.signatures[1].sig = Buffer.alloc(3308).toString('base64url');
    const result = await verifyMemoryProjectionPqCosignature(record, cosig, PIN);
    expect(result.valid).toBe(false);
    expect(result.checks.signature_valid).toBe(false);
  });

  it('refuses an Ed448 SPKI pinned as the Ed25519 half', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const { record, cosig } = await build();
    const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    cosig.proof.public_key = ed448Pub;
    const result = await verifyMemoryProjectionPqCosignature(
      record, cosig, { ...PIN, public_key: ed448Pub },
    );
    expect(result.valid).toBe(false);
    expect(result.checks.cosigner_key_pinned).toBe(false);
  });

  it('refuses replay onto a DIFFERENT record', async () => {
    const { cosig } = await build();
    const other = makeRecord('urn:ep:projection:2');
    const result = await verifyMemoryProjectionPqCosignature(other, cosig, PIN);
    expect(result.valid).toBe(false);
    expect(result.checks.bound_to_record).toBe(false);
  });

  it('refuses when the record was tampered after co-signing', async () => {
    const { record, cosig } = await build();
    const tampered = { ...record, projection_id: 'urn:ep:projection:mallory' };
    const result = await verifyMemoryProjectionPqCosignature(tampered, cosig, PIN);
    expect(result.valid).toBe(false);
    expect(result.checks.bound_to_record).toBe(false);
  });

  it('refuses pq_backend_unavailable rather than passing on the classical leg', async () => {
    const { record, cosig } = await build();
    const result = await verifyMemoryProjectionPqCosignature(
      record, cosig, PIN, { mldsaBackendLoader: () => null },
    );
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toContain('pq_backend_unavailable');
  });

  it('refuses an unpinned co-signer', async () => {
    const { record, cosig } = await build();
    const result = await verifyMemoryProjectionPqCosignature(record, cosig, null);
    expect(result.valid).toBe(false);
    expect(result.checks.cosigner_key_pinned).toBe(false);
  });

  it('refuses a co-signature carrying an unexpected version marker', async () => {
    const { record, cosig } = await build();
    cosig['@version'] = 'EP-MEMORY-PROJECTION-PQ-COSIGNATURE-v2';
    const result = await verifyMemoryProjectionPqCosignature(record, cosig, PIN);
    expect(result.valid).toBe(false);
    expect(result.checks.version).toBe(false);
  });

  it('never throws on hostile caller input', async () => {
    const record = makeRecord();
    for (const bad of [null, undefined, 'x', 7, [], { proof: null }]) {
      const result = await verifyMemoryProjectionPqCosignature(record, bad, PIN);
      expect(result.valid).toBe(false);
    }
    const { cosig } = await build();
    for (const badRecord of [null, undefined, 'x', 7, []]) {
      const result = await verifyMemoryProjectionPqCosignature(badRecord, cosig, PIN);
      expect(result.valid).toBe(false);
      expect(result.checks.bound_to_record).toBe(false);
    }
  });

  it('the signing-bytes helper refuses a non-registered algorithm set', async () => {
    const record = makeRecord();
    expect(() => memoryProjectionPqCosignatureSigningBytes(
      memoryProjectionPqCosignatureBody(record), ['Ed25519'],
    )).toThrow(/registered EP-MEMORY-PROJECTION-PQ-COSIGNATURE-v1 set/);
    expect(MEMORY_PROJECTION_PQ_REQUIRED_ALGORITHMS).toEqual(['Ed25519', 'ML-DSA-65']);
  });
});
