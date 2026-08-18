/**
 * EMILIA Protocol -- lib/commit.js OPT-IN hybrid mode (EP-COMMIT-HYBRID-v1)
 *
 * Two jobs:
 *
 *  1. THE REGRESSION. With no hybrid signer configured, issuance is
 *     byte-identical to the v1 path. This is proved WITHOUT calling
 *     lib/commit.js's own signing helpers: the test independently recomputes
 *     JSON.stringify(deepSortKeys(canonicalFields)) from the stored row's own
 *     columns and verifies the stored signature with raw node crypto. If the
 *     canonical bytes or the signature had shifted by one byte, this fails.
 *     It also pins the exact column set written to `commits`, so no field can
 *     leak into the row.
 *
 *  2. THE HYBRID PATH. With a dual-signer registered, the row stays byte-
 *     identical v1 AND a detached EP-COMMIT-HYBRID-v1 proof is returned,
 *     carrying an agility-shaped signature set whose required-algorithm set is
 *     committed into the signed bytes. Hostile cases: leg stripping, set
 *     narrowing (with the cryptographic half proved independently), an Ed448
 *     key masquerading as the Ed25519 half, and a proof lifted from another
 *     commit.
 *
 * Supabase, the canonical evaluator, and delegation are mocked (same pattern as
 * tests/commit.test.ts); no DB or network is touched. ML-DSA-65 runs for real.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import crypto from 'node:crypto';

// ---------------------------------------------------------------------------
// Mocks (declared before the module under test is imported)
// ---------------------------------------------------------------------------

function makeChain(resolveValue) {
  return {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    neq: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    is: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    insert: vi.fn().mockResolvedValue(resolveValue),
    update: vi.fn().mockReturnThis(),
    single: vi.fn().mockResolvedValue(resolveValue),
    maybeSingle: vi.fn().mockResolvedValue(resolveValue),
    then: (resolve) => Promise.resolve(resolveValue).then(resolve),
  };
}

const mockGetServiceClient = vi.fn();
const mockCanonicalEvaluate = vi.fn();
const mockVerifyDelegation = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));
vi.mock('../lib/canonical-evaluator.js', () => ({
  canonicalEvaluate: (...args) => mockCanonicalEvaluate(...args),
}));
vi.mock('../lib/delegation.js', () => ({
  verifyDelegation: (...args) => mockVerifyDelegation(...args),
}));

import { issueCommit, verifyCommit, _resetForTesting } from '../lib/commit.js';
import {
  COMMIT_HYBRID_PROFILE,
  COMMIT_HYBRID_REQUIRED_ALGORITHMS,
  COMMIT_HYBRID_REASONS,
  commitHybridSignedBytes,
  commitHybridSignedMaterial,
  createCommitHybridProof,
  verifyCommitHybridProof,
} from '../lib/commit-hybrid.js';
import { deepSortKeys } from '../lib/handshake/binding.js';
import {
  createExternalCustodySigner,
  registerCustodySigner,
  clearCustodySigner,
} from '../lib/key-custody.js';
import { softwareMldsaSigner, hybridSigner } from '../lib/custody-signers.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const ED25519_SPKI_DER_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * The v1 canonical column set of a `commits` row, frozen here on purpose: a new
 * key appearing in the insert payload is a wire/schema change and must fail
 * this test rather than reach Postgres.
 */
const V1_COMMIT_COLUMNS = [
  'commit_id', 'entity_id', 'kid', 'principal_id', 'counterparty_entity_id',
  'delegation_id', 'action_type', 'decision', 'scope', 'max_value_usd',
  'context', 'policy_snapshot', 'nonce', 'signature', 'public_key',
  'expires_at', 'status', 'evaluation_result', 'created_at',
].sort();

/** The exact fields lib/commit.js signs, rebuilt here from the STORED row. */
function canonicalFieldsFromRow(row) {
  return {
    commit_id: row.commit_id,
    entity_id: row.entity_id,
    kid: row.kid,
    principal_id: row.principal_id,
    counterparty_entity_id: row.counterparty_entity_id,
    delegation_id: row.delegation_id,
    action_type: row.action_type,
    decision: row.decision,
    scope: row.scope,
    max_value_usd: row.max_value_usd,
    context: row.context,
    nonce: row.nonce,
    expires_at: new Date(row.expires_at).toISOString(),
    created_at: new Date(row.created_at).toISOString(),
  };
}

/** Independent recomputation: NOT lib/commit.js's own signPayload/verifySignature. */
function v1SignatureVerifiesIndependently(row) {
  const canonical = JSON.stringify(deepSortKeys(canonicalFieldsFromRow(row)));
  const pubRaw = Buffer.from(row.public_key, 'base64');
  if (pubRaw.length !== 32) return false;
  const keyObject = crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_DER_PREFIX, pubRaw]),
    format: 'der',
    type: 'spki',
  });
  return crypto.verify(null, Buffer.from(canonical, 'utf8'), keyObject, Buffer.from(row.signature, 'base64'));
}

let insertedRows = [];

function buildMockDb(commitRecord = null) {
  const readChain = makeChain({ data: commitRecord, error: null });
  const insertFn = vi.fn(async (row) => { insertedRows.push(row); return { data: null, error: null }; });
  return {
    from: vi.fn((table) => {
      if (table === 'revoked_commit_keys') return makeChain({ data: null, error: null });
      return {
        select: (...args) => { readChain.select(...args); return readChain; },
        insert: insertFn,
        update: () => makeChain({ data: null, error: null }),
      };
    }),
  };
}

function mockEvaluation() {
  return {
    score: 0.8, confidence: 0.9, profile: { history_length: 10 }, anomaly: null,
    policyResult: { pass: true, failures: [], warnings: [] }, error: null,
  };
}

// ---------------------------------------------------------------------------
// Hybrid signer fixture
// ---------------------------------------------------------------------------

function makeHybridFixture() {
  const ed = crypto.generateKeyPairSync('ed25519');
  const spkiB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const classical = createExternalCustodySigner({
    mode: 'hsm',
    keyId: 'pkcs11:ep-commit#1',
    sign: async (bytes) => crypto.sign(null, Buffer.from(bytes), ed.privateKey).toString('base64url'),
    getPublicKey: () => spkiB64u,
  });
  const pqPair = ml_dsa65.keygen(crypto.randomBytes(32));
  const pq = softwareMldsaSigner({
    keyId: 'ep:key:commit-pq#1',
    secretKey: pqPair.secretKey,
    publicKeyRawB64u: pqPair.publicKey,
  });
  return {
    ed,
    spkiB64u,
    pqPair,
    signer: hybridSigner({ classical, pq }),
    keys: {
      ed25519PublicKey: spkiB64u,
      ed25519KeyId: 'pkcs11:ep-commit#1',
      mldsaPublicKey: Buffer.from(pqPair.publicKey).toString('base64url'),
      mldsaKeyId: 'ep:key:commit-pq#1',
    },
  };
}

let prevMode;
let prevKeyId;

function enableCustodyMode() {
  prevMode = process.env.EP_KEY_CUSTODY_MODE;
  prevKeyId = process.env.EP_HSM_KEY_ID;
  process.env.EP_KEY_CUSTODY_MODE = 'hsm';
  process.env.EP_HSM_KEY_ID = 'pkcs11:ep-commit#1';
}

function restoreCustodyMode() {
  if (prevMode === undefined) delete process.env.EP_KEY_CUSTODY_MODE;
  else process.env.EP_KEY_CUSTODY_MODE = prevMode;
  if (prevKeyId === undefined) delete process.env.EP_HSM_KEY_ID;
  else process.env.EP_HSM_KEY_ID = prevKeyId;
}

beforeEach(() => {
  vi.clearAllMocks();
  _resetForTesting();
  clearCustodySigner();
  insertedRows = [];
  mockCanonicalEvaluate.mockResolvedValue(mockEvaluation());
  mockGetServiceClient.mockReturnValue(buildMockDb());
});

afterEach(() => {
  clearCustodySigner();
  restoreCustodyMode();
});

// ===========================================================================
// 1. REGRESSION: the default path is byte-identical to v1
// ===========================================================================

describe('default path (no hybrid signer configured)', () => {
  it('writes exactly the v1 column set: nothing new reaches the commits table', async () => {
    await issueCommit({ entity_id: 'entity-default', action_type: 'install' });
    expect(insertedRows).toHaveLength(1);
    expect(Object.keys(insertedRows[0]).sort()).toEqual(V1_COMMIT_COLUMNS);
    expect(insertedRows[0]).not.toHaveProperty('hybrid_proof');
  });

  it('signs the v1 canonical bytes, verified by an INDEPENDENT recomputation', async () => {
    const commit = await issueCommit({ entity_id: 'entity-default', action_type: 'install' });
    expect(v1SignatureVerifiesIndependently(commit)).toBe(true);
  });

  it('returns the stored record itself, with no hybrid proof attached', async () => {
    const commit = await issueCommit({ entity_id: 'entity-default', action_type: 'connect' });
    expect(commit).toBe(insertedRows[0]);
    expect(commit).not.toHaveProperty('hybrid_proof');
  });

  it('verifyCommit with no options returns the v1 result object, with no hybrid key', async () => {
    const commit = await issueCommit({ entity_id: 'entity-default', action_type: 'install' });
    mockGetServiceClient.mockReturnValue(buildMockDb(commit));
    const res = await verifyCommit(commit.commit_id);
    expect(res.valid).toBe(true);
    expect(Object.keys(res).sort()).toEqual(['decision', 'expires_at', 'reasons', 'status', 'valid']);
  });
});

// ===========================================================================
// 2. HYBRID PATH
// ===========================================================================

describe('hybrid path (dual-signer registered)', () => {
  let fixture;

  beforeEach(() => {
    fixture = makeHybridFixture();
    enableCustodyMode();
    registerCustodySigner(fixture.signer);
  });

  it('keeps the stored row byte-identical v1 and returns a detached proof', async () => {
    const commit = await issueCommit({ entity_id: 'entity-hybrid', action_type: 'install' });

    // The row: unchanged v1 shape, unchanged v1 signature semantics.
    expect(Object.keys(insertedRows[0]).sort()).toEqual(V1_COMMIT_COLUMNS);
    expect(insertedRows[0]).not.toHaveProperty('hybrid_proof');
    expect(v1SignatureVerifiesIndependently(insertedRows[0])).toBe(true);

    // The proof: additive, detached, agility-shaped.
    expect(commit.hybrid_proof['@version']).toBe(COMMIT_HYBRID_PROFILE);
    expect(commit.hybrid_proof.profile.required_algorithms)
      .toEqual([...COMMIT_HYBRID_REQUIRED_ALGORITHMS]);
    expect(commit.hybrid_proof.signatures.map((s) => s.alg))
      .toEqual([...COMMIT_HYBRID_REQUIRED_ALGORITHMS]);
    expect(commit.hybrid_proof.commit_id).toBe(commit.commit_id);
  });

  it('commits the required algorithm set INTO the signed bytes', async () => {
    const commit = await issueCommit({ entity_id: 'entity-hybrid', action_type: 'install' });
    const bytes = commitHybridSignedBytes(commit.hybrid_proof.payload).toString('utf8');
    expect(bytes).toContain('"required_algorithms":["Ed25519","ML-DSA-65"]');
    expect(bytes).toContain(`"@version":"${COMMIT_HYBRID_PROFILE}"`);
  });

  it('both legs are real signatures over those exact bytes', async () => {
    const commit = await issueCommit({ entity_id: 'entity-hybrid', action_type: 'install' });
    const bytes = commitHybridSignedBytes(commit.hybrid_proof.payload);
    const [edLeg, pqLeg] = commit.hybrid_proof.signatures;
    expect(crypto.verify(null, bytes, fixture.ed.publicKey, Buffer.from(edLeg.sig, 'base64url'))).toBe(true);
    expect(ml_dsa65.verify(
      new Uint8Array(Buffer.from(pqLeg.sig, 'base64url')),
      new Uint8Array(bytes),
      fixture.pqPair.publicKey,
    )).toBe(true);
  });

  it('verifyCommit accepts the hybrid form under both pinned keys', async () => {
    const commit = await issueCommit({ entity_id: 'entity-hybrid', action_type: 'install' });
    mockGetServiceClient.mockReturnValue(buildMockDb(insertedRows[0]));
    const res = await verifyCommit(commit.commit_id, {
      hybrid: { required: true, proof: commit.hybrid_proof, keys: fixture.keys },
    });
    expect(res.valid).toBe(true);
    expect(res.hybrid?.verified).toBe(true);
  });

  it('a relying party pinning the hybrid leg REFUSES a commit presented without a proof', async () => {
    const commit = await issueCommit({ entity_id: 'entity-hybrid', action_type: 'install' });
    mockGetServiceClient.mockReturnValue(buildMockDb(insertedRows[0]));
    const res = await verifyCommit(commit.commit_id, { hybrid: { required: true } });
    expect(res.valid).toBe(false);
    expect(res.reasons).toContain('hybrid_proof_missing');
  });

  it('fails closed as a whole when the PQ leg cannot sign', async () => {
    clearCustodySigner();
    const ed = crypto.generateKeyPairSync('ed25519');
    const classical = createExternalCustodySigner({
      mode: 'hsm', keyId: 'pkcs11:ep-commit#1',
      sign: async (bytes) => crypto.sign(null, Buffer.from(bytes), ed.privateKey).toString('base64url'),
      getPublicKey: () => ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    });
    const pqPair = ml_dsa65.keygen(crypto.randomBytes(32));
    registerCustodySigner(hybridSigner({
      classical,
      pq: softwareMldsaSigner({
        keyId: 'ep:key:commit-pq#dead',
        secretKey: pqPair.secretKey,
        publicKeyRawB64u: pqPair.publicKey,
        mldsaBackend: {},
      }),
    }));
    await expect(issueCommit({ entity_id: 'entity-hybrid', action_type: 'install' }))
      .rejects.toThrow(/hybrid signing failed/);
    // Nothing half-signed was written.
    expect(insertedRows).toHaveLength(0);
  });
});

// ===========================================================================
// 3. HOSTILE: the proof never verifies on one leg alone
// ===========================================================================

describe('hybrid proof, hostile cases', () => {
  let fixture;
  let commit;

  beforeEach(async () => {
    fixture = makeHybridFixture();
    enableCustodyMode();
    registerCustodySigner(fixture.signer);
    commit = await issueCommit({ entity_id: 'entity-hostile', action_type: 'transact' });
    mockGetServiceClient.mockReturnValue(buildMockDb(insertedRows[0]));
  });

  async function verifyWith(proof, keys = fixture.keys) {
    return verifyCommit(commit.commit_id, { hybrid: { required: true, proof, keys } });
  }

  it('LEG STRIPPING: dropping the ML-DSA leg refuses', async () => {
    const proof = structuredClone(commit.hybrid_proof);
    proof.signatures = proof.signatures.filter((s) => s.alg === 'Ed25519');
    const res = await verifyWith(proof);
    expect(res.valid).toBe(false);
    expect(res.hybrid?.reason).toBe(COMMIT_HYBRID_REASONS.HYBRID_LEG_MISSING);
    expect(res.reasons).toContain(`hybrid_proof_invalid:${COMMIT_HYBRID_REASONS.HYBRID_LEG_MISSING}`);
  });

  it('LEG STRIPPING: dropping the Ed25519 leg refuses too', async () => {
    const proof = structuredClone(commit.hybrid_proof);
    proof.signatures = proof.signatures.filter((s) => s.alg === 'ML-DSA-65');
    expect((await verifyWith(proof)).valid).toBe(false);
  });

  it('SET NARROWING refuses structurally AND breaks the surviving signature', async () => {
    const proof = structuredClone(commit.hybrid_proof);
    proof.profile.required_algorithms = ['Ed25519'];
    proof.signatures = proof.signatures.filter((s) => s.alg === 'Ed25519');
    const res = await verifyWith(proof);
    expect(res.valid).toBe(false);
    expect(res.hybrid?.reason).toBe(COMMIT_HYBRID_REASONS.ALGORITHM_SET_MISMATCH);

    // The cryptographic half, proved independently of the structural refusal.
    const narrowed = Buffer.from(JSON.stringify(deepSortKeys({
      '@version': COMMIT_HYBRID_PROFILE,
      payload: proof.payload,
      required_algorithms: ['Ed25519'],
    })), 'utf8');
    expect(crypto.verify(
      null, narrowed, fixture.ed.publicKey, Buffer.from(proof.signatures[0].sig, 'base64url'),
    )).toBe(false);
  });

  it('DUPLICATE ALGORITHM refuses', async () => {
    const proof = structuredClone(commit.hybrid_proof);
    proof.signatures = [proof.signatures[0], proof.signatures[0]];
    const res = await verifyWith(proof);
    expect(res.valid).toBe(false);
    expect(res.hybrid?.reason).toBe(COMMIT_HYBRID_REASONS.DUPLICATE_ALGORITHM);
  });

  it('ED448 MASQUERADE: an Ed448 key pinned as the Ed25519 half refuses', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const res = await verifyWith(commit.hybrid_proof, {
      ...fixture.keys,
      ed25519PublicKey: ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    });
    expect(res.valid).toBe(false);
    expect(res.hybrid?.reason).toBe(COMMIT_HYBRID_REASONS.MISSING_KEY);
    expect(res.hybrid?.failed_algorithm).toBe('Ed25519');
  });

  it('a proof lifted from ANOTHER commit refuses on the payload binding', async () => {
    const other = await issueCommit({ entity_id: 'entity-other', action_type: 'install' });
    const res = await verifyWith(other.hybrid_proof);
    expect(res.valid).toBe(false);
    expect(res.hybrid?.reason).toBe(COMMIT_HYBRID_REASONS.PAYLOAD_MISMATCH);
  });

  it('an EP-RECEIPT-HYBRID-v1-shaped document is not accepted as a commit proof', async () => {
    const proof = structuredClone(commit.hybrid_proof);
    proof['@version'] = 'EP-RECEIPT-HYBRID-v1';
    const res = await verifyWith(proof);
    expect(res.valid).toBe(false);
    expect(res.hybrid?.reason).toBe(COMMIT_HYBRID_REASONS.UNKNOWN_PROFILE);
  });

  it('malformed proofs refuse without throwing', async () => {
    for (const junk of ['x', 42, [], {}, { '@version': COMMIT_HYBRID_PROFILE }]) {
      expect((await verifyWith(junk)).valid).toBe(false);
    }
  });

  it('refuses issuer misuse before any partial hybrid proof can be emitted', async () => {
    expect(() => commitHybridSignedMaterial(null as any)).toThrow(/plain object/);
    expect(() => commitHybridSignedMaterial({}, ['Ed25519'])).toThrow(/algorithm_set_mismatch/);
    await expect(createCommitHybridProof({
      commit_id: '',
      payload: {},
      signer: fixture.signer,
    })).rejects.toThrow(/commit_id is required/);
    await expect(createCommitHybridProof({
      commit_id: 'commit:bad-signer',
      payload: {},
      signer: {} as any,
    })).rejects.toThrow(/HybridCustodySigner/);
    await expect(createCommitHybridProof({
      commit_id: 'commit:missing-leg',
      payload: {},
      signer: {
        async signSet() {
          return [{ alg: 'Ed25519', sig: 'x', key_id: 'key:only-classical' }];
        },
      } as any,
    })).rejects.toThrow(/produced no ML-DSA-65 leg/);
  });

  it('classifies malformed payload, leg, algorithm, and key presentations without throwing', async () => {
    const payload = commit.hybrid_proof.payload;
    const proof = commit.hybrid_proof;
    const cases: Array<[unknown, unknown, unknown, string]> = [
      [[], proof, fixture.keys, COMMIT_HYBRID_REASONS.PAYLOAD_MISMATCH],
      [payload, { ...proof, payload: [] }, fixture.keys, COMMIT_HYBRID_REASONS.PAYLOAD_MISMATCH],
      [payload, { ...proof, signatures: [{ alg: 'Ed25519' }] }, fixture.keys, COMMIT_HYBRID_REASONS.MALFORMED_PROOF],
      [payload, {
        ...proof,
        signatures: [...proof.signatures, { alg: 'RSA', sig: 'not-used' }],
      }, fixture.keys, COMMIT_HYBRID_REASONS.UNEXPECTED_ALGORITHM],
      [payload, proof, null, COMMIT_HYBRID_REASONS.MISSING_KEY],
      [payload, proof, { ...fixture.keys, mldsaPublicKey: null }, COMMIT_HYBRID_REASONS.MISSING_KEY],
    ];
    for (const [held, presented, keys, reason] of cases) {
      await expect(verifyCommitHybridProof(
        held as any,
        presented,
        keys as any,
      )).resolves.toMatchObject({ verified: false, reason });
    }

    await expect(verifyCommitHybridProof(payload, proof, fixture.keys, {
      mldsaBackend: {},
      mldsaBackendLoader: async () => null,
    })).resolves.toMatchObject({
      verified: false,
      reason: COMMIT_HYBRID_REASONS.PQ_BACKEND_UNAVAILABLE,
    });
  });
});
