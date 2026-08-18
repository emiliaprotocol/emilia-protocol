/**
 * EMILIA Protocol -- FIPS operation-policy consult wired into the custody
 * signing path (lib/commit.ts, lib/commit-hybrid.ts).
 *
 * checkOperationPolicy() (packages/verify/src/fips-mode.ts, EP-FIPS-MODE-v1)
 * previously had zero production call sites. This file pins the two jobs of
 * wiring it into issuance:
 *
 *  1. THE REGRESSION. With no FIPS posture configured (EP_FIPS_REQUIRED unset
 *     or false), the consult is a complete no-op: it is never even evaluated,
 *     so a posture object that would otherwise DENY has no effect, and
 *     issueCommit()'s stored row is byte-identical to the pre-consult path
 *     (same proof technique as tests/commit-hybrid.test.ts: an INDEPENDENT
 *     recomputation of the canonical bytes and signature, not the module's
 *     own helpers).
 *
 *  2. THE CONSULT. With EP_FIPS_REQUIRED=true, an injected posture that the
 *     real (unmocked) checkOperationPolicy() denies causes a named refusal
 *     BEFORE the provider-side signing effect: for the hybrid proof, the
 *     custody signer's signSet() is never invoked.
 *
 * Supabase, the canonical evaluator, and delegation are mocked (same pattern
 * as tests/commit-hybrid.test.ts); no DB or network is touched. The FIPS
 * postures below are plain data objects fed through the REAL
 * checkOperationPolicy()/getFipsPosture() -- nothing about fips-mode.ts
 * itself is mocked.
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

import { issueCommit, _resetForTesting, _internals } from '../lib/commit.js';
import { createCommitHybridProof, consultFipsIssuancePolicy as commitHybridConsult } from '../lib/commit-hybrid.js';
import { deepSortKeys } from '../lib/handshake/binding.js';
import {
  createExternalCustodySigner,
  clearCustodySigner,
} from '../lib/key-custody.js';
import { softwareMldsaSigner, hybridSigner } from '../lib/custody-signers.js';
import { checkOperationPolicy } from '@emilia-protocol/verify/fips-mode';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const ED25519_SPKI_DER_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

const V1_COMMIT_COLUMNS = [
  'commit_id', 'entity_id', 'kid', 'principal_id', 'counterparty_entity_id',
  'delegation_id', 'action_type', 'decision', 'scope', 'max_value_usd',
  'context', 'policy_snapshot', 'nonce', 'signature', 'public_key',
  'expires_at', 'status', 'evaluation_result', 'created_at',
].sort();

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

function buildMockDb() {
  const insertFn = vi.fn(async (row) => { insertedRows.push(row); return { data: null, error: null }; });
  return {
    from: vi.fn((table) => {
      if (table === 'revoked_commit_keys') return makeChain({ data: null, error: null });
      const readChain = makeChain({ data: null, error: null });
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
// Posture fixtures -- plain data fed through the REAL checkOperationPolicy().
// ---------------------------------------------------------------------------

const INACTIVE_POSTURE = Object.freeze({
  version: 'EP-FIPS-MODE-v1',
  fips_status: 'inactive',
  fips_mode_active: false,
  openssl_version: null,
  node_version: null,
  openssl_operational: null,
  ed25519_operational: null,
  ed25519_in_validated_boundary: null,
  mldsa_backend: '@noble/post-quantum (pure JavaScript, FIPS 204 ML-DSA-65)',
  mldsa_validated_module: false,
});

/** Active FIPS mode, live OpenSSL, Ed25519 works but the boundary is declared OUTSIDE the certificate. */
const DENY_ED25519_POSTURE = Object.freeze({
  ...INACTIVE_POSTURE,
  fips_status: 'active',
  fips_mode_active: true,
  openssl_operational: true,
  ed25519_operational: true,
  ed25519_in_validated_boundary: false,
});

/** Same active posture; Ed25519 boundary declared INSIDE the certificate. */
const PERMIT_ED25519_POSTURE = Object.freeze({
  ...DENY_ED25519_POSTURE,
  ed25519_in_validated_boundary: true,
});

/** Active FIPS mode with no allow_unvalidated_mldsa acknowledgment -> ML-DSA-65 refused. */
const DENY_MLDSA_POSTURE = DENY_ED25519_POSTURE;

// Sanity: these fixtures actually exercise fips-mode.ts's real decision table,
// not a mock of it.
describe('sanity: posture fixtures drive the real checkOperationPolicy()', () => {
  it('DENY_ED25519_POSTURE is refused with the boundary reason', () => {
    const r = checkOperationPolicy('Ed25519', DENY_ED25519_POSTURE as any);
    expect(r.permitted).toBe(false);
    expect(r.reason).toBe('ed25519_outside_validated_boundary');
  });
  it('PERMIT_ED25519_POSTURE is permitted', () => {
    expect(checkOperationPolicy('Ed25519', PERMIT_ED25519_POSTURE as any).permitted).toBe(true);
  });
  it('DENY_MLDSA_POSTURE refuses ML-DSA-65 without acknowledgment', () => {
    const r = checkOperationPolicy('ML-DSA-65', DENY_MLDSA_POSTURE as any);
    expect(r.permitted).toBe(false);
    expect(r.reason).toBe('mldsa_implementation_unvalidated');
  });
});

let prevFipsRequired;
function enableFipsRequired() {
  prevFipsRequired = process.env.EP_FIPS_REQUIRED;
  process.env.EP_FIPS_REQUIRED = 'true';
}
function restoreFipsRequired() {
  if (prevFipsRequired === undefined) delete process.env.EP_FIPS_REQUIRED;
  else process.env.EP_FIPS_REQUIRED = prevFipsRequired;
}

beforeEach(() => {
  vi.clearAllMocks();
  _resetForTesting();
  clearCustodySigner();
  insertedRows = [];
  mockCanonicalEvaluate.mockResolvedValue(mockEvaluation());
  mockGetServiceClient.mockReturnValue(buildMockDb());
  delete process.env.EP_FIPS_REQUIRED;
});

afterEach(() => {
  clearCustodySigner();
  restoreFipsRequired();
});

// ===========================================================================
// 1. lib/commit.ts: _internals.consultFipsIssuancePolicy unit behavior
// ===========================================================================

describe('lib/commit.ts consultFipsIssuancePolicy (unit)', () => {
  it('is a no-op with no posture configured, even given a posture that would deny', () => {
    expect(() => _internals.consultFipsIssuancePolicy(
      'Ed25519', { fipsRequired: false }, DENY_ED25519_POSTURE as any,
    )).not.toThrow();
    expect(() => _internals.consultFipsIssuancePolicy(
      'Ed25519', null, DENY_ED25519_POSTURE as any,
    )).not.toThrow();
    expect(() => _internals.consultFipsIssuancePolicy(
      'Ed25519', undefined, DENY_ED25519_POSTURE as any,
    )).not.toThrow();
  });

  it('permits silently when configured and the policy allows', () => {
    expect(() => _internals.consultFipsIssuancePolicy(
      'Ed25519', { fipsRequired: true }, PERMIT_ED25519_POSTURE as any,
    )).not.toThrow();
  });

  it('refuses with a named reason when configured and the policy denies', () => {
    try {
      _internals.consultFipsIssuancePolicy('Ed25519', { fipsRequired: true }, DENY_ED25519_POSTURE as any);
      throw new Error('expected consultFipsIssuancePolicy to throw');
    } catch (e: any) {
      expect(e.code).toBe('fips_policy_denied');
      expect(e.status).toBe(403);
      expect(e.message).toContain('fips_policy_denied');
      expect(e.message).toContain('ed25519_outside_validated_boundary');
      expect(e.cause).toMatchObject({ alg: 'Ed25519', reason: 'ed25519_outside_validated_boundary' });
    }
  });
});

// ===========================================================================
// 2. lib/commit.ts: issueCommit() end-to-end regression
// ===========================================================================

describe('issueCommit(): byte-identical when no FIPS posture is configured', () => {
  it('writes exactly the v1 column set and an independently-verifiable signature', async () => {
    const commit = await issueCommit({ entity_id: 'entity-fips-unconfigured', action_type: 'install' });
    expect(insertedRows).toHaveLength(1);
    expect(Object.keys(insertedRows[0]).sort()).toEqual(V1_COMMIT_COLUMNS);
    expect(v1SignatureVerifiesIndependently(insertedRows[0])).toBe(true);
    expect(commit).not.toHaveProperty('hybrid_proof');
  });

  it('EP_FIPS_REQUIRED=true alone (no active FIPS runtime) does not change issuance', async () => {
    // The consult runs (fipsRequired is true), but this test host's live
    // crypto.getFips() posture is 'inactive', which checkOperationPolicy()
    // permits unconditionally for Ed25519 -- proving the flag alone is inert
    // on an ordinary, non-FIPS Node process.
    enableFipsRequired();
    const commit = await issueCommit({ entity_id: 'entity-fips-flag-only', action_type: 'install' });
    expect(v1SignatureVerifiesIndependently(insertedRows[0])).toBe(true);
    expect(commit.commit_id).toBeTruthy();
  });
});

// ===========================================================================
// 3. lib/commit-hybrid.ts: consultFipsIssuancePolicy unit behavior
// ===========================================================================

describe('lib/commit-hybrid.ts consultFipsIssuancePolicy (unit)', () => {
  it('is a no-op with EP_FIPS_REQUIRED unset, even given a denying posture', () => {
    expect(() => commitHybridConsult(['Ed25519', 'ML-DSA-65'], DENY_ED25519_POSTURE as any)).not.toThrow();
  });

  it('refuses naming the algorithm and the policy reason when configured and denied', () => {
    enableFipsRequired();
    try {
      commitHybridConsult(['Ed25519', 'ML-DSA-65'], DENY_MLDSA_POSTURE as any);
      throw new Error('expected consultFipsIssuancePolicy to throw');
    } catch (e: any) {
      expect(e.message).toContain('fips_policy_denied');
      // Ed25519 is checked first in the registered order and ALSO denied by
      // this fixture (boundary undeclared/outside) -- either failing
      // algorithm is an acceptable proof of "refuses, named, before signing".
      expect(e.message).toMatch(/Ed25519|ML-DSA-65/);
    }
  });

  it('permits silently when configured and both legs are allowed', () => {
    // ML-DSA-65 without an allow_unvalidated_mldsa acknowledgment is only
    // ever permitted when fips_status is verifiably 'inactive' -- this
    // helper does not thread an acknowledgment flag (no config surface
    // exists for it), so that is the only posture under which BOTH legs of
    // ['Ed25519', 'ML-DSA-65'] pass together. See fips-mode.ts mldsaPolicy().
    enableFipsRequired();
    expect(() => commitHybridConsult(['Ed25519', 'ML-DSA-65'], INACTIVE_POSTURE as any)).not.toThrow();
  });
});

// ===========================================================================
// 4. lib/commit-hybrid.ts: createCommitHybridProof() end-to-end
// ===========================================================================

function makeHybridFixture() {
  const ed = crypto.generateKeyPairSync('ed25519');
  const spkiB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const classical = createExternalCustodySigner({
    mode: 'hsm',
    keyId: 'pkcs11:ep-commit-fips#1',
    sign: async (bytes) => crypto.sign(null, Buffer.from(bytes), ed.privateKey).toString('base64url'),
    getPublicKey: () => spkiB64u,
  });
  const pqPair = ml_dsa65.keygen(crypto.randomBytes(32));
  const pq = softwareMldsaSigner({
    keyId: 'ep:key:commit-fips-pq#1',
    secretKey: pqPair.secretKey,
    publicKeyRawB64u: pqPair.publicKey,
  });
  return { ed, signer: hybridSigner({ classical, pq }) };
}

describe('createCommitHybridProof(): FIPS consult runs BEFORE signSet()', () => {
  it('with no posture configured, signSet still runs and the proof is unchanged', async () => {
    const fixture = makeHybridFixture();
    const signSetSpy = vi.spyOn(fixture.signer, 'signSet');
    const proof = await createCommitHybridProof({
      commit_id: 'epc_fips_test_1',
      payload: { commit_id: 'epc_fips_test_1', a: 1 },
      signer: fixture.signer,
    });
    expect(signSetSpy).toHaveBeenCalledTimes(1);
    expect(proof.signatures.map((s) => s.alg)).toEqual(['Ed25519', 'ML-DSA-65']);
  });

  it('a denied policy refuses BEFORE signSet() is ever called, naming the reason', async () => {
    enableFipsRequired();
    const fixture = makeHybridFixture();
    const signSetSpy = vi.spyOn(fixture.signer, 'signSet');
    await expect(createCommitHybridProof({
      commit_id: 'epc_fips_test_2',
      payload: { commit_id: 'epc_fips_test_2', a: 1 },
      signer: fixture.signer,
      fipsPosture: DENY_MLDSA_POSTURE as any,
    })).rejects.toThrow(/fips_policy_denied/);
    expect(signSetSpy).not.toHaveBeenCalled();
  });

  it('an allowed policy proceeds to sign both legs normally', async () => {
    // See the note in the unit-test block above: without an acknowledgment
    // flag, both legs pass together only under a verifiably-inactive posture.
    enableFipsRequired();
    const fixture = makeHybridFixture();
    const proof = await createCommitHybridProof({
      commit_id: 'epc_fips_test_3',
      payload: { commit_id: 'epc_fips_test_3', a: 1 },
      signer: fixture.signer,
      fipsPosture: INACTIVE_POSTURE as any,
    });
    expect(proof.signatures.map((s) => s.alg)).toEqual(['Ed25519', 'ML-DSA-65']);
  });
});
