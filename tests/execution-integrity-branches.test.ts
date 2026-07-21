// SPDX-License-Identifier: Apache-2.0
/**
 * EP-EXECUTION-INTEGRITY-v1 — defensive-branch + adversarial coverage suite.
 *
 * Locks the fail-closed behaviour of the EP-EXECUTION-INTEGRITY-v1 verifier and
 * its assembly helpers along the paths the primary suite does not exercise:
 *   - executedActionHash() input guard;
 *   - bindExecution() argument validation + async signer;
 *   - buildExecutionIntegrity() detached `proof`-block shape (assemble + verify);
 *   - the PIP-010 §5 object-arg calling convention (and execution.irreversible);
 *   - wrong @version, hash-only attestation, unhashable executed_action;
 *   - receipt with no action_hash to bind against;
 *   - binding_status that contradicts the hashes (status is never trusted);
 *   - executor key entirely absent from the pin set (identified-but-not-trusted);
 *   - signature/key missing, and a malformed (non-64-byte) signature.
 *
 * Executor signatures are minted LIVE (real Ed25519 over canonical bytes) using
 * the same canonicalize()/actionHash() as @emilia-protocol/issue, so the
 * negatives are genuine forgery / drift / unbinding attempts, never hand-edited
 * JSON that would have failed for an unrelated reason. Frozen Core
 * (packages/issue, packages/verify) is imported, never modified.
 */

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import {
  bindExecution,
  buildExecutionIntegrity,
  executedActionHash,
  verifyExecutionIntegrity,
  EXECUTION_INTEGRITY_VERSION,
} from '../lib/execution/integrity.js';
import executionIntegrityDefault from '../lib/execution/integrity.js';

import {
  canonicalize,
  actionHash,
  generateEd25519KeyPair,
} from '../packages/issue/index.js';

// ── reference material ───────────────────────────────────────────────────────
const APPROVED_ACTION = {
  action_type: 'payment.release',
  policy_id: 'policy.wires',
  initiator: 'ep:agent:worker',
  target_resource_id: 'wire/8841',
  amount: 2_400_000,
  currency: 'USD',
};
const APPROVED_HASH = actionHash(APPROVED_ACTION);

const DRIFTED_ACTION = {
  ...APPROVED_ACTION,
  target_resource_id: 'wire/9999',
  amount: 4_000_000,
};
const DRIFTED_HASH = actionHash(DRIFTED_ACTION);

const EXECUTOR_ID = 'ep:executor:emilia-primary';
const executorKp = generateEd25519KeyPair();

function executorSigner(kp = executorKp) {
  return {
    executorId: EXECUTOR_ID,
    publicKeyB64u: kp.publicKeyB64u,
    sign: (bytes) => crypto.sign(null, bytes, kp.privateKey).toString('base64url'),
  };
}

function pinnedKeys(kp = executorKp) {
  return { [EXECUTOR_ID]: { public_key: kp.publicKeyB64u } };
}

const RECEIPT = { action_hash: APPROVED_HASH, receipt_id: 'ep:receipt:test#1' };

// Re-sign a (possibly tampered) attestation over its canonical bytes, mirroring
// lib/execution/integrity.js executionSignedPayload() EXACTLY so a re-signed
// negative produces genuine drift / lying-hash WITHOUT an incidental signature
// break — the forensic target stays the intended check.
function reSign(att, kp = executorKp) {
  const payload = canonicalize({
    '@version': EXECUTION_INTEGRITY_VERSION,
    approved_action_hash: att.approved_action_hash,
    binding_status: att.binding_status ?? 'match',
    executed_action: att.executed_action ?? null,
    executed_action_hash: att.executed_action_hash,
    executed_at: att.executed_at ?? null,
    execution_id: att.execution_id ?? null,
    executor_id: att.executor_id ?? att.proof?.executor_key_id ?? null,
  });
  const sig = crypto.sign(null, Buffer.from(payload, 'utf8'), kp.privateKey).toString('base64url');
  return { ...att, signature_b64u: sig };
}

// ── executedActionHash() guard + happy path ──────────────────────────────────
describe('executedActionHash — input guard', () => {
  it('returns the frozen actionHash() for a canonical Action Object', () => {
    expect(executedActionHash(APPROVED_ACTION)).toBe(APPROVED_HASH);
  });

  it('throws TypeError when given a non-object (line 90 defensive guard)', () => {
    expect(() => executedActionHash(null)).toThrow(TypeError);
    expect(() => executedActionHash('not-an-object')).toThrow(/canonical executed Action Object/);
    expect(() => executedActionHash(undefined)).toThrow(TypeError);
  });
});

// ── bindExecution — argument validation + async signer ───────────────────────
describe('bindExecution — argument validation', () => {
  it('throws without approvedActionHash', () => {
    expect(() =>
      bindExecution({ executedAction: APPROVED_ACTION, signer: executorSigner() }),
    ).toThrow(/requires approvedActionHash/);
  });

  it('throws when executedAction is missing or not an object', () => {
    expect(() =>
      bindExecution({ approvedActionHash: APPROVED_HASH, executedAction: null, signer: executorSigner() }),
    ).toThrow(/requires the executed Action Object/);
    expect(() =>
      bindExecution({ approvedActionHash: APPROVED_HASH, executedAction: 'x', signer: executorSigner() }),
    ).toThrow(/requires the executed Action Object/);
  });

  it('throws when the signer is missing required members', () => {
    expect(() =>
      bindExecution({ approvedActionHash: APPROVED_HASH, executedAction: APPROVED_ACTION }),
    ).toThrow(/signer\.\{executorId,publicKeyB64u,sign\}/);
    expect(() =>
      bindExecution({
        approvedActionHash: APPROVED_HASH,
        executedAction: APPROVED_ACTION,
        signer: { executorId: EXECUTOR_ID, publicKeyB64u: executorKp.publicKeyB64u },
      }),
    ).toThrow(/signer\.\{executorId,publicKeyB64u,sign\}/);
    expect(() =>
      bindExecution({
        approvedActionHash: APPROVED_HASH,
        executedAction: APPROVED_ACTION,
        signer: { executorId: EXECUTOR_ID, sign: () => 'x' },
      }),
    ).toThrow(/signer\.\{executorId,publicKeyB64u,sign\}/);
  });

  it('called with no arguments at all throws (default-empty-object path)', () => {
    expect(() => bindExecution()).toThrow(/requires approvedActionHash/);
  });

  it('mints a verifiable attestation with an explicit executionId + executedAt', () => {
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      irreversible: true,
      signer: executorSigner(),
      executionId: 'exec-123',
      executedAt: '2026-01-02T03:04:05.000Z',
    });
    expect(att.execution_id).toBe('exec-123');
    expect(att.executed_at).toBe('2026-01-02T03:04:05.000Z');
    expect(att.irreversible).toBe(true);
    const r = verifyExecutionIntegrity(att, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(true);
  });

  it('supports an ASYNC signer (Promise.then assembly path, line 244)', async () => {
    const asyncSigner = {
      executorId: EXECUTOR_ID,
      publicKeyB64u: executorKp.publicKeyB64u,
      sign: async (bytes) => crypto.sign(null, bytes, executorKp.privateKey).toString('base64url'),
    };
    const attPromise = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      signer: asyncSigner,
    });
    expect(typeof attPromise.then).toBe('function');
    const att = await attPromise;
    expect(att.irreversible).toBe(false); // defaulted (irreversible !== true)
    const r = verifyExecutionIntegrity(att, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(true);
  });
});

// ── buildExecutionIntegrity — detached proof-block shape ─────────────────────
describe('buildExecutionIntegrity — detached `proof` block (PIP-010 §3)', () => {
  const executor = () => ({
    executor_key_id: EXECUTOR_ID,
    privateKey: executorKp.privateKey,
    publicKeyB64u: executorKp.publicKeyB64u,
  });

  it('assembles an unsigned attestation when no executor is supplied', () => {
    const att = buildExecutionIntegrity({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
    });
    expect(att['@version']).toBe(EXECUTION_INTEGRITY_VERSION);
    expect(att.binding_status).toBe('match');
    expect(att.proof).toBeUndefined();
    expect(att.executed_action_hash).toBe(APPROVED_HASH);
  });

  it('a well-formed proof-block attestation verifies valid:true under the pinned key', () => {
    const att = buildExecutionIntegrity({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      executor: executor(),
      executionId: 'exec-proof-1',
      executedAt: '2026-02-03T00:00:00.000Z',
    });
    expect(att.proof.algorithm).toBe('Ed25519');
    expect(att.proof.executor_key_id).toBe(EXECUTOR_ID);
    expect(att.execution_id).toBe('exec-proof-1');
    expect(att.executed_at).toBe('2026-02-03T00:00:00.000Z');
    const r = verifyExecutionIntegrity(att, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(true);
    expect(r.errors).toEqual([]);
  });

  it('honors a custom algorithm label on the proof block', () => {
    const att = buildExecutionIntegrity({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      executor: { ...executor(), algorithm: 'Ed25519-custom' },
    });
    expect(att.proof.algorithm).toBe('Ed25519-custom');
  });

  it('records binding_status="drift" when the executed action differs from approved', () => {
    const att = buildExecutionIntegrity({
      approvedActionHash: APPROVED_HASH,
      executedAction: DRIFTED_ACTION,
      executor: executor(),
    });
    expect(att.binding_status).toBe('drift');
    // verifier still fails closed on the drift even though the proof is genuine.
    const r = verifyExecutionIntegrity(att, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.executed_hash_matches_approved).toBe(false);
  });

  it('a proof-block signature over OTHER bytes fails signature_binds_attestation', () => {
    const att = buildExecutionIntegrity({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      executor: executor(),
      executedAt: '2026-02-03T00:00:00.000Z',
    });
    // Tamper a signed field WITHOUT re-signing the proof — drift + self-consistency
    // still pass, isolating the binding failure on the proof shape.
    const tampered = { ...att, executed_at: '1999-01-01T00:00:00.000Z' };
    const r = verifyExecutionIntegrity(tampered, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.signature_binds_attestation).toBe(false);
    expect(r.checks.executed_hash_matches_approved).toBe(true);
    expect(r.checks.executed_hash_self_consistent).toBe(true);
  });

  it('a proof-block key the verifier never pinned is rejected (no pin entry)', () => {
    const att = buildExecutionIntegrity({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      executor: executor(),
    });
    // empty pin set => executorKeys[keyId] is undefined => `!pinned` branch.
    const r = verifyExecutionIntegrity(att, RECEIPT, { executorKeys: {} });
    expect(r.valid).toBe(false);
    expect(r.checks.executor_key_pinned).toBe(false);
    expect(r.errors.some((e) => /no pinned key/.test(e))).toBe(true);
  });
});

// ── object-arg calling convention (PIP-010 §5) ───────────────────────────────
describe('verifyExecutionIntegrity — object-arg convention (B)', () => {
  it('accepts a well-formed attestation via { approvedActionHash, attestation }', () => {
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      signer: executorSigner(),
    });
    const r = verifyExecutionIntegrity(
      { approvedActionHash: APPROVED_HASH, executedAction: APPROVED_ACTION, attestation: att },
      { executorKeys: pinnedKeys() },
    );
    expect(r.valid).toBe(true);
  });

  it('fails closed on a missing attestation supplied through the object-arg', () => {
    const r = verifyExecutionIntegrity(
      { approvedActionHash: APPROVED_HASH, executedAction: APPROVED_ACTION, attestation: null },
      { executorKeys: pinnedKeys() },
    );
    expect(r.valid).toBe(false);
    expect(r.checks.attestation_present).toBe(false);
    expect(r.binding_status).toBeNull();
  });

  it('object-arg with execution.irreversible:false (producer self-label) stays fail-closed when no attestation', () => {
    const r = verifyExecutionIntegrity(
      {
        approvedActionHash: APPROVED_HASH,
        executedAction: APPROVED_ACTION,
        attestation: null,
        execution: { irreversible: false },
      },
      { executorKeys: pinnedKeys() },
    );
    // producer's own irreversible:false can NEVER drop the gate.
    expect(r.valid).toBe(false);
    expect(r.checks.attestation_present).toBe(false);
  });

  it('object-arg detects drift against the supplied approvedActionHash', () => {
    const att = reSign(
      bindExecution({
        approvedActionHash: APPROVED_HASH,
        executedAction: APPROVED_ACTION,
        signer: executorSigner(),
      }),
    );
    const drifted = reSign({ ...att, executed_action: DRIFTED_ACTION, executed_action_hash: DRIFTED_HASH });
    const r = verifyExecutionIntegrity(
      { approvedActionHash: APPROVED_HASH, attestation: drifted },
      { executorKeys: pinnedKeys() },
    );
    expect(r.valid).toBe(false);
    expect(r.checks.executed_hash_matches_approved).toBe(false);
  });

  it('object-arg carrying only { execution } with reversibility asserted accepts a missing attestation', () => {
    const r = verifyExecutionIntegrity(
      { approvedActionHash: APPROVED_HASH, execution: { irreversible: false } },
      { executorKeys: pinnedKeys(), reversibilityAsserted: () => true },
    );
    expect(r.valid).toBe(true);
    expect(r.binding_status).toBeNull();
  });
});

// ── version + self-consistency + receipt binding ─────────────────────────────
describe('verifyExecutionIntegrity — version + hash defensive branches', () => {
  it('rejects an unsupported @version and surfaces its binding_status', () => {
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      signer: executorSigner(),
    });
    const wrongVersion = { ...att, '@version': 'EP-EXECUTION-INTEGRITY-v999' };
    const r = verifyExecutionIntegrity(wrongVersion, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.version).toBe(false);
    expect(r.binding_status).toBe('match'); // carried through even on early return
    expect(r.errors.some((e) => /unsupported version/.test(e))).toBe(true);
  });

  it('rejects a version-less attestation arriving via the positional convention', () => {
    // No @version and not an object-arg shape: treated as a bad attestation.
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      signer: executorSigner(),
    });
    const noVersion = { ...att };
    delete noVersion['@version'];
    const r = verifyExecutionIntegrity(noVersion, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.version).toBe(false);
  });

  it('FAILS CLOSED (does not throw) on an executed_action that is not canonicalizable', () => {
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      signer: executorSigner(),
    });
    // A BigInt member cannot be canonicalized (JSON.stringify throws on BigInt).
    // The verifier's contract is FAIL-CLOSED + "never throws" (file header, and the
    // try/catch at line 389 around actionHash). A non-conforming evidence object
    // MUST yield { valid:false }, never an uncaught exception. This is the priority
    // "fail-closed on non-conforming evidence" path.
    const broken = { ...att, executed_action: { amount: 1n } };
    let result;
    expect(() => {
      result = verifyExecutionIntegrity(broken, RECEIPT, { executorKeys: pinnedKeys() });
    }).not.toThrow();
    expect(result.valid).toBe(false);
    // The self-consistency check itself DOES catch and flag the unhashable action.
    expect(result.checks.executed_hash_self_consistent).toBe(false);
    expect(result.errors.some((e) => /not hashable/.test(e))).toBe(true);
  });

  it('hash-only attestation (no executed_action) still binds via the declared hash', () => {
    // PIP-010 allows a hash-only attestation; self-consistency is vacuous but the
    // drift check on the declared hash still applies. Mint a proof-block hash-only
    // attestation by signing the matching declared hash, then dropping the object.
    const full = buildExecutionIntegrity({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      executor: {
        executor_key_id: EXECUTOR_ID,
        privateKey: executorKp.privateKey,
        publicKeyB64u: executorKp.publicKeyB64u,
      },
    });
    // Build a fresh hash-only attestation whose signed payload omits executed_action
    // (executed_action ?? null) — recompute the signature over the null-object form.
    const hashOnly = { ...full };
    delete hashOnly.executed_action;
    const payload = canonicalize({
      '@version': EXECUTION_INTEGRITY_VERSION,
      approved_action_hash: hashOnly.approved_action_hash,
      binding_status: hashOnly.binding_status ?? 'match',
      executed_action: null,
      executed_action_hash: hashOnly.executed_action_hash,
      executed_at: hashOnly.executed_at ?? null,
      execution_id: hashOnly.execution_id ?? null,
      executor_id: hashOnly.executor_id ?? hashOnly.proof?.executor_key_id ?? null,
    });
    hashOnly.proof = {
      ...hashOnly.proof,
      signature_b64u: crypto
        .sign(null, Buffer.from(payload, 'utf8'), executorKp.privateKey)
        .toString('base64url'),
    };
    const r = verifyExecutionIntegrity(hashOnly, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(true);
    expect(r.checks.executed_hash_self_consistent).toBe(true); // vacuous, stays true
  });

  it('rejects when the receipt carries NO action_hash to bind against (line 404)', () => {
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      signer: executorSigner(),
    });
    const r = verifyExecutionIntegrity(att, { receipt_id: 'no-hash' }, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.executed_hash_matches_approved).toBe(false);
    expect(r.errors.some((e) => /no action_hash to bind against/.test(e))).toBe(true);
  });

  it('rejects with an empty/undefined receipt entirely (positional, arg2 missing)', () => {
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      signer: executorSigner(),
    });
    const r = verifyExecutionIntegrity(att, undefined, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.executed_hash_matches_approved).toBe(false);
  });
});

// ── binding_status is never trusted ──────────────────────────────────────────
describe('verifyExecutionIntegrity — binding_status contradiction (status untrusted)', () => {
  it('rejects a "drift" binding_status even when the hashes actually match', () => {
    // Hashes match (no real drift) but the producer self-labels "drift": status is
    // not trusted, so the verifier rejects on the contradiction (line 411 branch).
    const att = reSign({
      '@version': EXECUTION_INTEGRITY_VERSION,
      executor_id: EXECUTOR_ID,
      executor_public_key: executorKp.publicKeyB64u,
      approved_action_hash: APPROVED_HASH,
      executed_action: APPROVED_ACTION,
      executed_action_hash: APPROVED_HASH,
      binding_status: 'drift',
      executed_at: '2026-01-01T00:00:00.000Z',
    });
    const r = verifyExecutionIntegrity(att, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.executed_hash_matches_approved).toBe(false);
    expect(r.errors.some((e) => /contradicts the hashes/.test(e))).toBe(true);
  });

  it('rejects a "match" binding_status that contradicts a real drift', () => {
    const att = reSign({
      '@version': EXECUTION_INTEGRITY_VERSION,
      executor_id: EXECUTOR_ID,
      executor_public_key: executorKp.publicKeyB64u,
      approved_action_hash: APPROVED_HASH,
      executed_action: DRIFTED_ACTION,
      executed_action_hash: DRIFTED_HASH,
      binding_status: 'match', // lies: actually a drift
      executed_at: '2026-01-01T00:00:00.000Z',
    });
    const r = verifyExecutionIntegrity(att, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.executed_hash_matches_approved).toBe(false);
  });
});

// ── pin set / key-binding negatives ──────────────────────────────────────────
describe('verifyExecutionIntegrity — executor key pinning negatives', () => {
  it('rejects when executorKeys is omitted entirely (no pin for the key, line 420)', () => {
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      signer: executorSigner(),
    });
    // No opts at all -> executorKeys defaults to {} -> `!pinned`.
    const r = verifyExecutionIntegrity(att, RECEIPT);
    expect(r.valid).toBe(false);
    expect(r.checks.executor_key_pinned).toBe(false);
    expect(r.errors.some((e) => /identified but not trusted/.test(e))).toBe(true);
  });

  it('rejects a presented key that differs from the pinned key (mismatch branch)', () => {
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      signer: executorSigner(),
    });
    const otherKp = generateEd25519KeyPair();
    const r = verifyExecutionIntegrity(att, RECEIPT, {
      executorKeys: { [EXECUTOR_ID]: { public_key: otherKp.publicKeyB64u } },
    });
    expect(r.valid).toBe(false);
    expect(r.checks.executor_key_pinned).toBe(false);
    expect(r.errors.some((e) => /does not match the pinned key/.test(e))).toBe(true);
  });
});

// ── signature/key-missing + malformed signature ──────────────────────────────
describe('verifyExecutionIntegrity — signature/key missing + malformed', () => {
  it('flags "signature or key missing" when the attestation has no signature at all (line 437)', () => {
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      signer: executorSigner(),
    });
    // Drop the signature; key is pinned (verifyKey truthy) but signatureB64u null.
    const noSig = { ...att };
    delete noSig.signature_b64u;
    const r = verifyExecutionIntegrity(noSig, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.executor_signature_valid).toBe(false);
    expect(r.errors.some((e) => /signature or key missing/.test(e))).toBe(true);
  });

  it('flags "signature or key missing" when no key is pinned AND the presented key is absent', () => {
    // proof-less attestation with no executor_public_key and no pin: verifyKey
    // becomes undefined -> the !verifyKey branch (line 437) with a signature set.
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      signer: executorSigner(),
    });
    const noKey = { ...att };
    delete noKey.executor_public_key;
    const r = verifyExecutionIntegrity(noKey, RECEIPT, { executorKeys: {} });
    expect(r.valid).toBe(false);
    expect(r.checks.executor_key_pinned).toBe(false);
    expect(r.checks.executor_signature_valid).toBe(false);
    expect(r.errors.some((e) => /signature or key missing/.test(e))).toBe(true);
  });

  it('a forged but MALFORMED (non-64-byte) signature fails as a plain signature failure, not a binding claim', () => {
    // isWellFormedSignature() is false (decoded length != 64), so the verifier
    // reports executor_signature_valid=false WITHOUT the binding-mismatch flag.
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      signer: executorSigner(),
    });
    const malformed = { ...att, signature_b64u: Buffer.from('short').toString('base64url') };
    const r = verifyExecutionIntegrity(malformed, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.executor_signature_valid).toBe(false);
    // malformed (not well-formed) => the binding-mismatch branch is NOT taken.
    expect(r.checks.signature_binds_attestation).toBe(true);
  });

  it('a well-formed 64-byte signature that verifies nowhere flags BOTH math and binding', () => {
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      signer: executorSigner(),
    });
    // 64 random bytes: well-formed length, but a genuine forgery that verifies
    // under no key -> both signature_binds_attestation and executor_signature_valid fail.
    const forged64 = { ...att, signature_b64u: crypto.randomBytes(64).toString('base64url') };
    const r = verifyExecutionIntegrity(forged64, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.executor_signature_valid).toBe(false);
    expect(r.checks.signature_binds_attestation).toBe(false);
  });
});

// ── signingMaterial fallback shapes + payload null-coalescing branches ───────
describe('verifyExecutionIntegrity — signing-material fallback shapes', () => {
  it('a proof block with empty members falls back to top-level executor fields', () => {
    // proof present but its keyId/public_key/signature_b64u are absent, so
    // signingMaterial() falls back to the top-level executor_id / executor_public_key
    // / (signature_b64u ?? null). Sign over the canonical payload so the binding holds.
    const base = {
      '@version': EXECUTION_INTEGRITY_VERSION,
      executor_id: EXECUTOR_ID,
      executor_public_key: executorKp.publicKeyB64u,
      approved_action_hash: APPROVED_HASH,
      executed_action: APPROVED_ACTION,
      executed_action_hash: APPROVED_HASH,
      binding_status: 'match',
      executed_at: '2026-03-03T00:00:00.000Z',
    };
    const payload = canonicalize({
      '@version': EXECUTION_INTEGRITY_VERSION,
      approved_action_hash: base.approved_action_hash,
      binding_status: base.binding_status,
      executed_action: base.executed_action,
      executed_action_hash: base.executed_action_hash,
      executed_at: base.executed_at,
      execution_id: null,
      executor_id: base.executor_id,
    });
    const sig = crypto.sign(null, Buffer.from(payload, 'utf8'), executorKp.privateKey).toString('base64url');
    // Empty proof object: every member undefined -> signingMaterial falls through.
    // The signature lives at the top level (signature_b64u), which the proof branch
    // does NOT read, so this must fail closed on a missing proof signature.
    const att = { ...base, proof: {}, signature_b64u: sig };
    const r = verifyExecutionIntegrity(att, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.executor_signature_valid).toBe(false);
    // key still resolves through the fallback (top-level executor_public_key).
    expect(r.checks.executor_key_pinned).toBe(true);
  });

  it('proof block carrying only signature_b64u falls back to top-level id/key (lines 157/158/117)', () => {
    // proof present but missing executor_key_id + public_key: signingMaterial()
    // falls back to att.executor_id / att.executor_public_key; the signed payload
    // resolves executor_id via att.executor_id (top-level present). Sign over the
    // canonical payload so the binding actually holds and we reach valid:true.
    const base = {
      '@version': EXECUTION_INTEGRITY_VERSION,
      executor_id: EXECUTOR_ID,
      executor_public_key: executorKp.publicKeyB64u,
      approved_action_hash: APPROVED_HASH,
      executed_action: APPROVED_ACTION,
      executed_action_hash: APPROVED_HASH,
      binding_status: 'match',
      executed_at: '2026-05-05T00:00:00.000Z',
    };
    const payload = canonicalize({
      '@version': EXECUTION_INTEGRITY_VERSION,
      approved_action_hash: base.approved_action_hash,
      binding_status: base.binding_status,
      executed_action: base.executed_action,
      executed_action_hash: base.executed_action_hash,
      executed_at: base.executed_at,
      execution_id: null,
      executor_id: base.executor_id,
    });
    const sig = crypto.sign(null, Buffer.from(payload, 'utf8'), executorKp.privateKey).toString('base64url');
    const att = { ...base, proof: { signature_b64u: sig } };
    const r = verifyExecutionIntegrity(att, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(true);
    expect(r.checks.executor_key_pinned).toBe(true);
    expect(r.checks.executor_signature_valid).toBe(true);
  });

  it('proof block keyed by executor_key_id with NO top-level executor_id (line 117 proof fallback)', () => {
    // No top-level executor_id: the signed payload must resolve executor_id from
    // att.proof.executor_key_id. Pin the key under that id.
    const base = {
      '@version': EXECUTION_INTEGRITY_VERSION,
      approved_action_hash: APPROVED_HASH,
      executed_action: APPROVED_ACTION,
      executed_action_hash: APPROVED_HASH,
      binding_status: 'match',
      executed_at: '2026-06-06T00:00:00.000Z',
    };
    const payload = canonicalize({
      '@version': EXECUTION_INTEGRITY_VERSION,
      approved_action_hash: base.approved_action_hash,
      binding_status: base.binding_status,
      executed_action: base.executed_action,
      executed_action_hash: base.executed_action_hash,
      executed_at: base.executed_at,
      execution_id: null,
      executor_id: EXECUTOR_ID, // resolved from proof.executor_key_id
    });
    const sig = crypto.sign(null, Buffer.from(payload, 'utf8'), executorKp.privateKey).toString('base64url');
    const att = {
      ...base,
      proof: {
        executor_key_id: EXECUTOR_ID,
        public_key: executorKp.publicKeyB64u,
        signature_b64u: sig,
      },
    };
    const r = verifyExecutionIntegrity(att, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(true);
    expect(r.checks.executor_signature_valid).toBe(true);
  });

  it('omitting binding_status entirely leaves it null in the result (?? null branches)', () => {
    // Sign a payload whose binding_status defaults to "match" (att.binding_status
    // is absent), so the signature binds; the verifier reports binding_status:null.
    const base = {
      '@version': EXECUTION_INTEGRITY_VERSION,
      executor_id: EXECUTOR_ID,
      executor_public_key: executorKp.publicKeyB64u,
      approved_action_hash: APPROVED_HASH,
      executed_action: APPROVED_ACTION,
      executed_action_hash: APPROVED_HASH,
      // binding_status intentionally omitted -> defaults to 'match' in payload.
    };
    const payload = canonicalize({
      '@version': EXECUTION_INTEGRITY_VERSION,
      approved_action_hash: base.approved_action_hash,
      binding_status: 'match',
      executed_action: base.executed_action,
      executed_action_hash: base.executed_action_hash,
      executed_at: null,
      execution_id: null,
      executor_id: base.executor_id,
    });
    const sig = crypto.sign(null, Buffer.from(payload, 'utf8'), executorKp.privateKey).toString('base64url');
    const att = { ...base, signature_b64u: sig };
    const r = verifyExecutionIntegrity(att, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(true);
    expect(r.binding_status).toBeNull();
  });

  it('wrong-version attestation with no binding_status returns binding_status:null (line 379)', () => {
    const att = {
      '@version': 'EP-EXECUTION-INTEGRITY-vX',
      executor_id: EXECUTOR_ID,
      executor_public_key: executorKp.publicKeyB64u,
      approved_action_hash: APPROVED_HASH,
      executed_action: APPROVED_ACTION,
      executed_action_hash: APPROVED_HASH,
      // no binding_status
    };
    const r = verifyExecutionIntegrity(att, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.version).toBe(false);
    expect(r.binding_status).toBeNull();
  });

  it('object-arg with NO opts argument at all (arg2 falls back to {})', () => {
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      signer: executorSigner(),
    });
    // object-arg, no second arg -> opts = { ...(undefined || {}) } and executorKeys = {}.
    const r = verifyExecutionIntegrity({ approvedActionHash: APPROVED_HASH, attestation: att });
    expect(r.valid).toBe(false);
    // no executorKeys pinned -> key-pinning fails closed.
    expect(r.checks.executor_key_pinned).toBe(false);
  });

  it('isWellFormedSignature receives a falsy signature via a null signature field', () => {
    // signature_b64u explicitly null -> String(null || "") -> length 0 -> not 64.
    // Reaches the false branch through the missing-signature path (line 437).
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      signer: executorSigner(),
    });
    const r = verifyExecutionIntegrity({ ...att, signature_b64u: null }, RECEIPT, {
      executorKeys: pinnedKeys(),
    });
    expect(r.valid).toBe(false);
    expect(r.checks.executor_signature_valid).toBe(false);
  });
});

// ── verifyEd25519 catch path via a structurally invalid pinned key ───────────
describe('verifyExecutionIntegrity — malformed pinned key (verifyEd25519 catch, line 139)', () => {
  it('a non-DER pinned public key makes signature verification fail closed without throwing', () => {
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      signer: executorSigner(),
    });
    // Pin a base64url string of GARBAGE bytes that is not valid SPKI DER. Both
    // publicKeyB64u and signatureB64u are truthy, so verifyEd25519 enters the try
    // and crypto.createPublicKey THROWS -> caught -> returns false (no crash).
    const garbageKey = Buffer.from('not-a-real-spki-der-public-key-blob').toString('base64url');
    let result;
    expect(() => {
      result = verifyExecutionIntegrity(att, RECEIPT, {
        executorKeys: { [EXECUTOR_ID]: { public_key: garbageKey } },
      });
    }).not.toThrow();
    expect(result.valid).toBe(false);
    // presented key (real) != pinned (garbage) -> pin mismatch fails first,
    // and the garbage key also breaks signature verification.
    expect(result.checks.executor_key_pinned).toBe(false);
    expect(result.checks.executor_signature_valid).toBe(false);
  });

  it('a garbage pinned key that EQUALS the presented key still fails closed in verifyEd25519', () => {
    // Force pinned === presented so the pin-mismatch branch is skipped and the
    // ONLY failure is verifyEd25519 throwing inside createPublicKey (line 139).
    const garbageKey = Buffer.from('garbage-key-bytes-not-valid-der').toString('base64url');
    const att = {
      '@version': EXECUTION_INTEGRITY_VERSION,
      executor_id: EXECUTOR_ID,
      executor_public_key: garbageKey, // presented == pinned (both garbage)
      approved_action_hash: APPROVED_HASH,
      executed_action: APPROVED_ACTION,
      executed_action_hash: APPROVED_HASH,
      binding_status: 'match',
      executed_at: '2026-04-04T00:00:00.000Z',
      signature_b64u: crypto.randomBytes(64).toString('base64url'), // well-formed length
    };
    let result;
    expect(() => {
      result = verifyExecutionIntegrity(att, RECEIPT, {
        executorKeys: { [EXECUTOR_ID]: { public_key: garbageKey } },
      });
    }).not.toThrow();
    expect(result.valid).toBe(false);
    expect(result.checks.executor_key_pinned).toBe(true); // pinned === presented
    expect(result.checks.executor_signature_valid).toBe(false);
  });
});

// ── default export surface ───────────────────────────────────────────────────
describe('module default export', () => {
  it('default export carries the same callable surface as the named exports', () => {
    expect(executionIntegrityDefault.EXECUTION_INTEGRITY_VERSION).toBe(EXECUTION_INTEGRITY_VERSION);
    expect(executionIntegrityDefault.bindExecution).toBe(bindExecution);
    expect(executionIntegrityDefault.buildExecutionIntegrity).toBe(buildExecutionIntegrity);
    expect(executionIntegrityDefault.executedActionHash).toBe(executedActionHash);
    expect(executionIntegrityDefault.verifyExecutionIntegrity).toBe(verifyExecutionIntegrity);
  });
});
