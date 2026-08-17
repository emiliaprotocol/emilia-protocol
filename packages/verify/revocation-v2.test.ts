// SPDX-License-Identifier: Apache-2.0
//
// EP-REVOCATION-v2 hybrid verifier test: the reference hybrid migration.
//
// Builds a REAL Ed25519 + ML-DSA-65 signed revocation statement over an exact
// target, then asserts the fail-closed predicate. The hostile half is the
// point: leg stripping, set narrowing, an Ed448 key masquerading as the
// Ed25519 half, algorithm relabelling, key substitution, and a v1 verifier
// handed a v2 statement.
//
// The PQ leg runs for real. This suite FAILS LOUDLY if @noble/post-quantum is
// missing rather than silently skipping, so a green run means ML-DSA-65
// actually verified.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { canonicalize } from './index.js';
import {
  REVOCATION_VERSION,
  REVOCATION_V2_VERSION,
  REVOCATION_V2_REQUIRED_ALGORITHMS,
  revocationV2SignedPayload,
  verifyRevocation,
  verifyRevocationV2,
  verifyRevocationStatement,
  isRevoked,
  isRevokedAny,
} from './revocation.js';
import { signAgileSet } from './pq-signature-agility.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const TARGET = { target_type: 'receipt', target_id: 'rcpt_v2_abc', action_hash: 'sha256:' + 'b'.repeat(64) };
const OTHER_ACTION_HASH = 'sha256:' + 'c'.repeat(64);
const REVOKER_ID = 'ep:revoker:v2_operator';
const NOW = '2026-08-17T12:00:00.000Z';

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const edKeyId = `ep:revoker-key:sha256:${crypto.createHash('sha256')
  .update(Buffer.from(edPubB64u, 'base64url')).digest('hex')}`;

const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const pqKeyId = `ep:revoker-key:ml-dsa-65:sha256:${crypto.createHash('sha256')
  .update(Buffer.from(pqPubB64u, 'base64url')).digest('hex')}`;

const PINS = { [REVOKER_ID]: { public_key: edPubB64u, pq_public_key: pqPubB64u } };
const OPTS = { revokerKeys: PINS, now: NOW };

/** Mint a real v2 statement; overrides let a test tamper AFTER signing. */
async function buildV2({
  revokerId = REVOKER_ID,
  revokedAt = '2026-06-20T12:00:00.000Z',
  reason = 'authority withdrawn',
  actionHash = TARGET.action_hash,
  requiredAlgorithms = [...REVOCATION_V2_REQUIRED_ALGORITHMS],
} = {}) {
  const fields = {
    '@version': REVOCATION_V2_VERSION,
    target_type: TARGET.target_type,
    target_id: TARGET.target_id,
    action_hash: actionHash,
    revoker_id: revokerId,
    revoked_at: revokedAt,
    reason,
  };
  const bytes = revocationV2SignedPayload(fields, REVOCATION_V2_REQUIRED_ALGORITHMS);
  const signatures = await signAgileSet(new Uint8Array(bytes), [
    { alg: 'Ed25519', private_key: ed.privateKey, key_id: edKeyId },
    { alg: 'ML-DSA-65', private_key: Buffer.from(pq.secretKey).toString('base64url'), key_id: pqKeyId },
  ]);
  const byAlg = new Map(signatures.map((s) => [s.alg, s]));
  return {
    ...fields,
    proof: {
      profile: REVOCATION_V2_VERSION,
      required_algorithms: requiredAlgorithms,
      revoker_key_id: edKeyId,
      public_key: edPubB64u,
      pq_key_id: pqKeyId,
      pq_public_key: pqPubB64u,
      signatures: [byAlg.get('Ed25519'), byAlg.get('ML-DSA-65')],
    },
  };
}

/** A real, valid EP-REVOCATION-v1 statement over the same target. */
function buildV1() {
  const fields = {
    '@version': REVOCATION_VERSION,
    action_hash: TARGET.action_hash,
    reason: 'authority withdrawn',
    revoked_at: '2026-06-20T12:00:00.000Z',
    revoker_id: REVOKER_ID,
    target_id: TARGET.target_id,
    target_type: TARGET.target_type,
  };
  const sig = crypto.sign(null, Buffer.from(canonicalize(fields), 'utf8'), ed.privateKey).toString('base64url');
  return {
    '@version': REVOCATION_VERSION,
    target_type: TARGET.target_type,
    target_id: TARGET.target_id,
    action_hash: TARGET.action_hash,
    revoker_id: REVOKER_ID,
    revoked_at: '2026-06-20T12:00:00.000Z',
    reason: 'authority withdrawn',
    proof: {
      algorithm: 'Ed25519',
      revoker_key_id: edKeyId,
      signature_b64u: sig,
      public_key: edPubB64u,
    },
  };
}

// --- honesty gate: the PQ leg must actually run ------------------------------

test('real ML-DSA-65 backend is available for this suite', () => {
  assert.ok(typeof ml_dsa65?.sign === 'function', 'expected @noble/post-quantum ml_dsa65 to be resolvable; PQ tests must run for real');
});

// --- happy path ---------------------------------------------------------------

test('a real hybrid statement verifies under both pinned keys', async () => {
  const res = await verifyRevocationV2(TARGET, await buildV2(), OPTS);
  assert.equal(res.valid, true, res.errors.join(' | '));
  assert.equal(res.checks.algorithm_set, true);
  assert.equal(res.checks.legs_present, true);
  assert.equal(res.checks.revoker_signature_valid, true);
});

test('the committed bytes carry the required algorithm set', async () => {
  const stmt = await buildV2();
  const bytes = revocationV2SignedPayload(stmt).toString('utf8');
  assert.ok(bytes.includes('"required_algorithms":["Ed25519","ML-DSA-65"]'), bytes);
  assert.ok(bytes.includes(`"@version":"${REVOCATION_V2_VERSION}"`), bytes);
});

// --- v1 / v2 compatibility ----------------------------------------------------

test('the v1 verifier refuses a v2 statement CLEANLY on the version marker', async () => {
  const res = verifyRevocation(TARGET, await buildV2(), { revokerKeys: { [REVOKER_ID]: { public_key: edPubB64u } }, now: NOW });
  assert.equal(res.valid, false);
  assert.equal(res.checks.version, false);
  assert.ok(res.errors.includes(`unsupported version: ${REVOCATION_V2_VERSION}`), res.errors.join(' | '));
  // It refuses, it does not throw, and it never reports a partial pass.
  assert.equal(typeof res.checks.revoker_signature_valid, 'boolean');
});

test('the v1 verifier still accepts a v1 statement, unchanged', () => {
  const res = verifyRevocation(TARGET, buildV1(), { revokerKeys: { [REVOKER_ID]: { public_key: edPubB64u } }, now: NOW });
  assert.equal(res.valid, true, res.errors.join(' | '));
});

test('the v2 verifier refuses a v1 statement on the version marker', async () => {
  const res = await verifyRevocationV2(TARGET, buildV1(), OPTS);
  assert.equal(res.valid, false);
  assert.equal(res.checks.version, false);
  assert.ok(res.errors.includes(`unsupported version: ${REVOCATION_VERSION}`), res.errors.join(' | '));
});

test('verifyRevocationStatement routes each version to its own verifier', async () => {
  assert.equal((await verifyRevocationStatement(TARGET, await buildV2(), OPTS)).valid, true);
  assert.equal((await verifyRevocationStatement(TARGET, buildV1(), { revokerKeys: { [REVOKER_ID]: { public_key: edPubB64u } }, now: NOW })).valid, true);
});

test('isRevoked (v1, sync) ignores a v2 statement; isRevokedAny honours both', async () => {
  const v2 = await buildV2();
  assert.equal(isRevoked(TARGET, [v2], OPTS), false);
  assert.equal(await isRevokedAny(TARGET, [v2], OPTS), true);
  assert.equal(await isRevokedAny(TARGET, [buildV1()], { revokerKeys: { [REVOKER_ID]: { public_key: edPubB64u } }, now: NOW }), true);
});

// --- anti-stripping -----------------------------------------------------------

test('LEG STRIPPING: removing the ML-DSA leg (set intact) refuses structurally', async () => {
  const stmt = await buildV2();
  stmt.proof.signatures = stmt.proof.signatures.filter((s) => s.alg === 'Ed25519');
  const res = await verifyRevocationV2(TARGET, stmt, OPTS);
  assert.equal(res.valid, false);
  assert.equal(res.checks.legs_present, false);
  assert.equal(res.checks.revoker_signature_valid, false);
  assert.ok(res.errors.some((e) => /missing required ML-DSA-65 signature/.test(e)), res.errors.join(' | '));
});

test('LEG STRIPPING: removing the Ed25519 leg refuses too (neither leg alone suffices)', async () => {
  const stmt = await buildV2();
  stmt.proof.signatures = stmt.proof.signatures.filter((s) => s.alg === 'ML-DSA-65');
  const res = await verifyRevocationV2(TARGET, stmt, OPTS);
  assert.equal(res.valid, false);
  assert.equal(res.checks.legs_present, false);
});

test('SET NARROWING: dropping the PQ leg AND narrowing required_algorithms fails BOTH structurally and cryptographically', async () => {
  const stmt = await buildV2({ requiredAlgorithms: ['Ed25519'] });
  stmt.proof.signatures = stmt.proof.signatures.filter((s) => s.alg === 'Ed25519');
  const res = await verifyRevocationV2(TARGET, stmt, OPTS);
  assert.equal(res.valid, false);
  assert.equal(res.checks.algorithm_set, false);
  assert.equal(res.checks.legs_present, false);

  // The cryptographic half, proved independently of the structural refusal:
  // the surviving Ed25519 signature was made over bytes committing to the FULL
  // set, so it cannot verify over the narrowed bytes.
  const narrowedBytes = Buffer.from(canonicalize({
    '@version': REVOCATION_V2_VERSION,
    action_hash: stmt.action_hash,
    reason: stmt.reason,
    required_algorithms: ['Ed25519'],
    revoked_at: stmt.revoked_at,
    revoker_id: stmt.revoker_id,
    target_id: stmt.target_id,
    target_type: stmt.target_type,
  }), 'utf8');
  const survivingSig = Buffer.from(stmt.proof.signatures[0].sig, 'base64url');
  assert.equal(
    crypto.verify(null, narrowedBytes, ed.publicKey, survivingSig),
    false,
    'narrowing the committed set must break the surviving signature',
  );
});

test('SET WIDENING: an extra algorithm in required_algorithms refuses', async () => {
  const stmt = await buildV2({ requiredAlgorithms: ['Ed25519', 'ML-DSA-65', 'Ed448'] });
  const res = await verifyRevocationV2(TARGET, stmt, OPTS);
  assert.equal(res.valid, false);
  assert.equal(res.checks.algorithm_set, false);
});

test('DUPLICATE ALGORITHM: two entries for one algorithm refuse', async () => {
  const stmt = await buildV2();
  stmt.proof.signatures = [stmt.proof.signatures[0], stmt.proof.signatures[0]];
  const res = await verifyRevocationV2(TARGET, stmt, OPTS);
  assert.equal(res.valid, false);
  assert.equal(res.checks.legs_present, false);
  assert.ok(res.errors.some((e) => /duplicate signature/.test(e)), res.errors.join(' | '));
});

// --- masquerade ---------------------------------------------------------------

test('ED448 MASQUERADE: an Ed448 SPKI presented and pinned as the Ed25519 half refuses', async () => {
  const ed448 = crypto.generateKeyPairSync('ed448');
  const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
  const stmt = await buildV2();
  stmt.proof.public_key = ed448Pub;
  const res = await verifyRevocationV2(TARGET, stmt, {
    revokerKeys: { [REVOKER_ID]: { public_key: ed448Pub, pq_public_key: pqPubB64u } },
    now: NOW,
  });
  assert.equal(res.valid, false);
  // Curve pinning refuses twice over: the key identifier cannot be derived from
  // a non-Ed25519 SPKI, and the agility module will not verify under it.
  assert.equal(res.checks.revoker_key_bound, false);
  assert.equal(res.checks.revoker_signature_valid, false);
});

test('ALGORITHM RELABELLING: calling the Ed25519 leg "Ed448" refuses (closed registry)', async () => {
  const stmt = await buildV2();
  stmt.proof.signatures = stmt.proof.signatures.map(
    (s) => (s.alg === 'Ed25519' ? { ...s, alg: 'Ed448' } : s),
  );
  const res = await verifyRevocationV2(TARGET, stmt, OPTS);
  assert.equal(res.valid, false);
  assert.equal(res.checks.legs_present, false);
  assert.ok(res.errors.some((e) => /unexpected algorithm "Ed448"/.test(e)), res.errors.join(' | '));
});

test('SWAPPED LEGS: the ML-DSA signature relabelled as Ed25519 refuses', async () => {
  const stmt = await buildV2();
  const pqLeg = stmt.proof.signatures.find((s) => s.alg === 'ML-DSA-65');
  stmt.proof.signatures = [{ ...pqLeg, alg: 'Ed25519' }, pqLeg];
  const res = await verifyRevocationV2(TARGET, stmt, OPTS);
  assert.equal(res.valid, false);
  assert.equal(res.checks.revoker_signature_valid, false);
});

// --- pinning ------------------------------------------------------------------

test('an unpinned revoker confers nothing, both legs valid or not', async () => {
  const res = await verifyRevocationV2(TARGET, await buildV2(), { revokerKeys: {}, now: NOW });
  assert.equal(res.valid, false);
  assert.equal(res.checks.revoker_key_pinned, false);
});

test('pinning the Ed25519 half but not the ML-DSA half refuses (both halves required)', async () => {
  const res = await verifyRevocationV2(TARGET, await buildV2(), {
    revokerKeys: { [REVOKER_ID]: { public_key: edPubB64u } },
    now: NOW,
  });
  assert.equal(res.valid, false);
  assert.equal(res.checks.revoker_key_pinned, false);
});

test('PQ KEY SUBSTITUTION: a different pinned ML-DSA key refuses', async () => {
  const other = ml_dsa65.keygen(crypto.randomBytes(32));
  const res = await verifyRevocationV2(TARGET, await buildV2(), {
    revokerKeys: {
      [REVOKER_ID]: { public_key: edPubB64u, pq_public_key: Buffer.from(other.publicKey).toString('base64url') },
    },
    now: NOW,
  });
  assert.equal(res.valid, false);
  assert.equal(res.checks.revoker_key_pinned, false);
  assert.equal(res.checks.revoker_signature_valid, false);
});

// --- binding ------------------------------------------------------------------

test('revoke-A-presented-for-B refuses on the target binding', async () => {
  const stmt = await buildV2({ actionHash: OTHER_ACTION_HASH });
  const res = await verifyRevocationV2(TARGET, stmt, OPTS);
  assert.equal(res.valid, false);
  assert.equal(res.checks.target_bound, false);
});

test('TAMPERED AFTER SIGNING: editing reason breaks the binding of BOTH legs', async () => {
  const stmt = await buildV2();
  stmt.reason = 'a different reason';
  const res = await verifyRevocationV2(TARGET, stmt, OPTS);
  assert.equal(res.valid, false);
  assert.equal(res.checks.revoker_signature_valid, false);
  assert.equal(res.checks.signature_binds_statement, false);
});

test('a revocation not yet effective at the decision time refuses', async () => {
  const stmt = await buildV2({ revokedAt: '2027-01-01T00:00:00.000Z' });
  const res = await verifyRevocationV2(TARGET, stmt, OPTS);
  assert.equal(res.valid, false);
  assert.equal(res.checks.effective_at_or_before_T, false);
});

test('an old terminal revocation never ages out', async () => {
  const stmt = await buildV2({ revokedAt: '2020-01-01T00:00:00.000Z' });
  const res = await verifyRevocationV2(TARGET, stmt, OPTS);
  assert.equal(res.valid, true, res.errors.join(' | '));
});

// --- fail-closed backend ------------------------------------------------------

test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
  const res = await verifyRevocationV2(TARGET, await buildV2(), {
    ...OPTS,
    mldsaBackendLoader: async () => null,
  });
  assert.equal(res.valid, false);
  assert.equal(res.checks.revoker_signature_valid, false);
  assert.ok(res.errors.some((e) => /pq_backend_unavailable/.test(e)), res.errors.join(' | '));
});

// --- fail-closed on junk ------------------------------------------------------

test('malformed input refuses without throwing', async () => {
  for (const junk of [null, undefined, 'x', 42, [], {}]) {
    const res = await verifyRevocationV2(TARGET, junk, OPTS);
    assert.equal(res.valid, false);
  }
  const stmt = await buildV2();
  delete stmt.proof.pq_public_key;
  assert.equal((await verifyRevocationV2(TARGET, stmt, OPTS)).valid, false);
});
