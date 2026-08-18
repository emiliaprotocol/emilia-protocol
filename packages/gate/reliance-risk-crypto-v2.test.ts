// SPDX-License-Identifier: Apache-2.0
//
// EP-RISK-HYBRID-v2 shared-helper test: the reference hybrid migration applied
// to the shared risk-artifact proof helper (packages/gate/src/reliance-risk-crypto.ts).
//
// Builds a REAL Ed25519 + ML-DSA-65 signed risk body, asserts the fail-closed
// predicate, and runs the hostile matrix (leg stripping both ways, set
// narrowing structural + independent crypto.verify, widening, duplicate alg,
// Ed448 masquerade, relabelling, swapped legs, PQ key substitution, tamper
// after signing, domain refusals, v1-refuses-v2 capture, v1 byte-identity
// regression). It ALSO proves an existing caller (Gate allowance v1) still
// verifies unchanged through the edited helper.
//
// The PQ leg runs for real. This suite FAILS LOUDLY if @noble/post-quantum is
// missing rather than silently skipping.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto, { generateKeyPairSync, sign } from 'node:crypto';

import {
  RISK_HYBRID_PROFILE,
  RISK_HYBRID_REQUIRED_ALGORITHMS,
  signRiskBody,
  verifyRiskBody,
  signRiskBodyV2,
  verifyRiskBodyV2,
} from './reliance-risk-crypto.js';
import { canonicalize } from './execution-binding.js';
import {
  GATE_ALLOWANCE_VERSION,
  signGateAllowance,
  verifyGateAllowance,
} from './allowance.js';
import { capabilityBaseReceiptDigest } from './capability-receipt.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const V2 = 'EP-RISK-TEST-v2';
const V1 = 'EP-RISK-TEST-v1';
const ISSUER = 'customer:example-security';
const KEY_ID = 'key:risk-authorizer';

const ed = generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');

const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqSecretB64u = Buffer.from(pq.secretKey).toString('base64url');
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');

const PINS = { [KEY_ID]: { issuer_id: ISSUER, public_key: edPubB64u, pq_public_key: pqPubB64u } };

const mutable = (x: unknown): any => JSON.parse(JSON.stringify(x));

function buildV2(fields: Record<string, unknown> = { claim: 'reliance-ok', amount: 42 }) {
  return signRiskBodyV2(V2, { '@version': V2, ...fields }, {
    issuer_id: ISSUER,
    key_id: KEY_ID,
    private_key: ed.privateKey,
    pq_private_key: pqSecretB64u,
  });
}

function buildV1(fields: Record<string, unknown> = { claim: 'reliance-ok', amount: 42 }) {
  return signRiskBody(V1, { '@version': V1, ...fields }, {
    issuer_id: ISSUER,
    key_id: KEY_ID,
    private_key: ed.privateKey,
  });
}

// --- honesty gate: the PQ leg must actually run ------------------------------

test('real ML-DSA-65 backend is available for this suite', () => {
  assert.ok(typeof ml_dsa65?.sign === 'function', 'expected @noble/post-quantum ml_dsa65 to be resolvable; PQ tests must run for real');
});

// --- happy path ---------------------------------------------------------------

test('a real hybrid risk body verifies under both pinned keys', async () => {
  const res = await verifyRiskBodyV2(await buildV2(), V2, PINS);
  assert.equal(res.valid, true, res.reason ?? '');
  assert.ok(res.body);
  assert.ok(res.artifact_digest);
});

test('the proof carries the EP-SIG-AGILITY-v1 set shape and committed set', async () => {
  const stmt: any = await buildV2();
  assert.equal(stmt.proof.profile, RISK_HYBRID_PROFILE);
  assert.deepEqual(stmt.proof.required_algorithms, [...RISK_HYBRID_REQUIRED_ALGORITHMS]);
  assert.equal(stmt.proof.signatures.length, 2);
  assert.deepEqual(stmt.proof.signatures.map((s: any) => s.alg), ['Ed25519', 'ML-DSA-65']);
});

// --- v1 / v2 compatibility ----------------------------------------------------

test('the v1 verifier refuses a v2 artifact on the version/envelope marker', async () => {
  const res = verifyRiskBody(await buildV2(), V2, { [KEY_ID]: { issuer_id: ISSUER, public_key: edPubB64u } });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'artifact_signature_envelope_invalid');
});

test('the v2 verifier refuses a v1 artifact on the version marker', async () => {
  const res = await verifyRiskBodyV2(buildV1(), V1, PINS as any);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'artifact_signature_envelope_invalid');
});

// --- v1 byte-identity regression ----------------------------------------------

test('v1 signing is byte-identical and still verifies (regression)', () => {
  const a: any = buildV1();
  const b: any = buildV1();
  assert.equal(a.proof.algorithm, 'Ed25519');
  assert.deepEqual(Object.keys(a.proof).sort(), ['algorithm', 'body_digest', 'key_id', 'signature_b64u']);
  assert.equal(a.proof.signature_b64u, b.proof.signature_b64u, 'Ed25519 signing must be deterministic and unchanged');
  const res = verifyRiskBody(a, V1, { [KEY_ID]: { issuer_id: ISSUER, public_key: edPubB64u } });
  assert.equal(res.valid, true, res.reason ?? '');
});

// --- existing caller unchanged through the edited helper ----------------------

test('an existing caller (Gate allowance v1) still verifies unchanged through the helper', () => {
  const pair = generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const signer = { issuer_id: 'customer:acme', key_id: 'key:allow', private_key: pair.privateKey };
  const receiptPayload = { receipt_id: 'r1', created_at: '2026-07-30T17:59:00.000Z', subject: 'o@x.test', claim: { action_type: 'gate.allowance.issue', outcome: 'allow', capability_only: true } };
  const receipt = {
    '@version': 'EP-RECEIPT-v1',
    payload: receiptPayload,
    signature: { algorithm: 'Ed25519', value: sign(null, Buffer.from(canonicalize(receiptPayload)), pair.privateKey).toString('base64url') },
    public_key: publicKey,
  };
  const input = {
    allowance_id: 'allowance:x:01', tenant_id: 'tenant:x', subject_id: 'agent:x', audience: 'gate:x',
    connector_id: 'stripe', action_type: 'stripe.payout.create', capability_id: 'cap:x',
    capability_issuer_key_digest: `sha256:${crypto.createHash('sha256').update(Buffer.from(publicKey, 'base64url')).digest('hex')}`,
    revision: 1, supersedes_allowance_digest: null,
    authorization_receipt_digest: capabilityBaseReceiptDigest(receipt),
    presentation_digest: `sha256:${crypto.createHash('sha256').update('pres').digest('hex')}`,
    issued_at: '2026-07-30T17:59:00.000Z', valid_from: '2026-07-30T18:00:00.000Z', expires_at: '2026-07-31T18:00:00.000Z',
    constraints: {
      currency: 'USD', aggregate_amount: 50000, max_amount_per_action: 5000,
      material_fields: ['action_type', 'amount', 'currency', 'destination', 'operation_id'],
      operation_id_field: 'operation_id', amount_field: 'amount', currency_field: 'currency', target_field: 'destination',
      allowed_targets: ['acct_a', 'acct_b'], allowed_values: {},
    },
  };
  const signed = signGateAllowance(input, signer);
  assert.equal((signed as any)['@version'], GATE_ALLOWANCE_VERSION);
  const res = verifyGateAllowance(signed, {
    trusted_keys: { 'key:allow': { issuer_id: 'customer:acme', public_key: publicKey } },
    now: Date.parse('2026-07-30T18:30:00.000Z'),
    expected_allowance_id: 'allowance:x:01', expected_tenant_id: 'tenant:x', expected_subject_id: 'agent:x',
    expected_audience: 'gate:x', expected_connector_id: 'stripe', expected_authorizer_id: 'customer:acme',
  });
  assert.equal((res as any).accepted, true, (res as any).reason ?? '');
});

// --- anti-stripping -----------------------------------------------------------

test('LEG STRIPPING: removing the ML-DSA leg (set intact) refuses structurally', async () => {
  const stmt = mutable(await buildV2());
  stmt.proof.signatures = stmt.proof.signatures.filter((s: any) => s.alg === 'Ed25519');
  const res = await verifyRiskBodyV2(stmt, V2, PINS);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'signature_set_incomplete');
});

test('LEG STRIPPING: removing the Ed25519 leg refuses too (neither leg alone suffices)', async () => {
  const stmt = mutable(await buildV2());
  stmt.proof.signatures = stmt.proof.signatures.filter((s: any) => s.alg === 'ML-DSA-65');
  const res = await verifyRiskBodyV2(stmt, V2, PINS);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'signature_set_incomplete');
});

test('SET NARROWING: dropping the PQ leg AND narrowing required_algorithms fails structurally AND cryptographically', async () => {
  const stmt = mutable(await buildV2());
  stmt.proof.required_algorithms = ['Ed25519'];
  const survivingEd = stmt.proof.signatures.find((s: any) => s.alg === 'Ed25519');
  stmt.proof.signatures = [survivingEd];
  const res = await verifyRiskBodyV2(stmt, V2, PINS);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'algorithm_set_invalid');

  // Cryptographic half, proved independently: the surviving Ed25519 signature
  // was made over bytes committing to the FULL set, so it cannot verify over
  // the narrowed bytes.
  const { proof: _p, ...body } = stmt;
  const narrowedBytes = Buffer.from(canonicalize({
    profile: RISK_HYBRID_PROFILE,
    required_algorithms: ['Ed25519'],
    version: V2,
    body,
  }), 'utf8');
  assert.equal(
    crypto.verify(null, narrowedBytes, ed.publicKey, Buffer.from(survivingEd.sig, 'base64url')),
    false,
    'narrowing the committed set must break the surviving signature',
  );
});

test('SET WIDENING: an extra algorithm in required_algorithms refuses', async () => {
  const stmt = mutable(await buildV2());
  stmt.proof.required_algorithms = ['Ed25519', 'ML-DSA-65', 'Ed448'];
  const res = await verifyRiskBodyV2(stmt, V2, PINS);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'algorithm_set_invalid');
});

test('DUPLICATE ALGORITHM: two entries for one algorithm refuse', async () => {
  const stmt = mutable(await buildV2());
  const edLeg = stmt.proof.signatures.find((s: any) => s.alg === 'Ed25519');
  stmt.proof.signatures = [edLeg, edLeg];
  const res = await verifyRiskBodyV2(stmt, V2, PINS);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'signature_set_invalid');
});

// --- masquerade ---------------------------------------------------------------

test('ED448 MASQUERADE: an Ed448 SPKI presented and pinned as the Ed25519 half refuses', async () => {
  const ed448 = generateKeyPairSync('ed448');
  const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
  const res = await verifyRiskBodyV2(await buildV2(), V2, {
    [KEY_ID]: { issuer_id: ISSUER, public_key: ed448Pub, pq_public_key: pqPubB64u },
  });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'pinned_key_invalid');
});

test('ALGORITHM RELABELLING: calling the Ed25519 leg "Ed448" refuses (closed registry)', async () => {
  const stmt = mutable(await buildV2());
  stmt.proof.signatures = stmt.proof.signatures.map((s: any) => (s.alg === 'Ed25519' ? { ...s, alg: 'Ed448' } : s));
  const res = await verifyRiskBodyV2(stmt, V2, PINS);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'signature_set_invalid');
});

test('SWAPPED LEGS: the ML-DSA signature relabelled as Ed25519 refuses', async () => {
  const stmt = mutable(await buildV2());
  const pqLeg = stmt.proof.signatures.find((s: any) => s.alg === 'ML-DSA-65');
  stmt.proof.signatures = [{ ...pqLeg, alg: 'Ed25519' }, pqLeg];
  const res = await verifyRiskBodyV2(stmt, V2, PINS);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'signature_invalid');
});

// --- pinning ------------------------------------------------------------------

test('an unpinned issuer confers nothing', async () => {
  const res = await verifyRiskBodyV2(await buildV2(), V2, {});
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'issuer_untrusted');
});

test('pinning the Ed25519 half but not the ML-DSA half refuses (both halves required)', async () => {
  const res = await verifyRiskBodyV2(await buildV2(), V2, {
    [KEY_ID]: { issuer_id: ISSUER, public_key: edPubB64u } as any,
  });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'issuer_untrusted');
});

test('PQ KEY SUBSTITUTION: a different pinned ML-DSA key refuses', async () => {
  const other = ml_dsa65.keygen(crypto.randomBytes(32));
  const res = await verifyRiskBodyV2(await buildV2(), V2, {
    [KEY_ID]: { issuer_id: ISSUER, public_key: edPubB64u, pq_public_key: Buffer.from(other.publicKey).toString('base64url') },
  });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'signature_invalid');
});

// --- binding ------------------------------------------------------------------

test('TAMPERED AFTER SIGNING: editing a body field breaks the binding', async () => {
  const stmt = mutable(await buildV2());
  stmt.amount = 43;
  const res = await verifyRiskBodyV2(stmt, V2, PINS);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'digest_mismatch');
});

// --- fail-closed backend ------------------------------------------------------

test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
  const res = await verifyRiskBodyV2(await buildV2(), V2, PINS, { mldsaBackendLoader: async () => null });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'pq_backend_unavailable');
});

// --- fail-closed on junk ------------------------------------------------------

test('malformed input refuses without throwing', async () => {
  for (const junk of [null, undefined, 'x', 42, [], {}]) {
    const res = await verifyRiskBodyV2(junk, V2, PINS);
    assert.equal(res.valid, false);
  }
  const stmt = mutable(await buildV2());
  delete stmt.proof.signatures;
  assert.equal((await verifyRiskBodyV2(stmt, V2, PINS)).valid, false);
});
