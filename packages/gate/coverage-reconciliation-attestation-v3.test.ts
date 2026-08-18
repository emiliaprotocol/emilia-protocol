// SPDX-License-Identifier: Apache-2.0
//
// EP-COVERAGE-RECONCILIATION-ATTESTATION-v3 hybrid verifier test. Applies the
// hostile matrix of the reference migration (packages/verify/revocation-v2.test.ts)
// through the SHARED EP-RISK-HYBRID-v2 helper (reliance-risk-crypto.ts).
//
// The PQ leg runs for real; a green run means ML-DSA-65 actually verified.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import {
  COVERAGE_RECONCILIATION_ATTESTATION_VERSION,
  COVERAGE_RECONCILIATION_ATTESTATION_V3_VERSION,
  signCoverageReconciliationAttestation,
  signCoverageReconciliationAttestationV3,
  verifyCoverageReconciliationAttestation,
  verifyCoverageReconciliationAttestationV3,
  verifyCoverageReconciliationAttestationAny,
} from './coverage-reconciliation-attestation.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const D = (c: string) => `sha256:${c.repeat(64)}`;
const program = { program_id: 'rp.payer.pas.1', version: 3, source_digest: D('1'), program_digest: D('2') };
const NOW = '2026-08-02T00:00:00Z';

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const pqPrivB64u = Buffer.from(pq.secretKey).toString('base64url');

const ISSUER_ID = 'payer:example';
const KEY_ID = 'risk-key-1';
const PINS_V3 = { [KEY_ID]: { issuer_id: ISSUER_ID, public_key: edPubB64u, pq_public_key: pqPubB64u } };

function fields() {
  return {
    attestation_id: 'coverage:2026-07', relying_party_id: ISSUER_ID, program,
    period: { start: '2026-07-01T00:00:00Z', end: '2026-08-01T00:00:00Z' },
    coverage_report_hash: D('3'), census_digest: D('7'),
    system_of_record: { inventory_id: 'pas:sor:2026-07', population_root: D('4'), count: 100 },
    receipt_population: { inventory_id: 'ep:receipts:2026-07', population_root: D('5'), count: 98 },
    joins: { matched: 95, effect_without_receipt: 3, receipted_without_observation: 1, indeterminate: 2, system_indeterminate: 0, excluded: 2, exception: 0 },
    issued_at: '2026-08-01T01:00:00Z', expires_at: '2026-08-08T01:00:00Z',
    timestamp_anchor: { method: 'rfc3161', evidence_digest: D('6') },
    claim_boundary: 'signed_reconciliation_of_supplied_populations_not_population_completeness',
  };
}

function signer() {
  return { issuer_id: ISSUER_ID, key_id: KEY_ID, private_key: ed.privateKey, pq_private_key: pqPrivB64u };
}

async function buildV3() {
  return signCoverageReconciliationAttestationV3(fields(), signer());
}

function verifyOpts(overrides: any = {}) {
  return {
    trusted_keys: PINS_V3, now: NOW, expected_program: program,
    expected_census_digest: D('7'), expected_relying_party_id: ISSUER_ID,
    ...overrides,
  };
}

// --- honesty gate --------------------------------------------------------

test('real ML-DSA-65 backend is available for this suite', () => {
  assert.ok(typeof ml_dsa65?.sign === 'function', 'PQ tests must run for real');
});

// --- happy path ------------------------------------------------------------

test('a real hybrid attestation verifies under both pinned keys (valid roundtrip)', async () => {
  const attestation = await buildV3();
  assert.equal(attestation['@version'], COVERAGE_RECONCILIATION_ATTESTATION_V3_VERSION);
  const res = await verifyCoverageReconciliationAttestationV3(attestation, verifyOpts());
  assert.equal(res.accepted, true, res.reason as string);
  assert.equal(res.verified, true);
});

// --- old-verifier-refuses-new -----------------------------------------------

test('the v2 (classical) verifier refuses a v3 hybrid attestation cleanly on the version marker', async () => {
  const attestation = await buildV3();
  const res = verifyCoverageReconciliationAttestation(attestation, { trusted_keys: { [KEY_ID]: { issuer_id: ISSUER_ID, public_key: edPubB64u } } });
  assert.equal(res.accepted, false);
  assert.equal(res.verified, false);
});

test('the v3 verifier refuses a v2 (classical) attestation on the version marker', async () => {
  const classical = signCoverageReconciliationAttestation(fields(), { issuer_id: ISSUER_ID, key_id: KEY_ID, private_key: ed.privateKey });
  assert.equal(classical['@version'], COVERAGE_RECONCILIATION_ATTESTATION_VERSION);
  const res = await verifyCoverageReconciliationAttestationV3(classical, verifyOpts());
  assert.equal(res.accepted, false);
});

test('verifyCoverageReconciliationAttestationAny routes each version to its own verifier', async () => {
  assert.equal((await verifyCoverageReconciliationAttestationAny(await buildV3(), verifyOpts())).accepted, true);
  const classical = signCoverageReconciliationAttestation(fields(), { issuer_id: ISSUER_ID, key_id: KEY_ID, private_key: ed.privateKey });
  assert.equal((await verifyCoverageReconciliationAttestationAny(classical, {
    trusted_keys: { [KEY_ID]: { issuer_id: ISSUER_ID, public_key: edPubB64u } },
    now: NOW, expected_program: program, expected_census_digest: D('7'), expected_relying_party_id: ISSUER_ID,
  })).accepted, true);
});

// --- anti-stripping ----------------------------------------------------------

test('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
  const stmt: any = structuredClone(await buildV3());
  stmt.proof.signatures = stmt.proof.signatures.filter((s: any) => s.alg === 'Ed25519');
  const res = await verifyCoverageReconciliationAttestationV3(stmt, verifyOpts());
  assert.equal(res.accepted, false);
});

test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
  const stmt: any = structuredClone(await buildV3());
  stmt.proof.signatures = stmt.proof.signatures.filter((s: any) => s.alg === 'ML-DSA-65');
  const res = await verifyCoverageReconciliationAttestationV3(stmt, verifyOpts());
  assert.equal(res.accepted, false);
});

test('SET NARROWING: dropping required_algorithms to Ed25519-only refuses', async () => {
  const stmt: any = structuredClone(await buildV3());
  stmt.proof.required_algorithms = ['Ed25519'];
  const res = await verifyCoverageReconciliationAttestationV3(stmt, verifyOpts());
  assert.equal(res.accepted, false);
  assert.equal(res.reason, 'algorithm_set_invalid');
});

test('DUPLICATE ALGORITHM: two entries for one algorithm refuse', async () => {
  const stmt: any = structuredClone(await buildV3());
  stmt.proof.signatures = [stmt.proof.signatures[0], stmt.proof.signatures[0]];
  const res = await verifyCoverageReconciliationAttestationV3(stmt, verifyOpts());
  assert.equal(res.accepted, false);
});

// --- wrong-length signature ---------------------------------------------------

test('WRONG-LENGTH SIGNATURE: a truncated Ed25519 leg refuses', async () => {
  const stmt: any = structuredClone(await buildV3());
  const ed25519Leg = stmt.proof.signatures.find((s: any) => s.alg === 'Ed25519');
  ed25519Leg.sig = Buffer.from(ed25519Leg.sig, 'base64url').subarray(0, 10).toString('base64url');
  const res = await verifyCoverageReconciliationAttestationV3(stmt, verifyOpts());
  assert.equal(res.accepted, false);
});

test('WRONG-LENGTH SIGNATURE: a truncated ML-DSA-65 leg refuses', async () => {
  const stmt: any = structuredClone(await buildV3());
  const pqLeg = stmt.proof.signatures.find((s: any) => s.alg === 'ML-DSA-65');
  pqLeg.sig = Buffer.from(pqLeg.sig, 'base64url').subarray(0, 10).toString('base64url');
  const res = await verifyCoverageReconciliationAttestationV3(stmt, verifyOpts());
  assert.equal(res.accepted, false);
});

// --- masquerade ----------------------------------------------------------------

test('ED448 MASQUERADE: an Ed448 SPKI pinned as the Ed25519 half refuses', async () => {
  const ed448 = crypto.generateKeyPairSync('ed448');
  const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
  const res = await verifyCoverageReconciliationAttestationV3(await buildV3(), verifyOpts({
    trusted_keys: { [KEY_ID]: { issuer_id: ISSUER_ID, public_key: ed448Pub, pq_public_key: pqPubB64u } },
  }));
  assert.equal(res.accepted, false);
});

// --- pinning ---------------------------------------------------------------

test('an unpinned issuer confers nothing', async () => {
  const res = await verifyCoverageReconciliationAttestationV3(await buildV3(), verifyOpts({ trusted_keys: {} }));
  assert.equal(res.accepted, false);
});

test('pinning the Ed25519 half but not the ML-DSA half refuses', async () => {
  const res = await verifyCoverageReconciliationAttestationV3(await buildV3(), verifyOpts({
    trusted_keys: { [KEY_ID]: { issuer_id: ISSUER_ID, public_key: edPubB64u } },
  }));
  assert.equal(res.accepted, false);
});

// --- fail-closed backend ------------------------------------------------------

test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
  const res = await verifyCoverageReconciliationAttestationV3(await buildV3(), verifyOpts({
    mldsaBackendLoader: async () => null,
  }));
  assert.equal(res.accepted, false);
});

// --- fail-closed on junk -------------------------------------------------------

test('malformed input refuses without throwing', async () => {
  for (const junk of [null, undefined, 'x', 42, [], {}]) {
    const res = await verifyCoverageReconciliationAttestationV3(junk, verifyOpts());
    assert.equal(res.accepted, false);
  }
});

test('TAMPERED AFTER SIGNING: editing joins after signing breaks both legs', async () => {
  const stmt: any = structuredClone(await buildV3());
  stmt.joins.matched = 96;
  const res = await verifyCoverageReconciliationAttestationV3(stmt, verifyOpts());
  assert.equal(res.accepted, false);
});
