// SPDX-License-Identifier: Apache-2.0
//
// EP-ACTION-REFUSAL-STATEMENT-v2 hybrid verifier test. Copies the hostile matrix
// of the reference migration (packages/verify/revocation-v2.test.ts): leg
// stripping both directions, set narrowing (structural + independent crypto.verify
// over the narrowed bytes), set widening, duplicate algorithm, an Ed448 SPKI
// masquerading as the Ed25519 half, algorithm relabelling, swapped legs, PQ-key
// substitution, tamper-after-signing, plus the refusal domain refusals, the
// v1-refuses-v2 capture, and a v1 byte-identity regression.
//
// The PQ leg runs for real; a green run means ML-DSA-65 actually verified.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { canonicalize } from './execution-binding.js';
import {
  ACTION_REFUSAL_CLAIM_BOUNDARY,
  ACTION_REFUSAL_STATEMENT_VERSION,
  ACTION_REFUSAL_STATEMENT_V2_VERSION,
  ACTION_REFUSAL_STATEMENT_V2_DOMAIN,
  ACTION_REFUSAL_V2_REQUIRED_ALGORITHMS,
  actionRefusalV2SignedPayload,
  signActionRefusalStatement,
  signActionRefusalStatementV2,
  verifyActionRefusalStatement,
  verifyActionRefusalStatementV2,
  verifyActionRefusalStatementAny,
} from './action-refusal-statement.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const NOW = Date.parse('2026-08-17T18:00:00.000Z');
const D = (c: string) => `sha256:${c.repeat(64)}`;
const CAID = `caid:1:health.prior-authorization-determination.1:jcs-sha256:${'A'.repeat(43)}`;

const ISSUER_ID = 'gate:synthetic-payer:prod';
const KEY_ID = 'gate-refusal-key-1';

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const pqSecretB64u = Buffer.from(pq.secretKey).toString('base64url');

const TRUSTED = { [KEY_ID]: { issuer_id: ISSUER_ID, public_key: edPubB64u, pq_public_key: pqPubB64u } };
const EXPECTED = {
  caid: CAID,
  action_digest: D('1'),
  relying_party_id: 'payer:synthetic-example',
  program_id: 'rp.synthetic-payer.pas-adverse-determination.1',
  program_version: 1,
  source_digest: D('2'),
  program_digest: D('3'),
  nonce: Buffer.alloc(32, 8).toString('base64url'),
};

function input(overrides: Record<string, any> = {}): Record<string, any> {
  return {
    refusal_id: 'refusal:synthetic-pas:001',
    relying_party_id: 'payer:synthetic-example',
    caid: CAID,
    action_digest: D('1'),
    program: {
      program_id: 'rp.synthetic-payer.pas-adverse-determination.1',
      version: 1,
      source_digest: D('2'),
      program_digest: D('3'),
    },
    failed_requirement_ids: ['reviewer-authority', 'licensed-review'],
    evidence_digests: [D('5'), D('4')],
    challenge_digests: [D('7'), D('6')],
    nonce: Buffer.alloc(32, 8).toString('base64url'),
    refused_at: '2026-08-17T17:59:00.000Z',
    expires_at: '2026-08-17T18:04:00.000Z',
    refusal_class: 'evidence_unsatisfied',
    semantics: {
      verification: 'VERIFIED', match: 'MATCH',
      satisfaction: 'NOT_SATISFIED', authorization: 'NOT_EVALUATED',
    },
    delivery: null,
    custody: null,
    transparency_anchor: null,
    claim_boundary: ACTION_REFUSAL_CLAIM_BOUNDARY,
    ...overrides,
  };
}

function signer() {
  return {
    issuer_id: ISSUER_ID,
    key_id: KEY_ID,
    private_key: ed.privateKey,
    pq_public_key: pqPubB64u,
    pq_private_key: pqSecretB64u,
  };
}

function buildV2(overrides: Record<string, any> = {}) {
  return signActionRefusalStatementV2(input(overrides), signer());
}

function opts(overrides: any = {}) {
  return { trusted_keys: TRUSTED, expected: EXPECTED, now: NOW, ...overrides };
}

// --- honesty gate -------------------------------------------------------------

test('real ML-DSA-65 backend is available for this suite', () => {
  assert.ok(typeof ml_dsa65?.sign === 'function', 'PQ tests must run for real');
});

// --- happy path ---------------------------------------------------------------

test('a real hybrid refusal statement verifies under both pinned keys', async () => {
  const res = await verifyActionRefusalStatementV2(await buildV2(), opts());
  assert.equal(res.verified, true, res.reason as string);
  assert.equal(res.checks.algorithm_set, true);
  assert.equal(res.checks.legs_present, true);
  assert.equal(res.checks.signature, true);
});

test('the committed bytes carry the required algorithm set and the v2 marker', async () => {
  const stmt: any = await buildV2();
  const { proof, ...bodyNoProof } = stmt;
  const bytes = actionRefusalV2SignedPayload(bodyNoProof).toString('utf8');
  assert.ok(bytes.startsWith(ACTION_REFUSAL_STATEMENT_V2_DOMAIN), bytes.slice(0, 64));
  assert.ok(bytes.includes('"required_algorithms":["Ed25519","ML-DSA-65"]'), bytes);
});

// --- v1 / v2 compatibility ----------------------------------------------------

test('the v1 verifier refuses a v2 statement CLEANLY on the version marker', async () => {
  const res = verifyActionRefusalStatement(await buildV2(), opts());
  assert.equal(res.verified, false);
  // verifyRiskBody refuses because @version !== v1; it never throws.
  assert.equal(typeof res.reason, 'string');
});

test('v1 byte-identity regression: a v1 statement verifies and re-signs identically', () => {
  const a: any = signActionRefusalStatement(input(), { issuer_id: ISSUER_ID, key_id: KEY_ID, private_key: ed.privateKey });
  const b: any = signActionRefusalStatement(input(), { issuer_id: ISSUER_ID, key_id: KEY_ID, private_key: ed.privateKey });
  assert.equal(a['@version'], ACTION_REFUSAL_STATEMENT_VERSION);
  assert.equal(a.proof.signature_b64u, b.proof.signature_b64u, 'v1 Ed25519 signing must stay byte-identical');
  const res = verifyActionRefusalStatement(a, {
    trusted_keys: { [KEY_ID]: { issuer_id: ISSUER_ID, public_key: edPubB64u } },
    expected: EXPECTED,
    now: NOW,
  });
  assert.equal(res.verified, true, res.reason as string);
});

test('the v2 verifier refuses a v1 statement on the version marker', async () => {
  const v1: any = signActionRefusalStatement(input(), { issuer_id: ISSUER_ID, key_id: KEY_ID, private_key: ed.privateKey });
  const res = await verifyActionRefusalStatementV2(v1, opts());
  assert.equal(res.verified, false);
  assert.equal(res.checks.version, false);
  assert.ok(/unsupported version/.test(res.reason as string), res.reason as string);
});

test('verifyActionRefusalStatementAny routes each version to its own verifier', async () => {
  assert.equal((await verifyActionRefusalStatementAny(await buildV2(), opts())).verified, true);
  const v1: any = signActionRefusalStatement(input(), { issuer_id: ISSUER_ID, key_id: KEY_ID, private_key: ed.privateKey });
  assert.equal((await verifyActionRefusalStatementAny(v1, {
    trusted_keys: { [KEY_ID]: { issuer_id: ISSUER_ID, public_key: edPubB64u } }, expected: EXPECTED, now: NOW,
  })).verified, true);
});

// --- anti-stripping -----------------------------------------------------------

test('LEG STRIPPING: removing the ML-DSA leg (set intact) refuses structurally', async () => {
  const stmt: any = structuredClone(await buildV2());
  stmt.proof.signatures = stmt.proof.signatures.filter((s: any) => s.alg === 'Ed25519');
  const res = await verifyActionRefusalStatementV2(stmt, opts());
  assert.equal(res.verified, false);
  assert.equal(res.checks.legs_present, false);
  assert.equal(res.reason, 'refusal_signature_leg_stripped');
});

test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
  const stmt: any = structuredClone(await buildV2());
  stmt.proof.signatures = stmt.proof.signatures.filter((s: any) => s.alg === 'ML-DSA-65');
  const res = await verifyActionRefusalStatementV2(stmt, opts());
  assert.equal(res.verified, false);
  assert.equal(res.checks.legs_present, false);
});

test('SET NARROWING: narrowing required_algorithms fails BOTH structurally and cryptographically', async () => {
  const stmt: any = structuredClone(await buildV2());
  stmt.proof.required_algorithms = ['Ed25519'];
  stmt.proof.signatures = stmt.proof.signatures.filter((s: any) => s.alg === 'Ed25519');
  const res = await verifyActionRefusalStatementV2(stmt, opts());
  assert.equal(res.verified, false);
  assert.equal(res.checks.algorithm_set, false);

  const { proof, ...bodyNoProof } = stmt;
  const narrowedBytes = Buffer.from(
    ACTION_REFUSAL_STATEMENT_V2_DOMAIN + canonicalize({ ...bodyNoProof, required_algorithms: ['Ed25519'] }),
    'utf8',
  );
  const survivingSig = Buffer.from(proof.signatures[0].sig, 'base64url');
  assert.equal(crypto.verify(null, narrowedBytes, ed.publicKey, survivingSig), false,
    'narrowing the committed set must break the surviving signature');
});

test('SET WIDENING: an extra algorithm in required_algorithms refuses', async () => {
  const stmt: any = structuredClone(await buildV2());
  stmt.proof.required_algorithms = ['Ed25519', 'ML-DSA-65', 'Ed448'];
  const res = await verifyActionRefusalStatementV2(stmt, opts());
  assert.equal(res.verified, false);
  assert.equal(res.checks.algorithm_set, false);
});

test('DUPLICATE ALGORITHM: two entries for one algorithm refuse', async () => {
  const stmt: any = structuredClone(await buildV2());
  stmt.proof.signatures = [{ ...stmt.proof.signatures[0] }, { ...stmt.proof.signatures[0] }];
  const res = await verifyActionRefusalStatementV2(stmt, opts());
  assert.equal(res.verified, false);
  assert.equal(res.reason, 'refusal_signature_leg_duplicate');
});

// --- masquerade ---------------------------------------------------------------

test('ED448 MASQUERADE: an Ed448 SPKI presented and pinned as the Ed25519 half refuses', async () => {
  const ed448 = crypto.generateKeyPairSync('ed448');
  const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
  const stmt: any = structuredClone(await buildV2());
  stmt.proof.public_key = ed448Pub;
  const res = await verifyActionRefusalStatementV2(stmt, opts({
    trusted_keys: { [KEY_ID]: { issuer_id: ISSUER_ID, public_key: ed448Pub, pq_public_key: pqPubB64u } },
  }));
  assert.equal(res.verified, false);
  // Curve pin: the ed key id cannot be derived from a non-Ed25519 SPKI.
  assert.equal(res.checks.issuer_key_bound, false);
});

test('ALGORITHM RELABELLING: calling the Ed25519 leg "Ed448" refuses (closed registry)', async () => {
  const stmt: any = structuredClone(await buildV2());
  stmt.proof.signatures = stmt.proof.signatures.map((s: any) => (s.alg === 'Ed25519' ? { ...s, alg: 'Ed448' } : s));
  const res = await verifyActionRefusalStatementV2(stmt, opts());
  assert.equal(res.verified, false);
  assert.equal(res.reason, 'refusal_signature_leg_unexpected');
});

test('SWAPPED LEGS: the ML-DSA signature relabelled as Ed25519 refuses', async () => {
  const stmt: any = structuredClone(await buildV2());
  const pqLeg = stmt.proof.signatures.find((s: any) => s.alg === 'ML-DSA-65');
  stmt.proof.signatures = [{ ...pqLeg, alg: 'Ed25519' }, pqLeg];
  const res = await verifyActionRefusalStatementV2(stmt, opts());
  assert.equal(res.verified, false);
  assert.equal(res.checks.signature, false);
});

// --- pinning ------------------------------------------------------------------

test('an unpinned issuer confers nothing', async () => {
  const res = await verifyActionRefusalStatementV2(await buildV2(), opts({ trusted_keys: {} }));
  assert.equal(res.verified, false);
  assert.equal(res.checks.issuer_pin, false);
});

test('pinning the Ed25519 half but not the ML-DSA half refuses (both halves required)', async () => {
  const res = await verifyActionRefusalStatementV2(await buildV2(), opts({
    trusted_keys: { [KEY_ID]: { issuer_id: ISSUER_ID, public_key: edPubB64u } },
  }));
  assert.equal(res.verified, false);
  assert.equal(res.checks.issuer_pin, false);
});

test('PQ KEY SUBSTITUTION: a different pinned ML-DSA key refuses', async () => {
  const other = ml_dsa65.keygen(crypto.randomBytes(32));
  const res = await verifyActionRefusalStatementV2(await buildV2(), opts({
    trusted_keys: { [KEY_ID]: { issuer_id: ISSUER_ID, public_key: edPubB64u, pq_public_key: Buffer.from(other.publicKey).toString('base64url') } },
  }));
  assert.equal(res.verified, false);
  assert.equal(res.checks.issuer_pin, false);
});

// --- refusal domain refusals --------------------------------------------------

test('TAMPERED AFTER SIGNING: editing a signed body field breaks the signature', async () => {
  const stmt: any = structuredClone(await buildV2());
  stmt.nonce = Buffer.alloc(32, 9).toString('base64url');
  const res = await verifyActionRefusalStatementV2(stmt, opts());
  assert.equal(res.verified, false);
  assert.equal(res.checks.signature, false);
});

test('an invalid refusal_class refuses on the v1 domain schema', async () => {
  const stmt: any = structuredClone(await buildV2());
  stmt.refusal_class = 'not_a_class';
  const res = await verifyActionRefusalStatementV2(stmt, opts());
  assert.equal(res.verified, false);
  assert.equal(res.checks.refusal_schema, false);
  assert.equal(res.reason, 'refusal_schema_invalid');
});

test('expected-binding mismatch refuses on expected_bindings', async () => {
  const res = await verifyActionRefusalStatementV2(await buildV2(), opts({ expected: { ...EXPECTED, action_digest: D('9') } }));
  assert.equal(res.verified, false);
  assert.equal(res.checks.expected_bindings, false);
  assert.equal(res.reason, 'action_digest_mismatch');
});

test('a refusal past its expiry refuses', async () => {
  const res = await verifyActionRefusalStatementV2(await buildV2(), opts({ now: Date.parse('2026-08-17T18:10:00.000Z') }));
  assert.equal(res.verified, false);
  assert.equal(res.reason, 'refusal_expired');
});

test('a refusal from the future refuses', async () => {
  const res = await verifyActionRefusalStatementV2(await buildV2(), opts({ now: Date.parse('2026-08-17T17:00:00.000Z') }));
  assert.equal(res.verified, false);
  assert.equal(res.reason, 'refusal_from_future');
});

// --- fail-closed backend ------------------------------------------------------

test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
  const res = await verifyActionRefusalStatementV2(await buildV2(), opts({ mldsaBackendLoader: async () => null }));
  assert.equal(res.verified, false);
  assert.equal(res.checks.signature, false);
  assert.ok(/pq_backend_unavailable/.test(res.reason as string), res.reason as string);
});

// --- fail-closed on junk ------------------------------------------------------

test('malformed input refuses without throwing', async () => {
  for (const junk of [null, undefined, 'x', 42, [], {}]) {
    const res = await verifyActionRefusalStatementV2(junk, opts());
    assert.equal(res.verified, false);
  }
  const stmt: any = structuredClone(await buildV2());
  delete stmt.proof.pq_public_key;
  assert.equal((await verifyActionRefusalStatementV2(stmt, opts())).verified, false);
});
