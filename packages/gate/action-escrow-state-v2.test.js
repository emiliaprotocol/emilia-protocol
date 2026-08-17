// SPDX-License-Identifier: Apache-2.0
// Generated from action-escrow-state-v2.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-ACTION-ESCROW-STATE-STATEMENT-v2 hybrid verifier test. Copies the hostile
// matrix of the reference migration (packages/verify/revocation-v2.test.ts):
// leg stripping both directions, set narrowing (structural + independent
// crypto.verify over the narrowed bytes), set widening, duplicate algorithm,
// an Ed448 SPKI masquerading as the Ed25519 half, algorithm relabelling,
// swapped legs, PQ-key substitution, tamper-after-signing, plus the escrow
// domain refusals, the v1-refuses-v2 capture, and a v1 byte-identity regression.
//
// The PQ leg runs for real; a green run means ML-DSA-65 actually verified.
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalize } from './execution-binding.js';
import { ACTION_ESCROW_STATE_STATEMENT_VERSION, ACTION_ESCROW_STATE_STATEMENT_V2_VERSION, ACTION_ESCROW_STATE_STATEMENT_V2_DOMAIN, ACTION_ESCROW_STATE_V2_REQUIRED_ALGORITHMS, signActionEscrowStateStatement, verifyActionEscrowStateStatement, verifyActionEscrowStateStatementV2, verifyActionEscrowStateStatementAny, stateV2SigningBytes, } from './action-escrow-state.js';
import { signAgileSet } from '@emilia-protocol/verify/pq-signature-agility';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const NOW = '2026-08-17T18:00:00.000Z';
const hashes = {
    binding: `sha256:${'11'.repeat(32)}`,
    action: `sha256:${'22'.repeat(32)}`,
    profile: `sha256:${'33'.repeat(32)}`,
    amendment: `sha256:${'44'.repeat(32)}`,
    previous: `sha256:${'55'.repeat(32)}`,
};
const stateRecord = {
    agreement_id: 'agreement-kitchen-001',
    state: 'released',
    revision: 7,
    release: { provider: 'external-custodian', effect_reference: 'release-001', status: 'released' },
};
const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const edKeyId = `ep:escrow-operator-key:sha256:${crypto.createHash('sha256')
    .update(Buffer.from(edPubB64u, 'base64url')).digest('hex')}`;
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const pqKeyId = `ep:escrow-operator-key:ml-dsa-65:sha256:${crypto.createHash('sha256')
    .update(Buffer.from(pqPubB64u, 'base64url')).digest('hex')}`;
const OPERATOR_ID = 'operator:emilia-gate';
const KEY_ID = 'key:operator-1';
const PINS = { [KEY_ID]: { operator_id: OPERATOR_ID, public_key: edPubB64u, pq_public_key: pqPubB64u } };
function baseOpts(overrides = {}) {
    return {
        trustedKeys: PINS,
        stateRecord,
        expectedAgreementId: 'agreement-kitchen-001',
        expectedBindingDigest: hashes.binding,
        expectedActionDigest: hashes.action,
        expectedProfileDigest: hashes.profile,
        expectedState: 'released',
        expectedRevision: 7,
        expectedAmendmentDigests: [hashes.amendment],
        expectedPreviousStatementDigest: hashes.previous,
        now: NOW,
        ...overrides,
    };
}
// Build a valid v1 statement first, then reuse its exact payload/issuer to mint
// a real hybrid v2 statement over the same durable snapshot.
function v1Statement() {
    return signActionEscrowStateStatement({
        statementId: 'state-001',
        agreementId: 'agreement-kitchen-001',
        bindingDigest: hashes.binding,
        actionDigest: hashes.action,
        profileDigest: hashes.profile,
        state: 'released',
        revision: 7,
        amendmentDigests: [hashes.amendment],
        stateRecord,
        previousStatementDigest: hashes.previous,
        occurredAt: '2026-08-17T17:59:00.000Z',
    }, { operatorId: OPERATOR_ID, keyId: KEY_ID, privateKey: ed.privateKey });
}
async function buildV2({ requiredAlgorithms = [...ACTION_ESCROW_STATE_V2_REQUIRED_ALGORITHMS], payloadOverride = null, } = {}) {
    const v1 = v1Statement();
    const issuer = { operator_id: OPERATOR_ID, key_id: KEY_ID };
    const payload = payloadOverride ?? structuredClone(v1.payload);
    const fields = { version: ACTION_ESCROW_STATE_STATEMENT_V2_VERSION, issuer, payload };
    const bytes = stateV2SigningBytes(fields, ACTION_ESCROW_STATE_V2_REQUIRED_ALGORITHMS);
    const sigs = await signAgileSet(new Uint8Array(bytes), [
        { alg: 'Ed25519', private_key: ed.privateKey, key_id: edKeyId },
        { alg: 'ML-DSA-65', private_key: Buffer.from(pq.secretKey).toString('base64url'), key_id: pqKeyId },
    ]);
    const byAlg = new Map(sigs.map((s) => [s.alg, s]));
    return {
        version: ACTION_ESCROW_STATE_STATEMENT_V2_VERSION,
        issuer,
        payload,
        statement_digest: `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`,
        signature: {
            profile: ACTION_ESCROW_STATE_STATEMENT_V2_VERSION,
            required_algorithms: requiredAlgorithms,
            public_key: edPubB64u,
            key_id: edKeyId,
            pq_public_key: pqPubB64u,
            pq_key_id: pqKeyId,
            signatures: [byAlg.get('Ed25519'), byAlg.get('ML-DSA-65')],
        },
    };
}
// --- honesty gate -------------------------------------------------------------
test('real ML-DSA-65 backend is available for this suite', () => {
    assert.ok(typeof ml_dsa65?.sign === 'function', 'PQ tests must run for real');
});
// --- happy path ---------------------------------------------------------------
test('a real hybrid state statement verifies under both pinned keys', async () => {
    const res = await verifyActionEscrowStateStatementV2(await buildV2(), baseOpts());
    assert.equal(res.valid, true, res.reason);
    assert.equal(res.checks.algorithm_set, true);
    assert.equal(res.checks.legs_present, true);
    assert.equal(res.checks.signature, true);
});
test('the committed bytes carry the required algorithm set and the v2 marker', async () => {
    const stmt = await buildV2();
    const bytes = stateV2SigningBytes(stmt).toString('utf8');
    assert.ok(bytes.startsWith(ACTION_ESCROW_STATE_STATEMENT_V2_DOMAIN), bytes.slice(0, 64));
    assert.ok(bytes.includes('"required_algorithms":["Ed25519","ML-DSA-65"]'), bytes);
});
// --- v1 / v2 compatibility ----------------------------------------------------
test('the v1 verifier refuses a v2 statement CLEANLY on the version marker', async () => {
    const res = verifyActionEscrowStateStatement(await buildV2(), baseOpts());
    assert.equal(res.valid, false);
    assert.equal(res.checks.structure, false);
    assert.equal(res.reason, 'malformed_state_statement');
});
test('v1 byte-identity regression: a v1 statement verifies and re-signs identically', () => {
    const a = v1Statement();
    const b = v1Statement();
    assert.equal(a.version, ACTION_ESCROW_STATE_STATEMENT_VERSION);
    assert.equal(a.statement_digest, b.statement_digest, 'Ed25519 v1 signing must stay deterministic/byte-identical');
    assert.equal(a.signature.signature_b64u, b.signature.signature_b64u);
    const res = verifyActionEscrowStateStatement(a, baseOpts({ trustedKeys: { [KEY_ID]: { operator_id: OPERATOR_ID, public_key: edPubB64u } } }));
    assert.equal(res.valid, true, res.reason);
});
test('the v2 verifier refuses a v1 statement on the version marker', async () => {
    const res = await verifyActionEscrowStateStatementV2(v1Statement(), baseOpts());
    assert.equal(res.valid, false);
    assert.equal(res.checks.structure, false);
});
test('verifyActionEscrowStateStatementAny routes each version to its own verifier', async () => {
    assert.equal((await verifyActionEscrowStateStatementAny(await buildV2(), baseOpts())).valid, true);
    assert.equal((await verifyActionEscrowStateStatementAny(v1Statement(), baseOpts({ trustedKeys: { [KEY_ID]: { operator_id: OPERATOR_ID, public_key: edPubB64u } } }))).valid, true);
});
// --- anti-stripping -----------------------------------------------------------
test('LEG STRIPPING: removing the ML-DSA leg (set intact) refuses structurally', async () => {
    const stmt = await buildV2();
    stmt.signature.signatures = stmt.signature.signatures.filter((s) => s.alg === 'Ed25519');
    const res = await verifyActionEscrowStateStatementV2(stmt, baseOpts());
    assert.equal(res.valid, false);
    assert.equal(res.checks.legs_present, false);
    assert.equal(res.reason, 'state_signature_leg_stripped');
});
test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const stmt = await buildV2();
    stmt.signature.signatures = stmt.signature.signatures.filter((s) => s.alg === 'ML-DSA-65');
    const res = await verifyActionEscrowStateStatementV2(stmt, baseOpts());
    assert.equal(res.valid, false);
    assert.equal(res.checks.legs_present, false);
});
test('SET NARROWING: dropping the PQ leg AND narrowing required_algorithms fails BOTH structurally and cryptographically', async () => {
    const stmt = await buildV2({ requiredAlgorithms: ['Ed25519'] });
    stmt.signature.signatures = stmt.signature.signatures.filter((s) => s.alg === 'Ed25519');
    const res = await verifyActionEscrowStateStatementV2(stmt, baseOpts());
    assert.equal(res.valid, false);
    assert.equal(res.checks.algorithm_set, false);
    // Independent cryptographic half: the surviving Ed25519 signature was made
    // over bytes committing to the FULL set, so it cannot verify over narrowed bytes.
    const narrowedBytes = Buffer.from(ACTION_ESCROW_STATE_STATEMENT_V2_DOMAIN + canonicalize({
        version: stmt.version,
        issuer: stmt.issuer,
        payload: stmt.payload,
        required_algorithms: ['Ed25519'],
    }), 'utf8');
    const survivingSig = Buffer.from(stmt.signature.signatures[0].sig, 'base64url');
    assert.equal(crypto.verify(null, narrowedBytes, ed.publicKey, survivingSig), false, 'narrowing the committed set must break the surviving signature');
});
test('SET WIDENING: an extra algorithm in required_algorithms refuses', async () => {
    const stmt = await buildV2({ requiredAlgorithms: ['Ed25519', 'ML-DSA-65', 'Ed448'] });
    const res = await verifyActionEscrowStateStatementV2(stmt, baseOpts());
    assert.equal(res.valid, false);
    assert.equal(res.checks.algorithm_set, false);
});
test('DUPLICATE ALGORITHM: two entries for one algorithm refuse', async () => {
    const stmt = await buildV2();
    stmt.signature.signatures = [stmt.signature.signatures[0], stmt.signature.signatures[0]];
    const res = await verifyActionEscrowStateStatementV2(stmt, baseOpts());
    assert.equal(res.valid, false);
    assert.equal(res.reason, 'state_signature_leg_duplicate');
});
// --- masquerade ---------------------------------------------------------------
test('ED448 MASQUERADE: an Ed448 SPKI presented and pinned as the Ed25519 half refuses', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const stmt = await buildV2();
    stmt.signature.public_key = ed448Pub;
    const res = await verifyActionEscrowStateStatementV2(stmt, baseOpts({
        trustedKeys: { [KEY_ID]: { operator_id: OPERATOR_ID, public_key: ed448Pub, pq_public_key: pqPubB64u } },
    }));
    assert.equal(res.valid, false);
    // Curve pinning refuses: the ed key id cannot be derived from a non-Ed25519 SPKI.
    assert.equal(res.reason, 'operator_key_not_pinned');
});
test('ALGORITHM RELABELLING: calling the Ed25519 leg "Ed448" refuses (closed registry)', async () => {
    const stmt = await buildV2();
    stmt.signature.signatures = stmt.signature.signatures.map((s) => (s.alg === 'Ed25519' ? { ...s, alg: 'Ed448' } : s));
    const res = await verifyActionEscrowStateStatementV2(stmt, baseOpts());
    assert.equal(res.valid, false);
    assert.equal(res.reason, 'state_signature_leg_unexpected');
});
test('SWAPPED LEGS: the ML-DSA signature relabelled as Ed25519 refuses', async () => {
    const stmt = await buildV2();
    const pqLeg = stmt.signature.signatures.find((s) => s.alg === 'ML-DSA-65');
    stmt.signature.signatures = [{ ...pqLeg, alg: 'Ed25519' }, pqLeg];
    const res = await verifyActionEscrowStateStatementV2(stmt, baseOpts());
    assert.equal(res.valid, false);
    assert.equal(res.checks.signature, false);
});
// --- pinning ------------------------------------------------------------------
test('an unpinned operator confers nothing', async () => {
    const res = await verifyActionEscrowStateStatementV2(await buildV2(), baseOpts({ trustedKeys: {} }));
    assert.equal(res.valid, false);
    assert.equal(res.checks.issuer_pin, false);
});
test('pinning the Ed25519 half but not the ML-DSA half refuses (both halves required)', async () => {
    const res = await verifyActionEscrowStateStatementV2(await buildV2(), baseOpts({
        trustedKeys: { [KEY_ID]: { operator_id: OPERATOR_ID, public_key: edPubB64u } },
    }));
    assert.equal(res.valid, false);
    assert.equal(res.checks.issuer_pin, false);
});
test('PQ KEY SUBSTITUTION: a different pinned ML-DSA key refuses', async () => {
    const other = ml_dsa65.keygen(crypto.randomBytes(32));
    const res = await verifyActionEscrowStateStatementV2(await buildV2(), baseOpts({
        trustedKeys: { [KEY_ID]: { operator_id: OPERATOR_ID, public_key: edPubB64u, pq_public_key: Buffer.from(other.publicKey).toString('base64url') } },
    }));
    assert.equal(res.valid, false);
    assert.equal(res.checks.issuer_pin, false);
});
// --- escrow domain refusals ---------------------------------------------------
test('TAMPERED AFTER SIGNING: editing a signed payload field breaks the signature', async () => {
    const stmt = await buildV2();
    stmt.payload.action_digest = `sha256:${'99'.repeat(32)}`;
    const res = await verifyActionEscrowStateStatementV2(stmt, baseOpts());
    assert.equal(res.valid, false);
    assert.equal(res.checks.signature, false);
});
test('state record mismatch refuses on state_record', async () => {
    const res = await verifyActionEscrowStateStatementV2(await buildV2(), baseOpts({ stateRecord: { ...stateRecord, revision: 8 } }));
    assert.equal(res.valid, false);
    assert.equal(res.checks.state_record, false);
});
test('expected-binding mismatch refuses on expected_bindings', async () => {
    const res = await verifyActionEscrowStateStatementV2(await buildV2(), baseOpts({ expectedActionDigest: `sha256:${'ab'.repeat(32)}` }));
    assert.equal(res.valid, false);
    assert.equal(res.checks.expected_bindings, false);
});
test('a statement occurring after the decision time refuses', async () => {
    const res = await verifyActionEscrowStateStatementV2(await buildV2(), baseOpts({ now: '2020-01-01T00:00:00.000Z' }));
    assert.equal(res.valid, false);
    assert.equal(res.checks.time, false);
});
// --- fail-closed backend ------------------------------------------------------
test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const res = await verifyActionEscrowStateStatementV2(await buildV2(), baseOpts({ mldsaBackendLoader: async () => null }));
    assert.equal(res.valid, false);
    assert.equal(res.checks.signature, false);
    assert.ok(/pq_backend_unavailable/.test(res.reason), res.reason);
});
// --- fail-closed on junk ------------------------------------------------------
test('malformed input refuses without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
        const res = await verifyActionEscrowStateStatementV2(junk, baseOpts());
        assert.equal(res.valid, false);
    }
    const stmt = await buildV2();
    delete stmt.signature.pq_public_key;
    assert.equal((await verifyActionEscrowStateStatementV2(stmt, baseOpts())).valid, false);
});
