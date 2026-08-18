// SPDX-License-Identifier: Apache-2.0
// Generated from agent-edge-continuity-v2.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-AGENT-EDGE-CONTINUITY-v2 hybrid verifier test. Copies the hostile matrix
// of the reference migration (revocation-v2.test.ts): leg stripping both
// directions, set narrowing (structural + independent crypto.verify over the
// narrowed bytes), duplicate algorithm, an Ed448 SPKI masquerading as the
// Ed25519 half, wrong-length signatures, plus the old-verifier-refuses-new
// capture and a valid hybrid roundtrip.
//
// The PQ leg runs for real; a green run means ML-DSA-65 actually verified.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { AGENT_CONTINUITY_VERSION, AGENT_CONTINUITY_V2_VERSION, createAgentContinuityEnvelope, createAgentContinuityEnvelopeV2, verifyAgentContinuityEnvelope, verifyAgentContinuityEnvelopeV2, verifyAgentContinuityEnvelopeAny, } from './agent-edge-continuity.js';
import { digestAeb, canonicalizeAeb } from './aeb-adapter-contract.js';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const CAID = `caid:1:order.purchase.1:jcs-sha256:${'A'.repeat(43)}`;
const ACTION = digestAeb({ action_type: 'order.purchase.1', order_id: 'o-1', amount_minor: '1000' });
const NOW = '2026-07-22T12:00:00Z';
const TOPOLOGY = {
    accepted_edges: ['user-harness', 'harness-model', 'model-harness', 'harness-tool', 'agent-agent', 'effect'],
    root_edges: ['user-harness'],
    allowed_transitions: { 'user-harness': ['harness-model'], 'harness-model': ['model-harness'] },
    execution_edges: ['harness-tool', 'agent-agent'],
    max_depth: 8,
    max_validity_seconds: 3600,
    max_age_seconds: 300,
};
const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const KEY_ID = 'key:continuity:hybrid-1';
const PINS_V2 = {
    [KEY_ID]: {
        public_key: edPubB64u,
        pq_public_key: pqPubB64u,
        status: 'active',
        valid_from: '2026-01-01T00:00:00Z',
        valid_until: '2027-01-01T00:00:00Z',
        allowed_sources: ['user:alice'],
        allowed_edges: ['user-harness'],
    },
};
async function buildV2(overrides = {}) {
    return createAgentContinuityEnvelopeV2({
        parent_continuity_id: null,
        edge: 'user-harness',
        source: 'user:alice',
        destination: 'agent:planner',
        relying_party_id: 'rp:test',
        pinned_config_digest: digestAeb({ config: 'test' }),
        initiator_id: 'user:alice',
        executor_id: 'executor:payments',
        caid: CAID,
        action_digest: ACTION,
        proposal_digest: digestAeb({ proposal: 'purchase-o-1' }),
        operation_id: 'op-1',
        evidence_refs: [],
        claims: {
            intent_digest: digestAeb({ intent: 'buy', order_id: 'o-1' }),
            display_digest: digestAeb({ display: 'confirm purchase o-1' }),
        },
        sequence: 0,
        issued_at: NOW,
        expires_at: '2026-07-22T13:00:00Z',
        handoff_nonce: 'nonce-user-hybrid-000001',
        signers: [
            { alg: 'Ed25519', private_key: ed.privateKey, key_id: KEY_ID },
            { alg: 'ML-DSA-65', private_key: Buffer.from(pq.secretKey).toString('base64url'), key_id: KEY_ID },
        ],
        proof_key_id: KEY_ID,
        ...overrides,
    });
}
function verifyOpts(overrides = {}) {
    return { signer_pins: PINS_V2, topology: TOPOLOGY, now: NOW, ...overrides };
}
// --- honesty gate --------------------------------------------------------
test('real ML-DSA-65 backend is available for this suite', () => {
    assert.ok(typeof ml_dsa65?.sign === 'function', 'PQ tests must run for real');
});
// --- happy path ------------------------------------------------------------
test('a real hybrid continuity envelope verifies under both pinned keys (valid roundtrip)', async () => {
    const envelope = await buildV2();
    assert.equal(envelope['@type'], AGENT_CONTINUITY_V2_VERSION);
    const res = await verifyAgentContinuityEnvelopeV2(envelope, verifyOpts());
    assert.equal(res.valid, true, res.reasons.join(' | '));
    assert.equal(res.checks.signature, true);
});
// --- old-verifier-refuses-new -----------------------------------------------
test('the v1 (classical) verifier refuses a v2 hybrid envelope cleanly on the type marker', async () => {
    const envelope = await buildV2();
    const res = verifyAgentContinuityEnvelope(envelope, { signer_pins: {}, topology: TOPOLOGY, now: NOW });
    assert.equal(res.valid, false);
    assert.ok(res.reasons.includes('invalid_type'));
});
test('the v2 verifier refuses a v1 (classical) envelope on the type marker', () => {
    const classical = createAgentContinuityEnvelope({
        parent_continuity_id: null,
        edge: 'user-harness',
        source: 'user:alice',
        destination: 'agent:planner',
        relying_party_id: 'rp:test',
        pinned_config_digest: digestAeb({ config: 'test' }),
        initiator_id: 'user:alice',
        executor_id: 'executor:payments',
        caid: CAID,
        action_digest: ACTION,
        proposal_digest: digestAeb({ proposal: 'purchase-o-1' }),
        operation_id: 'op-1',
        evidence_refs: [],
        claims: {
            intent_digest: digestAeb({ intent: 'buy', order_id: 'o-1' }),
            display_digest: digestAeb({ display: 'confirm purchase o-1' }),
        },
        sequence: 0,
        issued_at: NOW,
        expires_at: '2026-07-22T13:00:00Z',
        handoff_nonce: 'nonce-user-classical-000001',
        signer: { key_id: KEY_ID, private_key: ed.privateKey },
    });
    assert.equal(classical['@type'], AGENT_CONTINUITY_VERSION);
    return verifyAgentContinuityEnvelopeV2(classical, verifyOpts()).then((res) => {
        assert.equal(res.valid, false);
        assert.ok(res.reasons.includes('invalid_type'));
    });
});
test('verifyAgentContinuityEnvelopeAny routes each version to its own verifier', async () => {
    assert.equal((await verifyAgentContinuityEnvelopeAny(await buildV2(), verifyOpts())).valid, true);
});
// --- anti-stripping ----------------------------------------------------------
test('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
    const envelope = structuredClone(await buildV2());
    envelope.proof.signatures = envelope.proof.signatures.filter((s) => s.alg === 'Ed25519');
    const res = await verifyAgentContinuityEnvelopeV2(envelope, verifyOpts());
    assert.equal(res.valid, false);
    assert.ok(res.reasons.includes('invalid_proof'));
});
test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const envelope = structuredClone(await buildV2());
    envelope.proof.signatures = envelope.proof.signatures.filter((s) => s.alg === 'ML-DSA-65');
    const res = await verifyAgentContinuityEnvelopeV2(envelope, verifyOpts());
    assert.equal(res.valid, false);
});
test('SET NARROWING: narrowing required_algorithms to Ed25519-only refuses structurally and cryptographically', async () => {
    const envelope = structuredClone(await buildV2());
    envelope.proof.required_algorithms = ['Ed25519'];
    const res = await verifyAgentContinuityEnvelopeV2(envelope, verifyOpts());
    assert.equal(res.valid, false);
    assert.ok(res.reasons.includes('invalid_proof'));
    // Independent cryptographic half: the surviving Ed25519 signature was made
    // over bytes committing to the FULL set. continuityV2SigningBytes() itself
    // refuses a non-registered set (it only ever rebuilds from the REGISTERED
    // set), so the narrowed bytes are recomputed by hand here, mirroring what a
    // stripping attacker would have to forge.
    const raw = await buildV2();
    const { proof, ...unsigned } = raw;
    const narrowedBytes = Buffer.from(`${AGENT_CONTINUITY_V2_VERSION}\0${canonicalizeAeb({ ...unsigned, required_algorithms: ['Ed25519'] })}`, 'utf8');
    const survivingSig = Buffer.from(proof.signatures.find((s) => s.alg === 'Ed25519').sig, 'base64url');
    assert.equal(crypto.verify(null, narrowedBytes, ed.publicKey, survivingSig), false);
});
test('DUPLICATE ALGORITHM: two entries for one algorithm refuse', async () => {
    const envelope = structuredClone(await buildV2());
    envelope.proof.signatures = [envelope.proof.signatures[0], envelope.proof.signatures[0]];
    const res = await verifyAgentContinuityEnvelopeV2(envelope, verifyOpts());
    assert.equal(res.valid, false);
});
// --- wrong-length signature ---------------------------------------------------
test('WRONG-LENGTH SIGNATURE: a truncated Ed25519 leg refuses', async () => {
    const envelope = structuredClone(await buildV2());
    const leg = envelope.proof.signatures.find((s) => s.alg === 'Ed25519');
    leg.sig = Buffer.from(leg.sig, 'base64url').subarray(0, 10).toString('base64url');
    const res = await verifyAgentContinuityEnvelopeV2(envelope, verifyOpts());
    assert.equal(res.valid, false);
    assert.equal(res.checks.signature, false);
});
// --- masquerade ----------------------------------------------------------------
test('ED448 MASQUERADE: an Ed448 SPKI pinned as the Ed25519 half refuses', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const res = await verifyAgentContinuityEnvelopeV2(await buildV2(), verifyOpts({
        signer_pins: { [KEY_ID]: { ...PINS_V2[KEY_ID], public_key: ed448Pub } },
    }));
    assert.equal(res.valid, false);
    assert.equal(res.checks.signature, false);
});
// --- pinning ---------------------------------------------------------------
test('an unpinned signer key_id confers nothing', async () => {
    const res = await verifyAgentContinuityEnvelopeV2(await buildV2(), verifyOpts({ signer_pins: {} }));
    assert.equal(res.valid, false);
    assert.equal(res.checks.signature, false);
});
test('a pin missing the ML-DSA half refuses (both halves required)', async () => {
    const { pq_public_key: _pq, ...halfPin } = PINS_V2[KEY_ID];
    const res = await verifyAgentContinuityEnvelopeV2(await buildV2(), verifyOpts({
        signer_pins: { [KEY_ID]: halfPin },
    }));
    assert.equal(res.valid, false);
    assert.equal(res.checks.signature, false);
});
test('PQ KEY SUBSTITUTION: a different pinned ML-DSA key refuses', async () => {
    const other = ml_dsa65.keygen(crypto.randomBytes(32));
    const res = await verifyAgentContinuityEnvelopeV2(await buildV2(), verifyOpts({
        signer_pins: { [KEY_ID]: { ...PINS_V2[KEY_ID], pq_public_key: Buffer.from(other.publicKey).toString('base64url') } },
    }));
    assert.equal(res.valid, false);
});
// --- fail-closed backend ------------------------------------------------------
test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const res = await verifyAgentContinuityEnvelopeV2(await buildV2(), verifyOpts({ mldsaBackendLoader: async () => null }));
    assert.equal(res.valid, false);
    assert.equal(res.checks.signature, false);
});
// --- binding ---------------------------------------------------------------
test('TAMPERED AFTER SIGNING: editing the claims after signing breaks the signature', async () => {
    const envelope = structuredClone(await buildV2());
    envelope.claims.intent_digest = digestAeb({ intent: 'buy', order_id: 'tampered' });
    const res = await verifyAgentContinuityEnvelopeV2(envelope, verifyOpts());
    assert.equal(res.valid, false);
});
// --- fail-closed on junk -------------------------------------------------------
test('malformed input refuses without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
        const res = await verifyAgentContinuityEnvelopeV2(junk, verifyOpts());
        assert.equal(res.valid, false);
    }
});
