// Generated from trust-receipt-knobs.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * verifyTrustReceipt — OPT-IN transparency/currency knobs (wiring tests).
 *
 * These tests verify that the five additive knobs threaded into
 * verifyTrustReceipt behave exactly like the pre-existing priorCheckpoint knob:
 *   - each runs ONLY when its option is supplied;
 *   - each adds its own member to `checks` ONLY when active;
 *   - each folds into `valid` by conjunction;
 *   - with NO knob option set the result is byte-for-byte unchanged (the frozen
 *     seven-member `checks` set, and no extra top-level result members) — this
 *     is the backwards-compatibility contract, asserted directly below;
 *   - each FAILS CLOSED exactly as its module specifies.
 *
 * The knobs' underlying cryptography is exercised by each module's own test
 * (witness.test.js, timestamp-proof.test.js, currency.test.js,
 * consumption-proof.test.js, initiator-attestation.test.js). These tests target
 * the WIRING: option threading, checks-key addition, valid conjunction, and the
 * fail-closed refusal surfaced through verifyTrustReceipt.
 *
 * Run: node --test trust-receipt-knobs.test.js
 *
 * @license Apache-2.0
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { verifyTrustReceipt, witnessSigningDigest, WITNESS_VERSION, ReferenceConsumptionTree, bindInitiatorAttestation, INITIATOR_ATTESTATION_FIELD, } from './index.js';
import { buildConsistencyProof, merkleRoot } from './consistency.js';
// ── canonicalize + sha256: must match index.js ───────────────────────────────
function canonicalize(value) {
    if (value === null || value === undefined)
        return JSON.stringify(value);
    if (Array.isArray(value))
        return `[${value.map(canonicalize).join(',')}]`;
    if (typeof value === 'object') {
        return `{${Object.keys(value).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',')}}`;
    }
    return JSON.stringify(value);
}
const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const leafHashV2 = (canonicalPayload) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0x00]), Buffer.from(canonicalPayload, 'utf8')])).digest('hex');
const hashPairV2 = (left, right) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0x01]), Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8')])).digest('hex');
// ── fixture actors ───────────────────────────────────────────────────────────
function ed25519() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
function p256() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
const logKey = ed25519();
const approverB = ed25519();
const approverA = p256();
const KEYS = {
    'ep:key:controller#1': { approver_id: 'ep:approver:jchen-controller', public_key: approverB.pub, key_class: 'B', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
    'ep:key:cfo#1': { approver_id: 'ep:approver:mrios-cfo', public_key: approverA.pub, key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
};
function signB(digestHex) {
    return crypto.sign(null, Buffer.from(digestHex, 'hex'), approverB.privateKey).toString('base64url');
}
function signA(digestHex, { rpId = 'www.emiliaprotocol.ai', flags = 0x05 } = {}) {
    const challenge = Buffer.from(digestHex, 'hex').toString('base64url');
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://www.emiliaprotocol.ai' }), 'utf8');
    const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
    const authData = Buffer.concat([rpIdHash, Buffer.from([flags]), Buffer.from([0, 0, 0, 0])]);
    const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
    const signature = crypto.sign('sha256', signedData, approverA.privateKey);
    return {
        authenticator_data: authData.toString('base64url'),
        client_data_json: clientDataJSON.toString('base64url'),
        signature: signature.toString('base64url'),
    };
}
// ── receipt fixture builder (mirrors trust-receipt.test.js) ──────────────────
function buildReceipt(mutate = {}) {
    const action = {
        ep_version: '1.0',
        action_type: 'wire.release',
        target: { system: 'treasury.example', resource: 'wire/8841' },
        parameters: { amount: '2400000.00', currency: 'USD' },
        initiator: 'ep:entity:agent-recon-7',
        policy_id: 'ep:policy:wires-over-100k@v12',
        requested_at: '2026-06-09T17:21:04Z',
        ...(mutate.action || {}),
    };
    const action_hash = `sha256:${sha256hex(canonicalize(action))}`;
    const baseCtx = {
        ep_version: '1.0',
        context_type: 'ep.signoff.v1',
        action_hash,
        policy_id: 'ep:policy:wires-over-100k@v12',
        policy_hash: 'sha256:77ab1234',
        initiator: action.initiator,
        required_approvals: 2,
        issued_at: '2026-06-09T17:21:05Z',
        expires_at: '2026-06-09T17:36:05Z',
    };
    const ctx1 = { ...baseCtx, approver: 'ep:approver:jchen-controller', approver_index: 1, nonce: 'n-1' };
    const ctx2 = { ...baseCtx, approver: 'ep:approver:mrios-cfo', approver_index: 2, nonce: 'n-2' };
    const d1 = sha256hex(canonicalize(ctx1));
    const d2 = sha256hex(canonicalize(ctx2));
    const signoffs = [
        { context_hash: `sha256:${d1}`, signature: signB(d1), key_class: 'B', approver_key_id: 'ep:key:controller#1', signed_at: '2026-06-09T17:24:40Z' },
        { context_hash: `sha256:${d2}`, signature: 'unused-for-class-a', key_class: 'A', approver_key_id: 'ep:key:cfo#1', signed_at: '2026-06-09T17:25:01Z', webauthn: signA(d2) },
    ];
    const receipt = {
        receipt_id: 'ep:receipt:01JTEST',
        action,
        action_hash,
        contexts: [ctx1, ctx2],
        signoffs,
        consumption: { nonce: 'n-consume', state: 'COMMITTED', committed_at: '2026-06-09T17:25:02Z' },
    };
    const leaf = leafHashV2(canonicalize(receipt));
    const sibling1 = sha256hex('other-leaf-1');
    const sibling2 = sha256hex('other-subtree');
    const level1 = hashPairV2(leaf, sibling1);
    const root = hashPairV2(level1, sibling2);
    const checkpoint = {
        tree_size: 4,
        root_hash: `sha256:${root}`,
        log_key_id: 'ep:log:test#1',
        merkle_alg: 'EP-MERKLE-v2',
    };
    const log_signature = crypto.sign(null, crypto.createHash('sha256').update(canonicalize(checkpoint), 'utf8').digest(), logKey.privateKey).toString('base64url');
    receipt.log_proof = {
        alg: 'EP-MERKLE-v2',
        leaf_hash: `sha256:${leaf}`,
        leaf_index: 0,
        inclusion_path: [
            { hash: sibling1, position: 'right' },
            { hash: sibling2, position: 'right' },
        ],
        checkpoint: { ...checkpoint, log_signature },
    };
    return receipt;
}
const OPTS = { approverKeys: KEYS, logPublicKey: logKey.pub };
const FROZEN_CHECK_KEYS = [
    'action_hash', 'context_commitments', 'signoff_signatures', 'sod',
    'inclusion', 'checkpoint_signature', 'windows',
];
// ══════════════════════════════════════════════════════════════════════════
// BACKWARDS-COMPAT CONTRACT — no knob option ⇒ byte-for-byte unchanged.
// ══════════════════════════════════════════════════════════════════════════
test('BACKWARDS COMPAT: with no knob options the checks-key set is the frozen seven', () => {
    const r = verifyTrustReceipt(buildReceipt(), OPTS);
    assert.deepEqual(Object.keys(r.checks).sort(), [...FROZEN_CHECK_KEYS].sort(), JSON.stringify(r.errors));
    assert.equal(r.valid, true);
});
test('BACKWARDS COMPAT: with no knob options the result has exactly the pre-knob top-level members', () => {
    const r = verifyTrustReceipt(buildReceipt(), OPTS);
    assert.deepEqual(Object.keys(r).sort(), ['attestation', 'checks', 'errors', 'strict', 'valid'].sort());
    // None of the five optional result members appear.
    for (const k of ['witness_quorum', 'timestamp_proof', 'currency', 'consumption', 'initiator_attestation']) {
        assert.equal(k in r, false, `unexpected result member ${k} with no knob options`);
    }
});
// ══════════════════════════════════════════════════════════════════════════
// KNOB 1 — witnessQuorum (EP-WITNESS-v1)
// ══════════════════════════════════════════════════════════════════════════
function cosign(checkpoint, witnessId, keys) {
    const digest = witnessSigningDigest(checkpoint);
    return {
        alg: WITNESS_VERSION,
        witness_id: witnessId,
        tree_size: checkpoint.tree_size,
        root_hash: checkpoint.root_hash,
        log_key_id: checkpoint.log_key_id,
        signature: crypto.sign(null, digest, keys.privateKey).toString('base64url'),
    };
}
test('KNOB witnessQuorum — k distinct pinned witnesses over the receipt head passes', () => {
    const receipt = buildReceipt();
    const cp = receipt.log_proof.checkpoint;
    const w1 = ed25519();
    const w2 = ed25519();
    const r = verifyTrustReceipt(receipt, {
        ...OPTS,
        witnessQuorum: {
            cosignatures: [cosign(cp, 'witness-a', w1), cosign(cp, 'witness-b', w2)],
            pinnedWitnessKeys: [
                { witness_id: 'witness-a', public_key: w1.pub },
                { witness_id: 'witness-b', public_key: w2.pub },
            ],
            k: 2,
        },
    });
    assert.equal(r.checks.witness_quorum, true, JSON.stringify(r.errors));
    assert.equal(r.witness_quorum.ok, true);
    assert.equal(r.witness_quorum.met, 2);
    assert.equal(r.valid, true);
});
test('KNOB witnessQuorum — fewer than k distinct valid cosignatures fails closed', () => {
    const receipt = buildReceipt();
    const cp = receipt.log_proof.checkpoint;
    const w1 = ed25519();
    const w2 = ed25519();
    const r = verifyTrustReceipt(receipt, {
        ...OPTS,
        witnessQuorum: {
            cosignatures: [cosign(cp, 'witness-a', w1)], // only one
            pinnedWitnessKeys: [
                { witness_id: 'witness-a', public_key: w1.pub },
                { witness_id: 'witness-b', public_key: w2.pub },
            ],
            k: 2,
        },
    });
    assert.equal(r.checks.witness_quorum, false);
    assert.equal(r.witness_quorum.ok, false);
    assert.equal(r.valid, false);
});
test('KNOB witnessQuorum — set but the receipt has no checkpoint fails closed', () => {
    const receipt = buildReceipt();
    delete receipt.log_proof; // no checkpoint for witnesses to cosign
    const r = verifyTrustReceipt(receipt, {
        ...OPTS,
        witnessQuorum: { cosignatures: [], pinnedWitnessKeys: [], k: 1 },
    });
    assert.equal(r.checks.witness_quorum, false);
    assert.equal(r.valid, false);
    assert.match(r.errors.join(' '), /checkpoint is missing/);
});
// ══════════════════════════════════════════════════════════════════════════
// KNOB 2 — timestampProof (RFC 3161). Reuses the sibling's real token vector.
// ══════════════════════════════════════════════════════════════════════════
const TS = {
    DIGEST1: '8c554d22ef5028ca8314bcae8f6bd6b1d1b8717f366be3b582fbac3ec1a4b0bb',
    TOKEN1: 'MIIC6wYJKoZIhvcNAQcCoIIC3DCCAtgCAQMxDzANBglghkgBZQMEAgEFADCBpwYLKoZIhvcNAQkQAQSggZcEgZQwgZECAQEGBCoDBAEwMTANBglghkgBZQMEAgEFAAQgjFVNIu9QKMqDFLyuj2vWsdG4cX82a+O1gvusPsGksLsCAQIYDzIwMjYwNzA2MDM1NDQ5WjAKAgEBgAIB9IEBZAEB/6AwpC4wLDEUMBIGA1UEAwwLRVAgVGVzdCBUU0ExFDASBgNVBAoMC0VNSUxJQSBUZXN0MYICFjCCAhICAQEwRDAsMRQwEgYDVQQDDAtFUCBUZXN0IFRTQTEUMBIGA1UECgwLRU1JTElBIFRlc3QCFApPxUFPArNHXcoEjcCGW8713Ip8MA0GCWCGSAFlAwQCAQUAoIGkMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjYwNzA2MDM1NDQ5WjAvBgkqhkiG9w0BCQQxIgQgAal5/9QEFRIYpPzNpW+Y499A9LzP0OEs1nyu3ImgSNYwNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgXypn8plPJ9pykPrEQFWOZ0ApgZP47wX1qBov7/hNFFowDQYJKoZIhvcNAQEBBQAEggEAEpJbOrSfII6AE3p9ewZAQgSwV6dKLTxMPu5rge7HCPHlbCTdhSV+jjlNK2F9RUdB4DqYRGvPzbu+mMRzFIXAGBEnePPwPUjuQWmlqczR8TN7fkEAWsFGmskrL4MVwaNIjhyFrRkVWpYMzdGV3Xduufq3q5XUPRxnASRa/0ZflOCblb3qhgHasSsc4R6gMjO4SonRibmDUVSjId4igSSQsxn5ekrsJ7IxN9vuoERaCj03rLh1Tp/6M9wT34eyke0IfjaOLVrfjWDKPrSmT++Jbgt6aWsXNHaLNcIEE4JUGgfziNcV74eIqGUHQRZRmo57noEAmz7dzQoZmG6cxt1gLw==',
    SIGNER_SPKI: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtqo1wQcRsO9Cdm1fsyL7Cbi+rpgg4ayBykXrDy+P2Irj/0qiudo2D9SCjCB1dHAdgPSzAJ52GI16iP7WxRlL0SDEJE1XIE5qjy9YKZzGZjXBuuE4paD4k9Zna7bDoCYbxdTVN1NMJ4OGkC4BjV9Pte2h+4DnNziMdA0bqCeXMQlD87d64+AejpUtA2ed5RhClhyf8oEXjlFAEFDvgVY74N5lDzNBcUDnNHfpl8/S5XPfAl1y3IV++sEnwtgZA+uYnuIzcuyv9E+MT1/CvuFBkmgB4hJIsEhrK2TkR7LesHgP4Hq4TQ3CKsHvlymcteUfySwTCYgehoOWGxR0pVb7+wIDAQAB',
};
test('KNOB timestampProof — an authentic pinned token over the expected digest passes', () => {
    const r = verifyTrustReceipt(buildReceipt(), {
        ...OPTS,
        timestampProof: { token: TS.TOKEN1, expectedDigest: `sha256:${TS.DIGEST1}`, pinnedTsaKeys: TS.SIGNER_SPKI },
    });
    assert.equal(r.checks.timestamp_proof, true, JSON.stringify(r.errors));
    assert.equal(r.timestamp_proof.verified, true);
    assert.ok(r.timestamp_proof.gen_time);
    assert.equal(r.valid, true);
});
test('KNOB timestampProof — an unpinned TSA fails closed', () => {
    const r = verifyTrustReceipt(buildReceipt(), {
        ...OPTS,
        timestampProof: { token: TS.TOKEN1, expectedDigest: `sha256:${TS.DIGEST1}`, pinnedTsaKeys: [] },
    });
    assert.equal(r.checks.timestamp_proof, false);
    assert.equal(r.timestamp_proof.verified, false);
    assert.equal(r.timestamp_proof.reason, 'unpinned_tsa');
    assert.equal(r.valid, false);
});
test('KNOB timestampProof — wrong expected digest fails closed', () => {
    const r = verifyTrustReceipt(buildReceipt(), {
        ...OPTS,
        timestampProof: { token: TS.TOKEN1, expectedDigest: `sha256:${'00'.repeat(32)}`, pinnedTsaKeys: TS.SIGNER_SPKI },
    });
    assert.equal(r.checks.timestamp_proof, false);
    assert.equal(r.timestamp_proof.reason, 'digest_mismatch');
    assert.equal(r.valid, false);
});
// ══════════════════════════════════════════════════════════════════════════
// KNOB 3 — currency (EP-CURRENCY-v1). Only 'fresh' passes the gate.
// ══════════════════════════════════════════════════════════════════════════
test('KNOB currency — a recent non-revoking fresh head passes; status fresh', () => {
    const now = '2026-07-05T00:00:00Z';
    const r = verifyTrustReceipt(buildReceipt(), {
        ...OPTS,
        currency: {
            now,
            maxStalenessSeconds: 3600,
            freshHead: { observed_at: '2026-07-05T00:00:00Z' },
        },
    });
    assert.equal(r.currency.currency_at_T.status, 'fresh', JSON.stringify(r.currency));
    assert.equal(r.checks.currency, true);
    assert.equal(r.valid, true);
});
test('KNOB currency — offline-only (no fresh head) is unknown and FAILS the opted-in gate', () => {
    const r = verifyTrustReceipt(buildReceipt(), {
        ...OPTS,
        currency: { now: '2026-07-05T00:00:00Z', maxStalenessSeconds: 3600 },
    });
    // Honest default: offline can never prove currency.
    assert.equal(r.currency.currency_at_T.status, 'unknown');
    assert.equal(r.currency.currency_at_T.reason, 'offline_only_no_fresh_head');
    // Opting into the gate means unknown does NOT pass (fail-closed).
    assert.equal(r.checks.currency, false);
    assert.equal(r.valid, false);
});
test('KNOB currency — a head older than the staleness bound is stale and fails the gate', () => {
    const r = verifyTrustReceipt(buildReceipt(), {
        ...OPTS,
        currency: {
            now: '2026-07-05T12:00:00Z',
            maxStalenessSeconds: 60,
            freshHead: { observed_at: '2026-07-05T00:00:00Z' }, // 12h old vs 60s bound
        },
    });
    assert.equal(r.currency.currency_at_T.status, 'stale');
    assert.equal(r.checks.currency, false);
    assert.equal(r.valid, false);
});
test('KNOB currency — a revoking fresh head is stale and fails the gate', () => {
    const receipt = buildReceipt();
    const r = verifyTrustReceipt(receipt, {
        ...OPTS,
        currency: {
            now: '2026-07-05T00:00:00Z',
            maxStalenessSeconds: 3600,
            freshHead: {
                observed_at: '2026-07-05T00:00:00Z',
                revoked_target_hashes: [receipt.action_hash],
            },
        },
    });
    assert.equal(r.currency.currency_at_T.status, 'stale');
    assert.equal(r.currency.currency_at_T.reason, 'revoked_by_fresh_head');
    assert.equal(r.checks.currency, false);
    assert.equal(r.valid, false);
});
// ══════════════════════════════════════════════════════════════════════════
// KNOB 4 — consumptionProof (EP-SMT-CONSUME-v1)
// ══════════════════════════════════════════════════════════════════════════
function denseLeaf(content) {
    return crypto.createHash('sha256')
        .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(content, 'utf8')]))
        .digest('hex');
}
function makeConsumptionBundle({ nonce = 'nonce-A', otherNonces = ['nonce-B', 'nonce-C'], m = 3, n = 6 } = {}) {
    const treeBefore = new ReferenceConsumptionTree();
    for (const o of otherNonces)
        treeBefore.insert(o);
    const niProof = treeBefore.prove(nonce);
    const treeAfter = new ReferenceConsumptionTree();
    for (const o of otherNonces)
        treeAfter.insert(o);
    treeAfter.insert(nonce);
    const incProof = treeAfter.prove(nonce);
    const logLeaves = Array.from({ length: n }, (_, i) => denseLeaf(`log-entry-${i}`));
    const h1Root = merkleRoot(logLeaves.slice(0, m));
    const h2Root = merkleRoot(logLeaves);
    const consistency = buildConsistencyProof(m, n, logLeaves);
    return {
        nonce,
        non_inclusion_proof: niProof,
        inclusion_proof: incProof,
        consistency_proof: consistency,
        checkpoints: { h1: { tree_size: m, root_hash: h1Root }, h2: { tree_size: n, root_hash: h2Root } },
    };
}
test('KNOB consumptionProof — a valid absent->present bundle passes', () => {
    const r = verifyTrustReceipt(buildReceipt(), {
        ...OPTS,
        consumptionProof: makeConsumptionBundle(),
    });
    assert.equal(r.checks.consumption, true, JSON.stringify(r.errors));
    assert.equal(r.consumption.valid, true);
    assert.equal(r.valid, true);
});
test('KNOB consumptionProof — a non-inclusion proof asserting present fails closed', () => {
    const bundle = makeConsumptionBundle();
    // Corrupt: make the absent leg claim present.
    bundle.non_inclusion_proof = { ...bundle.non_inclusion_proof, present: true };
    const r = verifyTrustReceipt(buildReceipt(), { ...OPTS, consumptionProof: bundle });
    assert.equal(r.checks.consumption, false);
    assert.equal(r.consumption.reason, 'non_inclusion_proof_must_assert_absent');
    assert.equal(r.valid, false);
});
test('KNOB consumptionProof — a missing bundle fails closed', () => {
    const r = verifyTrustReceipt(buildReceipt(), { ...OPTS, consumptionProof: {} });
    assert.equal(r.checks.consumption, false);
    assert.equal(r.valid, false);
});
// ══════════════════════════════════════════════════════════════════════════
// KNOB 5 — requireInitiatorAttestation (EP-INITIATOR-ATTESTATION-v1)
// ══════════════════════════════════════════════════════════════════════════
const GOOD_ATTESTATION = {
    '@version': 'EP-INITIATOR-ATTESTATION-v1',
    model_id: 'claude-opus-4-8',
    model_version: '2026-01',
    tool_chain_digest: `sha256:${'ab'.repeat(32)}`,
};
test('KNOB requireInitiatorAttestation — a well-formed attestation in the action passes', () => {
    const receipt = buildReceipt();
    const bound = bindInitiatorAttestation(receipt.action, GOOD_ATTESTATION);
    receipt.action = bound.action;
    // Re-anchor the receipt to the new action (the attestation is inside the action).
    const rebuilt = reanchor(receipt);
    const r = verifyTrustReceipt(rebuilt, { ...OPTS, requireInitiatorAttestation: true });
    assert.equal(r.checks.initiator_attestation, true, JSON.stringify(r.errors));
    assert.equal(r.initiator_attestation.ok, true);
    assert.equal(r.valid, true);
});
test('KNOB requireInitiatorAttestation — set but attestation absent fails closed', () => {
    const r = verifyTrustReceipt(buildReceipt(), { ...OPTS, requireInitiatorAttestation: true });
    assert.equal(r.checks.initiator_attestation, false);
    assert.equal(r.initiator_attestation.ok, false);
    assert.match(r.errors.join(' '), /initiator_software is absent/);
    assert.equal(r.valid, false);
});
test('KNOB requireInitiatorAttestation — a malformed attestation fails closed', () => {
    const receipt = buildReceipt();
    // Attach a malformed attestation directly (missing model_version) and re-anchor.
    receipt.action = { ...receipt.action, [INITIATOR_ATTESTATION_FIELD]: { model_id: 'x', tool_chain_digest: `sha256:${'ab'.repeat(32)}` } };
    const rebuilt = reanchor(receipt);
    const r = verifyTrustReceipt(rebuilt, { ...OPTS, requireInitiatorAttestation: true });
    assert.equal(r.checks.initiator_attestation, false);
    assert.equal(r.initiator_attestation.ok, false);
    assert.equal(r.valid, false);
});
test('KNOB requireInitiatorAttestation — false/omitted does NOT add the checks key', () => {
    const r = verifyTrustReceipt(buildReceipt(), { ...OPTS, requireInitiatorAttestation: false });
    assert.equal('initiator_attestation' in r.checks, false);
    assert.equal('initiator_attestation' in r, false);
    assert.equal(r.valid, true);
});
// Rebuild the log_proof (leaf + inclusion path + checkpoint) after the action —
// and therefore action_hash and the contexts' committed action_hash — changed.
function reanchor(receipt) {
    const action = receipt.action;
    const action_hash = `sha256:${sha256hex(canonicalize(action))}`;
    receipt.action_hash = action_hash;
    // Rebuild contexts + signoffs so they commit to the new action_hash.
    const baseCtx = {
        ep_version: '1.0', context_type: 'ep.signoff.v1', action_hash,
        policy_id: 'ep:policy:wires-over-100k@v12', policy_hash: 'sha256:77ab1234',
        initiator: action.initiator, required_approvals: 2,
        issued_at: '2026-06-09T17:21:05Z', expires_at: '2026-06-09T17:36:05Z',
    };
    const ctx1 = { ...baseCtx, approver: 'ep:approver:jchen-controller', approver_index: 1, nonce: 'n-1' };
    const ctx2 = { ...baseCtx, approver: 'ep:approver:mrios-cfo', approver_index: 2, nonce: 'n-2' };
    const d1 = sha256hex(canonicalize(ctx1));
    const d2 = sha256hex(canonicalize(ctx2));
    receipt.contexts = [ctx1, ctx2];
    receipt.signoffs = [
        { context_hash: `sha256:${d1}`, signature: signB(d1), key_class: 'B', approver_key_id: 'ep:key:controller#1', signed_at: '2026-06-09T17:24:40Z' },
        { context_hash: `sha256:${d2}`, signature: 'unused-for-class-a', key_class: 'A', approver_key_id: 'ep:key:cfo#1', signed_at: '2026-06-09T17:25:01Z', webauthn: signA(d2) },
    ];
    const leafSource = { ...receipt };
    delete leafSource.log_proof;
    delete leafSource.approver_key_proofs;
    const leaf = leafHashV2(canonicalize(leafSource));
    const sibling1 = sha256hex('other-leaf-1');
    const sibling2 = sha256hex('other-subtree');
    const level1 = hashPairV2(leaf, sibling1);
    const root = hashPairV2(level1, sibling2);
    const checkpoint = { tree_size: 4, root_hash: `sha256:${root}`, log_key_id: 'ep:log:test#1', merkle_alg: 'EP-MERKLE-v2' };
    const log_signature = crypto.sign(null, crypto.createHash('sha256').update(canonicalize(checkpoint), 'utf8').digest(), logKey.privateKey).toString('base64url');
    receipt.log_proof = {
        alg: 'EP-MERKLE-v2', leaf_hash: `sha256:${leaf}`, leaf_index: 0,
        inclusion_path: [{ hash: sibling1, position: 'right' }, { hash: sibling2, position: 'right' }],
        checkpoint: { ...checkpoint, log_signature },
    };
    return receipt;
}
// ══════════════════════════════════════════════════════════════════════════
// COMPOSITION — multiple knobs at once; each key present and conjuncted.
// ══════════════════════════════════════════════════════════════════════════
test('COMPOSITION — witness + timestamp + currency + consumption all active and passing', () => {
    const receipt = buildReceipt();
    const cp = receipt.log_proof.checkpoint;
    const w1 = ed25519();
    const r = verifyTrustReceipt(receipt, {
        ...OPTS,
        witnessQuorum: {
            cosignatures: [cosign(cp, 'witness-a', w1)],
            pinnedWitnessKeys: [{ witness_id: 'witness-a', public_key: w1.pub }],
            k: 1,
        },
        timestampProof: { token: TS.TOKEN1, expectedDigest: `sha256:${TS.DIGEST1}`, pinnedTsaKeys: TS.SIGNER_SPKI },
        currency: { now: '2026-07-05T00:00:00Z', maxStalenessSeconds: 3600, freshHead: { observed_at: '2026-07-05T00:00:00Z' } },
        consumptionProof: makeConsumptionBundle(),
    });
    assert.deepEqual(Object.keys(r.checks).sort(), [...FROZEN_CHECK_KEYS, 'witness_quorum', 'timestamp_proof', 'currency', 'consumption'].sort(), JSON.stringify(r.errors));
    assert.equal(r.valid, true, JSON.stringify(r.errors));
});
test('COMPOSITION — one failing knob fails the whole receipt even when the others pass', () => {
    const receipt = buildReceipt();
    const cp = receipt.log_proof.checkpoint;
    const w1 = ed25519();
    const r = verifyTrustReceipt(receipt, {
        ...OPTS,
        witnessQuorum: {
            cosignatures: [cosign(cp, 'witness-a', w1)],
            pinnedWitnessKeys: [{ witness_id: 'witness-a', public_key: w1.pub }],
            k: 1,
        },
        // currency with no fresh head ⇒ unknown ⇒ fails the opted-in gate.
        currency: { now: '2026-07-05T00:00:00Z', maxStalenessSeconds: 3600 },
    });
    assert.equal(r.checks.witness_quorum, true);
    assert.equal(r.checks.currency, false);
    assert.equal(r.valid, false);
});
