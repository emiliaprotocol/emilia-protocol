// SPDX-License-Identifier: Apache-2.0
// Generated from generate-outcome-binding.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Deterministic, executable EP-OUTCOME-BINDING-v1 vectors.
//
// Unlike the semantic predicate/graph catalogue, every vector here runs the
// complete protocol path: a real two-approver Trust Receipt, a real v2 log
// proof, a real executor-signed observed-effects attestation, pinned keys, and
// the exact receipt/action/consumption bindings.
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { actionHash, buildContexts, buildReceiptAnchorV2, canonicalize, collectSignoffs, } from '../../packages/issue/index.js';
import { buildOutcomeAttestation, trustReceiptDigest, verifyOutcomeBinding, } from '../../packages/verify/index.js';
import { predictedEffectsDigest } from '../../packages/verify/effect-predicates.js';
function keyFromByte(byte) {
    const seed = Buffer.alloc(32, byte);
    return crypto.createPrivateKey({
        key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
        format: 'der',
        type: 'pkcs8',
    });
}
const publicKey = (privateKey) => crypto.createPublicKey(privateKey)
    .export({ type: 'spki', format: 'der' }).toString('base64url');
const hashBytes = (value) => crypto.createHash('sha256').update(value).digest();
const digest = (value) => `sha256:${hashBytes(Buffer.from(canonicalize(value), 'utf8')).toString('hex')}`;
const APPROVER_A = keyFromByte(0x61);
const APPROVER_B = keyFromByte(0x62);
const LOG_KEY = keyFromByte(0x63);
const EXECUTOR_KEY = keyFromByte(0x64);
const ISSUED = '2026-07-19T16:00:00.000Z';
const EXECUTED = '2026-07-19T16:01:00.000Z';
const NOW = '2026-07-19T16:02:00.000Z';
const PREDICTIONS = [
    { effect_type: 'payment', target: 'acct:vendor-9', predicate: { op: 'lte', value: '10.00' } },
];
function approver(privateKey, approverKeyId, approverId) {
    return {
        keyEntry: {
            approver_id: approverId,
            public_key: publicKey(privateKey),
            key_class: 'B',
            valid_from: '2026-01-01T00:00:00.000Z',
            valid_to: '2027-01-01T00:00:00.000Z',
        },
        signer: {
            approverKeyId,
            keyClass: 'B',
            signedAt: ISSUED,
            sign: (bytes) => crypto.sign(null, bytes, privateKey).toString('base64url'),
        },
    };
}
const a = approver(APPROVER_A, 'ep:key:approver-a#1', 'ep:approver:alice');
const b = approver(APPROVER_B, 'ep:key:approver-b#1', 'ep:approver:bob');
const action = {
    ep_version: '1.0',
    action_type: 'payment.release',
    target: { system: 'treasury.example', resource: 'payment/991' },
    parameters: { amount: '10.00', currency: 'USD' },
    initiator: 'ep:entity:agent-7',
    policy_id: 'ep:policy:payment@v1',
    requested_at: ISSUED,
    predicted_effects: PREDICTIONS,
    predicted_effects_digest: predictedEffectsDigest(PREDICTIONS),
};
const contexts = buildContexts({
    action,
    policyHash: `sha256:${'77'.repeat(32)}`,
    approvers: ['ep:approver:alice', 'ep:approver:bob'],
    requiredApprovals: 2,
    issuedAt: ISSUED,
    expiresAt: '2026-07-19T17:00:00.000Z',
});
contexts[0].nonce = 'outcome-vector-approver-a';
contexts[1].nonce = 'outcome-vector-approver-b';
const signoffs = await collectSignoffs(contexts, [a.signer, b.signer]);
const receipt = {
    receipt_id: 'ep:receipt:outcome-vector-1',
    action,
    action_hash: actionHash(action),
    contexts,
    signoffs,
    consumption: {
        nonce: 'outcome-vector-consumption',
        state: 'COMMITTED',
        committed_at: ISSUED,
    },
};
const anchor = buildReceiptAnchorV2(receipt);
const checkpoint = {
    tree_size: 1,
    root_hash: anchor.merkle_root,
    log_key_id: 'ep:log:outcome-vector#1',
    merkle_alg: 'EP-MERKLE-v2',
};
receipt.log_proof = {
    ...anchor,
    leaf_index: 0,
    inclusion_path: anchor.merkle_proof,
    checkpoint: {
        ...checkpoint,
        log_signature: crypto.sign(null, hashBytes(Buffer.from(canonicalize(checkpoint), 'utf8')), LOG_KEY).toString('base64url'),
    },
};
delete receipt.log_proof.merkle_proof;
delete receipt.log_proof.merkle_root;
const receiptOptions = {
    approverKeys: {
        'ep:key:approver-a#1': a.keyEntry,
        'ep:key:approver-b#1': b.keyEntry,
    },
    logPublicKey: publicKey(LOG_KEY),
};
const executorKeys = {
    'ep:executor:payments-1': { public_key: publicKey(EXECUTOR_KEY) },
};
function attestation(observedEffects, overrides = {}) {
    return buildOutcomeAttestation({
        receipt_id: receipt.receipt_id,
        receipt_digest: trustReceiptDigest(receipt),
        action_hash: receipt.action_hash,
        consumption_nonce: receipt.consumption.nonce,
        execution_id: 'ep:execution:outcome-vector-1',
        executor_id: 'ep:executor:payments-1',
        executed_at: EXECUTED,
        observed_effects: structuredClone(observedEffects),
        ...overrides,
        signer: { privateKey: EXECUTOR_KEY },
    });
}
const inBounds = [{ effect_type: 'payment', target: 'acct:vendor-9', value: '9.00' }];
/** @type {Array<{
 *   id: string,
 *   attestation: ReturnType<typeof attestation>,
 *   policy_predicted_effects?: unknown,
 *   executor_keys?: Record<string, { public_key: string }>,
 *   expect: {
 *     outcome: string,
 *     valid?: boolean,
 *     checks?: unknown,
 *     reasons?: unknown,
 *     receipt_digest?: string,
 *     attestation_digest?: string,
 *     result_digest?: string,
 *   },
 * }>} */
const vectors = [
    {
        id: 'accept_real_receipt_and_executor_attestation',
        attestation: attestation(inBounds),
        expect: { outcome: 'in_bounds' },
    },
    {
        id: 'reject_signed_effect_divergence',
        attestation: attestation([
            { effect_type: 'payment', target: 'acct:vendor-9', value: '11.00' },
        ]),
        expect: { outcome: 'divergent' },
    },
    {
        id: 'reject_policy_tightening_divergence',
        attestation: attestation(inBounds),
        policy_predicted_effects: [
            { effect_type: 'payment', target: 'acct:vendor-9', predicate: { op: 'lte', value: '5.00' } },
        ],
        expect: { outcome: 'divergent' },
    },
    {
        id: 'reject_resigned_receipt_id_swap',
        attestation: attestation(inBounds, { receipt_id: 'ep:receipt:other' }),
        expect: { outcome: 'incomparable' },
    },
    {
        id: 'reject_resigned_receipt_bytes_swap',
        attestation: attestation(inBounds, { receipt_digest: `sha256:${'bb'.repeat(32)}` }),
        expect: { outcome: 'incomparable' },
    },
    {
        id: 'reject_resigned_action_swap',
        attestation: attestation(inBounds, { action_hash: `sha256:${'aa'.repeat(32)}` }),
        expect: { outcome: 'incomparable' },
    },
    {
        id: 'reject_resigned_consumption_nonce_swap',
        attestation: attestation(inBounds, { consumption_nonce: 'other-consumption-nonce' }),
        expect: { outcome: 'incomparable' },
    },
    {
        id: 'reject_post_signature_observation_tamper',
        attestation: (() => {
            const value = attestation(inBounds);
            value.observed_effects[0].value = '0.01';
            return value;
        })(),
        expect: { outcome: 'incomparable' },
    },
    {
        id: 'reject_unpinned_executor',
        attestation: attestation(inBounds),
        executor_keys: {},
        expect: { outcome: 'incomparable' },
    },
    {
        id: 'reject_malformed_policy_predictions',
        attestation: attestation(inBounds),
        policy_predicted_effects: { allow: true },
        expect: { outcome: 'incomparable' },
    },
];
for (const vector of vectors) {
    const options = {
        receiptOptions,
        executorKeys: Object.hasOwn(vector, 'executor_keys') ? vector.executor_keys : executorKeys,
        now: NOW,
        ...(Object.hasOwn(vector, 'policy_predicted_effects')
            ? {
                policyPredictedEffects: vector.policy_predicted_effects,
            }
            : {}),
    };
    const result = verifyOutcomeBinding(receipt, vector.attestation, options);
    const expectedValid = vector.expect.outcome === 'in_bounds';
    if (result.valid !== expectedValid || result.outcome_binding.outcome !== vector.expect.outcome) {
        throw new Error(`${vector.id}: generator self-check failed: ${JSON.stringify(result)}`);
    }
    vector.expect = {
        outcome: result.outcome_binding.outcome,
        valid: result.valid,
        checks: result.checks,
        reasons: result.outcome_binding.reasons,
        receipt_digest: trustReceiptDigest(receipt),
        attestation_digest: digest(vector.attestation),
        result_digest: result.result_digest,
    };
}
const suite = {
    suite: 'EP-OUTCOME-BINDING-v1-real-crypto',
    profile: 'Executable full-protocol vectors: real Trust Receipt bytes, pinned approver/log/executor keys, signed observed-effects attestations, and exact typed outcome/check/reason/input/result-digest expectations.',
    vectors_version: '1.1.0',
    count: vectors.length,
    common: {
        receipt,
        receipt_options: receiptOptions,
        executor_keys: executorKeys,
        now: NOW,
    },
    vectors,
};
writeFileSync(new URL('./outcome-binding.exec.v1.json', import.meta.url), `${JSON.stringify(suite, null, 2)}\n`);
console.log(`wrote outcome-binding.exec.v1.json (${vectors.length} real-crypto vectors)`);
