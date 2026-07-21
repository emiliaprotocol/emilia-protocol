// SPDX-License-Identifier: Apache-2.0
// Generated from orprg.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { canonicalize as canonicalizeCaid } from '../../caid/impl/js/caid.mjs';
import { verifyAuthorizationChain } from './evidence-chain.js';
import { ORPRG_ACTION_PROFILE, ORPRG_JSON_JCS_PROFILE, computeOrprgActionDigest, createOrprgAecVerifier, verifyOrprgJsonJcsPermit, verifyOrprgJsonJcsPermitAsync, } from './orprg.js';
const NOW = '2026-07-19T12:00:00Z';
const POLICY_DIGEST = `sha256:${'a'.repeat(64)}`;
const EPOCH = 'policy-epoch-42';
const ISSUER_ID = 'https://policy.example/issuers/primary';
const KEY_ID = 'orprg-ed25519-2026-07';
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const PUBLIC_KEY = publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const ACTION = Object.freeze({
    effect_type: 'payment.release',
    interface_id: 'payments-api-v2',
    target_id: 'escrow_4821',
    tenant_id: 'tenant_acme',
    purpose_id: 'invoice-settlement',
    jurisdiction: ['US-CA'],
    audience: 'https://payments.example/commit',
    budget: {
        unit: 'USD-cent',
        amount: 50_000,
    },
    request: {
        destination_account: 'acct_vendor_9',
        invoice_id: 'inv_2026_0719',
        memo: 'Milestone 3',
    },
});
function jcs(value) {
    const result = canonicalizeCaid(value);
    assert.equal(result.ok, true, result.refusals?.join(', '));
    return result.canonical;
}
function signReceipt(receipt, key = privateKey) {
    const unsigned = {
        '@version': receipt['@version'],
        receipt_core: receipt.receipt_core,
        status: receipt.status,
        authenticity: {
            issuer_id: receipt.authenticity.issuer_id,
            key_id: receipt.authenticity.key_id,
            algorithm: receipt.authenticity.algorithm,
        },
    };
    receipt.authenticity.signature = crypto
        .sign(null, Buffer.from(jcs(unsigned), 'utf8'), key)
        .toString('base64url');
    return receipt;
}
function makeReceipt(mutator) {
    const receipt = {
        '@version': ORPRG_JSON_JCS_PROFILE,
        receipt_core: {
            policy_digest: POLICY_DIGEST,
            epoch_id: EPOCH,
            valid_from: '2026-07-19T11:55:00Z',
            valid_to: '2026-07-19T12:05:00Z',
            action_digest: computeOrprgActionDigest(ACTION),
            canonicalization_profile: ORPRG_ACTION_PROFILE,
            scope: {
                effect_type: ACTION.effect_type,
                interface_id: ACTION.interface_id,
                target_id: ACTION.target_id,
                tenant_id: ACTION.tenant_id,
                purpose_id: ACTION.purpose_id,
                jurisdiction: [...ACTION.jurisdiction],
                audience: ACTION.audience,
                budget: {
                    unit: ACTION.budget.unit,
                    limit: 100_000,
                },
            },
            anti_replay: {
                mode: 'single-use',
                nonce: 'S1ngleUseNonce_20260719_0001',
            },
        },
        status: {
            state: 'good',
            checked_at: '2026-07-19T11:59:00Z',
            next_update: '2026-07-19T12:03:00Z',
        },
        authenticity: {
            issuer_id: ISSUER_ID,
            key_id: KEY_ID,
            algorithm: 'Ed25519',
            signature: '',
        },
    };
    mutator?.(receipt);
    return signReceipt(receipt);
}
function replayStore({ durable = true, atomic = true, asynchronous = false, throws = false, } = {}) {
    const seen = new Set();
    const consume = (key) => {
        if (throws)
            throw new Error('replay backend unavailable');
        if (seen.has(key))
            return false;
        seen.add(key);
        return true;
    };
    return {
        durable,
        atomic,
        seen,
        consume: asynchronous ? async (key) => consume(key) : consume,
    };
}
function options(overrides = {}) {
    return {
        expectedAction: ACTION,
        expectedPolicyDigest: POLICY_DIGEST,
        expectedEpoch: EPOCH,
        verificationTime: NOW,
        maxReceiptAgeSeconds: 600,
        maxStatusAgeSeconds: 180,
        issuerKeys: {
            [ISSUER_ID]: {
                [KEY_ID]: PUBLIC_KEY,
            },
        },
        antiReplay: replayStore(),
        ...overrides,
    };
}
test('profile is explicit and JCS action digests are insertion-order independent', () => {
    assert.equal(ORPRG_JSON_JCS_PROFILE, 'ORPRG-JSON-JCS-ED25519-v1');
    assert.equal(ORPRG_ACTION_PROFILE, 'ORPRG-JCS-ACTION-v1');
    const reordered = {
        request: { memo: 'Milestone 3', invoice_id: 'inv_2026_0719', destination_account: 'acct_vendor_9' },
        budget: { amount: 50_000, unit: 'USD-cent' },
        audience: ACTION.audience,
        jurisdiction: ['US-CA'],
        purpose_id: ACTION.purpose_id,
        tenant_id: ACTION.tenant_id,
        target_id: ACTION.target_id,
        interface_id: ACTION.interface_id,
        effect_type: ACTION.effect_type,
    };
    assert.equal(computeOrprgActionDigest(reordered), computeOrprgActionDigest(ACTION));
    assert.match(computeOrprgActionDigest(ACTION), /^sha256:[0-9a-f]{64}$/);
});
test('a valid permit returns a clean AEC component result and consumes once', () => {
    const receipt = makeReceipt();
    const opts = options();
    const accepted = verifyOrprgJsonJcsPermit(receipt, opts);
    assert.equal(accepted.valid, true, accepted.detail?.reason);
    assert.equal(accepted.action_digest, computeOrprgActionDigest(ACTION));
    assert.equal(accepted.detail.decision, 'ALLOW');
    assert.equal(accepted.detail.denial_reason_code, null);
    assert.equal(accepted.detail.checks.anti_replay, true);
    assert.match(accepted.detail.evidence_digests.receipt_digest, /^sha256:[0-9a-f]{64}$/);
    const replay = verifyOrprgJsonJcsPermit(receipt, opts);
    assert.equal(replay.valid, false);
    assert.equal(replay.action_digest, null);
    assert.equal(replay.detail.denial_reason_code, 'ANTI_REPLAY_FAILURE');
});
test('re-signing different receipt bytes cannot reuse the same scoped nonce', () => {
    const opts = options();
    const first = verifyOrprgJsonJcsPermit(makeReceipt(), opts);
    assert.equal(first.valid, true, first.detail?.reason);
    const reissued = makeReceipt((receipt) => {
        receipt.status.next_update = '2026-07-19T12:04:00Z';
    });
    assert.notEqual(first.detail.evidence_digests.receipt_digest, verifyOrprgJsonJcsPermit(reissued, options()).detail.evidence_digests.receipt_digest);
    const replay = verifyOrprgJsonJcsPermit(reissued, opts);
    assert.equal(replay.valid, false);
    assert.equal(replay.detail.denial_reason_code, 'ANTI_REPLAY_FAILURE');
});
test('the AEC adapter satisfies only a relying-party-pinned same-action requirement', () => {
    const receipt = makeReceipt();
    const verifier = createOrprgAecVerifier(options({ expectedAction: undefined, verificationTime: undefined }));
    const chainAction = structuredClone(ACTION);
    const result = verifyAuthorizationChain({
        '@version': 'EP-AEC-v1',
        action: chainAction,
        action_digest: computeOrprgActionDigest(ACTION),
        components: [{
                type: 'orprg-json-jcs',
                evidence: receipt,
            }],
        requirement: 'orprg-json-jcs',
    }, {
        expectedAction: structuredClone(ACTION),
        requirement: 'orprg-json-jcs',
        verificationTime: NOW,
        verifiers: {
            'orprg-json-jcs': verifier,
        },
    });
    assert.equal(result.satisfied, true, result.reasons.join('; '));
    assert.equal(result.components[0].valid, true);
    assert.equal(result.components[0].bound, true);
});
test('closed schemas reject unknown fields at every security boundary', () => {
    const cases = [
        ['receipt', (r) => { r.unexpected = true; }],
        ['receipt_core', (r) => { r.receipt_core.unexpected = true; }],
        ['scope', (r) => { r.receipt_core.scope.unexpected = true; }],
        ['budget', (r) => { r.receipt_core.scope.budget.unexpected = true; }],
        ['anti_replay', (r) => { r.receipt_core.anti_replay.unexpected = true; }],
        ['status', (r) => { r.status.unexpected = true; }],
        ['authenticity', (r) => { r.authenticity.unexpected = true; }],
    ];
    for (const [label, mutate] of cases) {
        const result = verifyOrprgJsonJcsPermit(makeReceipt(mutate), options());
        assert.equal(result.valid, false, label);
        assert.equal(result.detail.denial_reason_code, 'MALFORMED_RECEIPT', label);
    }
});
test('missing and unknown required state never acquires defaults', () => {
    const cases = [
        (r) => { delete r.receipt_core.action_digest; },
        (r) => { delete r.receipt_core.scope.audience; },
        (r) => { delete r.receipt_core.anti_replay.nonce; },
        (r) => { delete r.status.checked_at; },
        (r) => { delete r.authenticity.issuer_id; },
        (r) => { r.status.state = 'maybe-good'; },
        (r) => { r.receipt_core.anti_replay.mode = 'best-effort'; },
    ];
    for (const mutate of cases) {
        const receipt = makeReceipt();
        mutate(receipt);
        const result = verifyOrprgJsonJcsPermit(receipt, options());
        assert.equal(result.valid, false);
        assert.equal(result.detail.denial_reason_code, 'MALFORMED_RECEIPT');
    }
});
test('raw JSON with duplicate member names is denied before parsing', () => {
    const raw = JSON.stringify(makeReceipt()).replace(`{"@version":"${ORPRG_JSON_JCS_PROFILE}",`, `{"@version":"${ORPRG_JSON_JCS_PROFILE}","@version":"${ORPRG_JSON_JCS_PROFILE}",`);
    const result = verifyOrprgJsonJcsPermit(raw, options());
    assert.equal(result.valid, false);
    assert.equal(result.detail.denial_reason_code, 'MALFORMED_RECEIPT');
});
test('the action profile is closed and refuses unsafe or ambiguous JSON', () => {
    assert.equal(computeOrprgActionDigest({ ...ACTION, unexpected: true }), null);
    assert.equal(computeOrprgActionDigest({ ...ACTION, request: { value: 1.5 } }), null);
    assert.equal(computeOrprgActionDigest({ ...ACTION, request: { bad: '\ud800' } }), null);
    assert.equal(computeOrprgActionDigest({ ...ACTION, jurisdiction: ['US-NY', 'US-CA'] }), null);
    assert.equal(computeOrprgActionDigest({ ...ACTION, jurisdiction: ['US-CA', 'US-CA'] }), null);
});
test('profile and action digest mismatches deny', () => {
    const wrongProfile = makeReceipt((r) => {
        r.receipt_core.canonicalization_profile = 'orprg-some-other-profile';
    });
    assert.equal(verifyOrprgJsonJcsPermit(wrongProfile, options()).detail.denial_reason_code, 'CANONICALIZATION_MISMATCH');
    const wrongDigest = makeReceipt((r) => {
        r.receipt_core.action_digest = `sha256:${'b'.repeat(64)}`;
    });
    assert.equal(verifyOrprgJsonJcsPermit(wrongDigest, options()).detail.denial_reason_code, 'ACTION_DIGEST_MISMATCH');
});
test('issuer trust is role-pinned and the Ed25519 signature binds the full receipt', () => {
    const receipt = makeReceipt();
    const untrusted = verifyOrprgJsonJcsPermit(receipt, options({ issuerKeys: {} }));
    assert.equal(untrusted.detail.denial_reason_code, 'ISSUER_UNTRUSTED');
    receipt.status.next_update = '2026-07-19T12:04:00Z';
    const tampered = verifyOrprgJsonJcsPermit(receipt, options());
    assert.equal(tampered.detail.denial_reason_code, 'SIGNATURE_INVALID');
    const attacker = crypto.generateKeyPairSync('ed25519');
    const attackerSigned = makeReceipt();
    signReceipt(attackerSigned, attacker.privateKey);
    const badSignature = verifyOrprgJsonJcsPermit(attackerSigned, options());
    assert.equal(badSignature.detail.denial_reason_code, 'SIGNATURE_INVALID');
});
test('missing or mismatched policy and epoch state deny', () => {
    const cases = [
        ['POLICY_MISMATCH', { expectedPolicyDigest: undefined }],
        ['POLICY_MISMATCH', { expectedPolicyDigest: `sha256:${'b'.repeat(64)}` }],
        ['EPOCH_MISMATCH', { expectedEpoch: undefined }],
        ['EPOCH_MISMATCH', { expectedEpoch: 'policy-epoch-41' }],
    ];
    for (const [code, override] of cases) {
        const result = verifyOrprgJsonJcsPermit(makeReceipt(), options(override));
        assert.equal(result.valid, false);
        assert.equal(result.detail.denial_reason_code, code);
    }
});
test('validity, receipt recency, status state, and status recency fail closed', () => {
    const cases = [
        ['AMBIGUOUS_CONTEXT', {}, { verificationTime: undefined }],
        ['VALIDITY_WINDOW_EXPIRED', {}, { verificationTime: '2026-07-19T12:06:00Z' }],
        ['VALIDITY_WINDOW_EXPIRED', {}, { maxReceiptAgeSeconds: 60 }],
        ['VALIDITY_WINDOW_EXPIRED', {}, { maxReceiptAgeSeconds: undefined }],
        ['REVOCATION_UNKNOWN_OR_STALE', (r) => { r.status.state = 'unknown'; }, {}],
        ['REVOKED_CONFIRMED', (r) => { r.status.state = 'revoked'; }, {}],
        ['REVOCATION_UNKNOWN_OR_STALE', (r) => { r.status.checked_at = '2026-07-19T11:50:00Z'; }, {}],
        ['REVOCATION_UNKNOWN_OR_STALE', (r) => { r.status.next_update = '2026-07-19T11:59:59Z'; }, {}],
        ['REVOCATION_UNKNOWN_OR_STALE', {}, { maxStatusAgeSeconds: undefined }],
    ];
    for (const [code, mutate, override] of cases) {
        const receipt = makeReceipt(typeof mutate === 'function' ? mutate : undefined);
        const result = verifyOrprgJsonJcsPermit(receipt, options(override));
        assert.equal(result.valid, false, code);
        assert.equal(result.detail.denial_reason_code, code);
    }
});
test('scope, audience, and budget are bound to the exact expected action', () => {
    const cases = [
        (r) => { r.receipt_core.scope.audience = 'https://attacker.example/commit'; },
        (r) => { r.receipt_core.scope.target_id = 'escrow_other'; },
        (r) => { delete r.receipt_core.scope.tenant_id; },
        (r) => { r.receipt_core.scope.jurisdiction = ['US-NY']; },
    ];
    for (const mutate of cases) {
        const result = verifyOrprgJsonJcsPermit(makeReceipt(mutate), options());
        assert.equal(result.valid, false);
        assert.equal(result.detail.denial_reason_code, 'SCOPE_VIOLATION');
    }
    const overspend = makeReceipt((r) => {
        r.receipt_core.scope.budget.limit = ACTION.budget.amount - 1;
    });
    assert.equal(verifyOrprgJsonJcsPermit(overspend, options()).detail.denial_reason_code, 'SCOPE_VIOLATION');
    const missingRequiredBudget = verifyOrprgJsonJcsPermit(makeReceipt((r) => { delete r.receipt_core.scope.budget; }), options({ requireBudget: true }));
    assert.equal(missingRequiredBudget.detail.denial_reason_code, 'SCOPE_VIOLATION');
});
test('anti-replay requires an atomic durable hook and treats uncertainty as denial', () => {
    const cases = [
        undefined,
        replayStore({ durable: false }),
        replayStore({ atomic: false }),
        replayStore({ throws: true }),
        replayStore({ asynchronous: true }),
    ];
    for (const antiReplay of cases) {
        const result = verifyOrprgJsonJcsPermit(makeReceipt(), options({ antiReplay }));
        assert.equal(result.valid, false);
        assert.equal(result.detail.denial_reason_code, 'ANTI_REPLAY_FAILURE');
    }
});
test('the async verifier supports an asynchronous atomic durable anti-replay hook', async () => {
    const receipt = makeReceipt();
    const opts = options({ antiReplay: replayStore({ asynchronous: true }) });
    const accepted = await verifyOrprgJsonJcsPermitAsync(receipt, opts);
    assert.equal(accepted.valid, true, accepted.detail?.reason);
    const replay = await verifyOrprgJsonJcsPermitAsync(receipt, opts);
    assert.equal(replay.valid, false);
    assert.equal(replay.detail.denial_reason_code, 'ANTI_REPLAY_FAILURE');
});
