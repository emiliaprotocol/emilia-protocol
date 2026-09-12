// SPDX-License-Identifier: Apache-2.0
// Generated from receipt-provider-entry-freshness.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Build Gate, then run: npx tsx --test packages/gate/receipt-provider-entry-freshness.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createGate, createEvidenceLog, MemoryConsumptionStore, createRuntimeMonitor, createMemoryCapabilityStore, mintCapabilityReceipt, CAPABILITY_SCOPE_PROFILE, capabilityActionDigest, } from './index.js';
import { canonicalEvidenceJson } from './evidence.js';
const START = Date.parse('2026-09-05T12:00:00.000Z');
const ACTION = 'payment.release';
const KEY = crypto.generateKeyPairSync('ed25519');
const PUBLIC_KEY = KEY.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const PROFILE = { id: 'ep:profile:entry-freshness', profile_hash: `sha256:${'a'.repeat(64)}` };
function mint({ expiresAt = START + 60_000, receiptId = crypto.randomUUID(), claim = {} } = {}) {
    const payload = {
        receipt_id: receiptId,
        subject: 'agent:entry-freshness-test',
        created_at: new Date(START).toISOString(),
        ...(expiresAt === null ? {} : { expires_at: new Date(expiresAt).toISOString() }),
        claim: { action_type: ACTION, outcome: 'allow', ...claim },
    };
    return {
        '@version': 'EP-RECEIPT-v1',
        payload,
        signature: {
            algorithm: 'Ed25519',
            value: crypto.sign(null, Buffer.from(canonicalEvidenceJson(payload)), KEY.privateKey).toString('base64url'),
        },
    };
}
function fixture({ delayAt = '', delayMs = 120_000, maxAgeSec = 900, releaseFails = false, onReserved = () => { } } = {}) {
    let clock = START;
    let calls = 0;
    let runtimeCycle = null;
    const transitions = [];
    const runtimeMonitor = createRuntimeMonitor({ now: () => clock });
    const beginExecution = runtimeMonitor.beginExecution.bind(runtimeMonitor);
    runtimeMonitor.beginExecution = (cycleId, authorization) => {
        runtimeCycle = cycleId;
        const result = beginExecution(cycleId, authorization);
        if (delayAt === 'runtime-monitor')
            clock += delayMs;
        return result;
    };
    class Store extends MemoryConsumptionStore {
        async reserve(key) {
            const reserved = await super.reserve(key);
            if (reserved) {
                if (delayAt === 'reserve')
                    clock += delayMs;
                onReserved();
            }
            return reserved;
        }
        async release(key) {
            transitions.push(`release:${key}`);
            if (releaseFails)
                throw new Error('backend unavailable');
            return super.release(key);
        }
        async commit(key) {
            transitions.push(`commit:${key}`);
            return super.commit(key);
        }
    }
    const store = new Store();
    const log = createEvidenceLog({
        strict: true,
        sink: async (record) => {
            if (delayAt === 'decision-log' && record.kind === 'decision' && record.allow)
                clock += delayMs;
        },
    });
    const gate = createGate({
        trustedKeys: [PUBLIC_KEY],
        allowEphemeralStore: true,
        store,
        log,
        now: () => clock,
        runtimeMonitor,
        maxAgeSec,
        ...(delayAt === 'admissibility' ? {
            requiredAdmissibilityProfile: PROFILE,
            verifyAdmissibilityPacket: async () => {
                clock += delayMs;
                return {
                    admissibility_profile: { id: PROFILE.id, version: '1' },
                    profile_hash: PROFILE.profile_hash,
                    verdict: 'admissible',
                };
            },
        } : {}),
        ...(delayAt === 'entry-guard' ? {
            providerEntryGuard: async () => {
                clock += delayMs;
                return { ok: true, evidence: { checked: true } };
            },
        } : {}),
    });
    return {
        gate, store, log, transitions, runtimeMonitor,
        runtimeState: () => runtimeMonitor.getState(runtimeCycle),
        calls: () => calls,
        advance: (ms) => { clock += ms; },
        invoke: (receipt, effect = async () => 'settled') => gate.run({ selector: { action_type: ACTION }, receipt }, async () => { calls += 1; return effect(); }),
    };
}
for (const delayAt of ['reserve', 'decision-log', 'admissibility', 'entry-guard']) {
    test(`receipt expiry during ${delayAt} refuses before provider entry and releases only its reservation`, async () => {
        const f = fixture({ delayAt });
        const receipt = mint();
        const out = await f.invoke(receipt);
        assert.equal(out.ok, false);
        assert.equal(f.calls(), 0);
        assert.equal(out.authorization.reason, 'receipt_rejected:receipt_expired');
        assert.equal(out.status, 428);
        assert.equal(out.authorization.evidence.kind, 'provider_entry');
        assert.equal(out.authorization.evidence.outcome, 'refused');
        assert.equal(out.authorization.evidence.reservation_disposition, 'release');
        assert.equal(out.authorization.evidence.reservation_transition_ok, true);
        assert.equal(out.authorization.prior_authorization, out.authorization.evidence.authorizes_decision);
        assert.equal(f.transitions.length, 1);
        assert.match(f.transitions[0], /^release:/);
        assert.equal(f.store.reserved.size, 0);
        assert.equal(f.store.seen.size, 0);
        const retry = await f.invoke(receipt);
        assert.equal(retry.ok, false);
        assert.equal(retry.authorization.reason, 'receipt_rejected:receipt_expired');
        assert.equal(f.calls(), 0);
        assert.equal(f.transitions.length, 1, 'a pre-check refusal must not release a reservation');
    });
}
test('relative maximum age is also rechecked after reservation', async () => {
    const f = fixture({ delayAt: 'reserve', maxAgeSec: 60 });
    const out = await f.invoke(mint({ expiresAt: null }));
    assert.equal(out.ok, false);
    assert.equal(out.authorization.reason, 'receipt_rejected:receipt_expired');
    assert.equal(f.calls(), 0);
});
test('expiry during synchronous runtime-monitor setup refuses, releases, and leaves the monitor healthy', async () => {
    const f = fixture({ delayAt: 'runtime-monitor' });
    const out = await f.invoke(mint());
    assert.equal(out.ok, false);
    assert.equal(f.calls(), 0);
    assert.equal(out.authorization.reason, 'receipt_rejected:receipt_expired');
    assert.equal(out.authorization.evidence.reservation_disposition, 'release');
    assert.equal(f.store.reserved.size, 0);
    assert.equal(f.store.seen.size, 0);
    assert.equal(f.transitions.length, 1);
    assert.match(f.transitions[0], /^release:/);
    assert.equal(f.runtimeMonitor.getMode(), 'normal');
    assert.equal(f.runtimeState().phase, 'provider_entry_refused');
    assert.equal(f.runtimeState().complete, true);
});
test('awaited reservation cannot substitute a later-expiring signed receipt for the verified one', async () => {
    const receipt = mint();
    const originalId = receipt.payload.receipt_id;
    const replacement = mint({ expiresAt: START + 900_000 });
    const f = fixture({
        delayAt: 'reserve',
        onReserved: () => { Object.assign(receipt, replacement); },
    });
    const out = await f.invoke(receipt);
    assert.equal(out.ok, false);
    assert.equal(out.authorization.reason, 'receipt_rejected:receipt_expired');
    assert.equal(f.calls(), 0);
    assert.equal(f.transitions.length, 1);
    assert.equal(f.transitions[0], `release:${JSON.stringify([null, originalId])}`);
    assert.equal(out.authorization.evidence.receipt_id, originalId);
    assert.equal(f.store.reserved.size, 0);
});
test('absolute expiry remains binding with the relative-age policy disabled', async () => {
    const f = fixture({ delayAt: 'reserve', delayMs: 60_000, maxAgeSec: 0 });
    const out = await f.invoke(mint());
    assert.equal(out.ok, false, 'the exact expiry instant is outside the validity interval');
    assert.equal(f.calls(), 0);
});
test('a failed pre-entry release remains held and reports its uncertainty', async () => {
    const f = fixture({ delayAt: 'reserve', releaseFails: true });
    const out = await f.invoke(mint());
    assert.equal(out.ok, false);
    assert.equal(out.status, 503);
    assert.equal(out.authorization.reason, 'provider_entry_reservation_transition_indeterminate');
    assert.equal(out.authorization.evidence.reservation_transition_ok, false);
    assert.equal(f.store.reserved.size, 1);
    assert.equal(f.calls(), 0);
});
test('a still-valid receipt executes once and replay never releases committed authority', async () => {
    const f = fixture({ delayAt: 'entry-guard', delayMs: 30_000 });
    const receipt = mint();
    const out = await f.invoke(receipt);
    assert.equal(out.ok, true);
    assert.equal(f.calls(), 1);
    const replay = await f.invoke(receipt);
    assert.equal(replay.ok, false);
    assert.equal(replay.authorization.reason, 'replay_refused');
    assert.equal(f.calls(), 1);
    assert.equal(f.transitions.length, 1);
    assert.match(f.transitions[0], /^commit:/);
});
test('expiry after provider entry never restores authority when the response is lost', async () => {
    const f = fixture();
    const receipt = mint();
    await assert.rejects(f.invoke(receipt, async () => {
        f.advance(120_000);
        throw new Error('provider response lost');
    }), /provider response lost/);
    assert.equal(f.calls(), 1);
    assert.equal(f.store.seen.size, 1);
    assert.equal(f.transitions.length, 1);
    assert.match(f.transitions[0], /^commit:/);
    const retry = await f.invoke(receipt);
    assert.equal(retry.ok, false);
    assert.equal(f.calls(), 1);
    assert.equal(f.transitions.length, 1);
});
test('unguarded pass-through does not acquire a receipt requirement at provider entry', async () => {
    const gate = createGate({
        manifest: { '@version': 'EP-ACTION-RISK-MANIFEST-v0.1', actions: [] },
        allowEphemeralStore: true,
        now: () => START,
    });
    const out = await gate.run({ selector: { action_type: 'read.status' } }, async () => 'read');
    assert.equal(out.ok, true);
    assert.equal(out.authorization.reason, 'not_guarded');
});
for (const delayAt of ['reserveSpend', 'beginProviderEntry']) {
    test(`capability base receipt expiring during ${delayAt} never invokes the provider or restores entered authority`, async () => {
        let clock = START;
        let calls = 0;
        const action = {
            action_type: ACTION, amount: 40, currency: 'USD',
            payment_instruction_id: `payment_${delayAt}`,
        };
        const receipt = mint({ expiresAt: START + 5_000, claim: { capability_only: true } });
        const capability = mintCapabilityReceipt(receipt, {
            issuerPrivateKey: KEY.privateKey,
            budget: { amount: 100, currency: 'USD' },
            expiry: START + 60_000,
            revocationMode: 'direct',
            secret: Buffer.alloc(32, 7),
            capabilityId: `cap_freshness_${delayAt}`,
            scope: {
                profile: CAPABILITY_SCOPE_PROFILE,
                operation_id_field: 'payment_instruction_id',
                action_digests: [capabilityActionDigest(action)],
            },
        });
        const capabilityStore = createMemoryCapabilityStore();
        assert.equal(capabilityStore.registerCapability(capability.capabilityReceipt), true);
        const delayedMethod = capabilityStore[delayAt].bind(capabilityStore);
        capabilityStore[delayAt] = async (input) => {
            const result = await delayedMethod(input);
            if (result.ok)
                clock += 10_000;
            return result;
        };
        const gate = createGate({
            trustedKeys: [PUBLIC_KEY],
            capabilityStore,
            capabilityTrustedIssuerKeys: [PUBLIC_KEY],
            allowEphemeralStore: true,
            now: () => clock,
        });
        const request = {
            selector: { action_type: ACTION },
            observedAction: action,
            capability: {
                capabilityReceipt: capability.capabilityReceipt,
                secret: capability.secret,
                action: { amount: 40, currency: 'USD' },
                operationId: action.payment_instruction_id,
            },
        };
        const out = await gate.run(request, async () => { calls += 1; return 'settled'; });
        assert.equal(out.ok, false);
        assert.equal(calls, 0);
        assert.equal(out.refusal.reason, 'effect_indeterminate');
        assert.equal(out.evidence.outcome, 'indeterminate');
        assert.equal(out.evidence.detail.code, 'provider_entry_committed_effect_not_invoked');
        assert.equal(out.evidence.detail.receipt_revalidation_reason, 'receipt_rejected:receipt_expired');
        const state = await capabilityStore.getState(`cap_freshness_${delayAt}`);
        assert.equal(state.consumed_amount, 40);
        assert.equal(state.reserved_amount, 0);
        const replay = await gate.run(request, async () => { calls += 1; });
        assert.equal(replay.ok, false);
        assert.equal(calls, 0);
    });
}
