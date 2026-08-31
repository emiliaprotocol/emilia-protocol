// SPDX-License-Identifier: Apache-2.0
// Generated from capability-gate.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { createDefaultActionRiskManifest, createEg1Harness, createGate, createMemoryCapabilityStore, createOrganizationStatusProviderEntryGuard, createRuntimeMonitor, mintCapabilityReceipt, CAPABILITY_SCOPE_PROFILE, capabilityActionDigest, } from './index.js';
const NOW = Date.now();
const SELECTOR = { protocol: 'mcp', tool: 'release_payment' };
const ACTION = {
    action_type: 'payment.release',
    amount_usd: 40,
    currency: 'USD',
    payment_instruction_id: 'pi_capability_gate',
    beneficiary_account_hash: 'sha256:capability-beneficiary',
};
function fixture({ budget = 100, baseAction = ACTION, providerEntryGuard = null } = {}) {
    const harness = createEg1Harness({ action: baseAction, now: () => NOW, idPrefix: 'cap-gate' });
    const issuer = generateKeyPairSync('ed25519');
    const issuerPublicKey = issuer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const baseReceipt = harness.mint({ outcome: 'allow_with_signoff', extra: { capability_only: true } });
    const capability = mintCapabilityReceipt(baseReceipt, {
        issuerPrivateKey: issuer.privateKey,
        budget: { amount: budget, currency: 'USD' },
        expiry: NOW + 60_000,
        revocationMode: 'direct',
        secret: Buffer.alloc(32, 7),
        capabilityId: `cap_${budget}`,
        scope: {
            profile: CAPABILITY_SCOPE_PROFILE,
            operation_id_field: 'payment_instruction_id',
            action_digests: [capabilityActionDigest(baseAction)],
        },
    });
    const capabilityStore = createMemoryCapabilityStore();
    assert.equal(capabilityStore.registerCapability(capability.capabilityReceipt), true);
    const runtimeMonitor = createRuntimeMonitor({ now: () => NOW });
    const gate = createGate({
        manifest: createDefaultActionRiskManifest(),
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        quorumPolicy: harness.quorumPolicy,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        capabilityStore,
        capabilityTrustedIssuerKeys: [issuerPublicKey],
        runtimeMonitor,
        providerEntryGuard,
        allowEphemeralStore: true,
        now: () => NOW,
    });
    return { gate, harness, capabilityStore, capability, action: baseAction, runtimeMonitor };
}
function request(fixtureValue, { operationId, amount = 40, action = fixtureValue.action } = {}) {
    return {
        selector: SELECTOR,
        observedAction: action,
        capability: {
            capabilityReceipt: fixtureValue.capability.capabilityReceipt,
            secret: fixtureValue.capability.secret,
            action: { amount, currency: 'USD' },
            operationId,
        },
    };
}
function secureConsumptionStore() {
    return {
        durable: true,
        ownershipFenced: true,
        permanentConsumption: true,
        async consume() { return true; },
        async reserve() { return true; },
        async commit() { return true; },
    };
}
function capabilityAdapter(overrides = {}) {
    return {
        durable: true,
        reconciliationCapable: true,
        revocationInheritanceCapable: true,
        registerCapability() { return true; },
        async revokeCapability() { return { ok: false }; },
        async reserveSpend() { return { ok: false }; },
        async beginProviderEntry() { return { ok: false }; },
        async recoverPreEntrySpend() { return { ok: false }; },
        async commitSpend() { return { ok: false }; },
        async reconcileSpend() { return { ok: false }; },
        ...overrides,
    };
}
test('production gate rejects the in-memory capability store unless test/demo state is explicit', () => {
    const capabilityStore = createMemoryCapabilityStore();
    assert.throws(() => createGate({
        store: secureConsumptionStore(),
        capabilityStore,
        capabilityTrustedIssuerKeys: ['pinned-capability-issuer'],
    }), /capabilityStore must be durable and reconciliation-capable/);
    assert.doesNotThrow(() => createGate({
        capabilityStore,
        capabilityTrustedIssuerKeys: ['pinned-capability-issuer'],
        allowEphemeralStore: true,
    }));
});
test('production gate rejects capability adapters without explicit durability and reconciliation markers', () => {
    for (const capabilityStore of [
        capabilityAdapter({ durable: undefined, reconciliationCapable: undefined }),
        capabilityAdapter({ reconciliationCapable: undefined }),
        capabilityAdapter({ durable: undefined }),
    ]) {
        assert.throws(() => createGate({
            store: secureConsumptionStore(),
            capabilityStore,
            capabilityTrustedIssuerKeys: ['pinned-capability-issuer'],
        }), /capabilityStore must be durable and reconciliation-capable/);
    }
});
test('capability adapters must implement reconciliation even when their security markers are present', () => {
    const capabilityStore = capabilityAdapter({ reconcileSpend: undefined });
    assert.throws(() => createGate({
        store: secureConsumptionStore(),
        capabilityStore,
        capabilityTrustedIssuerKeys: ['pinned-capability-issuer'],
    }), /capabilityStore must implement .*reconcileSpend\(\)/);
});
test('capability adapters must implement the provider-entry and pre-entry recovery boundary', () => {
    for (const capabilityStore of [
        capabilityAdapter({ beginProviderEntry: undefined }),
        capabilityAdapter({ recoverPreEntrySpend: undefined }),
    ]) {
        assert.throws(() => createGate({
            store: secureConsumptionStore(),
            capabilityStore,
            capabilityTrustedIssuerKeys: ['pinned-capability-issuer'],
        }), /capabilityStore must implement/);
    }
});
test('capability adapters must implement explicit revocation inheritance', () => {
    for (const capabilityStore of [
        capabilityAdapter({ revocationInheritanceCapable: undefined }),
        capabilityAdapter({ revokeCapability: undefined }),
    ]) {
        assert.throws(() => createGate({
            store: secureConsumptionStore(),
            capabilityStore,
            capabilityTrustedIssuerKeys: ['pinned-capability-issuer'],
        }), /capabilityStore must be durable and reconciliation-capable/);
    }
});
test('production gate accepts an explicitly marked durable reconciliation-capable adapter', () => {
    assert.doesNotThrow(() => createGate({
        store: secureConsumptionStore(),
        capabilityStore: capabilityAdapter(),
        capabilityTrustedIssuerKeys: ['pinned-capability-issuer'],
    }));
});
test('gate capability path reserves and commits budget around the effect', async () => {
    const f = fixture();
    let effects = 0;
    let providerKey = null;
    const first = await f.gate.run(request(f, { operationId: ACTION.payment_instruction_id }), async (_authorization, operation) => {
        effects += 1;
        providerKey = operation.providerIdempotencyKey;
        return 'settled';
    });
    assert.equal(first.ok, true, first.capability?.reason || first.authorization?.reason);
    assert.equal(first.result, 'settled');
    assert.equal(effects, 1);
    assert.equal(providerKey, ACTION.payment_instruction_id);
    assert.equal(f.capabilityStore.getState('cap_100').consumed_amount, 40);
    assert.equal(f.capabilityStore.getOperation(ACTION.payment_instruction_id).outcome, 'executed');
    assert.equal(first.authorization.evidence.consumption_mode, 'none');
    assert.equal(f.gate.evidence.verify().ok, true);
});
test('gate capability path derives the organization control domain from the guard', async () => {
    const controlDomainId = 'org:capability-gate';
    const f = fixture({
        providerEntryGuard: createOrganizationStatusProviderEntryGuard({
            organizationId: controlDomainId,
            resolveStatus: async () => ({
                organization_id: controlDomainId,
                status: 'active',
                epoch: 1,
                observed_at: new Date(NOW).toISOString(),
                authenticated: true,
            }),
            now: NOW,
        }),
    });
    assert.equal((await f.capabilityStore.registerControlDomain({
        controlDomainId,
        now: NOW,
    })).ok, true);
    let effects = 0;
    const result = await f.gate.run(request(f, { operationId: ACTION.payment_instruction_id }), async () => { effects += 1; return 'settled'; });
    assert.equal(result.ok, true, result.capability?.reason || result.authorization?.reason);
    assert.equal(effects, 1);
    assert.equal(f.capabilityStore.getOperation(ACTION.payment_instruction_id).control_domain_id, controlDomainId);
});
test('gate capability path preserves provider-entry evidence in the result and execution record', async () => {
    const providerEntryEvidence = {
        kind: 'equipment_status',
        source_id: 'source:operator-equipment-status',
        source_digest: `sha256:${'ab'.repeat(32)}`,
        observed_at: new Date(NOW).toISOString(),
    };
    const f = fixture({
        providerEntryGuard: async () => ({ ok: true, evidence: providerEntryEvidence }),
    });
    const result = await f.gate.run(request(f, { operationId: ACTION.payment_instruction_id }), async (_authorization, operation) => operation.providerEntryEvidence);
    assert.equal(result.ok, true, result.capability?.reason || result.authorization?.reason);
    assert.deepEqual(result.result, providerEntryEvidence);
    assert.deepEqual(result.capability.provider_entry_evidence, providerEntryEvidence);
    assert.deepEqual(result.execution.detail.provider_entry_evidence, providerEntryEvidence);
});
test('capability execution without a provider-entry guard preserves the legacy result shape', async () => {
    const f = fixture();
    let operationContext = null;
    const result = await f.gate.run(request(f, { operationId: ACTION.payment_instruction_id }), async (_authorization, operation) => {
        operationContext = operation;
        return 'settled';
    });
    assert.equal(result.ok, true);
    assert.equal(Object.hasOwn(operationContext, 'providerEntryEvidence'), false);
    assert.equal(Object.hasOwn(result.capability, 'provider_entry_evidence'), false);
    assert.equal(Object.hasOwn(result.execution.detail, 'provider_entry_evidence'), false);
});
test('gate capability refusal preserves provider-entry evidence in the result and capability event', async () => {
    const providerEntryEvidence = {
        version: 'EP-GATE-PROVIDER-ENTRY-GUARD-v1',
        kind: 'equipment_status',
        source_id: 'source:operator-equipment-status',
        source_digest: `sha256:${'cd'.repeat(32)}`,
        status: 'revoked',
        observed_at: new Date(NOW).toISOString(),
    };
    const f = fixture({
        providerEntryGuard: async () => ({
            ok: false,
            reason: 'equipment_status_revoked',
            status: 423,
            reservation: 'burn',
            evidence: providerEntryEvidence,
        }),
    });
    const result = await f.gate.run(request(f, { operationId: ACTION.payment_instruction_id }), async () => { throw new Error('effect must not run'); });
    assert.equal(result.ok, false);
    assert.equal(result.status, 423);
    assert.equal(result.capability.reason, 'equipment_status_revoked');
    assert.deepEqual(result.provider_entry_evidence, providerEntryEvidence);
    assert.deepEqual(result.capability.provider_entry_evidence, providerEntryEvidence);
    assert.equal(Object.hasOwn(result.refusal, 'provider_entry_evidence'), false);
    assert.equal(Object.hasOwn(result.refusal.challenge.rejected, 'provider_entry_evidence'), false);
    const capabilityEvent = f.gate.evidence.all().find((entry) => entry.kind === 'capability');
    assert.deepEqual(capabilityEvent?.provider_entry_evidence, providerEntryEvidence);
});
test('gate preserves successful guard evidence when the store refuses provider entry', async () => {
    const providerEntryEvidence = {
        kind: 'equipment_status',
        source_id: 'source:operator-equipment-status',
        source_digest: `sha256:${'ef'.repeat(32)}`,
        status: 'active',
        observed_at: new Date(NOW).toISOString(),
    };
    const f = fixture({
        providerEntryGuard: async () => ({ ok: true, evidence: providerEntryEvidence }),
    });
    f.capabilityStore.beginProviderEntry = async () => ({
        ok: false,
        reason: 'capability_provider_entry_refused',
    });
    let effects = 0;
    const result = await f.gate.run(request(f, { operationId: ACTION.payment_instruction_id }), async () => { effects += 1; return 'must-not-run'; });
    assert.equal(result.ok, false);
    assert.equal(result.capability.reason, 'capability_provider_entry_refused');
    assert.equal(effects, 0);
    assert.deepEqual(result.provider_entry_evidence, providerEntryEvidence);
    assert.deepEqual(result.capability.provider_entry_evidence, providerEntryEvidence);
    const capabilityEvent = f.gate.evidence.all().find((entry) => entry.kind === 'capability');
    assert.deepEqual(capabilityEvent?.provider_entry_evidence, providerEntryEvidence);
});
test('gate preserves refusal evidence when the pre-entry reservation transition is indeterminate', async () => {
    const providerEntryEvidence = {
        kind: 'equipment_status',
        source_id: 'source:operator-equipment-status',
        source_digest: `sha256:${'ac'.repeat(32)}`,
        status: 'revoked',
        observed_at: new Date(NOW).toISOString(),
    };
    const f = fixture({
        providerEntryGuard: async () => ({
            ok: false,
            reason: 'equipment_status_revoked',
            reservation: 'burn',
            evidence: providerEntryEvidence,
        }),
    });
    f.capabilityStore.recoverPreEntrySpend = async () => ({
        ok: false,
        reason: 'storage_outcome_unknown',
    });
    let effects = 0;
    const result = await f.gate.run(request(f, { operationId: ACTION.payment_instruction_id }), async () => { effects += 1; return 'must-not-run'; });
    assert.equal(result.ok, false);
    assert.equal(result.capability.reason, 'capability_provider_entry_reservation_transition_indeterminate');
    assert.equal(effects, 0);
    assert.deepEqual(result.provider_entry_evidence, providerEntryEvidence);
    assert.deepEqual(result.capability.provider_entry_evidence, providerEntryEvidence);
    assert.equal(Object.hasOwn(result.refusal.challenge.rejected, 'provider_entry_evidence'), false);
    const capabilityEvent = f.gate.evidence.all().find((entry) => entry.kind === 'capability');
    assert.deepEqual(capabilityEvent?.provider_entry_evidence, providerEntryEvidence);
});
test('gate refuses non-JSON provider-entry evidence before the effect', async () => {
    const f = fixture({
        providerEntryGuard: async () => ({
            ok: true,
            evidence: {
                kind: 'equipment_status',
                // A Date is structured-cloneable but is outside the bounded canonical
                // JSON evidence domain and must never survive until post-effect recording.
                observed_at: new Date(NOW),
            },
        }),
    });
    let effects = 0;
    const result = await f.gate.run(request(f, { operationId: ACTION.payment_instruction_id }), async () => { effects += 1; return 'must-not-run'; });
    assert.equal(result.ok, false);
    assert.equal(result.capability.reason, 'provider_entry_guard_evidence_invalid');
    assert.equal(effects, 0);
    assert.equal(f.capabilityStore.getState('cap_100').consumed_amount, 0);
    assert.equal(f.capabilityStore.getState('cap_100').reserved_amount, 40);
    assert.equal(f.capabilityStore.getOperation(ACTION.payment_instruction_id).status, 'reserved');
});
test('terminal metadata preserves provider-entry evidence when execution recording fails', async () => {
    const providerEntryEvidence = {
        kind: 'equipment_status',
        source_id: 'source:operator-equipment-status',
        source_digest: `sha256:${'bd'.repeat(32)}`,
        observed_at: new Date(NOW).toISOString(),
    };
    const f = fixture({
        providerEntryGuard: async () => ({ ok: true, evidence: providerEntryEvidence }),
    });
    const record = f.gate.evidence.record.bind(f.gate.evidence);
    f.gate.evidence.record = async (entry) => {
        if (entry?.kind === 'execution')
            throw new Error('evidence backend unavailable');
        return record(entry);
    };
    let effects = 0;
    await assert.rejects(f.gate.run(request(f, { operationId: ACTION.payment_instruction_id }), async () => { effects += 1; return { settled: true }; }), (error) => {
        assert.equal(error.code, 'EMILIA_GATE_TERMINAL_OUTCOME');
        assert.equal(error.emiliaGateOutcome.outcome, 'executed');
        assert.equal(error.emiliaGateOutcome.reason, 'execution_evidence_unavailable');
        assert.deepEqual(error.emiliaGateOutcome.provider_entry_evidence, providerEntryEvidence);
        return true;
    });
    assert.equal(effects, 1);
    assert.equal(f.capabilityStore.getOperation(ACTION.payment_instruction_id).outcome, 'executed');
});
test('terminal metadata preserves provider-entry evidence when capability refusal recording fails', async () => {
    const providerEntryEvidence = {
        kind: 'equipment_status',
        source_id: 'source:operator-equipment-status',
        source_digest: `sha256:${'ce'.repeat(32)}`,
        status: 'revoked',
        observed_at: new Date(NOW).toISOString(),
    };
    const f = fixture({
        providerEntryGuard: async () => ({
            ok: false,
            reason: 'equipment_status_revoked',
            status: 423,
            reservation: 'burn',
            evidence: providerEntryEvidence,
        }),
    });
    const record = f.gate.evidence.record.bind(f.gate.evidence);
    f.gate.evidence.record = async (entry) => {
        if (entry?.kind === 'capability')
            throw new Error('evidence backend unavailable');
        return record(entry);
    };
    let effects = 0;
    await assert.rejects(f.gate.run(request(f, { operationId: ACTION.payment_instruction_id }), async () => { effects += 1; return { settled: true }; }), (error) => {
        assert.equal(error.code, 'EMILIA_GATE_TERMINAL_OUTCOME');
        assert.equal(error.emiliaGateOutcome.outcome, 'refused');
        assert.equal(error.emiliaGateOutcome.reason, 'capability_evidence_unavailable');
        assert.equal(error.emiliaGateOutcome.result.reason, 'equipment_status_revoked');
        assert.deepEqual(error.emiliaGateOutcome.provider_entry_evidence, providerEntryEvidence);
        return true;
    });
    assert.equal(effects, 0);
    assert.equal(f.capabilityStore.getOperation(ACTION.payment_instruction_id).outcome, 'refused');
});
test('gate capability path refuses overspend before the effect', async () => {
    const f = fixture({ budget: 30 });
    let effects = 0;
    const out = await f.gate.run(request(f, { operationId: ACTION.payment_instruction_id }), async () => {
        effects += 1;
    });
    assert.equal(out.ok, false);
    assert.equal(out.capability.reason, 'budget_exceeded');
    assert.equal(out.status, 409);
    assert.equal(effects, 0);
    assert.equal(f.capabilityStore.getState('cap_30').consumed_amount, 0);
    assert.equal(f.runtimeMonitor.getMode(), 'normal');
});
test('gate capability path honors release, burn, and hold suspension dispositions', async (t) => {
    const cases = [
        { name: 'default hold', reservation: undefined, status: 'reserved', outcome: undefined, consumed: 0, reserved: 40 },
        { name: 'explicit release', reservation: 'release', status: 'released', outcome: 'not_entered', consumed: 0, reserved: 0 },
        { name: 'burn', reservation: 'burn', status: 'committed', outcome: 'refused', consumed: 40, reserved: 0 },
        { name: 'hold', reservation: 'hold', status: 'reserved', outcome: undefined, consumed: 0, reserved: 40 },
    ];
    for (const expected of cases) {
        await t.test(expected.name, async () => {
            const f = fixture({
                providerEntryGuard: async () => ({
                    ok: false,
                    reason: 'organization_suspended',
                    status: 423,
                    ...(expected.reservation === undefined ? {} : { reservation: expected.reservation }),
                }),
            });
            let effects = 0;
            const out = await f.gate.run(request(f, { operationId: ACTION.payment_instruction_id }), async () => {
                effects += 1;
            });
            assert.equal(out.ok, false);
            assert.equal(out.capability.reason, 'organization_suspended');
            assert.equal(effects, 0);
            const operation = f.capabilityStore.getOperation(ACTION.payment_instruction_id);
            assert.equal(operation.status, expected.status);
            assert.equal(operation.outcome, expected.outcome);
            assert.equal(f.capabilityStore.getState('cap_100').consumed_amount, expected.consumed);
            assert.equal(f.capabilityStore.getState('cap_100').reserved_amount, expected.reserved);
        });
    }
});
test('a burned capability refusal remains consumed and replay-fenced across run and route', async () => {
    const f = fixture({
        providerEntryGuard: async () => ({
            ok: false,
            reason: 'organization_suspended',
            status: 423,
            reservation: 'burn',
        }),
    });
    let effects = 0;
    const first = await f.gate.run(request(f, { operationId: ACTION.payment_instruction_id }), async () => {
        effects += 1;
    });
    assert.equal(first.ok, false);
    assert.equal(first.capability.reason, 'organization_suspended');
    let statusCode = null;
    const response = {
        status(code) { statusCode = code; return this; },
        json(body) { return body; },
        setHeader() { },
    };
    const guardedRoute = f.gate.route(async () => {
        effects += 1;
    }, {
        selector: SELECTOR,
        observedAction: f.action,
        capability: request(f, { operationId: ACTION.payment_instruction_id }).capability,
    });
    await guardedRoute({ headers: {}, body: {} }, response);
    assert.equal(statusCode, 409);
    assert.equal(effects, 0);
    assert.equal(f.capabilityStore.getOperation(ACTION.payment_instruction_id).status, 'committed');
    assert.equal(f.capabilityStore.getState('cap_100').consumed_amount, 40);
    assert.equal(f.capabilityStore.getState('cap_100').reserved_amount, 0);
});
test('a throwing provider-entry guard holds authority instead of restoring it', async () => {
    const f = fixture({
        providerEntryGuard: async () => { throw new Error('guard unavailable'); },
    });
    const out = await f.gate.run(request(f, { operationId: ACTION.payment_instruction_id }), async () => { throw new Error('effect must not run'); });
    assert.equal(out.ok, false);
    assert.equal(out.capability.reason, 'provider_entry_guard_unavailable');
    const operation = f.capabilityStore.getOperation(ACTION.payment_instruction_id);
    assert.equal(operation.status, 'reserved');
    assert.equal(f.capabilityStore.getState('cap_100').reserved_amount, 40);
});
test('runtime refusal after capability provider entry is recorded as indeterminate', async () => {
    const f = fixture({
        providerEntryGuard: async () => ({
            ok: true,
            evidence: { kind: 'equipment_status', source_digest: `sha256:${'fa'.repeat(32)}` },
        }),
    });
    f.runtimeMonitor.beginExecution = () => ({
        ok: false,
        reason: 'runtime_test_refusal',
        event: { theorem: 'test' },
    });
    let effects = 0;
    const out = await f.gate.run(request(f, { operationId: ACTION.payment_instruction_id }), async () => { effects += 1; });
    assert.equal(out.ok, false);
    assert.equal(out.capability.reason, 'effect_indeterminate');
    assert.equal(out.evidence.kind, 'execution');
    assert.equal(out.evidence.outcome, 'indeterminate');
    assert.equal(out.evidence.detail.code, 'provider_entry_committed_effect_not_invoked');
    assert.equal(f.capabilityStore.getOperation(ACTION.payment_instruction_id).outcome, 'indeterminate');
    assert.equal(f.capabilityStore.getState('cap_100').consumed_amount, 40);
    assert.equal(effects, 0);
});
test('gate capability path refuses a missing stable operation id before the effect', async () => {
    const f = fixture();
    let effects = 0;
    const out = await f.gate.run(request(f), async () => {
        effects += 1;
    });
    assert.equal(out.ok, false);
    assert.equal(out.capability.reason, 'capability_operation_id_required');
    assert.equal(effects, 0);
    assert.equal(f.capabilityStore.getState('cap_100').consumed_amount, 0);
});
test('capability-enabled gate requires an explicit role-scoped issuer pin', () => {
    const f = fixture();
    assert.throws(() => createGate({
        manifest: createDefaultActionRiskManifest(),
        trustedKeys: [f.harness.publicKey],
        approverKeys: f.harness.approverKeys,
        quorumPolicy: f.harness.quorumPolicy,
        rpId: f.harness.rpId,
        allowedOrigins: f.harness.allowedOrigins,
        capabilityStore: createMemoryCapabilityStore(),
        allowEphemeralStore: true,
    }), /capabilityTrustedIssuerKeys must explicitly pin/);
});
test('embedded capability receipt cannot bypass budget through ordinary run or route paths', async () => {
    const f = fixture();
    let effects = 0;
    const extractedReceipt = f.capability.capabilityReceipt.receipt;
    const direct = await f.gate.run({
        selector: SELECTOR,
        receipt: extractedReceipt,
        observedAction: f.action,
    }, async () => {
        effects += 1;
    });
    assert.equal(direct.ok, false);
    assert.equal(direct.authorization.reason, 'capability_required');
    let statusCode = null;
    const response = {
        status(code) { statusCode = code; return this; },
        json(body) { return body; },
        setHeader() { },
    };
    const guardedRoute = f.gate.route(async () => {
        effects += 1;
    }, {
        selector: SELECTOR,
        receipt: extractedReceipt,
        observedAction: f.action,
    });
    const routeResult = await guardedRoute({ headers: {}, body: {} }, response);
    assert.equal(statusCode, 428);
    assert.equal(routeResult.detail, 'capability_required');
    assert.equal(effects, 0);
});
test('gate capability path refuses replay and a new id cannot relabel the same exact action', async () => {
    const f = fixture();
    let effects = 0;
    const run = (operationId) => f.gate.run(request(f, { operationId, amount: 40 }), async () => {
        effects += 1;
        return effects;
    });
    const first = await run(ACTION.payment_instruction_id);
    const replay = await run(ACTION.payment_instruction_id);
    const relabelled = await run('attacker-new-operation');
    assert.equal(first.ok, true);
    assert.equal(replay.ok, false);
    assert.equal(replay.capability.reason, 'operation_already_committed');
    assert.equal(relabelled.ok, false);
    assert.equal(relabelled.capability.reason, 'capability_operation_binding_failed');
    assert.equal(effects, 1);
    assert.equal(f.capabilityStore.getState('cap_100').consumed_amount, 40);
});
test('gate capability path binds the spend amount to the observed action', async () => {
    const f = fixture({ baseAction: { ...ACTION, amount_usd: 41 } });
    let effects = 0;
    const out = await f.gate.run(request(f, { operationId: ACTION.payment_instruction_id, amount: 40 }), async () => {
        effects += 1;
    });
    assert.equal(out.ok, false);
    assert.equal(out.authorization.reason, 'capability_action_binding_failed');
    assert.equal(effects, 0);
    assert.equal(f.capabilityStore.getState('cap_100').consumed_amount, 0);
});
test('gate capability path burns an indeterminate spend if the effect throws', async () => {
    const f = fixture();
    let effects = 0;
    await assert.rejects(() => f.gate.run(request(f, { operationId: ACTION.payment_instruction_id }), async () => {
        effects += 1;
        throw new Error('provider response lost');
    }), /provider response lost/);
    assert.equal(effects, 1);
    assert.equal(f.capabilityStore.getState('cap_100').consumed_amount, 40);
    assert.equal(f.capabilityStore.getOperation(ACTION.payment_instruction_id).outcome, 'indeterminate');
    assert.equal(f.gate.evidence.all().find((entry) => entry.kind === 'execution')?.outcome, 'indeterminate');
});
test('guard() can source a capability and still refuses its replay', async () => {
    const f = fixture();
    let effects = 0;
    const release = f.gate.guard(async () => {
        effects += 1;
        return 'settled';
    }, {
        selector: SELECTOR,
        observedAction: f.action,
        capability: () => ({
            capabilityReceipt: f.capability.capabilityReceipt,
            secret: f.capability.secret,
            action: { amount: 40, currency: 'USD' },
            operationId: ACTION.payment_instruction_id,
        }),
    });
    assert.equal(await release(), 'settled');
    await assert.rejects(() => release(), /EMILIA Gate refused \(operation_already_committed\)/);
    assert.equal(effects, 1);
});
