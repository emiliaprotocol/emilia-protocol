// SPDX-License-Identifier: Apache-2.0
// Generated from provider-entry.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import { composeProviderEntryGuards, createOrganizationStatusProviderEntryGuard, evaluateProviderEntryGuard, providerEntryContext, requiredProviderEntryControlDomain, createDefaultActionRiskManifest, createEg1Harness, createGate, createRuntimeMonitor, } from './index.js';
const NOW = Date.parse('2026-08-03T12:00:00.000Z');
const ACTION = {
    action_type: 'payment.release',
    amount_usd: 40,
    amount: 40,
    amount_minor: 4_000,
    currency: 'USD',
    payment_instruction_id: 'pi_provider_entry',
    beneficiary_account_hash: 'sha256:provider-entry-beneficiary',
};
const SELECTOR = { protocol: 'mcp', tool: 'release_payment' };
test('provider-entry context is immutable and a throwing guard fails closed', async () => {
    const context = providerEntryContext({
        authorization: { allow: true },
        selector: SELECTOR,
        observedAction: ACTION,
        now: NOW,
    });
    assert.equal(context.checked_at, '2026-08-03T12:00:00.000Z');
    assert.equal(Object.isFrozen(context.observed_action), true);
    assert.throws(() => { context.observed_action.amount = 1; }, TypeError);
    assert.deepEqual(await evaluateProviderEntryGuard(async () => { throw new Error('status down'); }, context), { ok: false, reason: 'provider_entry_guard_unavailable', status: 503, reservation: 'hold' });
});
test('provider-entry evidence must be bounded finite JSON before provider entry', async () => {
    const context = providerEntryContext({ authorization: {}, now: NOW });
    assert.deepEqual(await evaluateProviderEntryGuard(async () => ({
        ok: true,
        evidence: { observed_at: new Date(NOW) },
    }), context), {
        ok: false,
        reason: 'provider_entry_guard_evidence_invalid',
        status: 503,
        reservation: 'hold',
    });
    const accepted = await evaluateProviderEntryGuard(async () => ({
        ok: true,
        evidence: { observed_at: new Date(NOW).toISOString(), epoch: 4, temperature_c: 21.5 },
    }), context);
    assert.deepEqual(accepted, {
        ok: true,
        evidence: { epoch: 4, observed_at: new Date(NOW).toISOString(), temperature_c: 21.5 },
    });
    assert.equal(Object.isFrozen(accepted.evidence), true);
});
test('an invalid reservation disposition is normalized to a held refusal', async () => {
    const context = providerEntryContext({ authorization: {}, now: NOW });
    assert.deepEqual(await evaluateProviderEntryGuard(async () => ({
        ok: false,
        reason: 'organization_suspended',
        reservation: 'restore',
    }), context), {
        ok: false,
        reason: 'provider_entry_guard_disposition_invalid',
        status: 409,
        evidence: null,
        reservation: 'hold',
    });
});
test('provider-entry refusal status is bounded to the HTTP error range', async () => {
    const context = providerEntryContext({ authorization: {}, now: NOW });
    assert.equal((await evaluateProviderEntryGuard(async () => ({
        ok: false,
        reason: 'status_typo',
        status: 999_999,
        reservation: 'hold',
    }), context)).status, 409);
    assert.equal((await evaluateProviderEntryGuard(async () => ({
        ok: false,
        reason: 'locked',
        status: 423,
        reservation: 'burn',
    }), context)).status, 423);
});
test('organization status guard refuses stale, mismatched, unauthenticated, and suspended state', async () => {
    let observation = {
        organization_id: 'org_a',
        status: 'active',
        epoch: 4,
        observed_at: new Date(NOW).toISOString(),
        authenticated: true,
    };
    const guard = createOrganizationStatusProviderEntryGuard({
        organizationId: 'org_a',
        resolveStatus: async () => observation,
        now: NOW,
    });
    const context = providerEntryContext({ authorization: {}, now: NOW });
    assert.equal((await guard(context)).ok, true);
    observation = { ...observation, status: 'suspended', epoch: 5 };
    assert.deepEqual(await guard(context), {
        ok: false,
        reason: 'organization_suspended',
        status: 423,
        reservation: 'burn',
        evidence: { organization_id: 'org_a', status: 'suspended', epoch: 5 },
    });
    observation = { ...observation, status: 'active', authenticated: false };
    assert.equal((await guard(context)).reason, 'organization_status_unauthenticated');
    observation = { ...observation, authenticated: true, organization_id: 'org_b' };
    assert.equal((await guard(context)).reason, 'organization_status_mismatch');
    observation = { ...observation, organization_id: 'org_a', observed_at: new Date(NOW - 6_000).toISOString() };
    assert.equal((await guard(context)).reason, 'organization_status_stale');
});
test('composed guards stop at the first refusal and preserve prior evidence', async () => {
    let second = 0;
    const guard = composeProviderEntryGuards(async () => ({ ok: true, evidence: { first: true } }), async () => {
        second += 1;
        return { ok: false, reason: 'panic', evidence: { second: 'refused' } };
    }, async () => { throw new Error('must not run'); });
    const result = await guard(providerEntryContext({ now: NOW }));
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'panic');
    assert.equal(second, 1);
    assert.deepEqual(result.evidence, {
        guards: [{ first: true }, { second: 'refused' }],
    });
});
test('organization control-domain requirements survive guard composition', () => {
    const organizationGuard = createOrganizationStatusProviderEntryGuard({
        organizationId: 'org_a',
        resolveStatus: async () => ({
            organization_id: 'org_a',
            status: 'active',
            epoch: 1,
            observed_at: new Date(NOW).toISOString(),
            authenticated: true,
        }),
        now: NOW,
    });
    const composed = composeProviderEntryGuards(async () => ({ ok: true }), organizationGuard);
    assert.equal(requiredProviderEntryControlDomain(organizationGuard), 'org_a');
    assert.equal(requiredProviderEntryControlDomain(composed), 'org_a');
    assert.throws(() => composeProviderEntryGuards(organizationGuard, createOrganizationStatusProviderEntryGuard({
        organizationId: 'org_b',
        resolveStatus: async () => ({
            organization_id: 'org_b',
            status: 'active',
            epoch: 1,
            observed_at: new Date(NOW).toISOString(),
            authenticated: true,
        }),
        now: NOW,
    })), /single serialized control domain/);
});
test('an observation-only organization guard cannot authorize an unserialized Gate path', async () => {
    const harness = createEg1Harness({ action: ACTION, now: () => NOW, idPrefix: 'provider-entry' });
    let status = 'suspended';
    const organizationGuard = createOrganizationStatusProviderEntryGuard({
        organizationId: 'org_a',
        resolveStatus: async () => ({
            organization_id: 'org_a',
            status,
            epoch: status === 'active' ? 2 : 1,
            observed_at: new Date(NOW).toISOString(),
            authenticated: true,
        }),
        now: () => NOW,
    });
    const gate = createGate({
        manifest: createDefaultActionRiskManifest(),
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        quorumPolicy: harness.quorumPolicy,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        providerEntryGuard: organizationGuard,
        allowEphemeralStore: true,
        now: () => NOW,
    });
    const receipt = harness.mint({ outcome: 'allow_with_signoff' });
    let effects = 0;
    const first = await gate.run({ selector: SELECTOR, receipt, observedAction: ACTION }, async () => { effects += 1; });
    assert.equal(first.ok, false);
    assert.equal(first.authorization.reason, 'provider_entry_serialized_control_domain_required');
    assert.equal(effects, 0);
    status = 'active';
    const replay = await gate.run({ selector: SELECTOR, receipt, observedAction: ACTION }, async () => { effects += 1; });
    assert.equal(replay.ok, false);
    assert.equal(replay.authorization.reason, 'replay_refused');
    assert.equal(effects, 0);
});
test('ordinary Gate execution preserves provider-entry evidence without exposing it in challenges', async () => {
    const providerEntryEvidence = {
        kind: 'equipment_status',
        source_id: 'source:reference-equipment-status',
        source_digest: `sha256:${'ab'.repeat(32)}`,
        observed_at: new Date(NOW).toISOString(),
    };
    const harness = createEg1Harness({ action: ACTION, now: () => NOW, idPrefix: 'provider-entry-success' });
    const gate = createGate({
        manifest: createDefaultActionRiskManifest(),
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        quorumPolicy: harness.quorumPolicy,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        providerEntryGuard: async () => ({ ok: true, evidence: providerEntryEvidence }),
        allowEphemeralStore: true,
        now: () => NOW,
    });
    let effectEvidence = null;
    const result = await gate.run({
        selector: SELECTOR,
        receipt: harness.mint({ outcome: 'allow_with_signoff' }),
        observedAction: ACTION,
    }, async (_authorization, operation) => {
        effectEvidence = operation.providerEntryEvidence;
        return { acknowledged: true };
    });
    assert.equal(result.ok, true);
    assert.deepEqual(effectEvidence, providerEntryEvidence);
    assert.deepEqual(result.provider_entry_evidence, providerEntryEvidence);
    assert.deepEqual(result.execution.detail.provider_entry_evidence, providerEntryEvidence);
});
test('route handlers receive provider-entry evidence before the provider effect', async () => {
    const providerEntryEvidence = {
        kind: 'equipment_status',
        source_digest: `sha256:${'bc'.repeat(32)}`,
    };
    const harness = createEg1Harness({ action: ACTION, now: () => NOW, idPrefix: 'provider-entry-route' });
    const gate = createGate({
        manifest: createDefaultActionRiskManifest(),
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        quorumPolicy: harness.quorumPolicy,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        providerEntryGuard: async () => ({ ok: true, evidence: providerEntryEvidence }),
        allowEphemeralStore: true,
        now: () => NOW,
    });
    const req = { headers: {} };
    let handlerEvidence = null;
    const wrapped = gate.route(async (request, _response, _authorization, operation) => {
        handlerEvidence = operation.providerEntryEvidence;
        assert.deepEqual(request.emiliaProviderEntryEvidence, providerEntryEvidence);
        return 'route-result';
    }, {
        selector: SELECTOR,
        receipt: harness.mint({ outcome: 'allow_with_signoff' }),
        observedAction: ACTION,
    });
    assert.equal(await wrapped(req, {}), 'route-result');
    assert.deepEqual(handlerEvidence, providerEntryEvidence);
    assert.deepEqual(req.emiliaGateExecution.detail.provider_entry_evidence, providerEntryEvidence);
});
test('ordinary no-guard execution preserves the one-argument callback and result shape', async () => {
    const harness = createEg1Harness({ action: ACTION, now: () => NOW, idPrefix: 'provider-entry-legacy' });
    const gate = createGate({
        manifest: createDefaultActionRiskManifest(),
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        quorumPolicy: harness.quorumPolicy,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        allowEphemeralStore: true,
        now: () => NOW,
    });
    let callbackArity = 0;
    const result = await gate.run({
        selector: SELECTOR,
        receipt: harness.mint({ outcome: 'allow_with_signoff' }),
        observedAction: ACTION,
    }, async function legacyCallback() {
        callbackArity = arguments.length;
        return 'legacy-result';
    });
    assert.equal(result.ok, true);
    assert.equal(callbackArity, 1);
    assert.equal(Object.hasOwn(result, 'provider_entry_evidence'), false);
    assert.equal(Object.hasOwn(result.execution, 'detail'), false);
});
test('ordinary runtime-monitor refusal retains accepted provider-entry evidence', async () => {
    const providerEntryEvidence = {
        kind: 'equipment_status',
        source_digest: `sha256:${'de'.repeat(32)}`,
    };
    const runtimeMonitor = createRuntimeMonitor({ now: () => NOW });
    runtimeMonitor.beginExecution = () => ({
        ok: false,
        reason: 'runtime_test_refusal',
        event: { theorem: 'test' },
    });
    const harness = createEg1Harness({ action: ACTION, now: () => NOW, idPrefix: 'provider-entry-runtime' });
    const gate = createGate({
        manifest: createDefaultActionRiskManifest(),
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        quorumPolicy: harness.quorumPolicy,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        providerEntryGuard: async () => ({ ok: true, evidence: providerEntryEvidence }),
        runtimeMonitor,
        allowEphemeralStore: true,
        now: () => NOW,
    });
    let effects = 0;
    await assert.rejects(gate.run({
        selector: SELECTOR,
        receipt: harness.mint({ outcome: 'allow_with_signoff' }),
        observedAction: ACTION,
    }, async () => { effects += 1; }), (error) => {
        assert.equal(error.code, 'EMILIA_RUNTIME_MONITOR_REFUSED');
        assert.equal(error.emiliaGateOutcome.outcome, 'refused');
        assert.equal(error.emiliaGateOutcome.reason, 'runtime_test_refusal');
        assert.deepEqual(error.emiliaGateOutcome.provider_entry_evidence, providerEntryEvidence);
        return true;
    });
    assert.equal(effects, 0);
});
test('ordinary Gate holds authority when a provider-entry guard fails without a disposition', async () => {
    const harness = createEg1Harness({ action: ACTION, now: () => NOW, idPrefix: 'provider-entry-hold' });
    const gate = createGate({
        manifest: createDefaultActionRiskManifest(),
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        quorumPolicy: harness.quorumPolicy,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        providerEntryGuard: async () => { throw new Error('status unavailable'); },
        allowEphemeralStore: true,
        now: () => NOW,
    });
    const receipt = harness.mint({ outcome: 'allow_with_signoff' });
    let effects = 0;
    const first = await gate.run({ selector: SELECTOR, receipt, observedAction: ACTION }, async () => {
        effects += 1;
    });
    const replay = await gate.run({ selector: SELECTOR, receipt, observedAction: ACTION }, async () => {
        effects += 1;
    });
    assert.equal(first.ok, false);
    assert.equal(first.authorization.reason, 'provider_entry_guard_unavailable');
    assert.equal(first.authorization.evidence.reservation_disposition, 'hold');
    assert.equal(Object.hasOwn(first.authorization.evidence, 'guard_evidence'), false);
    assert.equal(gate.evidence.all().find((entry) => entry.kind === 'provider_entry')?.reservation_disposition, 'hold');
    assert.equal(replay.ok, false);
    assert.equal(replay.authorization.reason, 'replay_refused');
    assert.equal(effects, 0);
});
test('ordinary provider-entry refusal recording failure returns structured terminal metadata', async () => {
    const providerEntryEvidence = {
        kind: 'equipment_status',
        status: 'revoked',
        source_digest: `sha256:${'cd'.repeat(32)}`,
    };
    const harness = createEg1Harness({ action: ACTION, now: () => NOW, idPrefix: 'provider-entry-sink' });
    const gate = createGate({
        manifest: createDefaultActionRiskManifest(),
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        quorumPolicy: harness.quorumPolicy,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        providerEntryGuard: async () => ({
            ok: false,
            reason: 'equipment_status_revoked',
            status: 423,
            reservation: 'burn',
            evidence: providerEntryEvidence,
        }),
        allowEphemeralStore: true,
        now: () => NOW,
    });
    const record = gate.evidence.record.bind(gate.evidence);
    gate.evidence.record = async (entry) => {
        if (entry?.kind === 'provider_entry')
            throw new Error('evidence backend unavailable');
        return record(entry);
    };
    let effects = 0;
    await assert.rejects(gate.run({
        selector: SELECTOR,
        receipt: harness.mint({ outcome: 'allow_with_signoff' }),
        observedAction: ACTION,
    }, async () => { effects += 1; }), (error) => {
        assert.equal(error.code, 'EMILIA_GATE_TERMINAL_OUTCOME');
        assert.equal(error.emiliaGateOutcome.outcome, 'refused');
        assert.equal(error.emiliaGateOutcome.reason, 'provider_entry_evidence_unavailable');
        assert.equal(error.emiliaGateOutcome.result.reason, 'equipment_status_revoked');
        assert.equal(error.emiliaGateOutcome.result.status, 423);
        assert.deepEqual(error.emiliaGateOutcome.provider_entry_evidence, providerEntryEvidence);
        return true;
    });
    assert.equal(effects, 0);
});
test('ordinary guard errors do not serialize provider-entry status evidence', async () => {
    const providerEntryEvidence = {
        kind: 'equipment_status',
        source_digest: `sha256:${'ef'.repeat(32)}`,
        confidential_status_detail: 'operator-only-status-detail',
    };
    const harness = createEg1Harness({ action: ACTION, now: () => NOW, idPrefix: 'provider-entry-confidential' });
    const gate = createGate({
        manifest: createDefaultActionRiskManifest(),
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        quorumPolicy: harness.quorumPolicy,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        providerEntryGuard: async () => ({
            ok: false,
            reason: 'equipment_status_restricted',
            status: 423,
            reservation: 'burn',
            evidence: providerEntryEvidence,
        }),
        allowEphemeralStore: true,
        now: () => NOW,
    });
    const protectedCall = gate.guard(async () => { throw new Error('effect must not run'); }, {
        selector: SELECTOR,
        receipt: harness.mint({ outcome: 'allow_with_signoff' }),
        observedAction: ACTION,
    });
    await assert.rejects(protectedCall(), (error) => {
        assert.equal(error.code, 'EMILIA_RECEIPT_REQUIRED');
        assert.equal(error.gate.reason, 'equipment_status_restricted');
        assert.equal(JSON.stringify(error.gate).includes('operator-only-status-detail'), false);
        assert.equal(Object.hasOwn(error.gate.evidence, 'guard_evidence'), false);
        return true;
    });
    const internal = gate.evidence.all().find((entry) => entry.kind === 'provider_entry');
    assert.deepEqual(internal.guard_evidence, providerEntryEvidence);
});
