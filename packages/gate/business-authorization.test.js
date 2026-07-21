// SPDX-License-Identifier: Apache-2.0
// Generated from business-authorization.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDefaultActionRiskManifest, createEg1Harness, createGate, } from './index.js';
const POLICY_ID = 'ep:policy:treasury-release@v7';
const POLICY_HASH = `sha256:${'ab'.repeat(32)}`;
const TENANT_ID = 'tenant:acme-finance';
const SELECTOR = { protocol: 'mcp', tool: 'release_payment' };
const ACTION = {
    action_type: 'payment.release',
    amount_usd: 40000,
    currency: 'USD',
    payment_instruction_id: 'pi_business_binding',
    beneficiary_account_hash: 'sha256:approved-beneficiary',
};
function fixture({ allowedApprovers } = {}) {
    const harness = createEg1Harness({ action: ACTION, idPrefix: 'business' });
    const manifest = createDefaultActionRiskManifest();
    const requirement = manifest.actions.find((entry) => entry.action_type === ACTION.action_type);
    requirement.business_authorization = {
        policy: { id: POLICY_ID, hash: POLICY_HASH },
        tenant_id: TENANT_ID,
        allowed_approvers: allowedApprovers || [
            { subject: 'ep:approver:eg1:cfo', role: 'cfo' },
        ],
    };
    const gate = createGate({
        manifest,
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        quorumPolicy: harness.quorumPolicy,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        allowEphemeralStore: true,
    });
    return { gate, harness };
}
function mint(harness, extra = {}) {
    return harness.mint({
        outcome: 'allow_with_signoff',
        extra: {
            policy_id: POLICY_ID,
            policy_hash: POLICY_HASH,
            tenant_id: TENANT_ID,
            approver_role: 'cfo',
            ...extra,
        },
    });
}
test('real crypto: exact business policy, tenant, and approver are recorded and execute', async () => {
    const { gate, harness } = fixture();
    const out = await gate.run({ selector: SELECTOR, receipt: mint(harness), observedAction: ACTION }, async () => 'executed');
    assert.equal(out.ok, true, out.authorization?.reason);
    assert.equal(out.packet.verdict, 'rely');
    assert.equal(out.packet.summary.policy_id, POLICY_ID);
    assert.equal(out.packet.summary.tenant_id, TENANT_ID);
    assert.equal(out.authorization.evidence.evaluated_policy_id, POLICY_ID);
    assert.equal(out.authorization.evidence.evaluated_policy_hash, POLICY_HASH);
    assert.equal(out.authorization.evidence.evaluated_tenant_id, TENANT_ID);
    assert.deepEqual(out.authorization.evidence.evaluated_approvers, [
        { subject: 'ep:approver:eg1:cfo', roles: ['cfo'] },
    ]);
});
for (const scenario of [
    ['wrong policy id', { policy_id: 'ep:policy:other@v1' }, 'business_policy_id_mismatch'],
    ['wrong policy hash', { policy_hash: `sha256:${'cd'.repeat(32)}` }, 'business_policy_hash_mismatch'],
    ['wrong tenant', { tenant_id: 'tenant:other' }, 'business_tenant_mismatch'],
    ['wrong approver role', { approver_role: 'auditor' }, 'business_approver_role_not_allowed'],
]) {
    test(`real crypto: ${scenario[0]} refuses before reservation and execution`, async () => {
        const { gate, harness } = fixture();
        let effects = 0;
        const out = await gate.run({ selector: SELECTOR, receipt: mint(harness, scenario[1]), observedAction: ACTION }, async () => { effects++; });
        assert.equal(out.ok, false);
        assert.equal(out.authorization.reason, scenario[2]);
        assert.equal(effects, 0);
        assert.equal(gate.store.size, 0);
    });
}
test('real crypto: a valid but unlisted approver subject refuses before reservation', async () => {
    const { gate, harness } = fixture({
        allowedApprovers: [{ subject: 'ep:approver:eg1:security-officer', role: 'security_officer' }],
    });
    let effects = 0;
    const out = await gate.run({ selector: SELECTOR, receipt: mint(harness), observedAction: ACTION }, async () => { effects++; });
    assert.equal(out.ok, false);
    assert.equal(out.authorization.reason, 'business_approver_not_allowed');
    assert.equal(out.authorization.evidence.evaluated_approvers[0].subject, 'ep:approver:eg1:cfo');
    assert.equal(effects, 0);
    assert.equal(gate.store.size, 0);
});
test('a partial business pin is rejected when the gate is constructed', () => {
    const manifest = createDefaultActionRiskManifest();
    manifest.actions[0].business_authorization = {
        policy: { id: POLICY_ID, hash: POLICY_HASH },
        tenant_id: TENANT_ID,
    };
    assert.throws(() => createGate({ manifest, allowEphemeralStore: true }), /business_authorization_incomplete/);
});
