// SPDX-License-Identifier: Apache-2.0
// Generated from mutation-closure.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MemoryConsumptionStore, createEg1Harness, createGate, createTrustedActionFirewall, } from '../index.js';
import { createAdapter } from './_kit.js';
import { createAwsManifest, guardAwsMutation } from './aws.js';
import { createSupabaseManifest, guardSupabaseMutation, rlsDefinitionDigest, RLS_DEFINITION_BINDING_VERSION, } from './supabase.js';
import { createVercelManifest, guardVercelMutation, secretValueDigest, SECRET_VALUE_BINDING_VERSION, } from './vercel.js';
function gateFor(manifest, action, store = undefined) {
    const harness = createEg1Harness({ action, idPrefix: 'mutation_closure' });
    const gate = createGate({
        manifest,
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        quorumPolicy: harness.quorumPolicy,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        allowEphemeralStore: true,
        ...(store ? { store } : {}),
    });
    return { gate, harness };
}
function delayedReservationStore() {
    const memory = new MemoryConsumptionStore();
    let enteredResolve;
    let releaseResolve;
    const entered = new Promise((resolve) => { enteredResolve = resolve; });
    const release = new Promise((resolve) => { releaseResolve = resolve; });
    return {
        entered,
        release: () => releaseResolve(),
        store: {
            consume: memory.consume.bind(memory),
            async reserve(key) {
                enteredResolve();
                await release;
                return memory.reserve(key);
            },
            commit: memory.commit.bind(memory),
        },
    };
}
test('common kit passes a frozen verified-field actuator and drops unrestricted params', async () => {
    const harness = createEg1Harness();
    const gate = createTrustedActionFirewall({
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        allowEphemeralStore: true,
    });
    let actuator;
    const adapter = createAdapter({
        system: 'closure-test',
        ops: {
            release: {
                selector: { protocol: 'mcp', tool: 'release_payment' },
                observed: (p) => ({
                    action_type: 'payment.release',
                    amount_usd: p.amount_usd,
                    currency: p.currency,
                    payment_instruction_id: p.payment_instruction_id,
                    beneficiary_account_hash: p.beneficiary_account_hash,
                }),
                perform: async (_client, value) => { actuator = value; return 'ok'; },
            },
        },
    });
    const result = await adapter.guard(gate, {}, {
        op: 'release',
        params: { ...harness.action, unrestricted_provider_override: 'attacker-value' },
        receipt: harness.mint({ outcome: 'allow_with_signoff' }),
    });
    assert.equal(result.result, 'ok');
    assert.equal(Object.isFrozen(actuator), true);
    assert.equal(Object.hasOwn(actuator, 'unrestricted_provider_override'), false);
    assert.deepEqual(actuator, harness.action);
});
test('AWS refuses protocol or to-port drift before the EC2 client call', async () => {
    const action = {
        action_type: 'aws.ec2.authorize_ingress',
        group_id: 'sg-1',
        cidr: '10.0.0.0/8',
        protocol: 'tcp',
        from_port: 443,
        to_port: 443,
    };
    const { gate, harness } = gateFor(createAwsManifest(), action);
    let calls = 0;
    const client = { ec2: { authorizeSecurityGroupIngress: async () => { calls++; } } };
    await assert.rejects(() => guardAwsMutation(gate, client, {
        op: 'ec2.authorize_ingress',
        params: { group_id: 'sg-1', cidr: '10.0.0.0/8', protocol: 'udp', from_port: 443, to_port: 444 },
        receipt: harness.mint({ outcome: 'allow_with_signoff', quorum: { threshold: 2 } }),
    }), (error) => error.gate?.reason === 'execution_binding_failed');
    assert.equal(calls, 0);
    assert.equal(gate.store.size, 0);
});
test('Supabase refuses a different canonical RLS definition before client call', async () => {
    const approvedDefinition = 'USING (owner_id = auth.uid())';
    const attemptedDefinition = 'USING (true)';
    const action = {
        action_type: 'supabase.rls.change',
        table: 'payments',
        policy: 'owner_only',
        rls_definition_digest: rlsDefinitionDigest(approvedDefinition),
        rls_definition_version: RLS_DEFINITION_BINDING_VERSION,
    };
    const { gate, harness } = gateFor(createSupabaseManifest(), action);
    let calls = 0;
    const client = { alterPolicy: async () => { calls++; } };
    await assert.rejects(() => guardSupabaseMutation(gate, client, {
        op: 'rls.change',
        params: { table: 'payments', policy: 'owner_only', definition: attemptedDefinition },
        receipt: harness.mint({ outcome: 'allow_with_signoff', quorum: { threshold: 2 } }),
    }), (error) => error.gate?.reason === 'execution_binding_failed');
    assert.equal(calls, 0);
    assert.doesNotMatch(JSON.stringify(gate.evidence.all()), /USING \(true\)/);
});
test('Vercel refuses a different secret value and never records either value', async () => {
    const approved = 'approved-secret-value';
    const attempted = 'attacker-secret-value';
    const action = {
        action_type: 'vercel.env.set',
        project: 'checkout',
        key: 'PAYMENT_TOKEN',
        target: 'production',
        secret_value_digest: secretValueDigest(approved),
        secret_value_version: SECRET_VALUE_BINDING_VERSION,
    };
    const { gate, harness } = gateFor(createVercelManifest(), action);
    let calls = 0;
    const client = { upsertEnv: async () => { calls++; } };
    await assert.rejects(() => guardVercelMutation(gate, client, {
        op: 'env.set',
        params: { project: 'checkout', key: 'PAYMENT_TOKEN', target: 'production', value: attempted },
        receipt: harness.mint({ outcome: 'allow_with_signoff' }),
    }), (error) => error.gate?.reason === 'execution_binding_failed');
    assert.equal(calls, 0);
    const evidence = JSON.stringify(gate.evidence.all());
    assert.doesNotMatch(evidence, /approved-secret-value/);
    assert.doesNotMatch(evidence, /attacker-secret-value/);
});
test('caller mutation while reservation awaits cannot change the Vercel actuator', async () => {
    const approved = 'stable-secret';
    const action = {
        action_type: 'vercel.env.set',
        project: 'checkout',
        key: 'PAYMENT_TOKEN',
        target: 'production',
        secret_value_digest: secretValueDigest(approved),
        secret_value_version: SECRET_VALUE_BINDING_VERSION,
    };
    const delayed = delayedReservationStore();
    const { gate, harness } = gateFor(createVercelManifest(), action, delayed.store);
    const params = { project: 'checkout', key: 'PAYMENT_TOKEN', target: 'production', value: approved };
    const calls = [];
    const client = { upsertEnv: async (value) => { calls.push(value); return { ok: true }; } };
    const pending = guardVercelMutation(gate, client, {
        op: 'env.set',
        params,
        receipt: harness.mint({ outcome: 'allow_with_signoff' }),
    });
    await delayed.entered;
    params.value = 'mutated-after-verification';
    params.target = 'preview';
    delayed.release();
    await pending;
    assert.deepEqual(calls, [{
            project: 'checkout',
            key: 'PAYMENT_TOKEN',
            value: approved,
            target: 'production',
        }]);
});
