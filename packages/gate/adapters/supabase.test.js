// SPDX-License-Identifier: Apache-2.0
// Generated from supabase.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { createGate, createEg1Harness } from '../index.js';
import { createSupabaseAllowanceConnector, createSupabaseManifest, guardSupabaseAllowanceMutation, guardSupabaseMutation, SUPABASE_OPS, isDestructiveSql, statementHash, rlsDefinitionDigest, RLS_DEFINITION_BINDING_VERSION, } from './supabase.js';
import { allowanceDigest, issueGateAllowance } from '../allowance.js';
import { createMemoryCapabilityStore } from '../capability-receipt.js';
const SUPABASE_CONNECTOR_ID = 'supabase:project:prod';
const supabaseConnector = (client) => createSupabaseAllowanceConnector({ client });
const currentAllowanceStatus = () => ({
    ok: true,
    status_epoch: 1,
    status_head_digest: `sha256:${'a'.repeat(64)}`,
});
function initializeAllowanceStatus(store, issued) {
    const status = currentAllowanceStatus();
    const result = store.advanceAllowanceStatus({
        allowance_profile_id: `${issued.allowance.tenant_id}/${issued.allowance.allowance_id}`,
        allowance_digest: allowanceDigest(issued.allowance),
        revision: issued.allowance.revision,
        status_epoch: status.status_epoch,
        status_head_digest: status.status_head_digest,
        expected_status_epoch: null,
        expected_status_head_digest: null,
        status: 'active',
    });
    assert.equal(result.ok, true);
}
function fakeDb(projectRef = 'prod') {
    const calls = [];
    return {
        calls,
        supabaseUrl: `https://${projectRef}.supabase.co`,
        query: async (sql) => { calls.push(['query', sql]); return { rowCount: 1 }; },
        export: async (table, recipient) => { calls.push(['export', table, recipient]); return { ok: true }; },
        alterPolicy: async (table, policy, def) => { calls.push(['rls', table, policy, def]); return { ok: true }; },
    };
}
function setup(action) {
    const harness = createEg1Harness({ action });
    return { harness, gate: createGate({ manifest: createSupabaseManifest(), trustedKeys: [harness.publicKey], approverKeys: harness.approverKeys, quorumPolicy: harness.quorumPolicy, rpId: harness.rpId, allowedOrigins: harness.allowedOrigins, allowEphemeralStore: true }), db: fakeDb() };
}
const SQL = 'DELETE FROM payments WHERE id = 1';
const SQL_ACTION = { action_type: 'supabase.sql.destructive', statement_hash: statementHash(SQL) };
test('isDestructiveSql flags the dangerous shapes', () => {
    assert.equal(isDestructiveSql('DELETE FROM t WHERE id=1'), true);
    assert.equal(isDestructiveSql('drop table t'), true);
    assert.equal(isDestructiveSql('TRUNCATE t'), true);
    assert.equal(isDestructiveSql('UPDATE t SET x=1'), true); // no WHERE
    assert.equal(isDestructiveSql('SELECT * FROM t'), false);
    assert.equal(isDestructiveSql('UPDATE t SET x=1 WHERE id=2'), false);
});
test('exposes the destructive Supabase ops', () => {
    assert.deepEqual([...SUPABASE_OPS].sort(), ['data.export', 'rls.change', 'sql.destructive']);
});
test('destructive SQL WITHOUT a receipt never executes', async () => {
    const { gate, db } = setup(SQL_ACTION);
    await assert.rejects(() => guardSupabaseMutation(gate, db, { op: 'sql.destructive', params: { sql: SQL } }), (e) => e.code === 'EMILIA_RECEIPT_REQUIRED' && e.status === 428);
    assert.equal(db.calls.length, 0);
});
test('destructive SQL WITH a valid Class-A receipt executes the exact statement', async () => {
    const { gate, harness, db } = setup(SQL_ACTION);
    const { result, reliance } = await guardSupabaseMutation(gate, db, {
        op: 'sql.destructive', params: { sql: SQL }, receipt: harness.mint({ outcome: 'allow_with_signoff' }),
    });
    assert.equal(result.rowCount, 1);
    assert.deepEqual(db.calls[0], ['query', SQL]);
    assert.equal(String(reliance.verdict).toLowerCase(), 'rely');
});
test('a receipt for one statement cannot authorize a different statement (drift)', async () => {
    const { gate, harness, db } = setup(SQL_ACTION); // authorizes the DELETE
    const receipt = harness.mint({ outcome: 'allow_with_signoff' });
    await assert.rejects(() => guardSupabaseMutation(gate, db, { op: 'sql.destructive', params: { sql: 'DROP TABLE payments' }, receipt }), (e) => /binding/.test(e.gate.reason));
    assert.equal(db.calls.length, 0);
});
test('RLS policy change requires quorum', async () => {
    const action = {
        action_type: 'supabase.rls.change',
        table: 'payments',
        policy: 'allow_all',
        rls_definition_digest: rlsDefinitionDigest('USING (true)'),
        rls_definition_version: RLS_DEFINITION_BINDING_VERSION,
    };
    const { gate, harness, db } = setup(action);
    const params = { table: 'payments', policy: 'allow_all', definition: 'USING (true)' };
    await assert.rejects(() => guardSupabaseMutation(gate, db, { op: 'rls.change', params, receipt: harness.mint({ outcome: 'allow_with_signoff' }) }), (e) => /assurance/.test(e.gate.reason));
    const quorum = harness.mint({ outcome: 'allow_with_signoff', quorum: { signers: ['ep:a', 'ep:b'], threshold: 2 } });
    const { result } = await guardSupabaseMutation(gate, db, { op: 'rls.change', params, receipt: quorum });
    assert.equal(result.ok, true, JSON.stringify(result));
});
function issueRlsAllowance({ table = 'public.payments', connectorId = SUPABASE_CONNECTOR_ID, allowedValues = {
    policy: ['finance_read'],
    rls_definition_digest: [
        rlsDefinitionDigest('USING (tenant_id = current_setting(\'app.tenant_id\')::uuid)'),
    ],
    rls_definition_version: [RLS_DEFINITION_BINDING_VERSION],
}, materialFields = [
    'action_type',
    'table',
    'policy',
    'rls_definition_digest',
    'rls_definition_version',
    'rls_definition',
    'amount',
    'currency',
    'operation_id',
], } = {}) {
    const keys = generateKeyPairSync('ed25519');
    const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const issued = issueGateAllowance({
        authorizationReceipt: {
            '@version': 'EP-RECEIPT-v1',
            payload: {
                receipt_id: 'receipt:supabase-rls-allowance:01',
                claim: { action_type: 'gate.allowance.issue', capability_only: true },
            },
        },
        allowance: {
            allowance_id: 'allowance:supabase-rls:adapter',
            tenant_id: 'tenant:example',
            subject_id: 'agent:database:01',
            audience: 'gate:supabase:production',
            connector_id: connectorId,
            action_type: 'supabase.rls.change',
            revision: 1,
            supersedes_allowance_digest: null,
            presentation_digest: `sha256:${'2'.repeat(64)}`,
            issued_at: '2026-07-30T17:59:00.000Z',
            valid_from: '2026-07-30T18:00:00.000Z',
            expires_at: '2026-07-31T18:00:00.000Z',
            constraints: {
                currency: 'RLSCHANGE',
                aggregate_amount: 2,
                max_amount_per_action: 1,
                material_fields: materialFields,
                operation_id_field: 'operation_id',
                amount_field: 'amount',
                currency_field: 'currency',
                target_field: 'table',
                allowed_targets: [table],
                allowed_values: allowedValues,
            },
        },
        signer: {
            issuer_id: 'customer:security',
            key_id: 'key:allowance',
            private_key: keys.privateKey,
        },
        capabilityIssuerPrivateKey: keys.privateKey,
    });
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(issued.capabilityReceipt), true);
    initializeAllowanceStatus(store, issued);
    return {
        issued,
        store,
        trustedAllowanceKeys: {
            'key:allowance': {
                issuer_id: 'customer:security',
                public_key: publicKey,
            },
        },
        trustedCapabilityIssuerKeys: [publicKey],
    };
}
function rlsAllowanceArgs(issued, store, trustedAllowanceKeys, trustedCapabilityIssuerKeys) {
    return {
        allowance: issued.allowance,
        capabilityReceipt: issued.capabilityReceipt,
        secret: issued.secret,
        store,
        verifyAuthorizationReceipt: () => true,
        verifyAllowanceStatus: () => currentAllowanceStatus(),
        trustedAllowanceKeys,
        trustedCapabilityIssuerKeys,
        expected: {
            allowance_id: 'allowance:supabase-rls:adapter',
            tenant_id: 'tenant:example',
            subject_id: 'agent:database:01',
            audience: 'gate:supabase:production',
            authorizer_id: 'customer:security',
        },
        now: Date.parse('2026-07-30T18:00:00.000Z'),
    };
}
test('typed Supabase RLS allowance executes an exact in-envelope policy replacement', async () => {
    const allowance = issueRlsAllowance();
    const db = fakeDb();
    const connector = await supabaseConnector(db);
    const result = await guardSupabaseAllowanceMutation({
        connector,
        params: {
            table: 'public.payments',
            policy: 'finance_read',
            definition: 'USING (tenant_id = current_setting(\'app.tenant_id\')::uuid)',
        },
        operationId: 'supabase:rls:01',
        ...rlsAllowanceArgs(allowance.issued, allowance.store, allowance.trustedAllowanceKeys, allowance.trustedCapabilityIssuerKeys),
    });
    assert.equal(result.ok, true);
    assert.equal(result.result.ok, true);
    assert.deepEqual(db.calls, [[
            'rls',
            'public.payments',
            'finance_read',
            'USING (tenant_id = current_setting(\'app.tenant_id\')::uuid)',
        ]]);
});
test('typed Supabase RLS allowance refuses a different table and never calls the database', async () => {
    const allowance = issueRlsAllowance();
    const db = fakeDb();
    const connector = await supabaseConnector(db);
    const result = await guardSupabaseAllowanceMutation({
        connector,
        params: {
            table: 'public.customers',
            policy: 'finance_read',
            definition: 'USING (true)',
        },
        operationId: 'supabase:rls:target-drift',
        ...rlsAllowanceArgs(allowance.issued, allowance.store, allowance.trustedAllowanceKeys, allowance.trustedCapabilityIssuerKeys),
    });
    assert.deepEqual(result, { ok: false, reason: 'allowance_target_not_allowed' });
    assert.equal(db.calls.length, 0);
});
test('typed Supabase RLS allowance refuses policy-definition substitution', async () => {
    const allowance = issueRlsAllowance();
    const db = fakeDb();
    const connector = await supabaseConnector(db);
    const result = await guardSupabaseAllowanceMutation({
        connector,
        params: {
            table: 'public.payments',
            policy: 'finance_read',
            definition: 'USING (true)',
        },
        operationId: 'supabase:rls:definition-drift',
        ...rlsAllowanceArgs(allowance.issued, allowance.store, allowance.trustedAllowanceKeys, allowance.trustedCapabilityIssuerKeys),
    });
    assert.deepEqual(result, { ok: false, reason: 'allowance_field_value_not_allowed' });
    assert.equal(db.calls.length, 0);
});
test('typed Supabase RLS allowance refuses a non-matching material-field shape', async () => {
    const allowance = issueRlsAllowance({
        materialFields: [
            'action_type',
            'table',
            'policy',
            'rls_definition_version',
            'amount',
            'currency',
            'operation_id',
        ],
        allowedValues: {
            policy: ['finance_read'],
            rls_definition_version: [RLS_DEFINITION_BINDING_VERSION],
        },
    });
    const db = fakeDb();
    const connector = await supabaseConnector(db);
    const result = await guardSupabaseAllowanceMutation({
        connector,
        params: {
            table: 'public.payments',
            policy: 'finance_read',
            definition: 'USING (true)',
        },
        operationId: 'supabase:rls:shape-drift',
        ...rlsAllowanceArgs(allowance.issued, allowance.store, allowance.trustedAllowanceKeys, allowance.trustedCapabilityIssuerKeys),
    });
    assert.deepEqual(result, { ok: false, reason: 'allowance_action_shape_invalid' });
    assert.equal(db.calls.length, 0);
});
test('typed Supabase RLS change executes the immutable verified action when caller params mutate during verification', async () => {
    const allowance = issueRlsAllowance();
    const db = fakeDb();
    const connector = await supabaseConnector(db);
    const params = {
        table: 'public.payments',
        policy: 'finance_read',
        definition: 'USING (tenant_id = current_setting(\'app.tenant_id\')::uuid)',
    };
    const args = rlsAllowanceArgs(allowance.issued, allowance.store, allowance.trustedAllowanceKeys, allowance.trustedCapabilityIssuerKeys);
    const result = await guardSupabaseAllowanceMutation({
        connector,
        params,
        operationId: 'supabase:rls:mutation',
        ...args,
        verifyAuthorizationReceipt: async () => {
            params.table = 'public.secrets';
            params.policy = 'allow_all';
            params.definition = 'USING (true)';
            return true;
        },
    });
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.deepEqual(db.calls, [[
            'rls',
            'public.payments',
            'finance_read',
            'USING (tenant_id = current_setting(\'app.tenant_id\')::uuid)',
        ]]);
});
test('typed Supabase RLS change refuses cross-protocol and cross-project connector substitution', async () => {
    for (const [signedConnectorId, providerProjectRef] of [
        ['github:installation:101', 'prod'],
        [SUPABASE_CONNECTOR_ID, 'attacker'],
    ]) {
        const allowance = issueRlsAllowance({ connectorId: signedConnectorId });
        const db = fakeDb(providerProjectRef);
        const connector = await supabaseConnector(db);
        const result = await guardSupabaseAllowanceMutation({
            connector,
            params: {
                table: 'public.payments',
                policy: 'finance_read',
                definition: 'USING (tenant_id = current_setting(\'app.tenant_id\')::uuid)',
            },
            operationId: `supabase:connector:${providerProjectRef}`,
            ...rlsAllowanceArgs(allowance.issued, allowance.store, allowance.trustedAllowanceKeys, allowance.trustedCapabilityIssuerKeys),
        });
        assert.deepEqual(result, { ok: false, reason: 'connector_mismatch' });
        assert.equal(db.calls.length, 0);
    }
});
