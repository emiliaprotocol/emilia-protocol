// SPDX-License-Identifier: Apache-2.0
// Generated from mongodb.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGate, createEg1Harness } from '../index.js';
import { createMongoConnector, createMongoManifest, guardMongoMutation, mongoFilterDigest, MONGODB_OPS, } from './mongodb.js';
function fakeMongo() {
    const calls = [];
    const client = {
        calls,
        db: (database) => ({
            collection: (collection) => ({
                deleteMany: async (filter, options) => {
                    calls.push(['deleteMany', database, collection, filter, options]);
                    return { deletedCount: 4 };
                },
                updateMany: async (filter, update, options) => {
                    calls.push(['updateMany', database, collection, filter, update, options]);
                    return { modifiedCount: 4 };
                },
                drop: async (options) => {
                    calls.push(['drop', database, collection, options]);
                    return true;
                },
            }),
        }),
    };
    return client;
}
function setup(action) {
    const harness = createEg1Harness({ action });
    const gate = createGate({
        manifest: createMongoManifest(),
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        quorumPolicy: harness.quorumPolicy,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        allowEphemeralStore: true,
    });
    const client = fakeMongo();
    const connector = createMongoConnector({ client, cluster: 'prod-us-east-1' });
    return { harness, gate, client, connector };
}
test('exposes the closed MongoDB operation set', () => {
    assert.deepEqual([...MONGODB_OPS].sort(), [
        'collection.drop',
        'document.delete_many',
        'document.update_many',
    ]);
});
test('missing receipt refuses before MongoDB is called', async () => {
    const filter = { tenant_id: 'tenant:1', status: 'expired' };
    const action = {
        action_type: 'mongodb.document.delete_many',
        cluster: 'prod-us-east-1',
        database: 'billing',
        collection: 'invoices',
        filter_digest: mongoFilterDigest(filter),
        operation_id: 'mongo:delete:0001',
    };
    const { gate, client, connector } = setup(action);
    await assert.rejects(() => guardMongoMutation(gate, connector, {
        op: 'document.delete_many',
        params: { database: 'billing', collection: 'invoices', filter, operation_id: 'mongo:delete:0001' },
    }), (error) => error.code === 'EMILIA_RECEIPT_REQUIRED' && error.status === 428);
    assert.equal(client.calls.length, 0);
});
test('valid Class-A receipt executes the exact filter preimage', async () => {
    const filter = { tenant_id: 'tenant:1', status: 'expired' };
    const action = {
        action_type: 'mongodb.document.delete_many',
        cluster: 'prod-us-east-1',
        database: 'billing',
        collection: 'invoices',
        filter_digest: mongoFilterDigest(filter),
        operation_id: 'mongo:delete:0002',
    };
    const { harness, gate, client, connector } = setup(action);
    const out = await guardMongoMutation(gate, connector, {
        op: 'document.delete_many',
        params: { database: 'billing', collection: 'invoices', filter, operation_id: 'mongo:delete:0002' },
        receipt: harness.mint({ outcome: 'allow_with_signoff' }),
    });
    assert.equal(out.result.deletedCount, 4);
    assert.deepEqual(client.calls, [[
            'deleteMany', 'billing', 'invoices', filter, { comment: 'mongo:delete:0002' },
        ]]);
});
test('filter substitution is refused and the provider sees nothing', async () => {
    const approved = { tenant_id: 'tenant:1', status: 'expired' };
    const substituted = { tenant_id: { $ne: 'tenant:1' } };
    const action = {
        action_type: 'mongodb.document.delete_many',
        cluster: 'prod-us-east-1',
        database: 'billing',
        collection: 'invoices',
        filter_digest: mongoFilterDigest(approved),
        operation_id: 'mongo:delete:0003',
    };
    const { harness, gate, client, connector } = setup(action);
    await assert.rejects(() => guardMongoMutation(gate, connector, {
        op: 'document.delete_many',
        params: { database: 'billing', collection: 'invoices', filter: substituted, operation_id: 'mongo:delete:0003' },
        receipt: harness.mint({ outcome: 'allow_with_signoff' }),
    }), (error) => /binding/.test(error.gate.reason));
    assert.equal(client.calls.length, 0);
});
test('caller cannot relabel the connector cluster', async () => {
    const action = {
        action_type: 'mongodb.collection.drop',
        cluster: 'prod-us-east-1',
        database: 'billing',
        collection: 'invoices',
        operation_id: 'mongo:drop:0001',
    };
    const { harness, gate, client, connector } = setup(action);
    await assert.rejects(() => guardMongoMutation(gate, connector, {
        op: 'collection.drop',
        params: {
            cluster: 'dev-us-east-1',
            database: 'billing',
            collection: 'invoices',
            operation_id: 'mongo:drop:0001',
        },
        receipt: harness.mint({ outcome: 'allow_with_signoff', quorum: { signers: ['ep:a', 'ep:b'], threshold: 2 } }),
    }), /conflicts with the connector identity/);
    assert.equal(client.calls.length, 0);
});
