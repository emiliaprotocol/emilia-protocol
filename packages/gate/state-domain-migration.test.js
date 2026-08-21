// SPDX-License-Identifier: Apache-2.0
// Generated from state-domain-migration.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto, { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { migrateStateDomain, verifyStateDomainMigrationReceipt, } from './state-domain-migration.js';
const D = (label) => `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
const NOW = '2026-08-20T18:00:00.000Z';
function harness(overrides = {}) {
    const events = [];
    const keys = generateKeyPairSync('ed25519');
    const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    let frozen = false;
    let active = false;
    const snapshot = {
        domain_id: 'state-domain:finance:source',
        epoch: 7,
        final_journal_head_digest: D('source-final-head'),
        unresolved_operation_count: 2,
        unresolved_operations_digest: D('source-unresolved-set'),
        state_digest: D('source-state'),
    };
    const source = {
        async freeze() { events.push('source.freeze'); frozen = true; return { ok: true }; },
        async readFrozenSnapshot() {
            events.push('source.snapshot');
            return frozen ? structuredClone(snapshot) : { ok: false, reason: 'not_frozen' };
        },
        async tombstone() { events.push('source.tombstone'); return { ok: true, tombstone_digest: D('source-tombstone') }; },
    };
    const target = {
        async importSealed(candidate) {
            events.push('target.import');
            assert.deepEqual(candidate, snapshot);
            return {
                ok: true,
                sealed_import_digest: D('sealed-import'),
                imported_state_digest: candidate.state_digest,
            };
        },
        async activate({ epoch }) {
            events.push('target.activate');
            active = true;
            return { ok: true, epoch, activation_digest: D('target-activation') };
        },
    };
    const externalFence = async () => {
        events.push('external.fence');
        return {
            statement: {
                source_domain_id: snapshot.domain_id,
                destination_domain_id: 'state-domain:finance:target',
                target_epoch: 8,
                source_authority_revoked: true,
                destination_authority_active: true,
                exclusive: true,
                evidence_digest: D('external-fence'),
            },
        };
    };
    const verifyExternalFence = async ({ statement }) => ({
        verified: statement.exclusive === true,
        ...statement,
    });
    return {
        events,
        get active() { return active; },
        trusted_keys: {
            'key:finance-migration': { issuer_id: 'customer:finance', public_key: publicKey },
        },
        input: {
            migration_id: 'migration:finance:01',
            tenant_id: 'tenant:finance',
            source_domain_id: snapshot.domain_id,
            destination_domain_id: 'state-domain:finance:target',
            target_epoch: 8,
            source,
            target,
            externalFence,
            verifyExternalFence,
            completed_at: NOW,
            signer: {
                issuer_id: 'customer:finance',
                key_id: 'key:finance-migration',
                private_key: keys.privateKey,
            },
            ...overrides,
        },
    };
}
test('migration freezes, seals, externally fences, activates, and tombstones in order', async () => {
    const fixture = harness();
    const result = await migrateStateDomain(fixture.input);
    assert.equal(result.ok, true);
    assert.deepEqual(fixture.events, [
        'source.freeze',
        'source.snapshot',
        'target.import',
        'external.fence',
        'target.activate',
        'source.tombstone',
    ]);
    assert.equal(fixture.active, true);
    const verified = verifyStateDomainMigrationReceipt(result.receipt, {
        trusted_keys: fixture.trusted_keys,
        expected: {
            migration_id: 'migration:finance:01',
            tenant_id: 'tenant:finance',
            source_domain_id: 'state-domain:finance:source',
            destination_domain_id: 'state-domain:finance:target',
            target_epoch: 8,
            authorizer_id: 'customer:finance',
        },
    });
    assert.equal(verified.accepted, true);
    assert.equal(verified.receipt.source_epoch, 7);
    assert.equal(verified.receipt.external_fence_evidence_digest, D('external-fence'));
});
test('an unverified external fence leaves the target sealed and emits no migration receipt', async () => {
    const fixture = harness({
        verifyExternalFence: async () => ({ verified: false, reason: 'credential_rotation_unverified' }),
    });
    const result = await migrateStateDomain(fixture.input);
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'credential_rotation_unverified');
    assert.equal(result.phase, 'external_fence');
    assert.equal(result.receipt, null);
    assert.equal(fixture.active, false);
    assert.deepEqual(fixture.events, [
        'source.freeze',
        'source.snapshot',
        'target.import',
        'external.fence',
    ]);
});
test('a tombstone failure is indeterminate and never fabricates a completed receipt', async () => {
    const fixture = harness({
        source: {
            async freeze() { fixture.events.push('source.freeze'); return { ok: true }; },
            async readFrozenSnapshot() {
                fixture.events.push('source.snapshot');
                return {
                    domain_id: 'state-domain:finance:source',
                    epoch: 7,
                    final_journal_head_digest: D('source-final-head'),
                    unresolved_operation_count: 2,
                    unresolved_operations_digest: D('source-unresolved-set'),
                    state_digest: D('source-state'),
                };
            },
            async tombstone() { fixture.events.push('source.tombstone'); return { ok: false, reason: 'tombstone_write_lost' }; },
        },
    });
    const result = await migrateStateDomain(fixture.input);
    assert.equal(result.ok, false);
    assert.equal(result.state, 'INDETERMINATE');
    assert.equal(result.phase, 'source_tombstone');
    assert.equal(result.receipt, null);
});
