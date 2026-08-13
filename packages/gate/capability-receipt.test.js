// SPDX-License-Identifier: Apache-2.0
// Generated from capability-receipt.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createRequire } from 'node:module';
import { canonicalize } from './execution-binding.js';
import { executeWithCapability, executeWithThreshold, reconcileCapabilityOperation, delegateCapabilityReceipt, createMemoryCapabilityStore, createPostgresCapabilityStore, isSecureCapabilityStore, CAPABILITY_STATE_DDL, CAPABILITY_SQL, mintCapabilityReceipt, reconstructCapabilitySecret, splitCapabilitySecret, verifyCapabilityReceipt, verifyCapabilityScope, CAPABILITY_RECEIPT_VERSION, CAPABILITY_SCOPE_PROFILE, CAPABILITY_CAID_SCOPE_PROFILE, CAPABILITY_ALLOWANCE_SCOPE_PROFILE, capabilityActionDigest, capabilityBaseReceiptDigest, } from './capability-receipt.js';
const NOW = Date.parse('2026-07-18T22:00:00.000Z');
const require = createRequire(import.meta.url);
function baseReceipt({ privateKey, publicKey, receiptId = 'base_1' } = {}) {
    const payload = {
        receipt_id: receiptId,
        created_at: new Date(NOW - 1000).toISOString(),
        subject: 'operator@example.test',
        claim: { action_type: 'payment.release', outcome: 'allow', capability_only: true },
    };
    return {
        '@version': 'EP-RECEIPT-v1',
        payload,
        signature: { algorithm: 'Ed25519', value: sign(null, Buffer.from(canonicalize(payload)), privateKey).toString('base64url') },
        public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    };
}
function issuer() {
    const keys = generateKeyPairSync('ed25519');
    return { ...keys, receipt: baseReceipt({ privateKey: keys.privateKey, publicKey: keys.publicKey }) };
}
function scopedAction(operation_id, overrides = {}) {
    return { amount: 1, currency: 'USD', operation_id, ...overrides };
}
const DEFAULT_SCOPE_ACTIONS = [
    scopedAction('op_1', { amount: 30, destination: 'acct_a' }),
    scopedAction('op_2', { amount: 60 }),
    scopedAction('op_3', { amount: 60 }),
    scopedAction('op_4', { amount: 10 }),
    scopedAction('bad_1'),
    scopedAction('bad_1', { currency: 'EUR' }),
    scopedAction('threshold_op_1', { amount: 25 }),
    scopedAction('envelope_collision_spend'),
    scopedAction('crash_before_provider_entry', { amount: 10 }),
    scopedAction('post_entry_negative_evidence', { amount: 10 }),
    scopedAction('unknown_guard_disposition', { amount: 10 }),
];
function options(overrides = {}) {
    return {
        budget: { amount: 100, currency: 'USD' },
        expiry: NOW + 60_000,
        revocationMode: 'direct',
        issuerPrivateKey: overrides.issuerPrivateKey,
        scope: {
            profile: CAPABILITY_SCOPE_PROFILE,
            operation_id_field: 'operation_id',
            action_digests: DEFAULT_SCOPE_ACTIONS.map(capabilityActionDigest),
        },
        ...overrides,
    };
}
test('capability stores expose explicit production durability and reconciliation markers', () => {
    const memory = createMemoryCapabilityStore();
    assert.equal(memory.durable, false);
    assert.equal(memory.reconciliationCapable, true);
    assert.equal(memory.providerEntryDispositionCapable, true);
    assert.equal(memory.revocationInheritanceCapable, true);
    assert.equal(isSecureCapabilityStore(memory), false);
    const postgres = createPostgresCapabilityStore({
        transaction: async () => assert.fail('store contract inspection must not open a transaction'),
    });
    assert.equal(postgres.durable, true);
    assert.equal(postgres.reconciliationCapable, true);
    assert.equal(postgres.providerEntryDispositionCapable, true);
    assert.equal(postgres.revocationInheritanceCapable, true);
    assert.equal(isSecureCapabilityStore(postgres), true);
    const methodsOnly = {
        registerCapability() { },
        reserveSpend() { },
        beginProviderEntry() { },
        recoverPreEntrySpend() { },
        commitSpend() { },
        reconcileSpend() { },
        revokeCapability() { },
    };
    assert.equal(isSecureCapabilityStore(methodsOnly), false);
    assert.equal(isSecureCapabilityStore({ ...methodsOnly, durable: true }), false);
    assert.equal(isSecureCapabilityStore({ ...methodsOnly, reconciliationCapable: true }), false);
});
test('revocation mode is signed, mandatory, and closed to direct or cascade', () => {
    const keys = issuer();
    assert.throws(() => mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        revocationMode: undefined,
    })), /revocation_mode/);
    assert.throws(() => mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        revocationMode: 'eventual',
    })), /revocation_mode/);
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'signed-revocation-mode',
        revocationMode: 'cascade',
    }));
    assert.equal(minted.capabilityReceipt.capability.revocation_mode, 'cascade');
    assert.equal(verifyCapabilityReceipt(minted.capabilityReceipt, {
        trustedIssuerKeys: [keys.receipt.public_key],
    }).ok, true);
    const forged = structuredClone(minted.capabilityReceipt);
    delete forged.capability.revocation_mode;
    resignEnvelope(forged, keys.privateKey);
    assert.equal(verifyCapabilityReceipt(forged, {
        trustedIssuerKeys: [keys.receipt.public_key],
    }).reason, 'capability_malformed');
});
test('memory capability operations isolate identical operation ids by capability', async () => {
    const keys = issuer();
    const first = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'operation_scope_a',
    }));
    const second = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'operation_scope_b',
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(first.capabilityReceipt), true);
    assert.equal(store.registerCapability(second.capabilityReceipt), true);
    const reserve = (minted, operationId) => store.reserveSpend({
        capabilityId: minted.capabilityReceipt.capability.id,
        capabilityFingerprint: store.getState(minted.capabilityReceipt.capability.id).capability_fingerprint,
        operationId,
        actionDigest: capabilityActionDigest(scopedAction(operationId)),
        amount: 1,
        currency: 'USD',
        now: NOW,
    });
    const firstReservation = await reserve(first, 'shared-operation');
    const secondReservation = await reserve(second, 'shared-operation');
    assert.equal(firstReservation.ok, true);
    assert.equal(secondReservation.ok, true);
    const repeated = await reserve(first, 'shared-operation');
    assert.equal(repeated.reason, 'operation_in_flight');
    assert.equal(repeated.action_digest, capabilityActionDigest(scopedAction('shared-operation')));
    assert.equal(repeated.action_fence_digest, repeated.action_digest);
    assert.equal(repeated.holding_operation_id, 'shared-operation');
    assert.equal((await store.beginProviderEntry({
        capabilityId: first.capabilityReceipt.capability.id,
        operationId: 'shared-operation',
        reservationToken: firstReservation.reservation_token,
        now: NOW,
    })).ok, true);
    assert.equal((await store.commitSpend({
        capabilityId: first.capabilityReceipt.capability.id,
        operationId: 'shared-operation',
        reservationToken: firstReservation.reservation_token,
        outcome: 'executed',
        now: NOW,
    })).ok, true);
    assert.equal(store.getOperation('shared-operation', first.capabilityReceipt.capability.id).outcome, 'executed');
    assert.equal(store.getOperation('shared-operation', second.capabilityReceipt.capability.id).status, 'reserved');
    assert.equal((await reserve(first, 'shared-operation')).reason, 'operation_already_committed');
    assert.equal((await store.beginProviderEntry({
        capabilityId: second.capabilityReceipt.capability.id,
        operationId: 'shared-operation',
        reservationToken: secondReservation.reservation_token,
        now: NOW,
    })).ok, true);
    assert.equal((await store.commitSpend({
        capabilityId: second.capabilityReceipt.capability.id,
        operationId: 'shared-operation',
        reservationToken: secondReservation.reservation_token,
        outcome: 'executed',
        now: NOW,
    })).ok, true);
    const firstIndeterminate = await reserve(first, 'shared-reconciliation');
    const secondIndeterminate = await reserve(second, 'shared-reconciliation');
    assert.equal((await store.beginProviderEntry({
        capabilityId: first.capabilityReceipt.capability.id,
        operationId: 'shared-reconciliation',
        reservationToken: firstIndeterminate.reservation_token,
        now: NOW,
    })).ok, true);
    await store.commitSpend({
        capabilityId: first.capabilityReceipt.capability.id,
        operationId: 'shared-reconciliation',
        reservationToken: firstIndeterminate.reservation_token,
        outcome: 'indeterminate',
        now: NOW,
    });
    assert.equal((await store.beginProviderEntry({
        capabilityId: second.capabilityReceipt.capability.id,
        operationId: 'shared-reconciliation',
        reservationToken: secondIndeterminate.reservation_token,
        now: NOW,
    })).ok, true);
    await store.commitSpend({
        capabilityId: second.capabilityReceipt.capability.id,
        operationId: 'shared-reconciliation',
        reservationToken: secondIndeterminate.reservation_token,
        outcome: 'indeterminate',
        now: NOW,
    });
    const firstEvidence = `sha256:${'1'.repeat(64)}`;
    const secondEvidence = `sha256:${'2'.repeat(64)}`;
    assert.equal((await store.reconcileSpend({
        capabilityId: first.capabilityReceipt.capability.id,
        operationId: 'shared-reconciliation',
        actionDigest: capabilityActionDigest(scopedAction('shared-reconciliation')),
        evidenceDigest: firstEvidence,
        outcome: 'executed',
        now: NOW + 1,
    })).ok, true);
    assert.equal(store.getOperation('shared-reconciliation', second.capabilityReceipt.capability.id).reconciliation_outcome, undefined);
    assert.equal((await store.reconcileSpend({
        capabilityId: second.capabilityReceipt.capability.id,
        operationId: 'shared-reconciliation',
        actionDigest: capabilityActionDigest(scopedAction('shared-reconciliation')),
        evidenceDigest: secondEvidence,
        outcome: 'executed',
        now: NOW + 1,
    })).ok, true);
    assert.equal(store.getOperation('shared-reconciliation', first.capabilityReceipt.capability.id).reconciliation_evidence_digest, firstEvidence);
    assert.equal(store.getOperation('shared-reconciliation', second.capabilityReceipt.capability.id).reconciliation_evidence_digest, secondEvidence);
});
test('postgres capability operations use a composite namespace and operation key', async () => {
    assert.match(CAPABILITY_STATE_DDL, /PRIMARY KEY \(operation_namespace, operation_id\)/);
    assert.doesNotMatch(CAPABILITY_STATE_DDL, /operation_id TEXT PRIMARY KEY/);
    assert.match(CAPABILITY_STATE_DDL, /entry_deadline_at TIMESTAMPTZ/);
    assert.match(CAPABILITY_STATE_DDL, /provider_entry_at TIMESTAMPTZ/);
    assert.match(CAPABILITY_STATE_DDL, /'provider_entered'/);
    assert.match(CAPABILITY_STATE_DDL, /'released'/);
    assert.match(CAPABILITY_STATE_DDL, /reconciliation_outcome IN \('executed', 'not_entered'\)/);
    assert.match(CAPABILITY_STATE_DDL, /revocation_mode TEXT NOT NULL CHECK \(revocation_mode IN \('direct', 'cascade'\)\)/);
    assert.match(CAPABILITY_STATE_DDL, /revocation_state_ready BOOLEAN NOT NULL DEFAULT TRUE/);
    assert.match(CAPABILITY_STATE_DDL, /NEW\.revocation_mode IS NULL/);
    assert.match(CAPABILITY_STATE_DDL, /FOREIGN KEY \(parent_capability_id\) REFERENCES ep_capability_state\(capability_id\)/);
    assert.match(CAPABILITY_SQL.readState, /FOR UPDATE/);
    assert.match(CAPABILITY_SQL.reserveState, /revoked_at IS NULL/);
    assert.match(CAPABILITY_SQL.reserveState, /revocation_state_ready IS TRUE/);
    assert.doesNotMatch(CAPABILITY_STATE_DDL, /SET revocation_mode = 'direct'/);
    assert.match(CAPABILITY_SQL.readOperation, /operation_namespace = \$1 AND operation_id = \$2/);
    assert.match(CAPABILITY_STATE_DDL, /CREATE TABLE IF NOT EXISTS ep_gate_allowance_status/);
    assert.match(CAPABILITY_SQL.readAllowanceStatus, /FOR UPDATE/);
    // The action fence: scoped to the namespace, restricted to statuses that still
    // hold the action, and row-locked so two concurrent reservations for one action
    // serialize rather than both passing the read.
    assert.match(CAPABILITY_STATE_DDL, /action_fence_digest TEXT NOT NULL/);
    assert.match(CAPABILITY_SQL.readActionHolder, /operation_namespace = \$1 AND action_fence_digest = \$2/);
    assert.match(CAPABILITY_SQL.readActionHolder, /'reserved', 'provider_entered', 'committed'/);
    assert.doesNotMatch(CAPABILITY_SQL.readActionHolder, /'released'/);
    assert.match(CAPABILITY_SQL.readActionHolder, /FOR UPDATE/);
    assert.match(CAPABILITY_SQL.releaseGuardRefusedOperation, /reservation_token = \$5 AND status = 'reserved'/);
    assert.match(CAPABILITY_SQL.releaseReservedOperation, /entry_deadline_at <= \$7/);
    assert.match(CAPABILITY_SQL.releaseReservedOperation, /status = 'reserved'/);
    assert.doesNotMatch(CAPABILITY_SQL.releaseReservedOperation, /provider_entered/);
    assert.equal(Object.hasOwn(CAPABILITY_SQL, 'releaseConsumedState'), false);
    assert.match(CAPABILITY_STATE_DDL, /CREATE UNIQUE INDEX IF NOT EXISTS ep_capability_operations_live_action_uniq\s+ON ep_capability_operations\(operation_namespace, action_fence_digest\)\s+WHERE status IN \('reserved', 'provider_entered', 'committed'\)/);
    assert.match(CAPABILITY_STATE_DDL, /duplicate live capability actions require operator reconciliation/);
    assert.match(CAPABILITY_STATE_DDL, /FROM pg_index AS i/);
    assert.match(CAPABILITY_STATE_DDL, /i\.indisunique/);
    assert.match(CAPABILITY_STATE_DDL, /i\.indisvalid/);
    assert.match(CAPABILITY_STATE_DDL, /i\.indisready/);
    assert.match(CAPABILITY_STATE_DDL, /i\.indnatts/);
    assert.match(CAPABILITY_STATE_DDL, /ARRAY\['operation_namespace', 'action_fence_digest'\]::TEXT\[\]/);
    assert.match(CAPABILITY_STATE_DDL, /capability action-fence index does not match its required contract/);
    const keys = issuer();
    const first = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'postgres_operation_scope_a',
    }));
    const second = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'postgres_operation_scope_b',
    }));
    const states = new Map();
    const operations = new Map();
    const operationKey = (operationNamespace, operationId) => `${operationNamespace}\u0000${operationId}`;
    const transaction = async (callback) => callback(async (sql, params) => {
        if (sql === CAPABILITY_SQL.register) {
            if (!states.has(params[0])) {
                states.set(params[0], {
                    capability_id: params[0],
                    capability_fingerprint: params[4],
                    budget_amount: String(params[1]),
                    currency: params[2],
                    consumed_amount: '0',
                    reserved_amount: '0',
                    expires_at: params[3],
                    semantic_fence_ready: true,
                    revocation_mode: params[7],
                    parent_capability_id: params[8],
                    revoked_at: null,
                    revocation_state_ready: true,
                });
            }
            return { rowCount: 1, rows: [] };
        }
        if (sql === CAPABILITY_SQL.readState) {
            const row = states.get(params[0]);
            return { rowCount: row ? 1 : 0, rows: row ? [row] : [] };
        }
        if (sql === CAPABILITY_SQL.readOperation) {
            assert.equal(params.length, 2);
            const row = operations.get(operationKey(params[0], params[1]));
            return { rowCount: row ? 1 : 0, rows: row ? [row] : [] };
        }
        if (sql === CAPABILITY_SQL.readActionHolder) {
            assert.equal(params.length, 2);
            const [operationNamespace, actionFenceDigest] = params;
            const row = [...operations.values()].find((entry) => entry.operation_namespace === operationNamespace
                && entry.action_fence_digest === actionFenceDigest
                && ['reserved', 'provider_entered', 'committed'].includes(entry.status));
            return { rowCount: row ? 1 : 0, rows: row ? [row] : [] };
        }
        if (sql === CAPABILITY_SQL.reserveState) {
            const row = states.get(params[0]);
            row.reserved_amount = String(Number(row.reserved_amount) + Number(params[1]));
            return { rowCount: 1, rows: [] };
        }
        if (sql === CAPABILITY_SQL.insertOperation) {
            const [operationNamespace, capabilityId, operationId, actionDigest, actionFenceDigest, amount, currency, reservationToken, reservedAt, entryDeadlineAt] = params;
            operations.set(operationKey(operationNamespace, operationId), {
                operation_namespace: operationNamespace,
                capability_id: capabilityId,
                operation_id: operationId,
                action_digest: actionDigest,
                action_fence_digest: actionFenceDigest,
                amount: String(amount),
                currency,
                reservation_token: reservationToken,
                status: 'reserved',
                outcome: null,
                reconciliation_outcome: null,
                reconciliation_evidence_digest: null,
                reserved_at: reservedAt,
                entry_deadline_at: entryDeadlineAt,
                provider_entry_at: null,
            });
            return { rowCount: 1, rows: [] };
        }
        if (sql === CAPABILITY_SQL.beginProviderEntry) {
            const [operationNamespace, operationId, capabilityId, reservationToken, enteredAt] = params;
            const row = operations.get(operationKey(operationNamespace, operationId));
            if (!row || row.capability_id !== capabilityId || row.status !== 'reserved'
                || row.reservation_token !== reservationToken
                || Date.parse(row.entry_deadline_at) <= Date.parse(enteredAt)) {
                return { rowCount: 0, rows: [] };
            }
            row.status = 'provider_entered';
            row.provider_entry_at = enteredAt;
            return { rowCount: 1, rows: [] };
        }
        if (sql === CAPABILITY_SQL.commitOperation) {
            const [operationNamespace, operationId, capabilityId, outcome, , reservationToken, expectedStatus] = params;
            const row = operations.get(operationKey(operationNamespace, operationId));
            if (!row || row.capability_id !== capabilityId || row.status !== expectedStatus || row.reservation_token !== reservationToken)
                return { rowCount: 0, rows: [] };
            row.status = 'committed';
            row.outcome = outcome;
            return { rowCount: 1, rows: [] };
        }
        if (sql === CAPABILITY_SQL.commitState) {
            const row = states.get(params[0]);
            row.reserved_amount = String(Number(row.reserved_amount) - Number(params[1]));
            row.consumed_amount = String(Number(row.consumed_amount) + Number(params[1]));
            return { rowCount: 1, rows: [] };
        }
        if (sql === CAPABILITY_SQL.recoverPreEntryOperation) {
            const [operationNamespace, operationId, capabilityId, actionDigest, recoveredAt] = params;
            const row = operations.get(operationKey(operationNamespace, operationId));
            if (!row || row.capability_id !== capabilityId || row.action_digest !== actionDigest
                || row.status !== 'reserved' || Date.parse(row.entry_deadline_at) > Date.parse(recoveredAt)) {
                return { rowCount: 0, rows: [] };
            }
            row.status = 'released';
            row.outcome = 'not_entered';
            return { rowCount: 1, rows: [] };
        }
        if (sql === CAPABILITY_SQL.releaseReservedState) {
            const row = states.get(params[0]);
            row.reserved_amount = String(Number(row.reserved_amount) - Number(params[1]));
            return { rowCount: 1, rows: [] };
        }
        if (sql === CAPABILITY_SQL.reconcileOperation) {
            const [operationNamespace, operationId, capabilityId, outcome, evidenceDigest] = params;
            const row = operations.get(operationKey(operationNamespace, operationId));
            if (!row || row.capability_id !== capabilityId || row.status !== 'committed' || row.outcome !== 'indeterminate' || row.reconciliation_outcome) {
                return { rowCount: 0, rows: [] };
            }
            row.reconciliation_outcome = outcome;
            row.reconciliation_evidence_digest = evidenceDigest;
            return { rowCount: 1, rows: [] };
        }
        throw new Error(`unexpected SQL in composite operation test: ${sql}`);
    });
    const store = createPostgresCapabilityStore({ transaction, providerEntryTimeoutMs: 1_000 });
    assert.equal(await store.registerCapability(first.capabilityReceipt), true);
    assert.equal(await store.registerCapability(second.capabilityReceipt), true);
    const reserve = (minted) => store.reserveSpend({
        capabilityId: minted.capabilityReceipt.capability.id,
        capabilityFingerprint: states.get(minted.capabilityReceipt.capability.id).capability_fingerprint,
        operationId: 'shared-postgres-operation',
        actionDigest: capabilityActionDigest(scopedAction('shared-postgres-operation')),
        amount: 1,
        currency: 'USD',
        now: NOW,
    });
    const firstReservation = await reserve(first);
    const secondReservation = await reserve(second);
    assert.equal(firstReservation.ok, true);
    assert.equal(secondReservation.ok, true);
    assert.equal((await reserve(first)).reason, 'operation_in_flight');
    for (const [minted, reservation] of [[first, firstReservation], [second, secondReservation]]) {
        assert.equal((await store.beginProviderEntry({
            capabilityId: minted.capabilityReceipt.capability.id,
            operationId: 'shared-postgres-operation',
            reservationToken: reservation.reservation_token,
            now: NOW,
        })).ok, true);
        assert.equal((await store.commitSpend({
            capabilityId: minted.capabilityReceipt.capability.id,
            operationId: 'shared-postgres-operation',
            reservationToken: reservation.reservation_token,
            outcome: 'indeterminate',
            now: NOW,
        })).ok, true);
    }
    const firstEvidence = `sha256:${'3'.repeat(64)}`;
    const secondEvidence = `sha256:${'4'.repeat(64)}`;
    for (const [minted, evidenceDigest] of [[first, firstEvidence], [second, secondEvidence]]) {
        assert.equal((await store.reconcileSpend({
            capabilityId: minted.capabilityReceipt.capability.id,
            operationId: 'shared-postgres-operation',
            actionDigest: capabilityActionDigest(scopedAction('shared-postgres-operation')),
            evidenceDigest,
            outcome: 'executed',
            now: NOW + 1,
        })).ok, true);
    }
    assert.equal(operations.get(operationKey(first.capabilityReceipt.capability.id, 'shared-postgres-operation')).reconciliation_evidence_digest, firstEvidence);
    assert.equal(operations.get(operationKey(second.capabilityReceipt.capability.id, 'shared-postgres-operation')).reconciliation_evidence_digest, secondEvidence);
    const abandoned = await store.reserveSpend({
        capabilityId: first.capabilityReceipt.capability.id,
        capabilityFingerprint: states.get(first.capabilityReceipt.capability.id).capability_fingerprint,
        operationId: 'postgres-abandoned-before-entry',
        actionDigest: capabilityActionDigest(scopedAction('postgres-abandoned-before-entry')),
        amount: 5,
        currency: 'USD',
        now: NOW,
    });
    assert.equal(abandoned.ok, true);
    assert.deepEqual(await store.recoverPreEntrySpend({
        capabilityId: first.capabilityReceipt.capability.id,
        operationId: 'postgres-abandoned-before-entry',
        actionDigest: capabilityActionDigest(scopedAction('postgres-abandoned-before-entry')),
        now: NOW + 999,
    }), { ok: false, reason: 'capability_recovery_deadline_active' });
    assert.equal((await store.recoverPreEntrySpend({
        capabilityId: first.capabilityReceipt.capability.id,
        operationId: 'postgres-abandoned-before-entry',
        actionDigest: capabilityActionDigest(scopedAction('postgres-abandoned-before-entry')),
        now: NOW + 1_000,
    })).ok, true);
    assert.equal(operations.get(operationKey(first.capabilityReceipt.capability.id, 'postgres-abandoned-before-entry')).status, 'released');
});
test('postgres reservation refuses a stale allowance head under the status row lock', async () => {
    const profileId = 'tenant:postgres/allowance:postgres';
    const allowanceDigest = `sha256:${'a'.repeat(64)}`;
    const activeHead = `sha256:${'b'.repeat(64)}`;
    const revokedHead = `sha256:${'c'.repeat(64)}`;
    const state = {
        capability_id: 'postgres_allowance_capability',
        capability_fingerprint: `sha256:${'d'.repeat(64)}`,
        budget_amount: '10',
        currency: 'USD',
        consumed_amount: '0',
        reserved_amount: '0',
        expires_at: new Date(NOW + 60_000).toISOString(),
        allowance_profile_id: profileId,
        allowance_digest: allowanceDigest,
        semantic_fence_ready: true,
        revocation_mode: 'direct',
        parent_capability_id: null,
        revoked_at: null,
        revocation_state_ready: true,
    };
    let status = null;
    const transaction = async (callback) => callback(async (sql, params) => {
        if (sql === CAPABILITY_SQL.readAllowanceStatus) {
            return { rowCount: status ? 1 : 0, rows: status ? [status] : [] };
        }
        if (sql === CAPABILITY_SQL.insertAllowanceStatus) {
            if (!status) {
                status = {
                    allowance_profile_id: params[0],
                    allowance_digest: params[1],
                    revision: String(params[2]),
                    status_epoch: String(params[3]),
                    status_head_digest: params[4],
                    status: params[5],
                };
            }
            return { rowCount: 1, rows: [] };
        }
        if (sql === CAPABILITY_SQL.updateAllowanceStatus) {
            if (!status || Number(status.status_epoch) !== params[1]
                || status.status_head_digest !== params[2])
                return { rowCount: 0, rows: [] };
            status = {
                allowance_profile_id: params[0],
                allowance_digest: params[3],
                revision: String(params[4]),
                status_epoch: String(params[5]),
                status_head_digest: params[6],
                status: params[7],
            };
            return { rowCount: 1, rows: [] };
        }
        if (sql === CAPABILITY_SQL.readState)
            return { rowCount: 1, rows: [state] };
        throw new Error(`unexpected SQL in allowance currentness test: ${sql}`);
    });
    const store = createPostgresCapabilityStore({ transaction });
    assert.equal((await store.advanceAllowanceStatus({
        allowance_profile_id: profileId,
        allowance_digest: allowanceDigest,
        revision: 1,
        status_epoch: 1,
        status_head_digest: activeHead,
        expected_status_epoch: null,
        expected_status_head_digest: null,
        status: 'active',
    })).ok, true);
    assert.equal((await store.advanceAllowanceStatus({
        allowance_profile_id: profileId,
        allowance_digest: allowanceDigest,
        revision: 1,
        status_epoch: 2,
        status_head_digest: revokedHead,
        expected_status_epoch: 1,
        expected_status_head_digest: activeHead,
        status: 'revoked',
    })).ok, true);
    const refused = await store.reserveSpend({
        capabilityId: state.capability_id,
        capabilityFingerprint: state.capability_fingerprint,
        operationNamespace: profileId,
        operationId: 'postgres-allowance-race',
        actionDigest: `sha256:${'e'.repeat(64)}`,
        amount: 1,
        currency: 'USD',
        allowanceStatus: {
            allowance_profile_id: profileId,
            allowance_digest: allowanceDigest,
            revision: 1,
            status_epoch: 1,
            status_head_digest: activeHead,
        },
        now: NOW,
    });
    assert.equal(refused.reason, 'allowance_revoked');
});
test('allowance suspension after reservation refuses provider entry and preserves the reservation', async () => {
    const keys = issuer();
    const profileId = 'tenant:memory/allowance:panic';
    const allowanceDigest = `sha256:${'1'.repeat(64)}`;
    const activeHead = `sha256:${'2'.repeat(64)}`;
    const suspendedHead = `sha256:${'3'.repeat(64)}`;
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'allowance_panic_capability',
        scope: {
            profile: CAPABILITY_ALLOWANCE_SCOPE_PROFILE,
            profile_id: profileId,
            profile_digest: allowanceDigest,
            operation_id_field: 'operation_id',
        },
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    assert.equal(store.advanceAllowanceStatus({
        allowance_profile_id: profileId,
        allowance_digest: allowanceDigest,
        revision: 1,
        status_epoch: 1,
        status_head_digest: activeHead,
        expected_status_epoch: null,
        expected_status_head_digest: null,
        status: 'active',
    }).ok, true);
    const capabilityId = minted.capabilityReceipt.capability.id;
    const reservation = await store.reserveSpend({
        capabilityId,
        capabilityFingerprint: store.getState(capabilityId).capability_fingerprint,
        operationNamespace: profileId,
        operationId: 'reserved-before-panic',
        actionDigest: `sha256:${'4'.repeat(64)}`,
        amount: 1,
        currency: 'USD',
        allowanceStatus: {
            allowance_profile_id: profileId,
            allowance_digest: allowanceDigest,
            revision: 1,
            status_epoch: 1,
            status_head_digest: activeHead,
        },
        now: NOW,
    });
    assert.equal(reservation.ok, true);
    assert.equal(store.advanceAllowanceStatus({
        allowance_profile_id: profileId,
        allowance_digest: allowanceDigest,
        revision: 1,
        status_epoch: 2,
        status_head_digest: suspendedHead,
        expected_status_epoch: 1,
        expected_status_head_digest: activeHead,
        status: 'suspended',
    }).ok, true);
    assert.deepEqual(await store.beginProviderEntry({
        capabilityId,
        operationNamespace: profileId,
        operationId: 'reserved-before-panic',
        reservationToken: reservation.reservation_token,
        now: NOW + 1,
    }), { ok: false, reason: 'allowance_suspended' });
    assert.equal(store.getOperation('reserved-before-panic', profileId).status, 'reserved');
    assert.equal(store.getState(capabilityId).reserved_amount, 1);
    assert.equal(store.getState(capabilityId).consumed_amount, 0);
});
test('postgres provider entry rechecks allowance currentness under the durable lock order', async () => {
    const profileId = 'tenant:postgres/allowance:panic';
    const allowanceDigest = `sha256:${'5'.repeat(64)}`;
    const activeHead = `sha256:${'6'.repeat(64)}`;
    const suspendedHead = `sha256:${'7'.repeat(64)}`;
    const reservationToken = 'reservation-token-1234';
    const state = {
        capability_id: 'postgres_allowance_panic_capability',
        allowance_profile_id: profileId,
        allowance_digest: allowanceDigest,
    };
    const status = {
        allowance_profile_id: profileId,
        allowance_digest: allowanceDigest,
        revision: '1',
        status_epoch: '2',
        status_head_digest: suspendedHead,
        status: 'suspended',
    };
    const operation = {
        operation_namespace: profileId,
        operation_id: 'postgres-reserved-before-panic',
        capability_id: state.capability_id,
        action_digest: `sha256:${'8'.repeat(64)}`,
        action_fence_digest: `sha256:${'8'.repeat(64)}`,
        amount: '1',
        currency: 'USD',
        reservation_token: reservationToken,
        status: 'reserved',
        entry_deadline_at: new Date(NOW + 60_000).toISOString(),
        allowance_revision: '1',
        allowance_status_epoch: '1',
        allowance_status_head_digest: activeHead,
    };
    const statements = [];
    const transaction = async (callback) => callback(async (sql) => {
        statements.push(sql);
        if (sql === CAPABILITY_SQL.readState)
            return { rowCount: 1, rows: [state] };
        if (sql === CAPABILITY_SQL.readAllowanceStatus)
            return { rowCount: 1, rows: [status] };
        if (sql === CAPABILITY_SQL.readOperation)
            return { rowCount: 1, rows: [operation] };
        if (sql === CAPABILITY_SQL.beginProviderEntry) {
            assert.fail('suspended allowance must refuse before provider entry');
        }
        throw new Error(`unexpected SQL in provider-entry currentness test: ${sql}`);
    });
    const store = createPostgresCapabilityStore({ transaction });
    assert.deepEqual(await store.beginProviderEntry({
        capabilityId: state.capability_id,
        operationNamespace: profileId,
        operationId: operation.operation_id,
        reservationToken,
        now: NOW + 1,
    }), { ok: false, reason: 'allowance_suspended' });
    assert.deepEqual(statements, [
        CAPABILITY_SQL.readState,
        CAPABILITY_SQL.readAllowanceStatus,
        CAPABILITY_SQL.readOperation,
    ]);
});
test('capability metadata is issuer-signed and tamper-evident', () => {
    const keys = issuer();
    const minted = mintCapabilityReceipt(keys.receipt, options({ issuerPrivateKey: keys.privateKey }));
    const trusted = keys.receipt.public_key;
    assert.equal(verifyCapabilityReceipt(minted.capabilityReceipt, { trustedIssuerKeys: [trusted] }).ok, true);
    assert.equal(verifyCapabilityReceipt(minted.capabilityReceipt).reason, 'capability_issuer_not_trusted');
    const tampered = structuredClone(minted.capabilityReceipt);
    tampered.capability.budget.amount = 1_000_000;
    assert.equal(verifyCapabilityReceipt(tampered, { trustedIssuerKeys: [trusted] }).ok, false);
    assert.equal(verifyCapabilityReceipt(minted.capabilityReceipt, { trustedIssuerKeys: ['wrong'] }).reason, 'capability_issuer_not_trusted');
});
test('capability issuer is separately pinned and signs the complete base-receipt digest', () => {
    const receiptIssuer = issuer();
    const capabilityIssuer = generateKeyPairSync('ed25519');
    const capabilityIssuerPublicKey = capabilityIssuer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const minted = mintCapabilityReceipt(receiptIssuer.receipt, options({
        issuerPrivateKey: capabilityIssuer.privateKey,
    }));
    assert.equal(verifyCapabilityReceipt(minted.capabilityReceipt, {
        trustedIssuerKeys: [capabilityIssuerPublicKey],
    }).ok, true);
    const substituted = structuredClone(minted.capabilityReceipt);
    substituted.receipt.payload.subject = 'attacker@example.test';
    assert.equal(verifyCapabilityReceipt(substituted, {
        trustedIssuerKeys: [capabilityIssuerPublicKey],
    }).reason, 'capability_signature_invalid');
});
test('capability scope is mandatory, signed, exact, and operation-bound', async () => {
    const keys = issuer();
    assert.throws(() => mintCapabilityReceipt(keys.receipt, {
        issuerPrivateKey: keys.privateKey,
        budget: { amount: 10, currency: 'USD' },
        expiry: NOW + 60_000,
        revocationMode: 'direct',
    }), /scope.profile/);
    const allowed = scopedAction('scope-op', { amount: 10, destination: 'acct_allowed' });
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        scope: {
            profile: CAPABILITY_SCOPE_PROFILE,
            operation_id_field: 'operation_id',
            action_digests: [capabilityActionDigest(allowed)],
        },
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    const common = {
        capabilityReceipt: minted.capabilityReceipt,
        secret: minted.secret,
        store,
        trustedIssuerKeys: [keys.receipt.public_key],
        verifyBaseReceipt: () => true,
        executeAction: async () => assert.fail('out-of-scope effect must not run'),
        now: NOW,
    };
    const substituted = await executeWithCapability({
        ...common,
        operationId: 'scope-op',
        action: { ...allowed, destination: 'acct_attacker' },
    });
    assert.equal(substituted.reason, 'capability_action_out_of_scope');
    const relabelled = await executeWithCapability({
        ...common,
        operationId: 'scope-op-attacker',
        action: allowed,
    });
    assert.equal(relabelled.reason, 'capability_operation_binding_failed');
    assert.equal(store.getState(minted.capabilityReceipt.capability.id).consumed_amount, 0);
});
test('allowance profile scope is closed, callback-verified, and operation-bound', async () => {
    const keys = issuer();
    const action = scopedAction('allowance-op', {
        amount: 10,
        action_type: 'stripe.payout.create',
        destination: 'acct_allowed',
    });
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        scope: {
            profile: CAPABILITY_ALLOWANCE_SCOPE_PROFILE,
            profile_id: 'allowance:stripe-payout:01',
            profile_digest: `sha256:${'a'.repeat(64)}`,
            operation_id_field: 'operation_id',
        },
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    const common = {
        capabilityReceipt: minted.capabilityReceipt,
        secret: minted.secret,
        action,
        operationId: action.operation_id,
        store,
        trustedIssuerKeys: [keys.receipt.public_key],
        verifyBaseReceipt: () => true,
        allowanceStatus: {
            allowance_profile_id: 'allowance:stripe-payout:01',
            allowance_digest: `sha256:${'a'.repeat(64)}`,
            revision: 1,
            status_epoch: 1,
            status_head_digest: `sha256:${'b'.repeat(64)}`,
        },
        executeAction: async () => ({ id: 'po_1' }),
        now: NOW,
    };
    assert.equal((await executeWithCapability({
        ...common,
        verifyActionProfile: () => ({
            ok: true,
            action_fence_digest: capabilityActionDigest({
                action_type: action.action_type,
                amount: action.amount,
                currency: action.currency,
                destination: action.destination,
            }),
        }),
    })).reason, 'allowance_status_not_initialized');
    assert.equal(store.advanceAllowanceStatus({
        allowance_profile_id: 'allowance:stripe-payout:01',
        allowance_digest: `sha256:${'a'.repeat(64)}`,
        revision: 1,
        status_epoch: 1,
        status_head_digest: `sha256:${'b'.repeat(64)}`,
        expected_status_epoch: null,
        expected_status_head_digest: null,
        status: 'active',
    }).ok, true);
    assert.equal((await executeWithCapability(common)).reason, 'capability_action_profile_verifier_required');
    assert.equal((await executeWithCapability({
        ...common,
        verifyActionProfile: () => ({ ok: false, reason: 'target_not_allowed' }),
    })).reason, 'target_not_allowed');
    const accepted = await executeWithCapability({
        ...common,
        verifyActionProfile: (_candidate, profile) => ({
            ok: profile.profile_id === 'allowance:stripe-payout:01'
                && profile.profile_digest === `sha256:${'a'.repeat(64)}`,
            action_fence_digest: capabilityActionDigest({
                action_type: action.action_type,
                amount: action.amount,
                currency: action.currency,
                destination: action.destination,
            }),
        }),
    });
    assert.equal(accepted.ok, true);
    assert.throws(() => mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        scope: {
            profile: CAPABILITY_ALLOWANCE_SCOPE_PROFILE,
            profile_id: 'allowance:stripe-payout:01',
            profile_digest: `sha256:${'a'.repeat(64)}`,
            operation_id_field: 'operation_id',
            ignored_constraint: true,
        },
    })), /scope is not closed/);
});
test('capability executes the exact immutable action that passed scope verification', async () => {
    const keys = issuer();
    const authorizedAction = scopedAction('exact-action-op', {
        amount: 10,
        destination: 'acct_authorized',
        material: { invoice_id: 'invoice_1' },
    });
    const unverifiedAction = {
        ...authorizedAction,
        destination: 'acct_attacker',
        material: { invoice_id: 'invoice_attacker' },
    };
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        scope: {
            profile: CAPABILITY_SCOPE_PROFILE,
            operation_id_field: 'operation_id',
            action_digests: [capabilityActionDigest(authorizedAction)],
        },
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    let verifierContext;
    let executedAction;
    const result = await executeWithCapability({
        capabilityReceipt: minted.capabilityReceipt,
        secret: minted.secret,
        action: unverifiedAction,
        observedAction: authorizedAction,
        operationId: authorizedAction.operation_id,
        store,
        trustedIssuerKeys: [keys.receipt.public_key],
        verifyBaseReceipt: (_receipt, context) => {
            verifierContext = context;
            assert.equal(Object.isFrozen(context.action), true);
            assert.equal(Object.isFrozen(context.action.material), true);
            return true;
        },
        executeAction: async (action) => {
            executedAction = action;
            return 'settled';
        },
        now: NOW,
    });
    assert.equal(result.ok, true);
    assert.equal(result.result, 'settled');
    assert.deepEqual(verifierContext.action, authorizedAction);
    assert.deepEqual(verifierContext.observedAction, authorizedAction);
    assert.deepEqual(executedAction, authorizedAction);
    assert.notDeepEqual(executedAction, unverifiedAction);
    assert.equal(store.getOperation(authorizedAction.operation_id).action_digest, capabilityActionDigest(authorizedAction));
    assert.equal(store.getOperation(authorizedAction.operation_id).amount, authorizedAction.amount);
    assert.equal(store.getState(minted.capabilityReceipt.capability.id).consumed_amount, authorizedAction.amount);
});
test('capability refuses an understated budget projection before execution', async () => {
    const keys = issuer();
    const authorizedAction = scopedAction('budget-binding-op', {
        amount: 10,
        destination: 'acct_authorized',
    });
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        scope: {
            profile: CAPABILITY_SCOPE_PROFILE,
            operation_id_field: 'operation_id',
            action_digests: [capabilityActionDigest(authorizedAction)],
        },
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    let effects = 0;
    const result = await executeWithCapability({
        capabilityReceipt: minted.capabilityReceipt,
        secret: minted.secret,
        action: { ...authorizedAction, amount: 1 },
        observedAction: authorizedAction,
        operationId: authorizedAction.operation_id,
        store,
        trustedIssuerKeys: [keys.receipt.public_key],
        verifyBaseReceipt: () => true,
        executeAction: async () => {
            effects += 1;
        },
        now: NOW,
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'capability budget projection does not match the verified action');
    assert.equal(effects, 0);
    assert.equal(store.getOperation(authorizedAction.operation_id), null);
    assert.equal(store.getState(minted.capabilityReceipt.capability.id).consumed_amount, 0);
});
test('CAID scope requires a pinned resolver and matches only an allowed CAID', async () => {
    const keys = issuer();
    const action = {
        action_type: 'science.bio.experiment.execute.1',
        operation_id: 'caid-op',
        amount: 5,
        currency: 'USD',
    };
    const caid = 'caid:1:science.bio.experiment.execute.1:jcs-sha256:AdzQBitumEFF9QO6nJ9YOexgCtOcHILorM5joy0-HzY';
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        scope: {
            profile: CAPABILITY_CAID_SCOPE_PROFILE,
            operation_id_field: 'operation_id',
            caids: [caid],
        },
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    const common = {
        capabilityReceipt: minted.capabilityReceipt,
        secret: minted.secret,
        action,
        operationId: 'caid-op',
        store,
        trustedIssuerKeys: [keys.receipt.public_key],
        verifyBaseReceipt: () => true,
        executeAction: async (_action, context) => context.caid,
        now: NOW,
    };
    assert.equal((await executeWithCapability(common)).reason, 'capability_caid_resolver_required');
    const result = await executeWithCapability({ ...common, resolveCaid: () => caid });
    assert.equal(result.ok, true);
    assert.equal(result.caid, caid);
    assert.equal(result.result, caid);
});
test('CAID-equivalent wrappers keep exact digests but share one runtime fence', async () => {
    const keys = issuer();
    const caid = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
    const firstAction = scopedAction('wrapper-a', {
        amount: 5,
        action_type: 'payment.release',
        destination: 'acct_material',
    });
    const secondAction = { ...firstAction, operation_id: 'wrapper-b' };
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'caid_action_fence',
        scope: {
            profile: CAPABILITY_CAID_SCOPE_PROFILE,
            operation_id_field: 'operation_id',
            caids: [caid],
        },
    }));
    const firstScope = verifyCapabilityScope(minted.capabilityReceipt.capability, firstAction, firstAction.operation_id, { resolveCaid: () => caid });
    const secondScope = verifyCapabilityScope(minted.capabilityReceipt.capability, secondAction, secondAction.operation_id, { resolveCaid: () => caid });
    assert.equal(firstScope.ok, true);
    assert.equal(secondScope.ok, true);
    assert.notEqual(firstScope.action_digest, secondScope.action_digest);
    assert.equal(firstScope.action_digest, capabilityActionDigest(firstAction));
    assert.equal(secondScope.action_digest, capabilityActionDigest(secondAction));
    assert.equal(firstScope.action_fence_digest, secondScope.action_fence_digest);
    assert.notEqual(firstScope.action_fence_digest, firstScope.action_digest);
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    const executions = [];
    const execute = (action) => executeWithCapability({
        capabilityReceipt: minted.capabilityReceipt,
        secret: minted.secret,
        action,
        operationId: action.operation_id,
        store,
        trustedIssuerKeys: [keys.receipt.public_key],
        resolveCaid: () => caid,
        verifyBaseReceipt: () => true,
        executeAction: async (_verifiedAction, context) => {
            executions.push(action.operation_id);
            return context.action_fence_digest;
        },
        now: NOW,
    });
    const first = await execute(firstAction);
    const duplicate = await execute(secondAction);
    assert.equal(first.ok, true);
    assert.equal(first.action_digest, capabilityActionDigest(firstAction));
    assert.equal(first.action_fence_digest, firstScope.action_fence_digest);
    assert.equal(duplicate.ok, false);
    assert.equal(duplicate.reason, 'action_already_committed');
    assert.equal(duplicate.action_digest, capabilityActionDigest(secondAction));
    assert.equal(duplicate.action_fence_digest, firstScope.action_fence_digest);
    assert.equal(duplicate.holding_operation_id, firstAction.operation_id);
    assert.deepEqual(executions, [firstAction.operation_id]);
    assert.equal(store.getOperation(firstAction.operation_id).action_digest, capabilityActionDigest(firstAction));
    assert.equal(store.getOperation(firstAction.operation_id).action_fence_digest, firstScope.action_fence_digest);
});
test('materially different CAIDs derive distinct runtime fences', async () => {
    const keys = issuer();
    const caidA = `caid:1:payment.release.1:jcs-sha256:${'B'.repeat(43)}`;
    const caidB = `caid:1:payment.release.1:jcs-sha256:${'C'.repeat(43)}`;
    const actions = [
        scopedAction('material-a', { amount: 5, destination: 'acct_a' }),
        scopedAction('material-b', { amount: 5, destination: 'acct_b' }),
    ];
    const resolveCaid = (action) => action.destination === 'acct_a' ? caidA : caidB;
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'caid_distinct_fences',
        scope: {
            profile: CAPABILITY_CAID_SCOPE_PROFILE,
            operation_id_field: 'operation_id',
            caids: [caidA, caidB],
        },
    }));
    const scopes = actions.map((action) => verifyCapabilityScope(minted.capabilityReceipt.capability, action, action.operation_id, { resolveCaid }));
    assert.equal(scopes.every((scope) => scope.ok), true);
    assert.notEqual(scopes[0].action_fence_digest, scopes[1].action_fence_digest);
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    const results = [];
    for (const action of actions) {
        results.push(await executeWithCapability({
            capabilityReceipt: minted.capabilityReceipt,
            secret: minted.secret,
            action,
            operationId: action.operation_id,
            store,
            trustedIssuerKeys: [keys.receipt.public_key],
            resolveCaid,
            verifyBaseReceipt: () => true,
            executeAction: async () => action.destination,
            now: NOW,
        }));
    }
    assert.equal(results.every((result) => result.ok), true);
    assert.notEqual(results[0].action_fence_digest, results[1].action_fence_digest);
});
test('allowance profile fences require a validated verifier digest', () => {
    const action = scopedAction('allowance-fence', { destination: 'acct_allowed' });
    const capability = {
        scope: {
            profile: CAPABILITY_ALLOWANCE_SCOPE_PROFILE,
            profile_id: 'allowance:profile-fence:01',
            profile_digest: `sha256:${'d'.repeat(64)}`,
            operation_id_field: 'operation_id',
        },
    };
    const exactDigest = capabilityActionDigest(action);
    const verifierFenceDigest = `sha256:${'e'.repeat(64)}`;
    const booleanOnly = verifyCapabilityScope(capability, action, action.operation_id, {
        verifyActionProfile: () => true,
    });
    assert.equal(booleanOnly.ok, false);
    assert.equal(booleanOnly.reason, 'capability_action_fence_digest_required');
    assert.equal(booleanOnly.action_digest, exactDigest);
    const objectOnly = verifyCapabilityScope(capability, action, action.operation_id, {
        verifyActionProfile: () => ({ ok: true }),
    });
    assert.equal(objectOnly.ok, false);
    assert.equal(objectOnly.reason, 'capability_action_fence_digest_required');
    assert.equal(objectOnly.action_digest, exactDigest);
    const supplied = verifyCapabilityScope(capability, action, action.operation_id, {
        verifyActionProfile: () => ({ ok: true, action_fence_digest: verifierFenceDigest }),
    });
    assert.equal(supplied.ok, true);
    assert.equal(supplied.action_digest, exactDigest);
    assert.equal(supplied.action_fence_digest, verifierFenceDigest);
    const malformed = verifyCapabilityScope(capability, action, action.operation_id, {
        verifyActionProfile: () => ({ ok: true, action_fence_digest: 'not-a-digest' }),
    });
    assert.equal(malformed.ok, false);
    assert.equal(malformed.reason, 'capability_action_fence_digest_invalid');
    assert.equal(malformed.action_digest, exactDigest);
});
test('atomic capability spending enforces the budget and consumes indeterminate effects', async () => {
    const keys = issuer();
    const minted = mintCapabilityReceipt(keys.receipt, options({ issuerPrivateKey: keys.privateKey }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    const common = {
        capabilityReceipt: minted.capabilityReceipt,
        secret: minted.secret,
        store,
        trustedIssuerKeys: [keys.receipt.public_key],
        verifyBaseReceipt: () => true,
        now: NOW,
    };
    const first = await executeWithCapability({
        ...common,
        operationId: 'op_1',
        action: scopedAction('op_1', { amount: 30, destination: 'acct_a' }),
        executeAction: async () => 'settled',
    });
    assert.equal(first.ok, true);
    assert.equal(first.result, 'settled');
    assert.equal(store.getOperation('op_1').action_digest, capabilityActionDigest(scopedAction('op_1', { amount: 30, destination: 'acct_a' })));
    assert.equal(store.getState(minted.capabilityReceipt.capability.id).consumed_amount, 30);
    const [left, right] = await Promise.all([
        executeWithCapability({ ...common, operationId: 'op_2', action: scopedAction('op_2', { amount: 60 }), executeAction: async () => 'left' }),
        executeWithCapability({ ...common, operationId: 'op_3', action: scopedAction('op_3', { amount: 60 }), executeAction: async () => 'right' }),
    ]);
    assert.equal([left.ok, right.ok].filter(Boolean).length, 1);
    assert.equal(store.getState(minted.capabilityReceipt.capability.id).consumed_amount, 90);
    const indeterminate = await executeWithCapability({
        ...common,
        operationId: 'op_4',
        action: scopedAction('op_4', { amount: 10 }),
        executeAction: async () => { throw new Error('provider response lost'); },
    });
    assert.equal(indeterminate.ok, false);
    assert.equal(indeterminate.reason, 'effect_indeterminate');
    assert.equal(store.getState(minted.capabilityReceipt.capability.id).consumed_amount, 100);
    const evidenceDigest = `sha256:${'a'.repeat(64)}`;
    const reconcile = () => reconcileCapabilityOperation({
        store,
        capabilityId: minted.capabilityReceipt.capability.id,
        operationId: 'op_4',
        action: scopedAction('op_4', { amount: 10 }),
        evidence: { provider: 'test' },
        now: NOW + 1,
        verifyEvidence: (_evidence, context) => ({
            valid: true,
            outcome: 'executed',
            action_digest: context.action_digest,
            evidence_digest: evidenceDigest,
        }),
    });
    assert.deepEqual(await reconcile(), {
        ok: true,
        outcome: 'executed',
        action_digest: capabilityActionDigest(scopedAction('op_4', { amount: 10 })),
        evidence_digest: evidenceDigest,
        idempotent: false,
    });
    assert.equal((await reconcile()).idempotent, true);
    assert.equal(store.getOperation('op_4').reconciliation_outcome, 'executed');
    assert.equal(store.getState(minted.capabilityReceipt.capability.id).consumed_amount, 100);
});
test('a crash after reserveSpend but before provider entry is recoverable only after its durable deadline', async () => {
    const keys = issuer();
    const minted = mintCapabilityReceipt(keys.receipt, options({ issuerPrivateKey: keys.privateKey }));
    const store = createMemoryCapabilityStore({ providerEntryTimeoutMs: 1_000 });
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    let effects = 0;
    const crashAfterReserve = {
        ...store,
        async reserveSpend(input) {
            const reserved = await store.reserveSpend(input);
            assert.equal(reserved.ok, true);
            throw new Error('simulated process crash after durable reserve');
        },
    };
    await assert.rejects(executeWithCapability({
        capabilityReceipt: minted.capabilityReceipt,
        secret: minted.secret,
        action: scopedAction('crash_before_provider_entry', { amount: 10 }),
        operationId: 'crash_before_provider_entry',
        store: crashAfterReserve,
        trustedIssuerKeys: [keys.receipt.public_key],
        verifyBaseReceipt: () => true,
        executeAction: async () => { effects += 1; },
        now: NOW,
    }), /simulated process crash/);
    const actionDigest = capabilityActionDigest(scopedAction('crash_before_provider_entry', { amount: 10 }));
    const operation = store.getOperation('crash_before_provider_entry', minted.capabilityReceipt.capability.id);
    assert.equal(effects, 0);
    assert.equal(operation.status, 'reserved');
    assert.equal(operation.entry_deadline_at, NOW + 1_000);
    assert.equal(store.getState(minted.capabilityReceipt.capability.id).reserved_amount, 10);
    assert.deepEqual(await store.recoverPreEntrySpend({
        capabilityId: minted.capabilityReceipt.capability.id,
        operationId: 'crash_before_provider_entry',
        actionDigest,
        now: NOW + 999,
    }), { ok: false, reason: 'capability_recovery_deadline_active' });
    const recovered = await store.recoverPreEntrySpend({
        capabilityId: minted.capabilityReceipt.capability.id,
        operationId: 'crash_before_provider_entry',
        actionDigest,
        now: NOW + 1_000,
    });
    assert.deepEqual(recovered, { ok: true, outcome: 'not_entered', released: 10, remaining: 100 });
    assert.equal(store.getState(minted.capabilityReceipt.capability.id).reserved_amount, 0);
    assert.equal(store.getState(minted.capabilityReceipt.capability.id).consumed_amount, 0);
    assert.equal(store.getOperation('crash_before_provider_entry').status, 'released');
    const blindRetry = await executeWithCapability({
        capabilityReceipt: minted.capabilityReceipt,
        secret: minted.secret,
        action: scopedAction('crash_before_provider_entry', { amount: 10 }),
        operationId: 'crash_before_provider_entry',
        store,
        trustedIssuerKeys: [keys.receipt.public_key],
        verifyBaseReceipt: () => true,
        executeAction: async () => { effects += 1; },
        now: NOW + 1_001,
    });
    assert.equal(blindRetry.reason, 'operation_already_finalized');
    assert.equal(effects, 0);
});
test('an unknown provider-entry disposition fails closed and holds the reservation', async () => {
    const keys = issuer();
    const action = scopedAction('unknown_guard_disposition', { amount: 10 });
    const minted = mintCapabilityReceipt(keys.receipt, options({ issuerPrivateKey: keys.privateKey }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    let effects = 0;
    const result = await executeWithCapability({
        capabilityReceipt: minted.capabilityReceipt,
        secret: minted.secret,
        action,
        operationId: action.operation_id,
        store,
        trustedIssuerKeys: [keys.receipt.public_key],
        verifyBaseReceipt: () => true,
        providerEntryGuard: async () => ({
            ok: false,
            reason: 'organization_suspended',
            reservation: 'restore',
        }),
        executeAction: async () => { effects += 1; },
        now: NOW,
    });
    assert.equal(result.reason, 'capability_provider_entry_disposition_invalid');
    assert.equal(effects, 0);
    assert.equal(store.getOperation(action.operation_id).status, 'reserved');
    assert.equal(store.getState(minted.capabilityReceipt.capability.id).consumed_amount, 0);
    assert.equal(store.getState(minted.capabilityReceipt.capability.id).reserved_amount, 10);
});
test('negative evidence must be final and fresh before it releases a still-reserved operation', async () => {
    const keys = issuer();
    const action = scopedAction('post_entry_negative_evidence', { amount: 10 });
    const actionDigest = capabilityActionDigest(action);
    const minted = mintCapabilityReceipt(keys.receipt, options({ issuerPrivateKey: keys.privateKey }));
    const store = createMemoryCapabilityStore({ providerEntryTimeoutMs: 1_000 });
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    const capabilityId = minted.capabilityReceipt.capability.id;
    const reserved = await store.reserveSpend({
        capabilityId,
        capabilityFingerprint: store.getState(capabilityId).capability_fingerprint,
        operationId: action.operation_id,
        actionDigest,
        amount: action.amount,
        currency: action.currency,
        now: NOW,
    });
    assert.equal(reserved.ok, true);
    const evidenceDigest = `sha256:${'b'.repeat(64)}`;
    const reconcile = (now, verifyEvidence) => reconcileCapabilityOperation({
        store,
        capabilityId,
        operationId: action.operation_id,
        action,
        evidence: { provider: 'test', operation_id: action.operation_id },
        verifyEvidence,
        now,
    });
    const unauthenticated = await reconcile(NOW + 1_000, (_evidence, context) => ({
        valid: true,
        outcome: 'not_entered',
        action_digest: context.action_digest,
        evidence_digest: evidenceDigest,
    }));
    assert.equal(unauthenticated.reason, 'capability_reconciliation_evidence_rejected');
    const verifiedNegative = (_evidence, context) => ({
        valid: true,
        authenticated: true,
        outcome: 'not_entered',
        capability_id: context.capability_id,
        operation_namespace: context.operation_namespace,
        operation_id: context.operation_id,
        action_digest: context.action_digest,
        evidence_profile: 'urn:test:provider-negative-entry:v1',
        evidence_digest: evidenceDigest,
        observed_at: new Date(NOW + 1_000).toISOString(),
    });
    assert.equal((await reconcile(NOW + 1_000, (_evidence, context) => ({
        ...verifiedNegative(_evidence, context),
        final: false,
    }))).reason, 'capability_reconciliation_evidence_rejected');
    assert.equal((await reconcile(NOW + 1_000, (_evidence, context) => ({
        ...verifiedNegative(_evidence, context),
        final: true,
        observed_at: new Date(NOW + 999).toISOString(),
    }))).reason, 'capability_reconciliation_evidence_stale');
    const released = await reconcile(NOW + 1_000, (_evidence, context) => ({
        ...verifiedNegative(_evidence, context),
        final: true,
    }));
    assert.deepEqual(released, {
        ok: true,
        outcome: 'not_entered',
        action_digest: actionDigest,
        evidence_digest: evidenceDigest,
        evidence_profile: 'urn:test:provider-negative-entry:v1',
        idempotent: false,
    });
    assert.equal(store.getOperation(action.operation_id).status, 'released');
    assert.equal(store.getOperation(action.operation_id).release_evidence_digest, evidenceDigest);
    assert.equal(store.getState(capabilityId).consumed_amount, 0);
    assert.equal(store.getState(capabilityId).reserved_amount, 0);
});
test('final negative evidence after provider entry records the outcome but never restores authority or budget', async () => {
    const keys = issuer();
    const action = scopedAction('post_entry_negative_evidence', { amount: 10 });
    const actionDigest = capabilityActionDigest(action);
    const minted = mintCapabilityReceipt(keys.receipt, options({ issuerPrivateKey: keys.privateKey }));
    const store = createMemoryCapabilityStore({ providerEntryTimeoutMs: 1_000 });
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    const capabilityId = minted.capabilityReceipt.capability.id;
    const reserved = await store.reserveSpend({
        capabilityId,
        capabilityFingerprint: store.getState(capabilityId).capability_fingerprint,
        operationId: action.operation_id,
        actionDigest,
        amount: action.amount,
        currency: action.currency,
        now: NOW,
    });
    assert.equal(reserved.ok, true);
    assert.equal((await store.beginProviderEntry({
        capabilityId,
        operationId: action.operation_id,
        reservationToken: reserved.reservation_token,
        now: NOW,
    })).ok, true);
    const evidenceDigest = `sha256:${'c'.repeat(64)}`;
    const reconciled = await reconcileCapabilityOperation({
        store,
        capabilityId,
        operationId: action.operation_id,
        action,
        evidence: { provider: 'test', operation_id: action.operation_id },
        now: NOW + 1_000,
        verifyEvidence: (_evidence, context) => ({
            valid: true,
            authenticated: true,
            final: true,
            outcome: 'not_entered',
            capability_id: context.capability_id,
            operation_namespace: context.operation_namespace,
            operation_id: context.operation_id,
            action_digest: context.action_digest,
            evidence_profile: 'urn:test:provider-negative-entry:v1',
            evidence_digest: evidenceDigest,
            observed_at: new Date(NOW + 1_000).toISOString(),
        }),
    });
    assert.deepEqual(reconciled, {
        ok: true,
        outcome: 'not_entered',
        action_digest: actionDigest,
        evidence_digest: evidenceDigest,
        evidence_profile: 'urn:test:provider-negative-entry:v1',
        idempotent: false,
    });
    const operation = store.getOperation(action.operation_id);
    assert.equal(operation.status, 'committed');
    assert.equal(operation.outcome, 'indeterminate');
    assert.equal(operation.reconciliation_outcome, 'not_entered');
    assert.equal(store.getState(capabilityId).consumed_amount, 10);
    assert.equal(store.getState(capabilityId).reserved_amount, 0);
    const lateCommit = await store.commitSpend({
        capabilityId,
        operationId: action.operation_id,
        reservationToken: reserved.reservation_token,
        outcome: 'executed',
        now: NOW + 1_001,
    });
    assert.equal(lateCommit.reason, 'capability_operation_already_finalized');
    assert.equal(store.getState(capabilityId).consumed_amount, 10);
    const crossRouteReplay = await store.reserveSpend({
        capabilityId,
        capabilityFingerprint: store.getState(capabilityId).capability_fingerprint,
        operationNamespace: capabilityId,
        operationId: 'alternate-route-operation',
        actionDigest,
        amount: action.amount,
        currency: action.currency,
        now: NOW + 1_001,
    });
    assert.equal(crossRouteReplay.reason, 'action_already_committed');
    const blindRetry = await executeWithCapability({
        capabilityReceipt: minted.capabilityReceipt,
        secret: minted.secret,
        action,
        operationId: action.operation_id,
        store,
        trustedIssuerKeys: [keys.receipt.public_key],
        verifyBaseReceipt: () => true,
        executeAction: async () => assert.fail('consumed operation must remain replay-fenced'),
        now: NOW + 1_001,
    });
    assert.equal(blindRetry.reason, 'operation_already_committed');
});
test('capability refuses invalid secret, currency, and unverified base authority', async () => {
    const keys = issuer();
    const minted = mintCapabilityReceipt(keys.receipt, options({ issuerPrivateKey: keys.privateKey }));
    const store = createMemoryCapabilityStore();
    store.registerCapability(minted.capabilityReceipt);
    const common = {
        capabilityReceipt: minted.capabilityReceipt,
        store,
        trustedIssuerKeys: [keys.receipt.public_key],
        verifyBaseReceipt: () => true,
        now: NOW,
        operationId: 'bad_1',
        executeAction: async () => assert.fail('effect must not run'),
    };
    assert.equal((await executeWithCapability({ ...common, secret: Buffer.alloc(32), action: scopedAction('bad_1') })).reason, 'invalid_secret');
    assert.equal((await executeWithCapability({ ...common, secret: minted.secret, action: scopedAction('bad_1', { currency: 'EUR' }) })).reason, 'capability action currency does not match the budget');
    assert.equal((await executeWithCapability({ ...common, secret: minted.secret, verifyBaseReceipt: () => false, action: scopedAction('bad_1') })).reason, 'base_receipt_rejected');
    assert.equal((await executeWithCapability({
        ...common,
        secret: minted.secret,
        operationId: null,
        action: scopedAction('bad_1'),
    })).reason, 'capability_operation_id_required');
});
test('threshold capability uses unique Shamir shares and requires m-of-n', async () => {
    const secret = Buffer.alloc(32, 7);
    const shares = splitCapabilitySecret(secret, { m: 2, n: 3 }, { randomBytesFn: () => Buffer.alloc(66, 9) });
    assert.equal(Buffer.compare(reconstructCapabilitySecret(shares.slice(0, 2), { m: 2, n: 3 }), secret), 0);
    assert.throws(() => reconstructCapabilitySecret([shares[0]], { m: 2, n: 3 }), /insufficient/);
    assert.throws(() => reconstructCapabilitySecret([shares[0], shares[0]], { m: 2, n: 3 }), /duplicate/);
    const keys = issuer();
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        threshold: { m: 2, n: 3 },
        secret,
        capabilityId: 'threshold_1',
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    const result = await executeWithThreshold({
        capabilityReceipt: minted.capabilityReceipt,
        shares: minted.shares.slice(0, 2),
        action: scopedAction('threshold_op_1', { amount: 25 }),
        store,
        trustedIssuerKeys: [keys.receipt.public_key],
        verifyBaseReceipt: () => true,
        now: NOW,
        operationId: 'threshold_op_1',
        executeAction: async () => 'threshold-settled',
    });
    assert.equal(result.ok, true);
    assert.equal(result.result, 'threshold-settled');
});
test('delegation burns parent budget before registering a spendable child', async () => {
    const keys = issuer();
    const parent = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'parent_1',
        secret: Buffer.alloc(32, 8),
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(parent.capabilityReceipt), true);
    const child = await delegateCapabilityReceipt({
        parentCapabilityReceipt: parent.capabilityReceipt,
        parentSecret: parent.secret,
        issuerPrivateKey: keys.privateKey,
        trustedIssuerKeys: [keys.receipt.public_key],
        budget: { amount: 40, currency: 'USD' },
        expiry: NOW + 30_000,
        revocationMode: 'direct',
        delegateId: 'pilot-operator',
        capabilityId: 'child_1',
        secret: Buffer.alloc(32, 9),
        store,
        now: NOW,
    });
    assert.equal(child.ok, true);
    assert.equal(child.capabilityReceipt.capability.delegation_chain.at(-1).parent_capability_id, 'parent_1');
    assert.equal(store.getState('parent_1').consumed_amount, 40);
    assert.equal(store.getState('child_1').budget_amount, 40);
    const tooLarge = await delegateCapabilityReceipt({
        parentCapabilityReceipt: parent.capabilityReceipt,
        parentSecret: parent.secret,
        issuerPrivateKey: keys.privateKey,
        trustedIssuerKeys: [keys.receipt.public_key],
        budget: { amount: 61, currency: 'USD' },
        expiry: NOW + 30_000,
        revocationMode: 'direct',
        delegateId: 'pilot-operator',
        capabilityId: 'child_2',
        store,
        now: NOW,
    });
    assert.equal(tooLarge.ok, false);
    assert.equal(tooLarge.reason, 'budget_exceeded');
    assert.equal(store.getState('parent_1').consumed_amount, 40);
});
test('concurrent N-sibling delegation transfers rather than copies parent authority', async () => {
    const keys = issuer();
    const parent = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'fanout_parent',
        secret: Buffer.alloc(32, 31),
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(parent.capabilityReceipt), true);
    const results = await Promise.all([1, 2, 3].map((index) => delegateCapabilityReceipt({
        parentCapabilityReceipt: parent.capabilityReceipt,
        parentSecret: parent.secret,
        issuerPrivateKey: keys.privateKey,
        trustedIssuerKeys: [keys.receipt.public_key],
        budget: { amount: 40, currency: 'USD' },
        expiry: NOW + 30_000,
        revocationMode: 'direct',
        delegateId: `fanout-operator-${index}`,
        capabilityId: `fanout_child_${index}`,
        operationId: `fanout_operation_${index}`,
        secret: Buffer.alloc(32, 31 + index),
        store,
        now: NOW,
    })));
    assert.equal(results.filter((result) => result.ok).length, 2);
    assert.equal(results.filter((result) => !result.ok && result.reason === 'budget_exceeded').length, 1);
    assert.equal(store.getState('fanout_parent').consumed_amount, 80);
    assert.equal([1, 2, 3].filter((index) => store.getState(`fanout_child_${index}`) !== null).length, 2);
});
test('one delegation operation identifier funds only one child digest', async () => {
    const keys = issuer();
    const parent = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'injective_parent',
        secret: Buffer.alloc(32, 41),
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(parent.capabilityReceipt), true);
    const results = await Promise.all(['a', 'b'].map((suffix, index) => delegateCapabilityReceipt({
        parentCapabilityReceipt: parent.capabilityReceipt,
        parentSecret: parent.secret,
        issuerPrivateKey: keys.privateKey,
        trustedIssuerKeys: [keys.receipt.public_key],
        budget: { amount: 30, currency: 'USD' },
        expiry: NOW + 30_000,
        revocationMode: 'direct',
        delegateId: `injective-operator-${suffix}`,
        capabilityId: `injective_child_${suffix}`,
        operationId: 'injective_operation',
        secret: Buffer.alloc(32, 42 + index),
        store,
        now: NOW,
    })));
    assert.equal(results.filter((result) => result.ok).length, 1);
    assert.equal(results.filter((result) => (!result.ok && ['operation_in_flight', 'operation_already_committed'].includes(result.reason))).length, 1);
    assert.equal(store.getState('injective_parent').consumed_amount, 30);
    assert.equal(['a', 'b'].filter((suffix) => store.getState(`injective_child_${suffix}`) !== null).length, 1);
});
test('a failed child registration remains a funded orphan and never refunds the parent', async () => {
    const keys = issuer();
    const parent = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'orphan_parent',
        secret: Buffer.alloc(32, 45),
    }));
    const conflicting = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'orphan_child',
        secret: Buffer.alloc(32, 46),
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(parent.capabilityReceipt), true);
    assert.equal(store.registerCapability(conflicting.capabilityReceipt), true);
    const result = await delegateCapabilityReceipt({
        parentCapabilityReceipt: parent.capabilityReceipt,
        parentSecret: parent.secret,
        issuerPrivateKey: keys.privateKey,
        trustedIssuerKeys: [keys.receipt.public_key],
        budget: { amount: 25, currency: 'USD' },
        expiry: NOW + 30_000,
        revocationMode: 'direct',
        delegateId: 'orphan-operator',
        capabilityId: 'orphan_child',
        operationId: 'orphan_operation',
        secret: Buffer.alloc(32, 47),
        store,
        now: NOW,
    });
    assert.deepEqual(result, {
        ok: false,
        reason: 'child_registration_failed',
        operation_id: 'orphan_operation',
    });
    assert.equal(store.getState('orphan_parent').consumed_amount, 25);
    assert.equal(store.getOperation('orphan_operation').outcome, 'delegated');
    assert.equal(store.getState('orphan_child').budget_amount, 100);
});
test('separate authority stores demonstrate the explicit cross-domain non-guarantee', async () => {
    const keys = issuer();
    const parent = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'fork_parent',
        secret: Buffer.alloc(32, 48),
    }));
    const stores = [createMemoryCapabilityStore(), createMemoryCapabilityStore()];
    for (const store of stores)
        assert.equal(store.registerCapability(parent.capabilityReceipt), true);
    const results = await Promise.all(stores.map((store, index) => delegateCapabilityReceipt({
        parentCapabilityReceipt: parent.capabilityReceipt,
        parentSecret: parent.secret,
        issuerPrivateKey: keys.privateKey,
        trustedIssuerKeys: [keys.receipt.public_key],
        budget: { amount: 60, currency: 'USD' },
        expiry: NOW + 30_000,
        revocationMode: 'direct',
        delegateId: `fork-operator-${index}`,
        capabilityId: `fork_child_${index}`,
        operationId: `fork_operation_${index}`,
        secret: Buffer.alloc(32, 49 + index),
        store,
        now: NOW,
    })));
    assert.ok(results.every((result) => result.ok));
    assert.deepEqual(stores.map((store) => store.getState('fork_parent').consumed_amount), [60, 60]);
});
test('delegation cannot outlive its parent, including across multiple hops', async () => {
    const keys = issuer();
    const parent = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'temporal_parent',
        expiry: NOW + 30_000,
        secret: Buffer.alloc(32, 10),
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(parent.capabilityReceipt), true);
    const directOutlivesParent = await delegateCapabilityReceipt({
        parentCapabilityReceipt: parent.capabilityReceipt,
        parentSecret: parent.secret,
        issuerPrivateKey: keys.privateKey,
        trustedIssuerKeys: [keys.receipt.public_key],
        budget: { amount: 10, currency: 'USD' },
        expiry: NOW + 30_001,
        revocationMode: 'direct',
        delegateId: 'temporal-direct',
        capabilityId: 'temporal_child_invalid',
        store,
        now: NOW,
    });
    assert.equal(directOutlivesParent.ok, false);
    assert.equal(directOutlivesParent.reason, 'delegated_capability_expiry_exceeds_parent');
    assert.equal(store.getState('temporal_parent').consumed_amount, 0);
    const child = await delegateCapabilityReceipt({
        parentCapabilityReceipt: parent.capabilityReceipt,
        parentSecret: parent.secret,
        issuerPrivateKey: keys.privateKey,
        trustedIssuerKeys: [keys.receipt.public_key],
        budget: { amount: 10, currency: 'USD' },
        expiry: NOW + 20_000,
        revocationMode: 'direct',
        delegateId: 'temporal-child',
        capabilityId: 'temporal_child',
        secret: Buffer.alloc(32, 11),
        store,
        now: NOW,
    });
    assert.equal(child.ok, true);
    const grandchildOutlivesChild = await delegateCapabilityReceipt({
        parentCapabilityReceipt: child.capabilityReceipt,
        parentSecret: child.secret,
        issuerPrivateKey: keys.privateKey,
        trustedIssuerKeys: [keys.receipt.public_key],
        budget: { amount: 5, currency: 'USD' },
        expiry: NOW + 20_001,
        revocationMode: 'direct',
        delegateId: 'temporal-grandchild',
        capabilityId: 'temporal_grandchild_invalid',
        store,
        now: NOW,
    });
    assert.equal(grandchildOutlivesChild.ok, false);
    assert.equal(grandchildOutlivesChild.reason, 'delegated_capability_expiry_exceeds_parent');
    assert.equal(store.getState('temporal_child').consumed_amount, 0);
});
test('capability stores bind an id to the complete signed envelope', async () => {
    const keys = issuer();
    const first = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'envelope_collision',
        secret: Buffer.alloc(32, 12),
    }));
    const conflicting = mintCapabilityReceipt(baseReceipt({
        privateKey: keys.privateKey,
        publicKey: keys.publicKey,
        receiptId: 'base_2',
    }), options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'envelope_collision',
        secret: Buffer.alloc(32, 13),
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(first.capabilityReceipt), true);
    assert.equal(store.registerCapability(first.capabilityReceipt), true);
    assert.equal(store.registerCapability(conflicting.capabilityReceipt), false);
    const spend = await executeWithCapability({
        capabilityReceipt: conflicting.capabilityReceipt,
        secret: conflicting.secret,
        action: scopedAction('envelope_collision_spend'),
        store,
        trustedIssuerKeys: [keys.receipt.public_key],
        verifyBaseReceipt: () => true,
        operationId: 'envelope_collision_spend',
        now: NOW,
        executeAction: async () => assert.fail('conflicting envelope must not spend'),
    });
    assert.equal(spend.ok, false);
    assert.equal(spend.reason, 'capability_envelope_mismatch');
});
test('postgres capability state also rejects a conflicting envelope', async () => {
    const keys = issuer();
    const first = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'postgres_envelope_collision',
        secret: Buffer.alloc(32, 14),
    }));
    const conflicting = mintCapabilityReceipt(baseReceipt({
        privateKey: keys.privateKey,
        publicKey: keys.publicKey,
        receiptId: 'base_3',
    }), options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'postgres_envelope_collision',
        secret: Buffer.alloc(32, 15),
    }));
    let row = null;
    const transaction = async (callback) => callback(async (sql, params) => {
        if (sql === CAPABILITY_SQL.register) {
            if (!row) {
                row = {
                    capability_id: params[0],
                    capability_fingerprint: params[4],
                    budget_amount: String(params[1]),
                    currency: params[2],
                    consumed_amount: '0',
                    reserved_amount: '0',
                    expires_at: params[3],
                    semantic_fence_ready: true,
                    revocation_mode: params[7],
                    parent_capability_id: params[8],
                    revoked_at: null,
                    revocation_state_ready: true,
                };
            }
            return { rowCount: row.capability_fingerprint === params[4] ? 1 : 0 };
        }
        if (sql === CAPABILITY_SQL.readState)
            return { rows: row ? [row] : [] };
        throw new Error(`unexpected SQL in registration test: ${sql}`);
    });
    const store = createPostgresCapabilityStore({ transaction });
    assert.equal(await store.registerCapability(first.capabilityReceipt), true);
    assert.equal(await store.registerCapability(first.capabilityReceipt), true);
    assert.equal(await store.registerCapability(conflicting.capabilityReceipt), false);
});
const ISO = new Date(NOW - 500).toISOString();
function chainEntry({ delegation_id, parent, delegate = 'operator', amount, currency = 'USD' }) {
    return { delegation_id, parent_capability_id: parent, delegate_id: delegate, amount, currency, issued_at: ISO };
}
// Re-sign a mutated capability envelope with a trusted issuer key so the only
// thing standing between a forged chain and acceptance is the structural
// ingest check, not the signature.
function resignEnvelope(capabilityReceipt, privateKey) {
    const body = {
        '@version': CAPABILITY_RECEIPT_VERSION,
        base_receipt_id: capabilityReceipt.receipt.payload.receipt_id,
        base_receipt_digest: capabilityBaseReceiptDigest(capabilityReceipt.receipt),
        capability: capabilityReceipt.capability,
    };
    capabilityReceipt.capability_signature.value = sign(null, Buffer.from(canonicalize(body)), privateKey).toString('base64url');
    return capabilityReceipt;
}
async function threeHopLineage({ keys, prefix, rootRevocationMode, store = createMemoryCapabilityStore(), }) {
    const root = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: `${prefix}_root`,
        secret: Buffer.alloc(32, 70),
        revocationMode: rootRevocationMode,
    }));
    assert.equal(await store.registerCapability(root.capabilityReceipt), true);
    const child = await delegateCapabilityReceipt({
        parentCapabilityReceipt: root.capabilityReceipt,
        parentSecret: root.secret,
        issuerPrivateKey: keys.privateKey,
        trustedIssuerKeys: [keys.receipt.public_key],
        budget: { amount: 50, currency: 'USD' },
        expiry: NOW + 40_000,
        revocationMode: 'direct',
        delegateId: `${prefix}-child-holder`,
        capabilityId: `${prefix}_child`,
        operationId: `${prefix}_delegate_child`,
        secret: Buffer.alloc(32, 71),
        store,
        now: NOW,
    });
    assert.equal(child.ok, true);
    const grandchild = await delegateCapabilityReceipt({
        parentCapabilityReceipt: child.capabilityReceipt,
        parentSecret: child.secret,
        issuerPrivateKey: keys.privateKey,
        trustedIssuerKeys: [keys.receipt.public_key],
        budget: { amount: 20, currency: 'USD' },
        expiry: NOW + 30_000,
        revocationMode: 'direct',
        delegateId: `${prefix}-grandchild-holder`,
        capabilityId: `${prefix}_grandchild`,
        operationId: `${prefix}_delegate_grandchild`,
        secret: Buffer.alloc(32, 72),
        store,
        now: NOW,
    });
    assert.equal(grandchild.ok, true);
    return { store, root, child, grandchild };
}
test('direct revocation blocks the named capability but preserves previously registered descendants', async () => {
    const keys = issuer();
    const lineage = await threeHopLineage({
        keys,
        prefix: 'direct-revocation',
        rootRevocationMode: 'direct',
    });
    const rootId = lineage.root.capabilityReceipt.capability.id;
    const revoked = await lineage.store.revokeCapability({
        capabilityId: rootId,
        capabilityFingerprint: lineage.store.getState(rootId).capability_fingerprint,
        now: NOW + 1,
    });
    assert.equal(revoked.ok, true);
    const descendantAction = scopedAction('op_4', { amount: 10 });
    let effects = 0;
    const descendant = await executeWithCapability({
        capabilityReceipt: lineage.grandchild.capabilityReceipt,
        secret: lineage.grandchild.secret,
        action: descendantAction,
        operationId: descendantAction.operation_id,
        store: lineage.store,
        trustedIssuerKeys: [keys.receipt.public_key],
        verifyBaseReceipt: () => true,
        executeAction: async () => { effects += 1; return 'executed'; },
        now: NOW + 2,
    });
    assert.equal(descendant.ok, true);
    assert.equal(effects, 1);
    const newChild = await delegateCapabilityReceipt({
        parentCapabilityReceipt: lineage.root.capabilityReceipt,
        parentSecret: lineage.root.secret,
        issuerPrivateKey: keys.privateKey,
        trustedIssuerKeys: [keys.receipt.public_key],
        budget: { amount: 1, currency: 'USD' },
        expiry: NOW + 20_000,
        revocationMode: 'direct',
        delegateId: 'late-child-holder',
        capabilityId: 'direct-revocation_late_child',
        operationId: 'direct-revocation_late_delegation',
        store: lineage.store,
        now: NOW + 2,
    });
    assert.equal(newChild.ok, false);
    assert.equal(newChild.reason, 'capability_revoked');
});
test('cascade revocation blocks later descendant reservations and child allocations', async () => {
    const keys = issuer();
    const lineage = await threeHopLineage({
        keys,
        prefix: 'cascade-revocation',
        rootRevocationMode: 'cascade',
    });
    const rootId = lineage.root.capabilityReceipt.capability.id;
    assert.equal((await lineage.store.revokeCapability({
        capabilityId: rootId,
        capabilityFingerprint: lineage.store.getState(rootId).capability_fingerprint,
        now: NOW + 1,
    })).ok, true);
    const descendantAction = scopedAction('op_4', { amount: 10 });
    const descendant = await executeWithCapability({
        capabilityReceipt: lineage.grandchild.capabilityReceipt,
        secret: lineage.grandchild.secret,
        action: descendantAction,
        operationId: descendantAction.operation_id,
        store: lineage.store,
        trustedIssuerKeys: [keys.receipt.public_key],
        verifyBaseReceipt: () => true,
        executeAction: async () => assert.fail('cascade-revoked lineage must not enter the effect'),
        now: NOW + 2,
    });
    assert.equal(descendant.ok, false);
    assert.equal(descendant.reason, 'capability_ancestor_revoked');
    const lateGrandchild = await delegateCapabilityReceipt({
        parentCapabilityReceipt: lineage.child.capabilityReceipt,
        parentSecret: lineage.child.secret,
        issuerPrivateKey: keys.privateKey,
        trustedIssuerKeys: [keys.receipt.public_key],
        budget: { amount: 1, currency: 'USD' },
        expiry: NOW + 20_000,
        revocationMode: 'direct',
        delegateId: 'late-grandchild-holder',
        capabilityId: 'cascade-revocation_late_grandchild',
        operationId: 'cascade-revocation_late_delegation',
        store: lineage.store,
        now: NOW + 2,
    });
    assert.equal(lateGrandchild.ok, false);
    assert.equal(lateGrandchild.reason, 'capability_ancestor_revoked');
});
test('ancestor revocation and descendant reservation serialize without reopening committed authority', async () => {
    const keys = issuer();
    const revocationFirst = await threeHopLineage({
        keys,
        prefix: 'race-revocation-first',
        rootRevocationMode: 'cascade',
    });
    const firstRootId = revocationFirst.root.capabilityReceipt.capability.id;
    const firstChildId = revocationFirst.child.capabilityReceipt.capability.id;
    const [revoked, refused] = await Promise.all([
        revocationFirst.store.revokeCapability({
            capabilityId: firstRootId,
            capabilityFingerprint: revocationFirst.store.getState(firstRootId).capability_fingerprint,
            now: NOW + 1,
        }),
        revocationFirst.store.reserveSpend({
            capabilityId: firstChildId,
            capabilityFingerprint: revocationFirst.store.getState(firstChildId).capability_fingerprint,
            operationId: 'race_after_revocation',
            actionDigest: capabilityActionDigest(scopedAction('race_after_revocation')),
            amount: 1,
            currency: 'USD',
            now: NOW + 1,
        }),
    ]);
    assert.equal(revoked.ok, true);
    assert.equal(refused.ok, false);
    assert.equal(refused.reason, 'capability_ancestor_revoked');
    const reservationFirst = await threeHopLineage({
        keys,
        prefix: 'race-reservation-first',
        rootRevocationMode: 'cascade',
    });
    const secondRootId = reservationFirst.root.capabilityReceipt.capability.id;
    const secondChildId = reservationFirst.child.capabilityReceipt.capability.id;
    const [reserved, lateRevocation] = await Promise.all([
        reservationFirst.store.reserveSpend({
            capabilityId: secondChildId,
            capabilityFingerprint: reservationFirst.store.getState(secondChildId).capability_fingerprint,
            operationId: 'race_before_revocation',
            actionDigest: capabilityActionDigest(scopedAction('race_before_revocation')),
            amount: 1,
            currency: 'USD',
            now: NOW + 1,
        }),
        reservationFirst.store.revokeCapability({
            capabilityId: secondRootId,
            capabilityFingerprint: reservationFirst.store.getState(secondRootId).capability_fingerprint,
            now: NOW + 1,
        }),
    ]);
    assert.equal(reserved.ok, true);
    assert.equal(lateRevocation.ok, true);
    assert.equal(reservationFirst.store.getOperation('race_before_revocation', secondChildId).status, 'reserved');
    assert.equal((await reservationFirst.store.beginProviderEntry({
        capabilityId: secondChildId,
        operationId: 'race_before_revocation',
        reservationToken: reserved.reservation_token,
        now: NOW + 2,
    })).ok, true);
    assert.equal((await reservationFirst.store.commitSpend({
        capabilityId: secondChildId,
        operationId: 'race_before_revocation',
        reservationToken: reserved.reservation_token,
        outcome: 'executed',
        now: NOW + 3,
    })).ok, true);
    assert.equal((await reservationFirst.store.reserveSpend({
        capabilityId: secondChildId,
        capabilityFingerprint: reservationFirst.store.getState(secondChildId).capability_fingerprint,
        operationId: 'race_later_claim',
        actionDigest: capabilityActionDigest(scopedAction('race_later_claim')),
        amount: 1,
        currency: 'USD',
        now: NOW + 4,
    })).reason, 'capability_ancestor_revoked');
});
test('postgres reservations refuse when any registered ancestor state is unavailable', async () => {
    const keys = issuer();
    const parent = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'postgres_missing_ancestor_parent',
    }));
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'postgres_missing_ancestor_leaf',
        delegationChain: [chainEntry({
                delegation_id: 'postgres-missing-ancestor-delegation',
                parent: 'postgres_missing_ancestor_parent',
                amount: 100,
            })],
    }));
    const reference = createMemoryCapabilityStore();
    assert.equal(reference.registerCapability(parent.capabilityReceipt), true);
    assert.equal(reference.registerCapability(minted.capabilityReceipt), true);
    const leafState = {
        capability_id: minted.capabilityReceipt.capability.id,
        capability_fingerprint: reference.getState(minted.capabilityReceipt.capability.id).capability_fingerprint,
        budget_amount: 100,
        currency: 'USD',
        consumed_amount: '0',
        reserved_amount: '0',
        expires_at: new Date(NOW + 60_000).toISOString(),
        allowance_profile_id: null,
        allowance_digest: null,
        semantic_fence_ready: true,
        revocation_mode: 'direct',
        parent_capability_id: 'postgres_missing_ancestor_parent',
        revoked_at: null,
        revocation_state_ready: true,
    };
    const transaction = async (callback) => callback(async (sql, params) => {
        if (sql === CAPABILITY_SQL.readState) {
            return params[0] === leafState.capability_id
                ? { rowCount: 1, rows: [leafState] }
                : { rowCount: 0, rows: [] };
        }
        throw new Error(`unexpected SQL in missing-ancestor test: ${sql}`);
    });
    const store = createPostgresCapabilityStore({ transaction });
    const result = await store.reserveSpend({
        capabilityId: leafState.capability_id,
        capabilityFingerprint: leafState.capability_fingerprint,
        operationId: 'postgres_missing_ancestor_reservation',
        actionDigest: capabilityActionDigest(scopedAction('postgres_missing_ancestor_reservation')),
        amount: 1,
        currency: 'USD',
        now: NOW,
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'capability_ancestor_status_unavailable');
});
test('postgres reservations refuse a quarantined ancestor even when it carries a valid-looking mode', async () => {
    const keys = issuer();
    const parent = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'postgres_quarantined_ancestor_parent',
    }));
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'postgres_quarantined_ancestor_leaf',
        delegationChain: [chainEntry({
                delegation_id: 'postgres-quarantined-ancestor-delegation',
                parent: 'postgres_quarantined_ancestor_parent',
                amount: 100,
            })],
    }));
    const reference = createMemoryCapabilityStore();
    assert.equal(reference.registerCapability(parent.capabilityReceipt), true);
    assert.equal(reference.registerCapability(minted.capabilityReceipt), true);
    const parentState = {
        ...reference.getState(parent.capabilityReceipt.capability.id),
        consumed_amount: '0',
        reserved_amount: '0',
        expires_at: new Date(NOW + 60_000).toISOString(),
        semantic_fence_ready: true,
        revocation_mode: 'cascade',
        parent_capability_id: null,
        revoked_at: null,
        revocation_state_ready: false,
    };
    const leafState = {
        ...reference.getState(minted.capabilityReceipt.capability.id),
        consumed_amount: '0',
        reserved_amount: '0',
        expires_at: new Date(NOW + 60_000).toISOString(),
        semantic_fence_ready: true,
        revocation_mode: 'direct',
        parent_capability_id: parentState.capability_id,
        revoked_at: null,
        revocation_state_ready: true,
    };
    const states = new Map([
        [leafState.capability_id, leafState],
        [parentState.capability_id, parentState],
    ]);
    const transaction = async (callback) => callback(async (sql, params) => {
        if (sql === CAPABILITY_SQL.readState) {
            const row = states.get(params[0]);
            return { rowCount: row ? 1 : 0, rows: row ? [row] : [] };
        }
        throw new Error(`unexpected SQL in quarantined-ancestor test: ${sql}`);
    });
    const store = createPostgresCapabilityStore({ transaction });
    const result = await store.reserveSpend({
        capabilityId: leafState.capability_id,
        capabilityFingerprint: leafState.capability_fingerprint,
        operationId: 'postgres_quarantined_ancestor_reservation',
        actionDigest: capabilityActionDigest(scopedAction('postgres_quarantined_ancestor_reservation')),
        amount: 1,
        currency: 'USD',
        now: NOW,
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'capability_ancestor_status_unavailable');
});
test('a valid linear delegation chain mints and verifies', () => {
    const keys = issuer();
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'linear_leaf',
        secret: Buffer.alloc(32, 20),
        delegationChain: [
            chainEntry({ delegation_id: 'd1', parent: 'root_cap', amount: 50 }),
            chainEntry({ delegation_id: 'd2', parent: 'mid_cap', amount: 30 }),
        ],
    }));
    assert.equal(verifyCapabilityReceipt(minted.capabilityReceipt, { trustedIssuerKeys: [keys.receipt.public_key] }).ok, true);
    assert.equal(minted.capabilityReceipt.capability.delegation_chain.length, 2);
});
test('a real multi-hop delegation produces a chain that survives acyclicity ingest', async () => {
    const keys = issuer();
    const parent = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'acyc_parent',
        expiry: NOW + 40_000,
        secret: Buffer.alloc(32, 21),
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(parent.capabilityReceipt), true);
    const child = await delegateCapabilityReceipt({
        parentCapabilityReceipt: parent.capabilityReceipt,
        parentSecret: parent.secret,
        issuerPrivateKey: keys.privateKey,
        trustedIssuerKeys: [keys.receipt.public_key],
        budget: { amount: 40, currency: 'USD' },
        expiry: NOW + 30_000,
        revocationMode: 'direct',
        delegateId: 'acyc-child',
        capabilityId: 'acyc_child',
        secret: Buffer.alloc(32, 22),
        store,
        now: NOW,
    });
    assert.equal(child.ok, true);
    const grandchild = await delegateCapabilityReceipt({
        parentCapabilityReceipt: child.capabilityReceipt,
        parentSecret: child.secret,
        issuerPrivateKey: keys.privateKey,
        trustedIssuerKeys: [keys.receipt.public_key],
        budget: { amount: 20, currency: 'USD' },
        expiry: NOW + 20_000,
        revocationMode: 'direct',
        delegateId: 'acyc-grandchild',
        capabilityId: 'acyc_grandchild',
        secret: Buffer.alloc(32, 23),
        store,
        now: NOW,
    });
    assert.equal(grandchild.ok, true);
    const chain = grandchild.capabilityReceipt.capability.delegation_chain;
    assert.equal(chain.length, 2);
    // Distinct parents, non-increasing amount: a genuine chain is a simple path.
    assert.equal(new Set(chain.map((e) => e.parent_capability_id)).size, 2);
    assert.ok(chain[1].amount <= chain[0].amount);
    assert.equal(verifyCapabilityReceipt(grandchild.capabilityReceipt, { trustedIssuerKeys: [keys.receipt.public_key] }).ok, true);
});
test('a cyclic delegation chain is rejected at ingest, even when validly signed', () => {
    const keys = issuer();
    const cyclic = [
        chainEntry({ delegation_id: 'd1', parent: 'cap_A', amount: 50 }),
        chainEntry({ delegation_id: 'd2', parent: 'cap_A', amount: 30 }), // cap_A recurs as parent
    ];
    // Minting refuses to construct the forged envelope.
    assert.throws(() => mintCapabilityReceipt(keys.receipt, options({ issuerPrivateKey: keys.privateKey, capabilityId: 'cyclic_leaf', delegationChain: cyclic })), /repeats a parent_capability_id/);
    // And a hand-crafted, correctly-signed envelope is still refused on ingest.
    const good = mintCapabilityReceipt(keys.receipt, options({ issuerPrivateKey: keys.privateKey, capabilityId: 'cyclic_leaf', secret: Buffer.alloc(32, 24) }));
    const forged = structuredClone(good.capabilityReceipt);
    forged.capability.delegation_chain = cyclic;
    resignEnvelope(forged, keys.privateKey);
    const verified = verifyCapabilityReceipt(forged, { trustedIssuerKeys: [keys.receipt.public_key] });
    assert.equal(verified.ok, false);
    assert.equal(verified.reason, 'capability_malformed');
});
test('a repeated delegation_id is rejected as a cycle', () => {
    const keys = issuer();
    assert.throws(() => mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'dupid_leaf',
        delegationChain: [
            chainEntry({ delegation_id: 'same', parent: 'cap_A', amount: 20 }),
            chainEntry({ delegation_id: 'same', parent: 'cap_B', amount: 10 }),
        ],
    })), /repeats a delegation_id/);
});
test('a delegation chain that grants increasing authority is rejected', () => {
    const keys = issuer();
    assert.throws(() => mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'inflate_leaf',
        delegationChain: [
            chainEntry({ delegation_id: 'd1', parent: 'cap_A', amount: 30 }),
            chainEntry({ delegation_id: 'd2', parent: 'cap_B', amount: 50 }), // 50 > 30
        ],
    })), /increasing authority/);
});
test('a delegation chain naming the leaf capability as a parent is rejected as a broken link', () => {
    const keys = issuer();
    assert.throws(() => mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'broken_leaf',
        delegationChain: [
            chainEntry({ delegation_id: 'd1', parent: 'broken_leaf', amount: 10 }), // parent == leaf id
        ],
    })), /references the leaf capability as a parent/);
});
test('the durable store fences on the separate action fence too, not only the memory store', async () => {
    // The memory fence had a behavioural test and the durable one did not: removing
    // the postgres call site left every test green because the only assertions on it
    // were about the SHAPE of the SQL string. A guard nothing exercises is a guard
    // nobody will notice losing.
    const keys = issuer();
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'postgres_action_fence',
    }));
    const states = new Map();
    const operations = new Map();
    const key = (ns, id) => `${ns}\u0000${id}`;
    const transaction = async (callback) => callback(async (sql, params) => {
        if (sql === CAPABILITY_SQL.register) {
            states.set(params[0], {
                capability_id: params[0], capability_fingerprint: params[4],
                budget_amount: String(params[1]), currency: params[2],
                consumed_amount: '0', reserved_amount: '0', expires_at: params[3],
                semantic_fence_ready: true,
                revocation_mode: params[7], parent_capability_id: params[8],
                revoked_at: null, revocation_state_ready: true,
            });
            return { rowCount: 1, rows: [] };
        }
        if (sql === CAPABILITY_SQL.readState) {
            const row = states.get(params[0]);
            return { rowCount: row ? 1 : 0, rows: row ? [row] : [] };
        }
        if (sql === CAPABILITY_SQL.readOperation) {
            const row = operations.get(key(params[0], params[1]));
            return { rowCount: row ? 1 : 0, rows: row ? [row] : [] };
        }
        if (sql === CAPABILITY_SQL.readActionHolder) {
            // Mirrors the partial unique index predicate in migration 20260803010000.
            const row = [...operations.values()].find((entry) => entry.operation_namespace === params[0]
                && entry.action_fence_digest === params[1]
                && ['reserved', 'provider_entered', 'committed'].includes(entry.status));
            return { rowCount: row ? 1 : 0, rows: row ? [row] : [] };
        }
        if (sql === CAPABILITY_SQL.reserveState) {
            const row = states.get(params[0]);
            row.reserved_amount = String(Number(row.reserved_amount) + Number(params[1]));
            return { rowCount: 1, rows: [] };
        }
        if (sql === CAPABILITY_SQL.insertOperation) {
            const [ns, capabilityId, operationId, actionDigest, actionFenceDigest, amount, currency, token, reservedAt, deadline] = params;
            operations.set(key(ns, operationId), {
                operation_namespace: ns, capability_id: capabilityId, operation_id: operationId,
                action_digest: actionDigest, action_fence_digest: actionFenceDigest,
                amount: String(amount), currency,
                reservation_token: token, status: 'reserved', outcome: null,
                reserved_at: reservedAt, entry_deadline_at: deadline, provider_entry_at: null,
            });
            return { rowCount: 1, rows: [] };
        }
        throw new Error(`unexpected SQL in postgres action fence test: ${sql}`);
    });
    const store = createPostgresCapabilityStore({ transaction, providerEntryTimeoutMs: 1_000 });
    assert.equal(await store.registerCapability(minted.capabilityReceipt), true);
    const capabilityId = minted.capabilityReceipt.capability.id;
    const firstAction = capabilityActionDigest(scopedAction('evt_1', { target: 'merge-pr-99' }));
    const secondAction = capabilityActionDigest(scopedAction('evt_2', { target: 'merge-pr-99' }));
    const oneFence = capabilityActionDigest({ target: 'merge-pr-99' });
    const reserve = (operationId, actionDigest, actionFenceDigest) => store.reserveSpend({
        capabilityId,
        capabilityFingerprint: states.get(capabilityId).capability_fingerprint,
        operationId,
        actionDigest,
        actionFenceDigest,
        amount: 1,
        currency: 'USD',
        now: NOW,
    });
    assert.equal((await reserve('evt_1', firstAction, oneFence)).ok, true);
    const duplicate = await reserve('evt_2', secondAction, oneFence);
    assert.equal(duplicate.ok, false);
    assert.equal(duplicate.reason, 'action_in_flight');
    assert.equal(duplicate.holding_operation_id, 'evt_1');
    assert.equal(duplicate.action_digest, secondAction);
    assert.equal(duplicate.action_fence_digest, oneFence);
    assert.equal(operations.get(key(capabilityId, 'evt_1')).action_digest, firstAction);
    assert.equal(operations.get(key(capabilityId, 'evt_1')).action_fence_digest, oneFence);
    // A different action is unaffected.
    const distinctAction = capabilityActionDigest(scopedAction('evt_3', { target: 'merge-pr-100' }));
    const distinctFence = capabilityActionDigest({ target: 'merge-pr-100' });
    assert.equal((await reserve('evt_3', distinctAction, distinctFence)).ok, true);
});
test('a concurrent postgres action-fence collision returns a closed refusal instead of escaping', async () => {
    const keys = issuer();
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'postgres_action_fence_race',
    }));
    const reference = createMemoryCapabilityStore();
    assert.equal(reference.registerCapability(minted.capabilityReceipt), true);
    const state = reference.getState(minted.capabilityReceipt.capability.id);
    let actionHolderReads = 0;
    const transaction = async (callback) => callback(async (sql) => {
        if (sql === CAPABILITY_SQL.register)
            return { rowCount: 1, rows: [] };
        if (sql === CAPABILITY_SQL.readState) {
            return {
                rowCount: 1,
                rows: [{
                        capability_id: state.capability_id,
                        capability_fingerprint: state.capability_fingerprint,
                        budget_amount: String(state.budget_amount),
                        currency: state.currency,
                        consumed_amount: '0',
                        reserved_amount: '0',
                        expires_at: new Date(state.expires_at).toISOString(),
                        semantic_fence_ready: true,
                        revocation_mode: 'direct',
                        parent_capability_id: null,
                        revoked_at: null,
                        revocation_state_ready: true,
                    }],
            };
        }
        if (sql === CAPABILITY_SQL.readOperation) {
            return { rowCount: 0, rows: [] };
        }
        if (sql === CAPABILITY_SQL.readActionHolder) {
            actionHolderReads += 1;
            return actionHolderReads === 1
                ? { rowCount: 0, rows: [] }
                : { rowCount: 1, rows: [{ operation_id: 'evt_racing_winner', status: 'reserved' }] };
        }
        if (sql === CAPABILITY_SQL.reserveState)
            return { rowCount: 1, rows: [] };
        if (sql === CAPABILITY_SQL.insertOperation) {
            const error = new Error('duplicate action holder');
            error.code = '23505';
            error.constraint = 'ep_capability_operations_live_action_uniq';
            throw error;
        }
        throw new Error(`unexpected SQL in postgres action-fence race test: ${sql}`);
    });
    const store = createPostgresCapabilityStore({ transaction });
    assert.equal(await store.registerCapability(minted.capabilityReceipt), true);
    const result = await store.reserveSpend({
        capabilityId: state.capability_id,
        capabilityFingerprint: state.capability_fingerprint,
        operationId: 'evt_racing_loser',
        actionDigest: capabilityActionDigest(scopedAction('merge-pr-race')),
        amount: 1,
        currency: 'USD',
        now: NOW,
    });
    assert.deepEqual(result, {
        ok: false,
        reason: 'action_in_flight',
        action_digest: capabilityActionDigest(scopedAction('merge-pr-race')),
        action_fence_digest: capabilityActionDigest(scopedAction('merge-pr-race')),
        holding_operation_id: 'evt_racing_winner',
    });
});
test('an unrelated postgres unique violation is not laundered into action_in_flight', async () => {
    const keys = issuer();
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'postgres_unrelated_unique_violation',
    }));
    const reference = createMemoryCapabilityStore();
    assert.equal(reference.registerCapability(minted.capabilityReceipt), true);
    const state = reference.getState(minted.capabilityReceipt.capability.id);
    const transaction = async (callback) => callback(async (sql) => {
        if (sql === CAPABILITY_SQL.register)
            return { rowCount: 1, rows: [] };
        if (sql === CAPABILITY_SQL.readState) {
            return {
                rowCount: 1,
                rows: [{
                        capability_id: state.capability_id,
                        capability_fingerprint: state.capability_fingerprint,
                        budget_amount: String(state.budget_amount),
                        currency: state.currency,
                        consumed_amount: '0',
                        reserved_amount: '0',
                        expires_at: new Date(state.expires_at).toISOString(),
                        semantic_fence_ready: true,
                        revocation_mode: 'direct',
                        parent_capability_id: null,
                        revoked_at: null,
                        revocation_state_ready: true,
                    }],
            };
        }
        if (sql === CAPABILITY_SQL.readOperation || sql === CAPABILITY_SQL.readActionHolder) {
            return { rowCount: 0, rows: [] };
        }
        if (sql === CAPABILITY_SQL.reserveState)
            return { rowCount: 1, rows: [] };
        if (sql === CAPABILITY_SQL.insertOperation) {
            const error = new Error('unrelated duplicate');
            error.code = '23505';
            error.constraint = 'some_other_unique_constraint';
            throw error;
        }
        throw new Error(`unexpected SQL in unrelated unique-violation test: ${sql}`);
    });
    const store = createPostgresCapabilityStore({ transaction });
    assert.equal(await store.registerCapability(minted.capabilityReceipt), true);
    await assert.rejects(store.reserveSpend({
        capabilityId: state.capability_id,
        capabilityFingerprint: state.capability_fingerprint,
        operationId: 'evt_unrelated_unique',
        actionDigest: capabilityActionDigest(scopedAction('unrelated-unique')),
        amount: 1,
        currency: 'USD',
        now: NOW,
    }), (error) => (error.code === '23505' && error.constraint === 'some_other_unique_constraint'));
});
const capabilityPostgresUrl = process.env.ADMISSION_STORE_POSTGRES_TEST_URL;
test('real PostgreSQL serializes cascade revocation against descendant reservation', {
    skip: capabilityPostgresUrl ? false : 'ADMISSION_STORE_POSTGRES_TEST_URL is not configured',
}, async () => {
    const { Pool } = require('pg');
    const pool = new Pool({ connectionString: capabilityPostgresUrl, max: 8 });
    const schemaPrefix = `ep_revocation_race_${process.pid}_${Date.now()}`;
    function latch() {
        let release;
        const waiting = new Promise((resolve) => { release = resolve; });
        return { waiting, release };
    }
    function transactionFor(schema, hooks = {}) {
        return async (callback) => {
            const client = await pool.connect();
            try {
                await client.query('BEGIN');
                await client.query(`SET LOCAL search_path TO ${schema}, public`);
                const result = await callback(async (sql, params = []) => {
                    await hooks.before?.(sql, params);
                    const queried = await client.query(sql, [...params]);
                    await hooks.after?.(sql, params);
                    return { rowCount: queried.rowCount ?? 0, rows: queried.rows };
                });
                await client.query('COMMIT');
                return result;
            }
            catch (error) {
                await client.query('ROLLBACK');
                throw error;
            }
            finally {
                client.release();
            }
        };
    }
    async function setupLineage(schema, prefix) {
        await pool.query(`CREATE SCHEMA ${schema}`);
        const setup = await pool.connect();
        try {
            await setup.query(`SET search_path TO ${schema}, public`);
            await setup.query(CAPABILITY_STATE_DDL);
        }
        finally {
            setup.release();
        }
        const keys = issuer();
        const store = createPostgresCapabilityStore({ transaction: transactionFor(schema) });
        const lineage = await threeHopLineage({
            keys,
            prefix,
            rootRevocationMode: 'cascade',
            store,
        });
        const rootId = lineage.root.capabilityReceipt.capability.id;
        const childId = lineage.child.capabilityReceipt.capability.id;
        const state = await pool.query(`
      SELECT capability_id, capability_fingerprint
      FROM ${schema}.ep_capability_state
      WHERE capability_id IN ($1, $2)
    `, [rootId, childId]);
        const fingerprints = new Map(state.rows.map((row) => [row.capability_id, row.capability_fingerprint]));
        return { rootId, childId, fingerprints };
    }
    try {
        const firstSchema = `${schemaPrefix}_revocation_first`;
        const first = await setupLineage(firstSchema, 'postgres-race-revocation-first');
        const revocationLocked = latch();
        const releaseRevocation = latch();
        const reservationReachedRoot = latch();
        let heldRevocation = false;
        let observedReservation = false;
        const revoker = createPostgresCapabilityStore({
            transaction: transactionFor(firstSchema, {
                async after(sql, params) {
                    if (!heldRevocation && sql === CAPABILITY_SQL.readState && params[0] === first.rootId) {
                        heldRevocation = true;
                        revocationLocked.release();
                        await releaseRevocation.waiting;
                    }
                },
            }),
        });
        const reserver = createPostgresCapabilityStore({
            transaction: transactionFor(firstSchema, {
                before(sql, params) {
                    if (!observedReservation && sql === CAPABILITY_SQL.readState && params[0] === first.rootId) {
                        observedReservation = true;
                        reservationReachedRoot.release();
                    }
                },
            }),
        });
        const revoking = revoker.revokeCapability({
            capabilityId: first.rootId,
            capabilityFingerprint: first.fingerprints.get(first.rootId),
            now: NOW + 1,
        });
        await revocationLocked.waiting;
        const reserving = reserver.reserveSpend({
            capabilityId: first.childId,
            capabilityFingerprint: first.fingerprints.get(first.childId),
            operationId: 'postgres_revocation_first_reservation',
            actionDigest: capabilityActionDigest(scopedAction('postgres_revocation_first_reservation')),
            amount: 1,
            currency: 'USD',
            now: NOW + 1,
        });
        await reservationReachedRoot.waiting;
        releaseRevocation.release();
        assert.equal((await revoking).ok, true);
        assert.deepEqual(await reserving, { ok: false, reason: 'capability_ancestor_revoked' });
        const secondSchema = `${schemaPrefix}_reservation_first`;
        const second = await setupLineage(secondSchema, 'postgres-race-reservation-first');
        const reservationLocked = latch();
        const releaseReservation = latch();
        const revocationReachedRoot = latch();
        let heldReservation = false;
        let observedRevocation = false;
        const firstReserver = createPostgresCapabilityStore({
            transaction: transactionFor(secondSchema, {
                async after(sql, params) {
                    if (!heldReservation && sql === CAPABILITY_SQL.readState && params[0] === second.rootId) {
                        heldReservation = true;
                        reservationLocked.release();
                        await releaseReservation.waiting;
                    }
                },
            }),
        });
        const lateRevoker = createPostgresCapabilityStore({
            transaction: transactionFor(secondSchema, {
                before(sql, params) {
                    if (!observedRevocation && sql === CAPABILITY_SQL.readState && params[0] === second.rootId) {
                        observedRevocation = true;
                        revocationReachedRoot.release();
                    }
                },
            }),
        });
        const reserved = firstReserver.reserveSpend({
            capabilityId: second.childId,
            capabilityFingerprint: second.fingerprints.get(second.childId),
            operationId: 'postgres_reservation_first_claim',
            actionDigest: capabilityActionDigest(scopedAction('postgres_reservation_first_claim')),
            amount: 1,
            currency: 'USD',
            now: NOW + 1,
        });
        await reservationLocked.waiting;
        const revoked = lateRevoker.revokeCapability({
            capabilityId: second.rootId,
            capabilityFingerprint: second.fingerprints.get(second.rootId),
            now: NOW + 1,
        });
        await revocationReachedRoot.waiting;
        releaseReservation.release();
        assert.equal((await reserved).ok, true);
        assert.equal((await revoked).ok, true);
    }
    finally {
        await pool.query(`DROP SCHEMA IF EXISTS ${schemaPrefix}_revocation_first CASCADE`);
        await pool.query(`DROP SCHEMA IF EXISTS ${schemaPrefix}_reservation_first CASCADE`);
        await pool.end();
    }
});
test('real PostgreSQL action fence is load-bearing across capability rows', {
    skip: capabilityPostgresUrl ? false : 'ADMISSION_STORE_POSTGRES_TEST_URL is not configured',
}, async () => {
    const { Pool } = require('pg');
    const pool = new Pool({ connectionString: capabilityPostgresUrl, max: 8 });
    const schemaPrefix = `ep_action_fence_${process.pid}_${Date.now()}`;
    async function runRace(schema, ddl) {
        await pool.query(`CREATE SCHEMA ${schema}`);
        const setup = await pool.connect();
        try {
            await setup.query(`SET search_path TO ${schema}, public`);
            await setup.query(ddl);
        }
        finally {
            setup.release();
        }
        let arrived = 0;
        let releaseBarrier;
        const barrier = new Promise((resolve) => { releaseBarrier = resolve; });
        const transaction = async (callback) => {
            const client = await pool.connect();
            try {
                await client.query('BEGIN');
                await client.query(`SET LOCAL search_path TO ${schema}, public`);
                const result = await callback(async (sql, params = []) => {
                    const queried = await client.query(sql, [...params]);
                    if (sql === CAPABILITY_SQL.readActionHolder && queried.rows.length === 0) {
                        arrived += 1;
                        if (arrived === 2)
                            releaseBarrier();
                        await barrier;
                    }
                    return { rowCount: queried.rowCount ?? 0, rows: queried.rows };
                });
                await client.query('COMMIT');
                return result;
            }
            catch (error) {
                await client.query('ROLLBACK');
                throw error;
            }
            finally {
                client.release();
            }
        };
        const keys = issuer();
        const first = mintCapabilityReceipt(keys.receipt, options({
            issuerPrivateKey: keys.privateKey,
            capabilityId: `${schema}_a`,
        }));
        const second = mintCapabilityReceipt(keys.receipt, options({
            issuerPrivateKey: keys.privateKey,
            capabilityId: `${schema}_b`,
        }));
        const reference = createMemoryCapabilityStore();
        assert.equal(reference.registerCapability(first.capabilityReceipt), true);
        assert.equal(reference.registerCapability(second.capabilityReceipt), true);
        const firstState = reference.getState(first.capabilityReceipt.capability.id);
        const secondState = reference.getState(second.capabilityReceipt.capability.id);
        const store = createPostgresCapabilityStore({ transaction });
        assert.equal(await store.registerCapability(first.capabilityReceipt), true);
        assert.equal(await store.registerCapability(second.capabilityReceipt), true);
        const actionDigest = capabilityActionDigest(scopedAction('stable-semantic-action'));
        const operationNamespace = 'tenant:shared-action-fence';
        const results = await Promise.all([
            store.reserveSpend({
                capabilityId: firstState.capability_id,
                capabilityFingerprint: firstState.capability_fingerprint,
                operationNamespace,
                operationId: 'request-wrapper-a',
                actionDigest,
                amount: 1,
                currency: 'USD',
                now: NOW,
            }),
            store.reserveSpend({
                capabilityId: secondState.capability_id,
                capabilityFingerprint: secondState.capability_fingerprint,
                operationNamespace,
                operationId: 'request-wrapper-b',
                actionDigest,
                amount: 1,
                currency: 'USD',
                now: NOW,
            }),
        ]);
        return results.filter((result) => result.ok).length;
    }
    try {
        assert.equal(await runRace(`${schemaPrefix}_shipped`, CAPABILITY_STATE_DDL), 1);
        const vulnerableDdl = CAPABILITY_STATE_DDL
            .replace('CREATE UNIQUE INDEX IF NOT EXISTS ep_capability_operations_live_action_uniq', 'CREATE INDEX IF NOT EXISTS ep_capability_operations_live_action_uniq')
            .replace(/DO \$capability_action_fence_index_contract\$[\s\S]*?\$capability_action_fence_index_contract\$;/, '');
        assert.notEqual(vulnerableDdl, CAPABILITY_STATE_DDL, 'mutation must remove uniqueness');
        assert.doesNotMatch(vulnerableDdl, /capability action-fence index does not match its required contract/);
        assert.equal(await runRace(`${schemaPrefix}_mutated`, vulnerableDdl), 2, 'the negative control must admit both reservations when uniqueness is removed');
    }
    finally {
        await pool.query(`DROP SCHEMA IF EXISTS ${schemaPrefix}_shipped CASCADE`);
        await pool.query(`DROP SCHEMA IF EXISTS ${schemaPrefix}_mutated CASCADE`);
        await pool.end();
    }
});
test('package DDL rejects a same-name index with a non-unique or wrong contract', {
    skip: capabilityPostgresUrl ? false : 'ADMISSION_STORE_POSTGRES_TEST_URL is not configured',
}, async () => {
    const { Pool } = require('pg');
    const pool = new Pool({ connectionString: capabilityPostgresUrl, max: 1 });
    const schemaPrefix = `ep_action_fence_contract_${process.pid}_${Date.now()}`;
    const conflictingIndexes = [
        `CREATE INDEX ep_capability_operations_live_action_uniq
       ON ep_capability_operations (operation_namespace, action_fence_digest)
       WHERE status IN ('reserved', 'provider_entered', 'committed')`,
        `CREATE UNIQUE INDEX ep_capability_operations_live_action_uniq
       ON ep_capability_operations (operation_namespace, action_digest)
       WHERE status IN ('reserved', 'provider_entered', 'committed')`,
        `CREATE UNIQUE INDEX ep_capability_operations_live_action_uniq
       ON ep_capability_operations (operation_namespace, action_fence_digest)
       INCLUDE (action_digest)
       WHERE status IN ('reserved', 'provider_entered', 'committed')`,
        `CREATE UNIQUE INDEX ep_capability_operations_live_action_uniq
       ON ep_capability_operations (operation_namespace text_pattern_ops, action_fence_digest)
       WHERE status IN ('reserved', 'provider_entered', 'committed')`,
        `CREATE UNIQUE INDEX ep_capability_operations_live_action_uniq
       ON ep_capability_operations (operation_namespace COLLATE "C", action_fence_digest COLLATE "C")
       WHERE status IN ('reserved', 'provider_entered', 'committed')`,
    ];
    try {
        for (const [index, conflictingIndex] of conflictingIndexes.entries()) {
            const schema = `${schemaPrefix}_${index}`;
            await pool.query(`CREATE SCHEMA ${schema}`);
            const client = await pool.connect();
            try {
                await client.query(`SET search_path TO ${schema}, public`);
                await client.query(CAPABILITY_STATE_DDL);
                await client.query('DROP INDEX ep_capability_operations_live_action_uniq');
                await client.query(conflictingIndex);
                await assert.rejects(client.query(CAPABILITY_STATE_DDL), (error) => error.code === '55000', `conflicting index ${index} must be rejected`);
            }
            finally {
                client.release();
            }
        }
    }
    finally {
        for (const index of conflictingIndexes.keys()) {
            await pool.query(`DROP SCHEMA IF EXISTS ${schemaPrefix}_${index} CASCADE`);
        }
        await pool.end();
    }
});
test('package DDL quarantines legacy capability ids at the database boundary', {
    skip: capabilityPostgresUrl ? false : 'ADMISSION_STORE_POSTGRES_TEST_URL is not configured',
}, async () => {
    const { Pool } = require('pg');
    const pool = new Pool({ connectionString: capabilityPostgresUrl, max: 1 });
    const schemaPrefix = `ep_semantic_fence_contract_${process.pid}_${Date.now()}`;
    async function directInsertOutcome(schema, ddl) {
        await pool.query(`CREATE SCHEMA ${schema}`);
        const client = await pool.connect();
        try {
            await client.query(`SET search_path TO ${schema}, public`);
            await client.query(ddl);
            await client.query(`
        INSERT INTO ep_capability_state (
          capability_id, capability_fingerprint, budget_amount, currency,
          consumed_amount, reserved_amount, expires_at, semantic_fence_ready,
          revocation_mode, revocation_state_ready
        ) VALUES ($1, $2, 10, 'USD', 0, 0, now() + interval '1 hour', FALSE, 'direct', TRUE)
      `, ['legacy:quarantined', `sha256:${'a'.repeat(64)}`]);
            try {
                await client.query(`
          INSERT INTO ep_capability_operations (
            operation_namespace, operation_id, capability_id, action_digest,
            action_fence_digest, amount, currency, status, reservation_token,
            reserved_at, entry_deadline_at
          ) VALUES ($1, $2, $3, $4, $5, 1, 'USD', 'reserved', $6, now(), now() + interval '1 minute')
        `, [
                    'legacy:quarantined',
                    'operation:must-not-enter',
                    'legacy:quarantined',
                    `sha256:${'b'.repeat(64)}`,
                    `sha256:${'c'.repeat(64)}`,
                    'reservation:must-not-enter',
                ]);
                return 'admitted';
            }
            catch (error) {
                return error.code ?? 'unknown_error';
            }
        }
        finally {
            client.release();
        }
    }
    try {
        assert.equal(await directInsertOutcome(`${schemaPrefix}_shipped`, CAPABILITY_STATE_DDL), '55000');
        const vulnerableDdl = CAPABILITY_STATE_DDL.replace(/CREATE OR REPLACE FUNCTION ep_require_semantic_capability_fence\(\)[\s\S]*?EXECUTE FUNCTION ep_require_semantic_capability_fence\(\);/, '');
        assert.notEqual(vulnerableDdl, CAPABILITY_STATE_DDL, 'mutation must remove the database guard');
        assert.equal(await directInsertOutcome(`${schemaPrefix}_mutated`, vulnerableDdl), 'admitted', 'the negative control must show that the trigger is load-bearing');
    }
    finally {
        await pool.query(`DROP SCHEMA IF EXISTS ${schemaPrefix}_shipped CASCADE`);
        await pool.query(`DROP SCHEMA IF EXISTS ${schemaPrefix}_mutated CASCADE`);
        await pool.end();
    }
});
test('package DDL quarantines an incomplete bootstrap that already defaulted the state flag to true', {
    skip: capabilityPostgresUrl ? false : 'ADMISSION_STORE_POSTGRES_TEST_URL is not configured',
}, async () => {
    const { Pool } = require('pg');
    const pool = new Pool({ connectionString: capabilityPostgresUrl, max: 1 });
    const schemaPrefix = `ep_semantic_fence_upgrade_${process.pid}_${Date.now()}`;
    async function upgradeOutcome(schema, ddl) {
        await pool.query(`CREATE SCHEMA ${schema}`);
        const client = await pool.connect();
        try {
            await client.query(`SET search_path TO ${schema}, public`);
            await client.query(CAPABILITY_STATE_DDL);
            await client.query(`
        DROP TRIGGER ep_capability_operations_semantic_fence_guard
          ON ep_capability_operations;
        ALTER TABLE ep_capability_operations
          DROP CONSTRAINT ep_capability_operations_pkey,
          ALTER COLUMN operation_namespace DROP NOT NULL,
          ALTER COLUMN action_fence_digest DROP NOT NULL;
        ALTER TABLE ep_capability_operations
          ADD CONSTRAINT ep_capability_operations_pkey PRIMARY KEY (operation_id)
      `);
            await client.query(`
        INSERT INTO ep_capability_state (
          capability_id, capability_fingerprint, budget_amount, currency,
          consumed_amount, reserved_amount, expires_at, semantic_fence_ready,
          revocation_mode, revocation_state_ready
        ) VALUES ($1, $2, 10, 'USD', 0, 0, now() + interval '1 hour', TRUE, 'direct', TRUE)
      `, ['legacy:already-true', `sha256:${'a'.repeat(64)}`]);
            await client.query(`
        INSERT INTO ep_capability_operations (
          operation_namespace, operation_id, capability_id, action_digest,
          action_fence_digest, amount, currency, status, reservation_token,
          reserved_at
        ) VALUES (NULL, $1, $2, $3, NULL, 1, 'USD', 'committed', $4, now())
      `, [
                'operation:historical',
                'legacy:already-true',
                `sha256:${'b'.repeat(64)}`,
                'reservation:historical',
            ]);
            await client.query(ddl);
            const state = await client.query(`
        SELECT semantic_fence_ready
        FROM ep_capability_state
        WHERE capability_id = 'legacy:already-true'
      `);
            let insert = 'admitted';
            try {
                await client.query(`
          INSERT INTO ep_capability_operations (
            operation_namespace, operation_id, capability_id, action_digest,
            action_fence_digest, amount, currency, status, reservation_token,
            reserved_at, entry_deadline_at
          ) VALUES ($1, $2, $3, $4, $5, 1, 'USD', 'reserved', $6, now(), now() + interval '1 minute')
        `, [
                    'legacy:already-true',
                    'operation:must-not-enter',
                    'legacy:already-true',
                    `sha256:${'c'.repeat(64)}`,
                    `sha256:${'d'.repeat(64)}`,
                    'reservation:must-not-enter',
                ]);
            }
            catch (error) {
                insert = error.code ?? 'unknown_error';
            }
            return {
                ready: state.rows[0]?.semantic_fence_ready ?? true,
                insert,
            };
        }
        finally {
            client.release();
        }
    }
    try {
        assert.deepEqual(await upgradeOutcome(`${schemaPrefix}_shipped`, CAPABILITY_STATE_DDL), { ready: false, insert: '55000' });
        const vulnerableDdl = CAPABILITY_STATE_DDL.replace(`WHERE operation_namespace IS NULL\n   OR action_fence_digest IS NULL;`, 'WHERE FALSE;');
        assert.notEqual(vulnerableDdl, CAPABILITY_STATE_DDL, 'mutation must erase legacy-id capture');
        assert.deepEqual(await upgradeOutcome(`${schemaPrefix}_mutated`, vulnerableDdl), { ready: true, insert: 'admitted' }, 'the negative control must reproduce the incomplete-bootstrap bypass');
    }
    finally {
        await pool.query(`DROP SCHEMA IF EXISTS ${schemaPrefix}_shipped CASCADE`);
        await pool.query(`DROP SCHEMA IF EXISTS ${schemaPrefix}_mutated CASCADE`);
        await pool.end();
    }
});
test('a second operation id cannot re-authorize an action another operation already holds', async () => {
    // Anton Dziatkovskii, reviewing anthropics/claude-cookbooks#803: "request_approval
    // is a tool call like any other, so it can arrive twice for one pr: the agent
    // retries after a timeout, or the first user.custom_tool_result never lands and it
    // asks again. each call gets its own event_id, both entries carry the same
    // action_digest, and consume_approval only asks 'was this token used', never 'was
    // this action already done'."
    //
    // That was true of this store too. Dedup keyed on (namespace, operation_id), and
    // action_digest was recorded on the row without ever being consulted. Budget is
    // not material-action identity: two wrappers can both reserve positive occurrence
    // units while still referring to one merge/delete/deploy action.
    const keys = issuer();
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'action_fence',
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    const capabilityId = minted.capabilityReceipt.capability.id;
    const fingerprint = store.getState(capabilityId).capability_fingerprint;
    // ONE action. Two request ids, exactly as a retried approval produces.
    const oneAction = capabilityActionDigest(scopedAction('merge-pr-42'));
    const reserve = (operationId, actionDigest = oneAction) => store.reserveSpend({
        capabilityId,
        capabilityFingerprint: fingerprint,
        operationId,
        actionDigest,
        amount: 1,
        currency: 'USD',
        now: NOW,
    });
    const first = await reserve('evt_1');
    assert.equal(first.ok, true);
    const second = await reserve('evt_2');
    assert.equal(second.ok, false);
    assert.equal(second.reason, 'action_in_flight');
    // The refusal names WHICH operation holds it, so an operator can find the
    // outstanding approval instead of guessing.
    assert.equal(second.holding_operation_id, 'evt_1');
    assert.equal(second.action_digest, oneAction);
    // A different action under the same capability is unaffected.
    assert.equal((await reserve('evt_3', capabilityActionDigest(scopedAction('merge-pr-43')))).ok, true);
    // Once the first commits, the action is done, and the reason sharpens from
    // in-flight to already-committed. Still refused.
    assert.equal((await store.beginProviderEntry({
        capabilityId, operationId: 'evt_1', reservationToken: first.reservation_token, now: NOW,
    })).ok, true);
    assert.equal((await store.commitSpend({
        capabilityId, operationId: 'evt_1', reservationToken: first.reservation_token,
        outcome: 'executed', now: NOW,
    })).ok, true);
    const afterCommit = await reserve('evt_4');
    assert.equal(afterCommit.ok, false);
    assert.equal(afterCommit.reason, 'action_already_committed');
});
test('a released action can be re-authorized, because the provider never received it', async () => {
    // The fence must not turn a proven non-entry into a permanently dead action.
    // 'released' carries outcome 'not_entered', so retrying is correct.
    const keys = issuer();
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'action_fence_release',
    }));
    const store = createMemoryCapabilityStore({ providerEntryTimeoutMs: 1000 });
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    const capabilityId = minted.capabilityReceipt.capability.id;
    const fingerprint = store.getState(capabilityId).capability_fingerprint;
    const oneAction = capabilityActionDigest(scopedAction('deploy-build-9'));
    const reserve = (operationId, now) => store.reserveSpend({
        capabilityId,
        capabilityFingerprint: fingerprint,
        operationId,
        actionDigest: oneAction,
        amount: 1,
        currency: 'USD',
        now,
    });
    assert.equal((await reserve('evt_a', NOW)).ok, true);
    assert.equal((await reserve('evt_b', NOW)).reason, 'action_in_flight');
    const recovered = await store.recoverPreEntrySpend({
        capabilityId,
        operationId: 'evt_a',
        actionDigest: oneAction,
        now: NOW + 5000,
    });
    assert.equal(recovered.ok, true);
    assert.equal(store.getOperation('evt_a', capabilityId).status, 'released');
    // The action is free again.
    assert.equal((await reserve('evt_b', NOW + 5000)).ok, true);
});
test('two distinct capabilities may each hold one action, so quorum stays possible', async () => {
    // The fence is scoped to the authorization namespace, which defaults to the
    // capability id. A global fence would make N-of-M approval of one action
    // unsatisfiable: the second approver could never reserve.
    const keys = issuer();
    const a = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey, capabilityId: 'quorum_a',
    }));
    const b = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey, capabilityId: 'quorum_b',
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(a.capabilityReceipt), true);
    assert.equal(store.registerCapability(b.capabilityReceipt), true);
    const sameAction = capabilityActionDigest(scopedAction('wire-transfer-7'));
    const reserve = (minted) => store.reserveSpend({
        capabilityId: minted.capabilityReceipt.capability.id,
        capabilityFingerprint: store.getState(minted.capabilityReceipt.capability.id).capability_fingerprint,
        operationId: 'approval',
        actionDigest: sameAction,
        amount: 1,
        currency: 'USD',
        now: NOW,
    });
    assert.equal((await reserve(a)).ok, true);
    assert.equal((await reserve(b)).ok, true);
});
test('aggregate capability accounting refuses a second executor on a different atomic state domain', async () => {
    const keys = issuer();
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'aggregate-domain-fence',
    }));
    const authoritativeStore = createMemoryCapabilityStore();
    const forkedStore = createMemoryCapabilityStore();
    assert.equal(authoritativeStore.registerCapability(minted.capabilityReceipt), true);
    assert.equal(forkedStore.registerCapability(minted.capabilityReceipt), true);
    assert.notEqual(authoritativeStore.stateDomainDigest, forkedStore.stateDomainDigest);
    let effects = 0;
    const common = {
        capabilityReceipt: minted.capabilityReceipt,
        secret: minted.secret,
        trustedIssuerKeys: [keys.receipt.public_key],
        verifyBaseReceipt: () => true,
        executeAction: async () => { effects += 1; return 'executed'; },
        now: NOW,
        executionDomain: {
            executor_id: 'executor:primary',
            expected_state_domain_digest: authoritativeStore.stateDomainDigest,
            require_aggregate: true,
        },
    };
    const first = await executeWithCapability({
        ...common,
        store: authoritativeStore,
        operationId: 'op_1',
        action: scopedAction('op_1', { amount: 30, destination: 'acct_a' }),
    });
    assert.equal(first.ok, true);
    assert.deepEqual(first.budget_guarantee, {
        mode: 'aggregate_atomic_domain',
        executor_id: 'executor:primary',
        state_domain_digest: authoritativeStore.stateDomainDigest,
    });
    const forked = await executeWithCapability({
        ...common,
        store: forkedStore,
        operationId: 'op_2',
        action: scopedAction('op_2', { amount: 60 }),
        executionDomain: {
            ...common.executionDomain,
            executor_id: 'executor:fork',
        },
    });
    assert.equal(forked.ok, false);
    assert.equal(forked.reason, 'capability_state_domain_mismatch');
    assert.equal(effects, 1);
    assert.equal(forkedStore.getState(minted.capabilityReceipt.capability.id).reserved_amount, 0);
    assert.equal(forkedStore.getState(minted.capabilityReceipt.capability.id).consumed_amount, 0);
});
test('state-domain mismatch may fall back only to the relying-party-pinned single executor', async () => {
    const keys = issuer();
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'single-executor-fallback',
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    const mismatchedDomain = `sha256:${'d'.repeat(64)}`;
    assert.notEqual(store.stateDomainDigest, mismatchedDomain);
    const common = {
        capabilityReceipt: minted.capabilityReceipt,
        secret: minted.secret,
        store,
        trustedIssuerKeys: [keys.receipt.public_key],
        verifyBaseReceipt: () => true,
        executeAction: async () => 'executed',
        now: NOW,
        executionDomain: {
            executor_id: 'executor:only',
            expected_state_domain_digest: mismatchedDomain,
            single_executor_id: 'executor:only',
            require_aggregate: false,
        },
    };
    const accepted = await executeWithCapability({
        ...common,
        operationId: 'op_1',
        action: scopedAction('op_1', { amount: 30, destination: 'acct_a' }),
    });
    assert.equal(accepted.ok, true);
    assert.deepEqual(accepted.budget_guarantee, {
        mode: 'single_executor',
        executor_id: 'executor:only',
        state_domain_digest: null,
    });
    const refused = await executeWithCapability({
        ...common,
        operationId: 'op_2',
        action: scopedAction('op_2', { amount: 60 }),
        executionDomain: {
            ...common.executionDomain,
            executor_id: 'executor:other',
        },
    });
    assert.equal(refused.ok, false);
    assert.equal(refused.reason, 'capability_executor_mismatch');
});
test('per-action human authorization cannot be substituted by a policy allow or wrong-action proof', async () => {
    const keys = issuer();
    const action = scopedAction('op_1', { amount: 30, destination: 'acct_a' });
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'human-authorization-fail-closed',
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    let effects = 0;
    const common = {
        capabilityReceipt: minted.capabilityReceipt,
        secret: minted.secret,
        action,
        operationId: action.operation_id,
        store,
        trustedIssuerKeys: [keys.receipt.public_key],
        verifyBaseReceipt: () => ({ ok: true, allow: true, decision: 'policy_allow' }),
        executeAction: async () => { effects += 1; },
        now: NOW,
        executionDomain: {
            executor_id: 'executor:human',
            expected_state_domain_digest: store.stateDomainDigest,
            require_aggregate: true,
        },
        requireHumanAuthorization: true,
        humanAuthorizationPins: { verifier_profile: 'ep-human-authorization:v1' },
    };
    const missing = await executeWithCapability(common);
    assert.equal(missing.ok, false);
    assert.equal(missing.reason, 'capability_human_authorization_required');
    const policyShaped = await executeWithCapability({
        ...common,
        humanAuthorization: { receipt_id: 'human_policy_shape' },
        verifyHumanAuthorization: () => ({ ok: true, allow: true }),
    });
    assert.equal(policyShaped.ok, false);
    assert.equal(policyShaped.reason, 'capability_human_authorization_invalid');
    const wrongAction = await executeWithCapability({
        ...common,
        humanAuthorization: { receipt_id: 'human_wrong_action' },
        verifyHumanAuthorization: () => ({
            native_verification: 'VERIFIED',
            acceptance: 'ACCEPTED',
            evidence_type: 'human_authorization',
            action_digest: `sha256:${'f'.repeat(64)}`,
            evidence_digest: `sha256:${'e'.repeat(64)}`,
        }),
    });
    assert.equal(wrongAction.ok, false);
    assert.equal(wrongAction.reason, 'capability_human_authorization_action_mismatch');
    assert.equal(effects, 0);
    assert.equal(store.getState(minted.capabilityReceipt.capability.id).reserved_amount, 0);
});
test('matching atomic domain and native exact-action human authorization admit one valid exercise', async () => {
    const keys = issuer();
    const action = scopedAction('op_1', { amount: 30, destination: 'acct_a' });
    const actionDigest = capabilityActionDigest(action);
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: 'bounded-composition-valid',
    }));
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    const artifact = { receipt_id: 'human_valid', action_digest: actionDigest };
    const pins = {
        verifier_profile: 'ep-human-authorization:v1',
        issuer_key_digests: [`sha256:${'a'.repeat(64)}`],
    };
    let effects = 0;
    const result = await executeWithCapability({
        capabilityReceipt: minted.capabilityReceipt,
        secret: minted.secret,
        action,
        operationId: action.operation_id,
        store,
        trustedIssuerKeys: [keys.receipt.public_key],
        verifyBaseReceipt: () => ({ ok: true, allow: true, decision: 'policy_allow' }),
        executeAction: async (_executed, context) => {
            effects += 1;
            assert.equal(context.action_digest, actionDigest);
            assert.equal(context.human_authorization.evidence_digest, `sha256:${'b'.repeat(64)}`);
            assert.equal(context.budget_guarantee.mode, 'aggregate_atomic_domain');
            return 'executed';
        },
        now: NOW,
        executionDomain: {
            executor_id: 'executor:human',
            expected_state_domain_digest: store.stateDomainDigest,
            require_aggregate: true,
        },
        requireHumanAuthorization: true,
        humanAuthorization: artifact,
        humanAuthorizationPins: pins,
        verifyHumanAuthorization: (candidate, context) => {
            assert.deepEqual(candidate, artifact);
            assert.equal(context.action_digest, actionDigest);
            assert.deepEqual(context.pins, pins);
            assert.equal(Object.isFrozen(context.action), true);
            assert.equal(Object.isFrozen(context.pins), true);
            return {
                native_verification: 'VERIFIED',
                acceptance: 'ACCEPTED',
                evidence_type: 'human_authorization',
                action_digest: context.action_digest,
                evidence_digest: `sha256:${'b'.repeat(64)}`,
            };
        },
    });
    assert.equal(result.ok, true);
    assert.equal(effects, 1);
    assert.equal(result.human_authorization.native_verification, 'VERIFIED');
    assert.equal(result.human_authorization.action_digest, actionDigest);
    assert.deepEqual(result.budget_guarantee, {
        mode: 'aggregate_atomic_domain',
        executor_id: 'executor:human',
        state_domain_digest: store.stateDomainDigest,
    });
});
const FREEZE_ACTION_DIGEST = `sha256:${'a1'.repeat(32)}`;
const RESTORE_ACTION_DIGEST = `sha256:${'b2'.repeat(32)}`;
const CONTROL_AUTHORITY_DIGEST = `sha256:${'c3'.repeat(32)}`;
test('real PostgreSQL serializes emergency freeze against provider entry and preserves accounting', {
    skip: capabilityPostgresUrl ? false : 'ADMISSION_STORE_POSTGRES_TEST_URL is not configured',
}, async () => {
    const { Pool } = require('pg');
    const pool = new Pool({ connectionString: capabilityPostgresUrl, max: 8 });
    const schema = `ep_control_domain_${process.pid}_${Date.now()}`;
    function latch() {
        let release;
        const waiting = new Promise((resolve) => { release = resolve; });
        return { waiting, release };
    }
    const transactionFor = (hooks = {}) => async (callback) => {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query(`SET LOCAL search_path TO ${schema}, public`);
            const result = await callback(async (sql, params = []) => {
                await hooks.before?.(sql, params);
                const queried = await client.query(sql, [...params]);
                await hooks.after?.(sql, params);
                return { rowCount: queried.rowCount ?? 0, rows: queried.rows };
            });
            await client.query('COMMIT');
            return result;
        }
        catch (error) {
            await client.query('ROLLBACK');
            throw error;
        }
        finally {
            client.release();
        }
    };
    const transaction = transactionFor();
    try {
        await pool.query(`CREATE SCHEMA ${schema}`);
        const setup = await pool.connect();
        try {
            await setup.query(`SET search_path TO ${schema}, public`);
            await setup.query(CAPABILITY_STATE_DDL);
        }
        finally {
            setup.release();
        }
        const keys = issuer();
        const minted = mintCapabilityReceipt(keys.receipt, options({
            issuerPrivateKey: keys.privateKey,
            capabilityId: 'postgres_control_domain_capability',
        }));
        const store = createPostgresCapabilityStore({ transaction, verifyControlTransition });
        assert.equal(await store.registerCapability(minted.capabilityReceipt), true);
        assert.equal((await store.registerControlDomain({
            controlDomainId: 'postgres_control_domain',
            now: NOW,
        })).epoch, 1);
        const capabilityId = minted.capabilityReceipt.capability.id;
        const memory = createMemoryCapabilityStore();
        assert.equal(memory.registerCapability(minted.capabilityReceipt), true);
        const fingerprint = memory.getState(capabilityId).capability_fingerprint;
        const preFreezeAction = scopedAction('postgres_control_pre_entry', { amount: 10 });
        const held = await store.reserveSpend({
            capabilityId,
            capabilityFingerprint: fingerprint,
            controlDomainId: 'postgres_control_domain',
            operationId: preFreezeAction.operation_id,
            actionDigest: capabilityActionDigest(preFreezeAction),
            amount: 10,
            currency: 'USD',
            now: NOW,
        });
        assert.equal(held.ok, true);
        assert.equal(held.reserved_control_epoch, 1);
        const freeze = await store.freezeControlDomain({
            controlDomainId: 'postgres_control_domain',
            operationId: 'postgres_freeze_1',
            actionDigest: FREEZE_ACTION_DIGEST,
            authorization: controlAuthorization(FREEZE_ACTION_DIGEST),
            now: NOW + 1,
        });
        assert.equal(freeze.epoch, 2);
        const alreadyFrozen = await store.freezeControlDomain({
            controlDomainId: 'postgres_control_domain',
            operationId: 'postgres_freeze_already_frozen',
            actionDigest: FREEZE_ACTION_DIGEST,
            authorization: controlAuthorization(FREEZE_ACTION_DIGEST),
            now: NOW + 1,
        });
        assert.equal(alreadyFrozen.status, 'already_frozen');
        assert.equal(alreadyFrozen.epoch, 2);
        assert.equal((await store.beginProviderEntry({
            capabilityId,
            controlDomainId: 'postgres_control_domain',
            operationId: preFreezeAction.operation_id,
            reservationToken: held.reservation_token,
            now: NOW + 2,
        })).reservation, 'released');
        const releasedState = await pool.query(`
      SELECT consumed_amount, reserved_amount FROM ${schema}.ep_capability_state
      WHERE capability_id = $1
    `, [capabilityId]);
        assert.deepEqual(releasedState.rows[0], { consumed_amount: '0', reserved_amount: '0' });
        const releasedOperation = await pool.query(`
      SELECT status, outcome, release_reason FROM ${schema}.ep_capability_operations
      WHERE operation_id = $1
    `, [preFreezeAction.operation_id]);
        assert.deepEqual(releasedOperation.rows[0], {
            status: 'released',
            outcome: 'not_entered',
            release_reason: 'control_domain_frozen',
        });
        const restore = await store.restoreControlDomain({
            controlDomainId: 'postgres_control_domain',
            operationId: 'postgres_restore_1',
            actionDigest: RESTORE_ACTION_DIGEST,
            authorization: controlAuthorization(RESTORE_ACTION_DIGEST),
            now: NOW + 3,
        });
        assert.equal(restore.epoch, 3);
        const alreadyFrozenRetry = await store.freezeControlDomain({
            controlDomainId: 'postgres_control_domain',
            operationId: 'postgres_freeze_already_frozen',
            actionDigest: FREEZE_ACTION_DIGEST,
            authorization: controlAuthorization(FREEZE_ACTION_DIGEST, { currently_authorized: false }),
            now: NOW + 4,
        });
        assert.deepEqual(alreadyFrozenRetry, { ...alreadyFrozen, idempotent: true });
        assert.equal((await store.getControlDomain('postgres_control_domain')).status, 'active');
        assert.equal((await store.beginProviderEntry({
            capabilityId,
            controlDomainId: 'postgres_control_domain',
            operationId: preFreezeAction.operation_id,
            reservationToken: held.reservation_token,
            now: NOW + 4,
        })).reason, 'capability_operation_already_finalized');
        const enteredAction = scopedAction('postgres_control_entered', { amount: 10 });
        const next = await store.reserveSpend({
            capabilityId,
            capabilityFingerprint: fingerprint,
            controlDomainId: 'postgres_control_domain',
            operationId: enteredAction.operation_id,
            actionDigest: capabilityActionDigest(enteredAction),
            amount: 10,
            currency: 'USD',
            now: NOW + 5,
        });
        assert.equal((await store.beginProviderEntry({
            capabilityId,
            controlDomainId: 'postgres_control_domain',
            operationId: enteredAction.operation_id,
            reservationToken: next.reservation_token,
            now: NOW + 6,
        })).ok, true);
        assert.equal((await store.freezeControlDomain({
            controlDomainId: 'postgres_control_domain',
            operationId: 'postgres_freeze_2',
            actionDigest: FREEZE_ACTION_DIGEST,
            authorization: controlAuthorization(FREEZE_ACTION_DIGEST),
            now: NOW + 7,
        })).epoch, 4);
        assert.equal((await store.commitSpend({
            capabilityId,
            operationId: enteredAction.operation_id,
            reservationToken: next.reservation_token,
            outcome: 'indeterminate',
            now: NOW + 8,
        })).ok, true);
        const enteredState = await pool.query(`
      SELECT consumed_amount, reserved_amount FROM ${schema}.ep_capability_state
      WHERE capability_id = $1
    `, [capabilityId]);
        assert.deepEqual(enteredState.rows[0], { consumed_amount: '10', reserved_amount: '0' });
        const retry = await store.freezeControlDomain({
            controlDomainId: 'postgres_control_domain',
            operationId: 'postgres_freeze_2',
            actionDigest: FREEZE_ACTION_DIGEST,
            authorization: controlAuthorization(FREEZE_ACTION_DIGEST, { currently_authorized: false }),
            now: NOW + 9,
        });
        assert.equal(retry.idempotent, true);
        assert.equal(retry.epoch, 4);
        const events = await pool.query(`
      SELECT count(*)::int AS count FROM ${schema}.ep_gate_control_domain_events
      WHERE operation_id = 'postgres_freeze_2'
    `);
        assert.equal(events.rows[0].count, 1);
        assert.equal((await store.restoreControlDomain({
            controlDomainId: 'postgres_control_domain',
            operationId: 'postgres_restore_2',
            actionDigest: RESTORE_ACTION_DIGEST,
            authorization: controlAuthorization(RESTORE_ACTION_DIGEST),
            now: NOW + 10,
        })).epoch, 5);
        const entryFirstAction = scopedAction('postgres_entry_wins_race', { amount: 10 });
        const entryFirstReservation = await store.reserveSpend({
            capabilityId,
            capabilityFingerprint: fingerprint,
            controlDomainId: 'postgres_control_domain',
            operationId: entryFirstAction.operation_id,
            actionDigest: capabilityActionDigest(entryFirstAction),
            amount: 10,
            currency: 'USD',
            now: NOW + 11,
        });
        const entryLocked = latch();
        const releaseEntry = latch();
        const freezeReachedLock = latch();
        let entryHeld = false;
        const entryFirstStore = createPostgresCapabilityStore({
            transaction: transactionFor({
                async after(sql) {
                    if (!entryHeld && sql === CAPABILITY_SQL.readControlDomain) {
                        entryHeld = true;
                        entryLocked.release();
                        await releaseEntry.waiting;
                    }
                },
            }),
            verifyControlTransition,
        });
        const lateFreezeStore = createPostgresCapabilityStore({
            transaction: transactionFor({
                before(sql) {
                    if (sql === CAPABILITY_SQL.readControlDomain)
                        freezeReachedLock.release();
                },
            }),
            verifyControlTransition,
        });
        const entering = entryFirstStore.beginProviderEntry({
            capabilityId,
            controlDomainId: 'postgres_control_domain',
            operationId: entryFirstAction.operation_id,
            reservationToken: entryFirstReservation.reservation_token,
            now: NOW + 12,
        });
        await entryLocked.waiting;
        const freezingAfterEntry = lateFreezeStore.freezeControlDomain({
            controlDomainId: 'postgres_control_domain',
            operationId: 'postgres_freeze_entry_race',
            actionDigest: FREEZE_ACTION_DIGEST,
            authorization: controlAuthorization(FREEZE_ACTION_DIGEST),
            now: NOW + 13,
        });
        await freezeReachedLock.waiting;
        releaseEntry.release();
        assert.equal((await entering).ok, true);
        assert.equal((await freezingAfterEntry).epoch, 6);
        assert.equal((await store.commitSpend({
            capabilityId,
            operationId: entryFirstAction.operation_id,
            reservationToken: entryFirstReservation.reservation_token,
            outcome: 'indeterminate',
            now: NOW + 14,
        })).ok, true);
        assert.equal((await store.restoreControlDomain({
            controlDomainId: 'postgres_control_domain',
            operationId: 'postgres_restore_3',
            actionDigest: RESTORE_ACTION_DIGEST,
            authorization: controlAuthorization(RESTORE_ACTION_DIGEST),
            now: NOW + 15,
        })).epoch, 7);
        const freezeFirstAction = scopedAction('postgres_freeze_wins_race', { amount: 10 });
        const freezeFirstReservation = await store.reserveSpend({
            capabilityId,
            capabilityFingerprint: fingerprint,
            controlDomainId: 'postgres_control_domain',
            operationId: freezeFirstAction.operation_id,
            actionDigest: capabilityActionDigest(freezeFirstAction),
            amount: 10,
            currency: 'USD',
            now: NOW + 16,
        });
        const freezeLocked = latch();
        const releaseFreeze = latch();
        const entryReachedLock = latch();
        let freezeHeld = false;
        const freezeFirstStore = createPostgresCapabilityStore({
            transaction: transactionFor({
                async after(sql) {
                    if (!freezeHeld && sql === CAPABILITY_SQL.readControlDomain) {
                        freezeHeld = true;
                        freezeLocked.release();
                        await releaseFreeze.waiting;
                    }
                },
            }),
            verifyControlTransition,
        });
        const lateEntryStore = createPostgresCapabilityStore({
            transaction: transactionFor({
                before(sql) {
                    if (sql === CAPABILITY_SQL.readControlDomain)
                        entryReachedLock.release();
                },
            }),
            verifyControlTransition,
        });
        const freezingFirst = freezeFirstStore.freezeControlDomain({
            controlDomainId: 'postgres_control_domain',
            operationId: 'postgres_freeze_first_race',
            actionDigest: FREEZE_ACTION_DIGEST,
            authorization: controlAuthorization(FREEZE_ACTION_DIGEST),
            now: NOW + 17,
        });
        await freezeLocked.waiting;
        const enteringLate = lateEntryStore.beginProviderEntry({
            capabilityId,
            controlDomainId: 'postgres_control_domain',
            operationId: freezeFirstAction.operation_id,
            reservationToken: freezeFirstReservation.reservation_token,
            now: NOW + 18,
        });
        await entryReachedLock.waiting;
        releaseFreeze.release();
        assert.equal((await freezingFirst).epoch, 8);
        assert.equal((await enteringLate).reservation, 'released');
    }
    finally {
        await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
        await pool.end();
    }
});
function verifyControlTransition(input) {
    const authorization = input.authorization;
    if (!authorization || authorization.authenticated !== true) {
        return { authenticated: false, authorized: false };
    }
    return {
        authenticated: true,
        authorized: authorization.currently_authorized === true,
        authority_instance_digest: authorization.authority_instance_digest,
        action_digest: authorization.action_digest,
    };
}
function controlAuthorization(actionDigest, overrides = {}) {
    return {
        authenticated: true,
        currently_authorized: true,
        authority_instance_digest: CONTROL_AUTHORITY_DIGEST,
        action_digest: actionDigest,
        ...overrides,
    };
}
async function controlDomainHarness(prefix) {
    const keys = issuer();
    const minted = mintCapabilityReceipt(keys.receipt, options({
        issuerPrivateKey: keys.privateKey,
        capabilityId: `${prefix}_capability`,
    }));
    const store = createMemoryCapabilityStore({ verifyControlTransition });
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    assert.deepEqual(await store.registerControlDomain({
        controlDomainId: `${prefix}_domain`,
        now: NOW,
    }), {
        ok: true,
        idempotent: false,
        control_domain_id: `${prefix}_domain`,
        status: 'active',
        epoch: 1,
    });
    return { keys, minted, store, controlDomainId: `${prefix}_domain` };
}
test('capability accounting moves held budget to spent at provider entry and never debits again at commit', async () => {
    const { minted, store, controlDomainId } = await controlDomainHarness('entry_debit');
    const action = scopedAction('op_4', { amount: 10 });
    const capabilityId = minted.capabilityReceipt.capability.id;
    const reserved = await store.reserveSpend({
        capabilityId,
        capabilityFingerprint: store.getState(capabilityId).capability_fingerprint,
        controlDomainId,
        operationId: action.operation_id,
        actionDigest: capabilityActionDigest(action),
        amount: 10,
        currency: 'USD',
        now: NOW,
    });
    assert.equal(reserved.ok, true);
    assert.deepEqual({ reserved: store.getState(capabilityId).reserved_amount, consumed: store.getState(capabilityId).consumed_amount }, { reserved: 10, consumed: 0 });
    assert.equal(store.getOperation(action.operation_id, capabilityId).reserved_control_epoch, 1);
    assert.deepEqual(await store.beginProviderEntry({
        capabilityId,
        operationId: action.operation_id,
        reservationToken: reserved.reservation_token,
        now: NOW + 1,
    }), { ok: false, reason: 'capability_control_domain_required' });
    assert.deepEqual({ reserved: store.getState(capabilityId).reserved_amount, consumed: store.getState(capabilityId).consumed_amount }, { reserved: 10, consumed: 0 });
    assert.equal((await store.beginProviderEntry({
        capabilityId,
        controlDomainId,
        operationId: action.operation_id,
        reservationToken: reserved.reservation_token,
        now: NOW + 1,
    })).ok, true);
    assert.deepEqual({ reserved: store.getState(capabilityId).reserved_amount, consumed: store.getState(capabilityId).consumed_amount }, { reserved: 0, consumed: 10 });
    assert.equal((await store.commitSpend({
        capabilityId,
        operationId: action.operation_id,
        reservationToken: reserved.reservation_token,
        outcome: 'executed',
        now: NOW + 2,
    })).ok, true);
    assert.deepEqual({ reserved: store.getState(capabilityId).reserved_amount, consumed: store.getState(capabilityId).consumed_amount }, { reserved: 0, consumed: 10 });
});
test('freeze after reservation establishes non-entry, releases held budget, and restore never revives the old reservation', async () => {
    const { minted, store, controlDomainId } = await controlDomainHarness('freeze_before_entry');
    const capabilityId = minted.capabilityReceipt.capability.id;
    const action = scopedAction('crash_before_provider_entry', { amount: 10 });
    const reserved = await store.reserveSpend({
        capabilityId,
        capabilityFingerprint: store.getState(capabilityId).capability_fingerprint,
        controlDomainId,
        operationId: action.operation_id,
        actionDigest: capabilityActionDigest(action),
        amount: 10,
        currency: 'USD',
        now: NOW,
    });
    assert.equal(reserved.ok, true);
    const frozen = await store.freezeControlDomain({
        controlDomainId,
        operationId: 'freeze_1',
        actionDigest: FREEZE_ACTION_DIGEST,
        authorization: controlAuthorization(FREEZE_ACTION_DIGEST),
        now: NOW + 1,
    });
    assert.deepEqual(frozen, {
        ok: true,
        idempotent: false,
        status: 'frozen',
        control_domain_id: controlDomainId,
        epoch: 2,
    });
    const stopped = await store.beginProviderEntry({
        capabilityId,
        controlDomainId,
        operationId: action.operation_id,
        reservationToken: reserved.reservation_token,
        now: NOW + 2,
    });
    assert.deepEqual(stopped, {
        ok: false,
        reason: 'capability_control_domain_frozen',
        outcome: 'not_entered',
        reservation: 'released',
    });
    assert.equal(store.getOperation(action.operation_id, capabilityId).status, 'released');
    assert.deepEqual({ reserved: store.getState(capabilityId).reserved_amount, consumed: store.getState(capabilityId).consumed_amount }, { reserved: 0, consumed: 0 });
    const restored = await store.restoreControlDomain({
        controlDomainId,
        operationId: 'restore_1',
        actionDigest: RESTORE_ACTION_DIGEST,
        authorization: controlAuthorization(RESTORE_ACTION_DIGEST),
        now: NOW + 3,
    });
    assert.deepEqual(restored, {
        ok: true,
        idempotent: false,
        status: 'active',
        control_domain_id: controlDomainId,
        epoch: 3,
    });
    assert.equal((await store.beginProviderEntry({
        capabilityId,
        controlDomainId,
        operationId: action.operation_id,
        reservationToken: reserved.reservation_token,
        now: NOW + 4,
    })).reason, 'capability_operation_already_finalized');
});
test('provider entry that wins the freeze race stays consumed and reconcilable', async () => {
    const { minted, store, controlDomainId } = await controlDomainHarness('entry_before_freeze');
    const capabilityId = minted.capabilityReceipt.capability.id;
    const action = scopedAction('post_entry_negative_evidence', { amount: 10 });
    const reserved = await store.reserveSpend({
        capabilityId,
        capabilityFingerprint: store.getState(capabilityId).capability_fingerprint,
        controlDomainId,
        operationId: action.operation_id,
        actionDigest: capabilityActionDigest(action),
        amount: 10,
        currency: 'USD',
        now: NOW,
    });
    assert.equal((await store.beginProviderEntry({
        capabilityId,
        controlDomainId,
        operationId: action.operation_id,
        reservationToken: reserved.reservation_token,
        now: NOW + 1,
    })).ok, true);
    assert.equal((await store.freezeControlDomain({
        controlDomainId,
        operationId: 'freeze_after_entry',
        actionDigest: FREEZE_ACTION_DIGEST,
        authorization: controlAuthorization(FREEZE_ACTION_DIGEST),
        now: NOW + 2,
    })).ok, true);
    assert.equal((await store.commitSpend({
        capabilityId,
        operationId: action.operation_id,
        reservationToken: reserved.reservation_token,
        outcome: 'indeterminate',
        now: NOW + 3,
    })).ok, true);
    assert.equal(store.getOperation(action.operation_id, capabilityId).outcome, 'indeterminate');
    assert.deepEqual({ reserved: store.getState(capabilityId).reserved_amount, consumed: store.getState(capabilityId).consumed_amount }, { reserved: 0, consumed: 10 });
});
test('wrong holder cannot use a freeze to release another owner reservation', async () => {
    const { minted, store, controlDomainId } = await controlDomainHarness('wrong_holder_freeze');
    const capabilityId = minted.capabilityReceipt.capability.id;
    const action = scopedAction('crash_before_provider_entry', { amount: 10 });
    const reserved = await store.reserveSpend({
        capabilityId,
        capabilityFingerprint: store.getState(capabilityId).capability_fingerprint,
        controlDomainId,
        operationId: action.operation_id,
        actionDigest: capabilityActionDigest(action),
        amount: 10,
        currency: 'USD',
        now: NOW,
    });
    await store.freezeControlDomain({
        controlDomainId,
        operationId: 'freeze_wrong_holder',
        actionDigest: FREEZE_ACTION_DIGEST,
        authorization: controlAuthorization(FREEZE_ACTION_DIGEST),
        now: NOW + 1,
    });
    assert.equal((await store.beginProviderEntry({
        capabilityId,
        controlDomainId,
        operationId: action.operation_id,
        reservationToken: '00000000-0000-4000-8000-000000000000',
        now: NOW + 2,
    })).reason, 'capability_reservation_owner_mismatch');
    assert.equal(store.getOperation(action.operation_id, capabilityId).status, 'reserved');
    assert.equal(store.getState(capabilityId).reserved_amount, 10);
    assert.equal((await store.beginProviderEntry({
        capabilityId,
        controlDomainId,
        operationId: action.operation_id,
        reservationToken: reserved.reservation_token,
        now: NOW + 3,
    })).reservation, 'released');
});
test('control transition idempotency authenticates before returning a prior result', async () => {
    const { store, controlDomainId } = await controlDomainHarness('freeze_idempotency');
    const request = {
        controlDomainId,
        operationId: 'freeze_idempotent',
        actionDigest: FREEZE_ACTION_DIGEST,
        authorization: controlAuthorization(FREEZE_ACTION_DIGEST),
        now: NOW,
    };
    const first = await store.freezeControlDomain(request);
    assert.equal(first.idempotent, false);
    const expiredRetry = await store.freezeControlDomain({
        ...request,
        authorization: controlAuthorization(FREEZE_ACTION_DIGEST, { currently_authorized: false }),
        now: NOW + 60_000,
    });
    assert.deepEqual(expiredRetry, { ...first, idempotent: true });
    const unauthenticated = await store.freezeControlDomain({
        ...request,
        authorization: { authenticated: false },
        now: NOW + 60_001,
    });
    assert.deepEqual(unauthenticated, { ok: false, reason: 'control_transition_refused' });
    const substitutedAuthority = await store.freezeControlDomain({
        ...request,
        authorization: controlAuthorization(FREEZE_ACTION_DIGEST, {
            authority_instance_digest: `sha256:${'d4'.repeat(32)}`,
        }),
        now: NOW + 60_002,
    });
    assert.deepEqual(substitutedAuthority, { ok: false, reason: 'control_transition_refused' });
    assert.equal(store.getControlDomain(controlDomainId).epoch, 2);
});
test('an already-frozen transition is recorded and cannot be replayed after restore', async () => {
    const { store, controlDomainId } = await controlDomainHarness('already_frozen_idempotency');
    assert.equal((await store.freezeControlDomain({
        controlDomainId,
        operationId: 'freeze_primary',
        actionDigest: FREEZE_ACTION_DIGEST,
        authorization: controlAuthorization(FREEZE_ACTION_DIGEST),
        now: NOW,
    })).status, 'frozen');
    const whileFrozen = await store.freezeControlDomain({
        controlDomainId,
        operationId: 'freeze_while_already_frozen',
        actionDigest: FREEZE_ACTION_DIGEST,
        authorization: controlAuthorization(FREEZE_ACTION_DIGEST),
        now: NOW + 1,
    });
    assert.deepEqual(whileFrozen, {
        ok: true,
        idempotent: false,
        status: 'already_frozen',
        control_domain_id: controlDomainId,
        epoch: 2,
    });
    assert.equal(store.getControlDomainEvent('freeze_while_already_frozen').epoch_at_event, 2);
    assert.equal((await store.restoreControlDomain({
        controlDomainId,
        operationId: 'restore_after_already_frozen',
        actionDigest: RESTORE_ACTION_DIGEST,
        authorization: controlAuthorization(RESTORE_ACTION_DIGEST),
        now: NOW + 2,
    })).status, 'active');
    const retry = await store.freezeControlDomain({
        controlDomainId,
        operationId: 'freeze_while_already_frozen',
        actionDigest: FREEZE_ACTION_DIGEST,
        authorization: controlAuthorization(FREEZE_ACTION_DIGEST, { currently_authorized: false }),
        now: NOW + 3,
    });
    assert.deepEqual(retry, { ...whileFrozen, idempotent: true });
    assert.equal(store.getControlDomain(controlDomainId).status, 'active');
    assert.equal(store.getControlDomain(controlDomainId).epoch, 3);
});
