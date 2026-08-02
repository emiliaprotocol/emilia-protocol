// SPDX-License-Identifier: Apache-2.0
// Generated from authority-allocation.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import test from 'node:test';
import { AUTHORITY_ALLOCATION_DDL, AUTHORITY_ALLOCATION_SQL, AUTHORITY_ALLOCATION_VERSION, AuthorityAllocationValidationError, createMemoryAuthorityAllocationStore, createPostgresAuthorityAllocationStore, isDurableAuthorityAllocationStore, validateAuthorityAllocationSnapshot, } from './authority-allocation.js';
const HEAD = `sha256:${'1'.repeat(64)}`;
const NOW = '2026-07-24T12:00:00.000Z';
const EXPIRY = '2026-07-25T12:00:00.000Z';
const PIN = {
    relying_party_id: 'rp:merchant-control',
    authority_head: HEAD,
    authority_epoch: 17,
};
function snapshot(overrides = {}) {
    return {
        version: AUTHORITY_ALLOCATION_VERSION,
        relying_party_id: PIN.relying_party_id,
        parent_id: 'authority:treasury',
        authority_head: PIN.authority_head,
        authority_epoch: PIN.authority_epoch,
        actions: ['inspect', 'release'],
        audiences: ['merchant-a', 'merchant-b'],
        budget: { cents: 100, calls: 4 },
        max_active_children: 2,
        expires_at: EXPIRY,
        sibling_allocations: [
            {
                allocation_id: 'branch:a',
                parent_id: 'authority:treasury',
                actions: ['release'],
                audiences: ['merchant-a'],
                budget: { cents: 60, calls: 2 },
                expires_at: EXPIRY,
            },
            {
                allocation_id: 'branch:b',
                parent_id: 'authority:treasury',
                actions: ['inspect'],
                audiences: ['merchant-b'],
                budget: { cents: 40, calls: 2 },
                expires_at: EXPIRY,
            },
        ],
        ...overrides,
    };
}
function validationCode(run) {
    try {
        run();
        return undefined;
    }
    catch (error) {
        assert.ok(error instanceof AuthorityAllocationValidationError);
        return error.code;
    }
}
function reservation(reservationId, allocationId = 'branch:a', budget = { cents: 40, calls: 1 }) {
    return {
        relying_party_id: PIN.relying_party_id,
        parent_id: 'authority:treasury',
        allocation_id: allocationId,
        reservation_id: reservationId,
        authority_head: PIN.authority_head,
        authority_epoch: PIN.authority_epoch,
        budget,
        now: NOW,
    };
}
test('rejects stale or missing relying-party authority pins', () => {
    assert.equal(validationCode(() => validateAuthorityAllocationSnapshot(snapshot(), { ...PIN, authority_epoch: 18 })), 'authority_pin_mismatch');
    assert.equal(validationCode(() => validateAuthorityAllocationSnapshot(snapshot(), { ...PIN, authority_head: undefined })), 'missing_authority_pin');
});
test('rejects child audience widening', () => {
    const base = snapshot();
    assert.equal(validationCode(() => validateAuthorityAllocationSnapshot(snapshot({
        sibling_allocations: [
            { ...base.sibling_allocations[0], audiences: ['merchant-a', 'merchant-c'] },
        ],
    }), PIN)), 'child_audience_widening');
});
test('rejects action or expiry widening and duplicate branches', () => {
    const base = snapshot();
    assert.equal(validationCode(() => validateAuthorityAllocationSnapshot(snapshot({
        sibling_allocations: [
            { ...base.sibling_allocations[0], actions: ['release', 'delete'] },
        ],
    }), PIN)), 'child_action_widening');
    assert.equal(validationCode(() => validateAuthorityAllocationSnapshot(snapshot({
        sibling_allocations: [
            { ...base.sibling_allocations[0], expires_at: '2026-07-26T12:00:00.000Z' },
        ],
    }), PIN)), 'child_expiry_widening');
    assert.equal(validationCode(() => validateAuthorityAllocationSnapshot(snapshot({
        sibling_allocations: [
            base.sibling_allocations[0],
            { ...base.sibling_allocations[0] },
        ],
    }), PIN)), 'duplicate_branch');
});
test('rejects aggregate sibling cents overspend', () => {
    const base = snapshot();
    assert.equal(validationCode(() => validateAuthorityAllocationSnapshot(snapshot({
        sibling_allocations: [
            base.sibling_allocations[0],
            { ...base.sibling_allocations[1], budget: { cents: 41, calls: 2 } },
        ],
    }), PIN)), 'aggregate_sibling_overspend');
});
test('conserves the calls dimension independently of cents', () => {
    const base = snapshot();
    assert.equal(validationCode(() => validateAuthorityAllocationSnapshot(snapshot({
        sibling_allocations: [
            base.sibling_allocations[0],
            { ...base.sibling_allocations[1], budget: { cents: 40, calls: 3 } },
        ],
    }), PIN)), 'aggregate_sibling_overspend');
});
test('limits active sibling allocations independently of their resource budgets', () => {
    const base = snapshot();
    assert.equal(validationCode(() => validateAuthorityAllocationSnapshot(snapshot({
        max_active_children: 1,
        sibling_allocations: base.sibling_allocations,
    }), PIN)), 'active_child_limit_exceeded');
    assert.equal(validationCode(() => validateAuthorityAllocationSnapshot(snapshot({
        max_active_children: 0,
    }), PIN)), 'invalid_active_child_limit');
});
test('rejects N-sibling aggregate over-allocation, not only the two-child case', () => {
    const base = snapshot();
    assert.equal(validationCode(() => validateAuthorityAllocationSnapshot(snapshot({
        budget: { cents: 100, calls: 6 },
        max_active_children: 3,
        sibling_allocations: [
            { ...base.sibling_allocations[0], allocation_id: 'branch:a', budget: { cents: 34, calls: 2 } },
            { ...base.sibling_allocations[0], allocation_id: 'branch:b', budget: { cents: 34, calls: 2 } },
            { ...base.sibling_allocations[0], allocation_id: 'branch:c', budget: { cents: 34, calls: 2 } },
        ],
    }), PIN)), 'aggregate_sibling_overspend');
});
test('stale reservation epoch is refused against the exact installed head and epoch', async () => {
    const store = createMemoryAuthorityAllocationStore();
    assert.deepEqual((await store.installSnapshot(snapshot(), PIN)).ok, true);
    const result = await store.reserve({
        ...reservation('reservation:stale'),
        authority_epoch: PIN.authority_epoch - 1,
    });
    assert.deepEqual(result, { ok: false, reason: 'authority_pin_mismatch' });
});
test('concurrent conflicting reservations linearize and committed state stays bounded', async () => {
    const store = createMemoryAuthorityAllocationStore();
    await store.installSnapshot(snapshot(), PIN);
    const results = await Promise.all([
        store.reserve(reservation('reservation:race-a')),
        store.reserve(reservation('reservation:race-b')),
    ]);
    const winners = results.filter((result) => result.ok);
    assert.equal(winners.length, 1);
    assert.equal(results.filter((result) => !result.ok && result.reason === 'budget_exceeded').length, 1);
    const winner = winners[0];
    assert.ok(winner?.ok);
    assert.deepEqual(await store.commit({
        relying_party_id: PIN.relying_party_id,
        parent_id: 'authority:treasury',
        allocation_id: winner.allocation_id,
        reservation_id: winner.reservation_id,
        ...winner.owner,
    }), { ok: true, state: 'committed' });
    const committed = await store.inspect({ ...PIN, parent_id: 'authority:treasury' });
    assert.ok(committed);
    assert.deepEqual(committed.usage.parent, {
        reserved: { cents: 0, calls: 0 },
        committed: { cents: 40, calls: 1 },
    });
    assert.deepEqual(committed.usage.branches['branch:a'], {
        reserved: { cents: 0, calls: 0 },
        committed: { cents: 40, calls: 1 },
    });
    assert.equal(committed.reservations.length, 1);
    assert.equal(committed.reservations[0].state, 'committed');
    assert.equal(Object.hasOwn(committed.reservations[0], 'owner_token'), false);
});
test('reservation replay and wrong owner or fence cannot mutate committed state', async () => {
    const store = createMemoryAuthorityAllocationStore();
    await store.installSnapshot(snapshot(), PIN);
    const reserved = await store.reserve(reservation('reservation:owned'));
    assert.ok(reserved.ok);
    const finalize = {
        relying_party_id: PIN.relying_party_id,
        parent_id: 'authority:treasury',
        allocation_id: reserved.allocation_id,
        reservation_id: reserved.reservation_id,
        ...reserved.owner,
    };
    assert.deepEqual(await store.commit({
        ...finalize,
        owner_token: 'authority-owner:v1:wrong_owner_token_000000000000',
    }), { ok: false, reason: 'reservation_owner_mismatch' });
    assert.deepEqual(await store.commit({
        ...finalize,
        fencing_token: finalize.fencing_token + 1,
    }), { ok: false, reason: 'reservation_owner_mismatch' });
    assert.deepEqual(await store.commit(finalize), { ok: true, state: 'committed' });
    assert.deepEqual(await store.commit(finalize), {
        ok: false,
        reason: 'reservation_already_committed',
    });
    assert.deepEqual(await store.reserve(reservation('reservation:owned')), {
        ok: false,
        reason: 'reservation_replayed',
    });
    const committed = await store.inspect({ ...PIN, parent_id: 'authority:treasury' });
    assert.deepEqual(committed?.usage.parent.committed, { cents: 40, calls: 1 });
});
test('PostgreSQL boundary is durable, transaction-locked, fenced, and owner-digesting', () => {
    const store = createPostgresAuthorityAllocationStore({
        transaction: async (callback) => callback(async () => ({ rowCount: 0, rows: [] })),
    });
    assert.equal(isDurableAuthorityAllocationStore(store), true);
    assert.match(AUTHORITY_ALLOCATION_DDL, /PRIMARY KEY \(relying_party_id, parent_id, reservation_id\)/);
    assert.match(AUTHORITY_ALLOCATION_DDL, /UNIQUE \(relying_party_id, parent_id, fencing_token\)/);
    assert.match(AUTHORITY_ALLOCATION_DDL, /owner_digest/);
    assert.doesNotMatch(AUTHORITY_ALLOCATION_DDL, /owner_token/);
    assert.match(AUTHORITY_ALLOCATION_SQL.lockParent, /pg_advisory_xact_lock/);
    assert.match(AUTHORITY_ALLOCATION_SQL.nextFence, /next_fencing_token = next_fencing_token \+ 1/);
    assert.match(AUTHORITY_ALLOCATION_SQL.commitReservation, /authority_head = \$5/);
    assert.match(AUTHORITY_ALLOCATION_SQL.commitReservation, /authority_epoch = \$6/);
});
