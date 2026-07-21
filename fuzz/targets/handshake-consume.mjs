// SPDX-License-Identifier: Apache-2.0
// Generated from handshake-consume.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Fuzz target: consume-once under concurrency.
//
// SCOPE, stated honestly. The production handshake consume-once guarantee
// (lib/handshake/consume.js) is enforced inside PostgreSQL: the
// `consume_handshake_atomic` RPC takes FOR UPDATE on the handshake row and a
// UNIQUE constraint on handshake_id in handshake_consumptions makes a second
// consume a 23505 error (migrations 074 / 085). That path is NOT runnable in a
// CI fuzz harness — it needs a live Supabase/Postgres — so this target does not
// pretend to drive it.
//
// What it DOES drive is the real, shipped, in-process consumption store that
// enforces the identical invariant the handshake DB path mirrors: a receipt /
// key authorizes exactly ONE action, once. `MemoryConsumptionStore` and
// `createDurableConsumptionStore` are imported unmodified from
// packages/gate/store.js. The durable-store scenario runs several independent
// store instances over ONE shared backend — the fleet model (many pods, one
// Redis/Postgres) — which is exactly where a naive check-then-act consume would
// double-execute. The invariant is: across all concurrent consumers of a single
// key, exactly one succeeds.
import { MemoryConsumptionStore, createDurableConsumptionStore, createMemoryBackend, } from '../../packages/gate/store.js';
import { invariant, interleave } from '../harness.mjs';
export default {
    name: 'handshake-consume',
    invariants: [
        'consume-once (exactly one concurrent consumer succeeds)',
        'no-consume-after-commit',
        'reservation-ownership-fenced',
    ],
    async iterate({ rng, iteration }) {
        const key = `handshake:${iteration}:${rng.int(0, 1_000_000)}`;
        let opsDriven = 0;
        // ── Scenario A: direct single-shot consume() on the gate store ─────────
        // N consumers race consume(key). Replay defense requires exactly one true.
        {
            const store = new MemoryConsumptionStore();
            const consumers = rng.int(2, 32);
            opsDriven += consumers;
            let successes = 0;
            const ops = [];
            for (let i = 0; i < consumers; i += 1) {
                ops.push([
                    async () => {
                        const ok = await store.consume(key);
                        if (ok)
                            successes += 1;
                    },
                ]);
            }
            await interleave(ops, rng);
            invariant(successes === 1, 'consume-once (exactly one concurrent consumer succeeds)', `${consumers} consumers, ${successes} succeeded (expected 1)`);
            // A post-hoc consume must also fail: the key is spent.
            invariant((await store.consume(key)) === false, 'no-consume-after-commit', 'a later consume of an already-consumed key succeeded');
        }
        // ── Scenario B: fleet reserve/commit over ONE shared backend ───────────
        // Independent durable-store instances model separate pods sharing a single
        // atomic backend. Only one may reserve the key; only that owner may commit;
        // a foreign store must not be able to commit or release another's
        // reservation, and once committed the key must never consume again.
        {
            const backend = createMemoryBackend();
            const pods = rng.int(2, 16);
            opsDriven += pods;
            const stores = Array.from({ length: pods }, () => createDurableConsumptionStore(backend));
            const reserved = new Array(pods).fill(false);
            let reserveWins = 0;
            let ownerIndex = -1;
            // Phase 1: every pod tries to reserve the same key, interleaved.
            const reserveOps = stores.map((store, i) => [
                async () => {
                    const ok = await store.reserve(key);
                    reserved[i] = ok;
                    if (ok) {
                        reserveWins += 1;
                        ownerIndex = i;
                    }
                },
            ]);
            await interleave(reserveOps, rng);
            invariant(reserveWins === 1, 'consume-once (exactly one concurrent consumer succeeds)', `${pods} pods reserved the key, ${reserveWins} won (expected 1)`);
            // Phase 2: a NON-owner attempting to commit must be refused (ownership
            // fencing throws inside the store); the owner's commit must succeed.
            for (let i = 0; i < pods; i += 1) {
                if (i === ownerIndex)
                    continue;
                let refused = false;
                try {
                    await stores[i].commit(key);
                }
                catch {
                    refused = true;
                }
                invariant(refused, 'reservation-ownership-fenced', `pod ${i} committed a reservation owned by pod ${ownerIndex}`);
            }
            await stores[ownerIndex].commit(key);
            // Phase 3: the key is now committed; no store may consume it again.
            const late = createDurableConsumptionStore(backend);
            invariant((await late.consume(key)) === false, 'no-consume-after-commit', 'consume succeeded on an already-committed key');
            return { ops: opsDriven };
        }
    },
};
