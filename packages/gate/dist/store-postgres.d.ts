/**
 * EMILIA Gate — reference DURABLE consumption backend: Postgres
 * (EP-GATE-PG-CONSUMPTION-v2).
 *
 * Replay defense that survives restarts. This module implements the backend
 * contract consumed by `createDurableConsumptionStore` in ./store.js:
 *
 *   backend = {
 *     async addIfAbsent(key, value, { ttlSeconds }?) : boolean  // true iff inserted
 *     async compareAndSet(key, expected, replacement, { ttlSeconds }?) : boolean
 *     async deleteIfValue(key, expected)             : boolean
 *     async has(key)                                 : boolean
 *   }
 *
 * plus a `cleanupExpired(now)` garbage-collection statement.
 *
 * Each transition is one SQL statement. `addIfAbsent` decides first use;
 * `compareAndSet` and `deleteIfValue` bind commit/release to the opaque owner of
 * the current reservation. There is no read-then-write interval in which a
 * delayed worker can overwrite or remove a newer worker's reservation.
 *
 * FAIL-CLOSED CONTRACT: if the injected `query` THROWS (connection down,
 * timeout, constraint other than the PK, ...) the error PROPAGATES to the
 * caller — nothing here catches it. The gate must refuse an action when
 * one-time-use cannot be proven; a backend error is NEVER treated as
 * not-consumed (which would admit replays during an outage) and never treated
 * as consumed-silently (which would mask the outage as a replay verdict).
 * Likewise, an EXPIRED row that cleanup has not yet removed still refuses:
 * TTL expiry is garbage collection, never a grant — the gate already rejects
 * stale receipts on freshness, so nothing is lost by refusing conservatively.
 *
 * Deterministic by construction: the pg-style `query(text, params)` function
 * and the clock (`now`) are both injected, so tests run against an in-memory
 * fake with real ON CONFLICT semantics — no network, no database.
 */
export declare const PG_CONSUMPTION_VERSION = "EP-GATE-PG-CONSUMPTION-v2";
/** Single consumption table. Timestamps are epoch milliseconds (BIGINT) so the
 * injected JS clock maps 1:1 onto column values with no timezone ambiguity. */
export declare const CONSUMPTION_TABLE = "ep_gate_consumption";
export declare const CONSUMPTION_TABLE_DDL = "CREATE TABLE IF NOT EXISTS ep_gate_consumption (\n  consumption_key TEXT PRIMARY KEY,\n  state           TEXT NOT NULL,\n  consumed_at     BIGINT NOT NULL,\n  expires_at      BIGINT\n);\nCREATE INDEX IF NOT EXISTS ep_gate_consumption_expires_idx\n  ON ep_gate_consumption (expires_at) WHERE expires_at IS NOT NULL;";
/** The exact statements the backend issues — exported for transparency and so
 * a fake client can implement them without parsing SQL. */
export declare const CONSUMPTION_SQL: {
    health: string;
    /** $1 key, $2 state, $3 consumed_at ms, $4 expires_at ms|null. rowCount 1 = consumed, 0 = replay. */
    addIfAbsent: string;
    /** $1 key, $2 expected state, $3 replacement, $4 consumed_at ms, $5 expires_at ms|null. */
    compareAndSet: string;
    /** $1 key, $2 expected state. */
    deleteIfValue: string;
    /** $1 key. Any row — even an expired one — counts as consumed until cleaned. */
    has: string;
    /** $1 now ms. Removes ONLY rows whose TTL has elapsed; NULL expires_at never expires. */
    cleanupExpired: string;
};
/**
 * Create the Postgres consumption backend.
 * @param {{ query?: (text: string, params: any[]) => Promise<{ rowCount: number, rows?: any[] }>, now?: number|function }} [o]
 *   `query` is a pg-style query function (e.g. `pool.query.bind(pool)`). Injected
 *   so tests need no database. MUST throw on failure — errors propagate (fail
 *   closed). `now` is the injected clock (ms or () => ms).
 * @returns backend conforming to createDurableConsumptionStore, plus cleanupExpired(now).
 */
export declare function createPostgresBackend({ query, now, }?: {
    query?: (text: string, params: any[]) => Promise<{
        rowCount: number;
        rows?: any[];
    }>;
    now?: number | (() => number);
}): {
    durable: boolean;
    health(): Promise<{
        ok: boolean;
        version: string;
    }>;
    /** True iff THIS call inserted the row — the atomic consumed-vs-replay decision. */
    addIfAbsent(key: any, value: any, opt: any): Promise<boolean>;
    /** Ownership-fenced reserved -> committed transition. */
    compareAndSet(key: any, expected: any, replacement: any, opt: any): Promise<boolean>;
    /** Remove only the reservation owned by the caller. */
    deleteIfValue(key: any, expected: any): Promise<boolean>;
    /** Present = consumed. Expired-but-uncleaned rows still count (conservative). */
    has(key: any): Promise<boolean>;
    /** Garbage-collect rows whose TTL elapsed. Returns the number removed. */
    cleanupExpired(at: any): Promise<number>;
};
declare const _default: {
    createPostgresBackend: typeof createPostgresBackend;
    CONSUMPTION_TABLE_DDL: string;
    CONSUMPTION_TABLE: string;
    CONSUMPTION_SQL: {
        health: string;
        /** $1 key, $2 state, $3 consumed_at ms, $4 expires_at ms|null. rowCount 1 = consumed, 0 = replay. */
        addIfAbsent: string;
        /** $1 key, $2 expected state, $3 replacement, $4 consumed_at ms, $5 expires_at ms|null. */
        compareAndSet: string;
        /** $1 key, $2 expected state. */
        deleteIfValue: string;
        /** $1 key. Any row — even an expired one — counts as consumed until cleaned. */
        has: string;
        /** $1 now ms. Removes ONLY rows whose TTL has elapsed; NULL expires_at never expires. */
        cleanupExpired: string;
    };
    PG_CONSUMPTION_VERSION: string;
};
export default _default;
//# sourceMappingURL=store-postgres.d.ts.map