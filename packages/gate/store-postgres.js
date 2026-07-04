// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — reference DURABLE consumption backend: Postgres
 * (EP-GATE-PG-CONSUMPTION-v1).
 *
 * Replay defense that survives restarts. This module implements the backend
 * contract consumed by `createDurableConsumptionStore` in ./store.js:
 *
 *   backend = {
 *     async addIfAbsent(key, value, { ttlSeconds }?) : boolean  // true iff inserted
 *     async set(key, value, { ttlSeconds }?)         : void     // overwrite
 *     async delete(key)                              : void
 *     async has(key)                                 : boolean
 *   }
 *
 * plus a `cleanupExpired(now)` garbage-collection statement.
 *
 * THE ONE CORRECTNESS PRIMITIVE — atomic insert-if-absent. `addIfAbsent` is a
 * SINGLE statement: `INSERT ... ON CONFLICT (consumption_key) DO NOTHING`, and
 * the returned row count decides consumed-vs-replay. There is no read-then-
 * write, so there is no race: when two pods consume the same receipt id
 * concurrently, Postgres serializes the inserts on the primary key and exactly
 * one caller sees rowCount === 1. Everyone else is a replay.
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

export const PG_CONSUMPTION_VERSION = 'EP-GATE-PG-CONSUMPTION-v1';

/** Single consumption table. Timestamps are epoch milliseconds (BIGINT) so the
 * injected JS clock maps 1:1 onto column values with no timezone ambiguity. */
export const CONSUMPTION_TABLE = 'ep_gate_consumption';

export const CONSUMPTION_TABLE_DDL = `CREATE TABLE IF NOT EXISTS ${CONSUMPTION_TABLE} (
  consumption_key TEXT PRIMARY KEY,
  state           TEXT NOT NULL,
  consumed_at     BIGINT NOT NULL,
  expires_at      BIGINT
);
CREATE INDEX IF NOT EXISTS ${CONSUMPTION_TABLE}_expires_idx
  ON ${CONSUMPTION_TABLE} (expires_at) WHERE expires_at IS NOT NULL;`;

/** The exact statements the backend issues — exported for transparency and so
 * a fake client can implement them without parsing SQL. */
export const CONSUMPTION_SQL = {
  /** $1 key, $2 state, $3 consumed_at ms, $4 expires_at ms|null. rowCount 1 = consumed, 0 = replay. */
  addIfAbsent: `INSERT INTO ${CONSUMPTION_TABLE} (consumption_key, state, consumed_at, expires_at) `
    + 'VALUES ($1, $2, $3, $4) ON CONFLICT (consumption_key) DO NOTHING',
  /** $1 key, $2 state, $3 consumed_at ms, $4 expires_at ms|null. Upsert (overwrite). */
  set: `INSERT INTO ${CONSUMPTION_TABLE} (consumption_key, state, consumed_at, expires_at) `
    + 'VALUES ($1, $2, $3, $4) ON CONFLICT (consumption_key) DO UPDATE '
    + 'SET state = EXCLUDED.state, consumed_at = EXCLUDED.consumed_at, expires_at = EXCLUDED.expires_at',
  /** $1 key. */
  delete: `DELETE FROM ${CONSUMPTION_TABLE} WHERE consumption_key = $1`,
  /** $1 key. Any row — even an expired one — counts as consumed until cleaned. */
  has: `SELECT 1 FROM ${CONSUMPTION_TABLE} WHERE consumption_key = $1`,
  /** $1 now ms. Removes ONLY rows whose TTL has elapsed; NULL expires_at never expires. */
  cleanupExpired: `DELETE FROM ${CONSUMPTION_TABLE} WHERE expires_at IS NOT NULL AND expires_at <= $1`,
};

/**
 * Create the Postgres consumption backend.
 * @param {object} o
 * @param {(text: string, params: any[]) => Promise<{ rowCount: number, rows?: any[] }>} o.query
 *   pg-style query function (e.g. `pool.query.bind(pool)`). Injected so tests
 *   need no database. MUST throw on failure — errors propagate (fail closed).
 * @param {number|function} [o.now=Date.now] injected clock (ms or () => ms).
 * @returns backend conforming to createDurableConsumptionStore, plus cleanupExpired(now).
 */
export function createPostgresBackend({ query, now = Date.now } = {}) {
  if (typeof query !== 'function') {
    throw new Error('createPostgresBackend: query must be an async (text, params) => { rowCount } function '
      + '(e.g. pg pool.query). It must THROW on failure — a backend error must never look like a verdict.');
  }
  const nowMs = () => (typeof now === 'function' ? now() : now);
  const expiryFor = (opt) => {
    const ttl = Number(opt?.ttlSeconds);
    return Number.isFinite(ttl) && ttl > 0 ? nowMs() + ttl * 1000 : null;
  };

  return {
    /** True iff THIS call inserted the row — the atomic consumed-vs-replay decision. */
    async addIfAbsent(key, value, opt) {
      const res = await query(CONSUMPTION_SQL.addIfAbsent, [key, value, nowMs(), expiryFor(opt)]);
      // Fail closed on a malformed driver result: without a numeric rowCount we
      // cannot PROVE first-use, so refuse loudly rather than guess.
      if (!res || typeof res.rowCount !== 'number') {
        throw new Error('addIfAbsent: query result has no numeric rowCount — cannot prove one-time use');
      }
      return res.rowCount === 1;
    },

    /** Overwrite (used by commit(): 'reserved' -> 'committed'). */
    async set(key, value, opt) {
      await query(CONSUMPTION_SQL.set, [key, value, nowMs(), expiryFor(opt)]);
    },

    /** Remove (used by release(): a failed action leaves the approval retryable). */
    async delete(key) {
      await query(CONSUMPTION_SQL.delete, [key]);
    },

    /** Present = consumed. Expired-but-uncleaned rows still count (conservative). */
    async has(key) {
      const res = await query(CONSUMPTION_SQL.has, [key]);
      return (res?.rows?.length ?? res?.rowCount ?? 0) > 0;
    },

    /** Garbage-collect rows whose TTL elapsed. Returns the number removed. */
    async cleanupExpired(at = nowMs()) {
      const res = await query(CONSUMPTION_SQL.cleanupExpired, [at]);
      return res?.rowCount ?? 0;
    },
  };
}

export default { createPostgresBackend, CONSUMPTION_TABLE_DDL, CONSUMPTION_TABLE, CONSUMPTION_SQL, PG_CONSUMPTION_VERSION };
