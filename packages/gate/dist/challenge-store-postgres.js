// @ts-nocheck
export const AE_CHALLENGE_POSTGRES_OWNER_VERSION = 'EP-AE-CHALLENGE-PG-OWNER-v1';
export const AE_CHALLENGE_LOCK_TABLE = 'ep_ae_challenge_owner_locks';
export const AE_CHALLENGE_RECORD_TABLE = 'ep_ae_challenge_owner_records';
export const AE_CHALLENGE_CAPACITY_TABLE = 'ep_ae_challenge_owner_capacity';
export const AE_CHALLENGE_OWNER_DDL = `CREATE TABLE IF NOT EXISTS ${AE_CHALLENGE_LOCK_TABLE} (
  owner_id   TEXT NOT NULL,
  replay_key TEXT NOT NULL,
  PRIMARY KEY (owner_id, replay_key)
);
CREATE TABLE IF NOT EXISTS ${AE_CHALLENGE_RECORD_TABLE} (
  owner_id    TEXT NOT NULL,
  replay_key  TEXT NOT NULL,
  record_json TEXT NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (owner_id, replay_key),
  FOREIGN KEY (owner_id, replay_key)
    REFERENCES ${AE_CHALLENGE_LOCK_TABLE} (owner_id, replay_key)
);
CREATE TABLE IF NOT EXISTS ${AE_CHALLENGE_CAPACITY_TABLE} (
  owner_id   TEXT NOT NULL,
  bucket_key TEXT NOT NULL,
  used_units BIGINT NOT NULL CHECK (used_units >= 0),
  hard_limit BIGINT NOT NULL CHECK (hard_limit > 0 AND used_units <= hard_limit),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (owner_id, bucket_key)
);`;
export const AE_CHALLENGE_POSTGRES_SQL = Object.freeze({
    begin: 'BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE',
    commit: 'COMMIT',
    rollback: 'ROLLBACK',
    authoritativeNow: `SELECT floor(extract(epoch FROM transaction_timestamp()) * 1000)::bigint AS now_ms`,
    ensureChallengeLock: `INSERT INTO ${AE_CHALLENGE_LOCK_TABLE} (owner_id, replay_key)
VALUES ($1, $2) ON CONFLICT (owner_id, replay_key) DO NOTHING`,
    lockChallenge: `SELECT replay_key FROM ${AE_CHALLENGE_LOCK_TABLE}
WHERE owner_id = $1 AND replay_key = $2 FOR UPDATE`,
    readChallenge: `SELECT record_json FROM ${AE_CHALLENGE_RECORD_TABLE}
WHERE owner_id = $1 AND replay_key = $2`,
    insertChallenge: `INSERT INTO ${AE_CHALLENGE_RECORD_TABLE} (owner_id, replay_key, record_json)
VALUES ($1, $2, $3) ON CONFLICT (owner_id, replay_key) DO NOTHING`,
    writeChallenge: `UPDATE ${AE_CHALLENGE_RECORD_TABLE}
SET record_json = $3, updated_at = transaction_timestamp()
WHERE owner_id = $1 AND replay_key = $2`,
    ensureCapacity: `INSERT INTO ${AE_CHALLENGE_CAPACITY_TABLE}
  (owner_id, bucket_key, used_units, hard_limit)
VALUES ($1, $2, 0, $3)
ON CONFLICT (owner_id, bucket_key) DO NOTHING`,
    lockCapacity: `SELECT bucket_key, used_units, hard_limit
FROM ${AE_CHALLENGE_CAPACITY_TABLE}
WHERE owner_id = $1 AND bucket_key = ANY($2::text[])
ORDER BY bucket_key FOR UPDATE`,
    writeCapacity: `UPDATE ${AE_CHALLENGE_CAPACITY_TABLE}
SET used_units = $3, updated_at = transaction_timestamp()
WHERE owner_id = $1 AND bucket_key = $2 AND hard_limit >= $3`,
    health: `SELECT
  to_regclass('public.${AE_CHALLENGE_LOCK_TABLE}') IS NOT NULL AS locks_ready,
  to_regclass('public.${AE_CHALLENGE_RECORD_TABLE}') IS NOT NULL AS records_ready,
  to_regclass('public.${AE_CHALLENGE_CAPACITY_TABLE}') IS NOT NULL AS capacity_ready`,
});
function exactOne(result, operation) {
    if (!result || result.rowCount !== 1 || !Array.isArray(result.rows) || result.rows.length !== 1) {
        throw new Error(`AE challenge PostgreSQL ${operation} result is ambiguous`);
    }
    return result.rows[0];
}
function compareCapacityKeys(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
function ownerId(value) {
    if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 1
        || Buffer.byteLength(value, 'utf8') > 512 || /[\u0000-\u001f\u007f]/.test(value)) {
        throw new Error('AE challenge PostgreSQL ownerId is invalid');
    }
    return value;
}
function encodeRecord(record) {
    const json = JSON.stringify(record);
    if (Buffer.byteLength(json, 'utf8') > 1024 * 1024) {
        throw new Error('AE challenge owner record exceeds one MiB');
    }
    return json;
}
function decodeRecord(value) {
    if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > 1024 * 1024) {
        throw new Error('AE challenge PostgreSQL record is malformed');
    }
    try {
        const parsed = JSON.parse(value);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
            throw new Error('not an object');
        return parsed;
    }
    catch {
        throw new Error('AE challenge PostgreSQL record is not valid JSON');
    }
}
/**
 * The backend pins all owner operations to one pg client and one transaction.
 * PostgreSQL transaction time, not a caller timestamp, decides expiry and
 * recovery. Sorted row locks serialize each replay key and every cap bucket.
 */
export function createPostgresChallengeOwnerBackend({ pool, ownerId: configuredOwnerId, } = {}) {
    if (!pool || typeof pool.connect !== 'function') {
        throw new Error('createPostgresChallengeOwnerBackend requires a transaction-capable pg pool');
    }
    const pinnedPool = pool;
    const owner = ownerId(configuredOwnerId);
    async function transaction(work) {
        const client = await pinnedPool.connect();
        if (!client || typeof client.query !== 'function' || typeof client.release !== 'function') {
            throw new Error('AE challenge PostgreSQL pool returned an invalid client');
        }
        let began = false;
        try {
            await client.query(AE_CHALLENGE_POSTGRES_SQL.begin);
            began = true;
            const tx = {
                async authoritativeNowMs() {
                    const row = exactOne(await client.query(AE_CHALLENGE_POSTGRES_SQL.authoritativeNow, []), 'authoritative time');
                    const value = typeof row.now_ms === 'string' ? Number(row.now_ms) : row.now_ms;
                    if (!Number.isSafeInteger(value) || value < 0) {
                        throw new Error('AE challenge PostgreSQL authoritative time is malformed');
                    }
                    return value;
                },
                async lockChallenge(key) {
                    const ensured = await client.query(AE_CHALLENGE_POSTGRES_SQL.ensureChallengeLock, [owner, key]);
                    if (!ensured || typeof ensured.rowCount !== 'number') {
                        throw new Error('AE challenge PostgreSQL lock insertion is ambiguous');
                    }
                    exactOne(await client.query(AE_CHALLENGE_POSTGRES_SQL.lockChallenge, [owner, key]), 'challenge lock');
                },
                async readChallenge(key) {
                    const result = await client.query(AE_CHALLENGE_POSTGRES_SQL.readChallenge, [owner, key]);
                    if (!result || typeof result.rowCount !== 'number' || !Array.isArray(result.rows)) {
                        throw new Error('AE challenge PostgreSQL read result is ambiguous');
                    }
                    if (result.rowCount === 0)
                        return null;
                    if (result.rowCount !== 1 || result.rows.length !== 1) {
                        throw new Error('AE challenge PostgreSQL read returned duplicate records');
                    }
                    return decodeRecord(result.rows[0]?.record_json);
                },
                async insertChallenge(key, record) {
                    const result = await client.query(AE_CHALLENGE_POSTGRES_SQL.insertChallenge, [owner, key, encodeRecord(record)]);
                    if (!result || typeof result.rowCount !== 'number') {
                        throw new Error('AE challenge PostgreSQL insert result is ambiguous');
                    }
                    return result.rowCount === 1;
                },
                async writeChallenge(key, record) {
                    const result = await client.query(AE_CHALLENGE_POSTGRES_SQL.writeChallenge, [owner, key, encodeRecord(record)]);
                    if (!result || result.rowCount !== 1) {
                        throw new Error('AE challenge PostgreSQL challenge update lost its row lock');
                    }
                },
                async lockCapacity(buckets) {
                    const sorted = [...buckets].sort((a, b) => compareCapacityKeys(a.key, b.key));
                    for (const bucket of sorted) {
                        const result = await client.query(AE_CHALLENGE_POSTGRES_SQL.ensureCapacity, [owner, bucket.key, bucket.limit]);
                        if (!result || typeof result.rowCount !== 'number') {
                            throw new Error('AE challenge PostgreSQL capacity insertion is ambiguous');
                        }
                    }
                    const result = await client.query(AE_CHALLENGE_POSTGRES_SQL.lockCapacity, [owner, sorted.map(({ key }) => key)]);
                    if (!result || result.rowCount !== sorted.length || !Array.isArray(result.rows)
                        || result.rows.length !== sorted.length) {
                        throw new Error('AE challenge PostgreSQL capacity lock is incomplete');
                    }
                    const expected = new Map(sorted.map(({ key, limit }) => [key, limit]));
                    const rows = Object.create(null);
                    for (const row of result.rows) {
                        const used = typeof row.used_units === 'string' ? Number(row.used_units) : row.used_units;
                        const limit = typeof row.hard_limit === 'string' ? Number(row.hard_limit) : row.hard_limit;
                        if (typeof row.bucket_key !== 'string' || !expected.has(row.bucket_key)
                            || Object.hasOwn(rows, row.bucket_key) || limit !== expected.get(row.bucket_key)
                            || !Number.isSafeInteger(used) || used < 0 || !Number.isSafeInteger(limit) || limit < 1) {
                            throw new Error('AE challenge PostgreSQL capacity row violates the pinned policy');
                        }
                        rows[row.bucket_key] = { used, limit };
                    }
                    if (Object.keys(rows).length !== sorted.length) {
                        throw new Error('AE challenge PostgreSQL capacity lock omitted a pinned bucket');
                    }
                    return rows;
                },
                async writeCapacity(used) {
                    for (const [key, value] of Object.entries(used).sort(([a], [b]) => compareCapacityKeys(a, b))) {
                        const result = await client.query(AE_CHALLENGE_POSTGRES_SQL.writeCapacity, [owner, key, value]);
                        if (!result || result.rowCount !== 1) {
                            throw new Error('AE challenge PostgreSQL capacity update lost its row lock or exceeded its cap');
                        }
                    }
                },
            };
            const value = await work(tx);
            await client.query(AE_CHALLENGE_POSTGRES_SQL.commit);
            began = false;
            return value;
        }
        catch (error) {
            if (began) {
                try {
                    await client.query(AE_CHALLENGE_POSTGRES_SQL.rollback);
                }
                catch (rollbackError) {
                    throw new AggregateError([error, rollbackError], 'AE challenge transaction and rollback both failed');
                }
            }
            throw error;
        }
        finally {
            client.release();
        }
    }
    return Object.freeze({
        durable: true,
        transaction,
        async health() {
            const client = await pinnedPool.connect();
            try {
                const row = exactOne(await client.query(AE_CHALLENGE_POSTGRES_SQL.health, []), 'health');
                if (row.locks_ready !== true || row.records_ready !== true || row.capacity_ready !== true) {
                    throw new Error('AE challenge PostgreSQL owner schema is not ready');
                }
                return { ok: true, version: AE_CHALLENGE_POSTGRES_OWNER_VERSION };
            }
            finally {
                client.release();
            }
        },
    });
}
export default {
    AE_CHALLENGE_POSTGRES_OWNER_VERSION,
    AE_CHALLENGE_OWNER_DDL,
    AE_CHALLENGE_POSTGRES_SQL,
    createPostgresChallengeOwnerBackend,
};
//# sourceMappingURL=challenge-store-postgres.js.map