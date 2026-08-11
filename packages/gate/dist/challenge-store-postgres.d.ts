/** PostgreSQL transaction backend for the AE-CHALLENGE -07 owner state machine. */
import type { ChallengeOwnerBackend } from './challenge-store.js';
export declare const AE_CHALLENGE_POSTGRES_OWNER_VERSION = "EP-AE-CHALLENGE-PG-OWNER-v1";
export declare const AE_CHALLENGE_LOCK_TABLE = "ep_ae_challenge_owner_locks";
export declare const AE_CHALLENGE_RECORD_TABLE = "ep_ae_challenge_owner_records";
export declare const AE_CHALLENGE_CAPACITY_TABLE = "ep_ae_challenge_owner_capacity";
export declare const AE_CHALLENGE_OWNER_DDL = "CREATE TABLE IF NOT EXISTS ep_ae_challenge_owner_locks (\n  owner_id   TEXT NOT NULL,\n  replay_key TEXT NOT NULL,\n  PRIMARY KEY (owner_id, replay_key)\n);\nCREATE TABLE IF NOT EXISTS ep_ae_challenge_owner_records (\n  owner_id    TEXT NOT NULL,\n  replay_key  TEXT NOT NULL,\n  record_json TEXT NOT NULL,\n  updated_at  TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),\n  PRIMARY KEY (owner_id, replay_key),\n  FOREIGN KEY (owner_id, replay_key)\n    REFERENCES ep_ae_challenge_owner_locks (owner_id, replay_key)\n);\nCREATE TABLE IF NOT EXISTS ep_ae_challenge_owner_capacity (\n  owner_id   TEXT NOT NULL,\n  bucket_key TEXT NOT NULL,\n  used_units BIGINT NOT NULL CHECK (used_units >= 0),\n  hard_limit BIGINT NOT NULL CHECK (hard_limit > 0 AND used_units <= hard_limit),\n  updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),\n  PRIMARY KEY (owner_id, bucket_key)\n);";
export declare const AE_CHALLENGE_POSTGRES_SQL: Readonly<{
    begin: "BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE";
    commit: "COMMIT";
    rollback: "ROLLBACK";
    authoritativeNow: "SELECT floor(extract(epoch FROM transaction_timestamp()) * 1000)::bigint AS now_ms";
    ensureChallengeLock: "INSERT INTO ep_ae_challenge_owner_locks (owner_id, replay_key)\nVALUES ($1, $2) ON CONFLICT (owner_id, replay_key) DO NOTHING";
    lockChallenge: "SELECT replay_key FROM ep_ae_challenge_owner_locks\nWHERE owner_id = $1 AND replay_key = $2 FOR UPDATE";
    readChallenge: "SELECT record_json FROM ep_ae_challenge_owner_records\nWHERE owner_id = $1 AND replay_key = $2";
    insertChallenge: "INSERT INTO ep_ae_challenge_owner_records (owner_id, replay_key, record_json)\nVALUES ($1, $2, $3) ON CONFLICT (owner_id, replay_key) DO NOTHING";
    writeChallenge: "UPDATE ep_ae_challenge_owner_records\nSET record_json = $3, updated_at = transaction_timestamp()\nWHERE owner_id = $1 AND replay_key = $2";
    ensureCapacity: "INSERT INTO ep_ae_challenge_owner_capacity\n  (owner_id, bucket_key, used_units, hard_limit)\nVALUES ($1, $2, 0, $3)\nON CONFLICT (owner_id, bucket_key) DO NOTHING";
    lockCapacity: "SELECT bucket_key, used_units, hard_limit\nFROM ep_ae_challenge_owner_capacity\nWHERE owner_id = $1 AND bucket_key = ANY($2::text[])\nORDER BY bucket_key FOR UPDATE";
    writeCapacity: "UPDATE ep_ae_challenge_owner_capacity\nSET used_units = $3, updated_at = transaction_timestamp()\nWHERE owner_id = $1 AND bucket_key = $2 AND hard_limit >= $3";
    health: "SELECT\n  to_regclass('public.ep_ae_challenge_owner_locks') IS NOT NULL AS locks_ready,\n  to_regclass('public.ep_ae_challenge_owner_records') IS NOT NULL AS records_ready,\n  to_regclass('public.ep_ae_challenge_owner_capacity') IS NOT NULL AS capacity_ready";
}>;
type QueryResult = {
    rowCount: number | null;
    rows?: any[];
};
type PgClient = {
    query: (text: string, params?: any[]) => Promise<QueryResult>;
    release: () => void;
};
type PgPool = {
    connect: () => Promise<PgClient>;
};
/**
 * The backend pins all owner operations to one pg client and one transaction.
 * PostgreSQL transaction time, not a caller timestamp, decides expiry and
 * recovery. Sorted row locks serialize each replay key and every cap bucket.
 */
export declare function createPostgresChallengeOwnerBackend({ pool, ownerId: configuredOwnerId, }?: {
    pool?: PgPool;
    ownerId?: string;
}): ChallengeOwnerBackend & {
    health: () => Promise<{
        ok: true;
        version: string;
    }>;
};
declare const _default: {
    AE_CHALLENGE_POSTGRES_OWNER_VERSION: string;
    AE_CHALLENGE_OWNER_DDL: string;
    AE_CHALLENGE_POSTGRES_SQL: Readonly<{
        begin: "BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE";
        commit: "COMMIT";
        rollback: "ROLLBACK";
        authoritativeNow: "SELECT floor(extract(epoch FROM transaction_timestamp()) * 1000)::bigint AS now_ms";
        ensureChallengeLock: "INSERT INTO ep_ae_challenge_owner_locks (owner_id, replay_key)\nVALUES ($1, $2) ON CONFLICT (owner_id, replay_key) DO NOTHING";
        lockChallenge: "SELECT replay_key FROM ep_ae_challenge_owner_locks\nWHERE owner_id = $1 AND replay_key = $2 FOR UPDATE";
        readChallenge: "SELECT record_json FROM ep_ae_challenge_owner_records\nWHERE owner_id = $1 AND replay_key = $2";
        insertChallenge: "INSERT INTO ep_ae_challenge_owner_records (owner_id, replay_key, record_json)\nVALUES ($1, $2, $3) ON CONFLICT (owner_id, replay_key) DO NOTHING";
        writeChallenge: "UPDATE ep_ae_challenge_owner_records\nSET record_json = $3, updated_at = transaction_timestamp()\nWHERE owner_id = $1 AND replay_key = $2";
        ensureCapacity: "INSERT INTO ep_ae_challenge_owner_capacity\n  (owner_id, bucket_key, used_units, hard_limit)\nVALUES ($1, $2, 0, $3)\nON CONFLICT (owner_id, bucket_key) DO NOTHING";
        lockCapacity: "SELECT bucket_key, used_units, hard_limit\nFROM ep_ae_challenge_owner_capacity\nWHERE owner_id = $1 AND bucket_key = ANY($2::text[])\nORDER BY bucket_key FOR UPDATE";
        writeCapacity: "UPDATE ep_ae_challenge_owner_capacity\nSET used_units = $3, updated_at = transaction_timestamp()\nWHERE owner_id = $1 AND bucket_key = $2 AND hard_limit >= $3";
        health: "SELECT\n  to_regclass('public.ep_ae_challenge_owner_locks') IS NOT NULL AS locks_ready,\n  to_regclass('public.ep_ae_challenge_owner_records') IS NOT NULL AS records_ready,\n  to_regclass('public.ep_ae_challenge_owner_capacity') IS NOT NULL AS capacity_ready";
    }>;
    createPostgresChallengeOwnerBackend: typeof createPostgresChallengeOwnerBackend;
};
export default _default;
//# sourceMappingURL=challenge-store-postgres.d.ts.map