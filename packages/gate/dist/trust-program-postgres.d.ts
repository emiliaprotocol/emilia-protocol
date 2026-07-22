import type { TrustProgramStore } from './trust-program.js';
export declare const TRUST_PROGRAM_PG_STORE_VERSION = "EP-GATE-TRUST-PROGRAM-PG-STORE-v1";
export declare const TRUST_PROGRAM_MAX_STATE_BYTES: number;
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
export declare const TRUST_PROGRAM_POSTGRES_SQL: Readonly<{
    create: "SELECT ok, reason, tenant_id, instance_id, revision, state_json, state_digest\nFROM trust_program_private.trust_program_create(\n  $1::text, $2::text, $3::text, $4::text, $5::text\n)";
    get: "SELECT ok, reason, tenant_id, instance_id, revision, state_json, state_digest\nFROM trust_program_private.trust_program_get($1::text, $2::text)";
    compareAndSwap: "SELECT ok, reason, tenant_id, instance_id, revision, state_json, state_digest\nFROM trust_program_private.trust_program_compare_and_swap(\n  $1::text, $2::text, $3::bigint, $4::bigint, $5::text, $6::text, $7::text\n)";
    invalidate: "SELECT ok, reason, tenant_id, instance_id, revision, state_json, state_digest\nFROM trust_program_private.trust_program_invalidate(\n  $1::text, $2::text, $3::bigint, $4::text, $5::text, $6::text, $7::text\n)";
}>;
/**
 * Create the exact durable store consumed by createTrustProgramKernel().
 * `pool` must provide node-postgres-style connect(), returning a pinned client
 * with query() and release().
 */
export declare function createTrustProgramPostgresStore({ pool }?: {
    pool?: PgPool;
}): TrustProgramStore;
declare const _default: {
    TRUST_PROGRAM_PG_STORE_VERSION: string;
    TRUST_PROGRAM_MAX_STATE_BYTES: number;
    TRUST_PROGRAM_POSTGRES_SQL: Readonly<{
        create: "SELECT ok, reason, tenant_id, instance_id, revision, state_json, state_digest\nFROM trust_program_private.trust_program_create(\n  $1::text, $2::text, $3::text, $4::text, $5::text\n)";
        get: "SELECT ok, reason, tenant_id, instance_id, revision, state_json, state_digest\nFROM trust_program_private.trust_program_get($1::text, $2::text)";
        compareAndSwap: "SELECT ok, reason, tenant_id, instance_id, revision, state_json, state_digest\nFROM trust_program_private.trust_program_compare_and_swap(\n  $1::text, $2::text, $3::bigint, $4::bigint, $5::text, $6::text, $7::text\n)";
        invalidate: "SELECT ok, reason, tenant_id, instance_id, revision, state_json, state_digest\nFROM trust_program_private.trust_program_invalidate(\n  $1::text, $2::text, $3::bigint, $4::text, $5::text, $6::text, $7::text\n)";
    }>;
    createTrustProgramPostgresStore: typeof createTrustProgramPostgresStore;
};
export default _default;
//# sourceMappingURL=trust-program-postgres.d.ts.map