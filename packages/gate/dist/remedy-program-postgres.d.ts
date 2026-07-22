import type { RemedyProgramStore } from './remedy-program.js';
export declare const REMEDY_PROGRAM_PG_STORE_VERSION = "EP-GATE-REMEDY-PROGRAM-PG-STORE-v1";
export declare const REMEDY_PROGRAM_MAX_STATE_BYTES: number;
export declare const REMEDY_PROGRAM_MAX_FORWARD_SKEW_MINUTES = 5;
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
export declare const REMEDY_PROGRAM_POSTGRES_SQL: Readonly<{
    create: "SELECT ok, reason, tenant_id, instance_id, revision, state_json, state_digest, recorded_at\nFROM remedy_program_private.remedy_program_create(\n  $1::text, $2::text, $3::text, $4::text, $5::text\n)";
    get: "SELECT ok, reason, tenant_id, instance_id, revision, state_json, state_digest, recorded_at\nFROM remedy_program_private.remedy_program_get($1::text, $2::text)";
    compareAndSwap: "SELECT ok, reason, tenant_id, instance_id, revision, state_json, state_digest, recorded_at\nFROM remedy_program_private.remedy_program_compare_and_swap(\n  $1::text, $2::text, $3::bigint, $4::bigint, $5::text, $6::text, $7::text\n)";
}>;
/** Build the exact durable store consumed by createRemedyProgramKernel(). */
export declare function createRemedyProgramPostgresStore({ pool }?: {
    pool?: PgPool;
}): RemedyProgramStore;
declare const _default: {
    REMEDY_PROGRAM_PG_STORE_VERSION: string;
    REMEDY_PROGRAM_MAX_STATE_BYTES: number;
    REMEDY_PROGRAM_MAX_FORWARD_SKEW_MINUTES: number;
    REMEDY_PROGRAM_POSTGRES_SQL: Readonly<{
        create: "SELECT ok, reason, tenant_id, instance_id, revision, state_json, state_digest, recorded_at\nFROM remedy_program_private.remedy_program_create(\n  $1::text, $2::text, $3::text, $4::text, $5::text\n)";
        get: "SELECT ok, reason, tenant_id, instance_id, revision, state_json, state_digest, recorded_at\nFROM remedy_program_private.remedy_program_get($1::text, $2::text)";
        compareAndSwap: "SELECT ok, reason, tenant_id, instance_id, revision, state_json, state_digest, recorded_at\nFROM remedy_program_private.remedy_program_compare_and_swap(\n  $1::text, $2::text, $3::bigint, $4::bigint, $5::text, $6::text, $7::text\n)";
    }>;
    createRemedyProgramPostgresStore: typeof createRemedyProgramPostgresStore;
};
export default _default;
//# sourceMappingURL=remedy-program-postgres.d.ts.map