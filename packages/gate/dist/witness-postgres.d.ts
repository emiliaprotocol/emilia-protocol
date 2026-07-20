/**
 * Tenant-scoped Postgres sequence store for EP-GATE-NETWORK-WITNESS-v1.
 *
 * The migration owns synchronization and authorization. Runtime callers get
 * EXECUTE on one SECURITY DEFINER function, not INSERT/UPDATE privileges on the
 * checkpoint table. Database ambiguity is allowed to throw so the witness
 * ingestion kernel can fail closed as `sequence_store_unavailable`.
 */
export declare const PG_WITNESS_SEQUENCE_VERSION = "EP-GATE-PG-WITNESS-SEQUENCE-v1";
export declare const WITNESS_CHECKPOINT_FUNCTION = "emilia_gate_evidence.advance_network_witness_checkpoint";
export declare const WITNESS_SEQUENCE_SQL: Readonly<{
    advance: "SELECT accepted, reason\nFROM emilia_gate_evidence.advance_network_witness_checkpoint($1, $2, $3::bytea, $4::bigint, $5)";
}>;
/**
 * Create the durable store expected by acceptNetworkWitnessStatement().
 * `query` is a node-postgres style function such as pool.query.bind(pool).
 * @param {{ query?: Function, tenantId?: string|number, gateId?: string|number }} [o]
 */
export declare function createPostgresWitnessSequenceStore({ query, tenantId, gateId, }?: {
    query?: (sql: string, params?: any[]) => Promise<any>;
    tenantId?: string | number;
    gateId?: string | number;
}): Readonly<{
    durable: true;
    scope: Readonly<{
        tenantId: string;
        gateId: string;
    }>;
    advance(streamId: any, sequence: any, statementDigest: any): Promise<{
        accepted: boolean;
        reason: any;
    }>;
}>;
declare const _default: {
    PG_WITNESS_SEQUENCE_VERSION: string;
    WITNESS_CHECKPOINT_FUNCTION: string;
    WITNESS_SEQUENCE_SQL: Readonly<{
        advance: "SELECT accepted, reason\nFROM emilia_gate_evidence.advance_network_witness_checkpoint($1, $2, $3::bytea, $4::bigint, $5)";
    }>;
    createPostgresWitnessSequenceStore: typeof createPostgresWitnessSequenceStore;
};
export default _default;
//# sourceMappingURL=witness-postgres.d.ts.map