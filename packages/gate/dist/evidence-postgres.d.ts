/**
 * EMILIA Gate production evidence backend for Postgres.
 *
 * The deployment SQL exposes one SECURITY DEFINER append function. That
 * function locks the tenant/gate/stream head, checks the caller's expected
 * head, inserts one immutable record, and advances the head in the same SQL
 * statement transaction. Runtime roles receive SELECT and EXECUTE only; they
 * cannot insert, update, delete, or truncate evidence tables directly.
 *
 * Database errors and malformed driver responses always propagate on the
 * write path. A storage outage must never be mistaken for a successful append
 * or an ordinary contention retry.
 */
export declare const PG_EVIDENCE_VERSION = "EP-GATE-PG-EVIDENCE-v1";
export declare const EVIDENCE_SCHEMA = "emilia_gate_evidence";
export declare const EVIDENCE_RECORDS_TABLE = "emilia_gate_evidence.records";
export declare const EVIDENCE_HEADS_TABLE = "emilia_gate_evidence.heads";
export declare const EVIDENCE_APPEND_FUNCTION = "emilia_gate_evidence.append_record";
/** Exact statements issued by the adapter, exported for audit and test fakes. */
export declare const EVIDENCE_SQL: Readonly<{
    health: "SELECT\n  to_regclass('emilia_gate_evidence.records') IS NOT NULL AS records_ready,\n  to_regclass('emilia_gate_evidence.heads') IS NOT NULL AS heads_ready,\n  to_regprocedure('emilia_gate_evidence.append_record(text,text,text,text,jsonb,text)') IS NOT NULL AS append_ready,\n  CASE WHEN to_regclass('emilia_gate_evidence.records') IS NULL THEN FALSE\n    ELSE has_table_privilege(current_user, to_regclass('emilia_gate_evidence.records'), 'SELECT') END AS can_read_records,\n  CASE WHEN to_regclass('emilia_gate_evidence.heads') IS NULL THEN FALSE\n    ELSE has_table_privilege(current_user, to_regclass('emilia_gate_evidence.heads'), 'SELECT') END AS can_read_heads,\n  CASE WHEN to_regclass('emilia_gate_evidence.records') IS NULL THEN FALSE ELSE (\n    has_table_privilege(current_user, to_regclass('emilia_gate_evidence.records'), 'INSERT')\n    OR has_table_privilege(current_user, to_regclass('emilia_gate_evidence.records'), 'UPDATE')\n    OR has_table_privilege(current_user, to_regclass('emilia_gate_evidence.records'), 'DELETE')\n    OR has_table_privilege(current_user, to_regclass('emilia_gate_evidence.records'), 'TRUNCATE')\n  ) END AS can_write_records_directly,\n  CASE WHEN to_regclass('emilia_gate_evidence.heads') IS NULL THEN FALSE ELSE (\n    has_table_privilege(current_user, to_regclass('emilia_gate_evidence.heads'), 'INSERT')\n    OR has_table_privilege(current_user, to_regclass('emilia_gate_evidence.heads'), 'UPDATE')\n    OR has_table_privilege(current_user, to_regclass('emilia_gate_evidence.heads'), 'DELETE')\n    OR has_table_privilege(current_user, to_regclass('emilia_gate_evidence.heads'), 'TRUNCATE')\n  ) END AS can_write_heads_directly,\n  CASE WHEN to_regprocedure('emilia_gate_evidence.append_record(text,text,text,text,jsonb,text)') IS NULL THEN FALSE\n    ELSE has_function_privilege(current_user,\n      to_regprocedure('emilia_gate_evidence.append_record(text,text,text,text,jsonb,text)'), 'EXECUTE') END AS can_append";
    readHead: "SELECT head_seq AS seq, head_hash AS hash\nFROM emilia_gate_evidence.heads\nWHERE tenant_id = $1 AND gate_id = $2 AND stream_id = $3";
    getById: "SELECT seq, record_id, prev_hash, hash, record\nFROM emilia_gate_evidence.records\nWHERE tenant_id = $1 AND gate_id = $2 AND stream_id = $3 AND record_id = $4";
    readAll: "SELECT seq, record_id, prev_hash, hash, record\nFROM emilia_gate_evidence.records\nWHERE tenant_id = $1 AND gate_id = $2 AND stream_id = $3\nORDER BY seq ASC";
    snapshot: "SELECT\n  COALESCE((\n    SELECT jsonb_agg(jsonb_build_object(\n      'seq', r.seq,\n      'record_id', r.record_id,\n      'prev_hash', r.prev_hash,\n      'hash', r.hash,\n      'record', r.record\n    ) ORDER BY r.seq ASC)\n    FROM emilia_gate_evidence.records r\n    WHERE r.tenant_id = $1 AND r.gate_id = $2 AND r.stream_id = $3\n  ), '[]'::jsonb) AS record_rows,\n  (\n    SELECT CASE WHEN h.head_seq = -1 THEN NULL ELSE jsonb_build_object(\n      'seq', h.head_seq, 'hash', h.head_hash\n    ) END\n    FROM emilia_gate_evidence.heads h\n    WHERE h.tenant_id = $1 AND h.gate_id = $2 AND h.stream_id = $3\n  ) AS head";
    appendIfHead: "SELECT emilia_gate_evidence.append_record($1, $2, $3, $4, $5::jsonb, $6) AS appended";
}>;
/**
 * Create a tenant-and-gate-bound backend for createAtomicEvidenceLog().
 *
 * `query` is a node-postgres style function such as `pool.query.bind(pool)`.
 * The migration must be installed and the connection role must inherit or SET
 * ROLE to `emilia_gate_evidence_runtime`.
 *
 * @param {{ query?: (text: string, params: any[]) => Promise<{ rowCount: number, rows?: any[] }>, tenantId?: any, gateId?: any }} [options]
 */
export declare function createPostgresEvidenceBackend({ query, tenantId, gateId, }?: {
    query?: (text: string, params: any[]) => Promise<{
        rowCount: number;
        rows?: any[];
    }>;
    tenantId?: string;
    gateId?: string;
}): {
    durable: boolean;
    persisted: boolean;
    strict: boolean;
    forkAware: boolean;
    atomicAppend: boolean;
    appendOnly: boolean;
    version: string;
    scope: Readonly<{
        tenantId: string;
        gateId: string;
    }>;
    readHead: (streamId: any) => Promise<{
        seq: any;
        hash: any;
    } | null>;
    head: (streamId: any) => Promise<{
        seq: any;
        hash: any;
    } | null>;
    getById: (streamId: any, recordId: any) => Promise<any>;
    appendIfHead: (streamId: any, expectedHeadHash: any, record: any) => Promise<any>;
    readAll: (streamId: any) => Promise<any>;
    all: (streamId: any) => Promise<any>;
    verify(streamId: any): Promise<{
        ok: boolean;
        at: any;
        reason: string;
        length?: undefined;
        head?: undefined;
    } | {
        ok: boolean;
        reason: string;
        at?: undefined;
        length?: undefined;
        head?: undefined;
    } | {
        ok: boolean;
        length: any;
        head: string | null;
        at?: undefined;
        reason?: undefined;
    }>;
    health(): Promise<{
        ok: boolean;
        version: string;
        scope: Readonly<{
            tenantId: string;
            gateId: string;
        }>;
        checks: {
            recordsReady: boolean;
            headsReady: boolean;
            appendReady: boolean;
            canReadRecords: boolean;
            canReadHeads: boolean;
            noDirectRecordWrites: boolean;
            noDirectHeadWrites: boolean;
            canAppend: boolean;
        };
    }>;
};
declare const postgresEvidence: {
    createPostgresEvidenceBackend: typeof createPostgresEvidenceBackend;
    EVIDENCE_SQL: Readonly<{
        health: "SELECT\n  to_regclass('emilia_gate_evidence.records') IS NOT NULL AS records_ready,\n  to_regclass('emilia_gate_evidence.heads') IS NOT NULL AS heads_ready,\n  to_regprocedure('emilia_gate_evidence.append_record(text,text,text,text,jsonb,text)') IS NOT NULL AS append_ready,\n  CASE WHEN to_regclass('emilia_gate_evidence.records') IS NULL THEN FALSE\n    ELSE has_table_privilege(current_user, to_regclass('emilia_gate_evidence.records'), 'SELECT') END AS can_read_records,\n  CASE WHEN to_regclass('emilia_gate_evidence.heads') IS NULL THEN FALSE\n    ELSE has_table_privilege(current_user, to_regclass('emilia_gate_evidence.heads'), 'SELECT') END AS can_read_heads,\n  CASE WHEN to_regclass('emilia_gate_evidence.records') IS NULL THEN FALSE ELSE (\n    has_table_privilege(current_user, to_regclass('emilia_gate_evidence.records'), 'INSERT')\n    OR has_table_privilege(current_user, to_regclass('emilia_gate_evidence.records'), 'UPDATE')\n    OR has_table_privilege(current_user, to_regclass('emilia_gate_evidence.records'), 'DELETE')\n    OR has_table_privilege(current_user, to_regclass('emilia_gate_evidence.records'), 'TRUNCATE')\n  ) END AS can_write_records_directly,\n  CASE WHEN to_regclass('emilia_gate_evidence.heads') IS NULL THEN FALSE ELSE (\n    has_table_privilege(current_user, to_regclass('emilia_gate_evidence.heads'), 'INSERT')\n    OR has_table_privilege(current_user, to_regclass('emilia_gate_evidence.heads'), 'UPDATE')\n    OR has_table_privilege(current_user, to_regclass('emilia_gate_evidence.heads'), 'DELETE')\n    OR has_table_privilege(current_user, to_regclass('emilia_gate_evidence.heads'), 'TRUNCATE')\n  ) END AS can_write_heads_directly,\n  CASE WHEN to_regprocedure('emilia_gate_evidence.append_record(text,text,text,text,jsonb,text)') IS NULL THEN FALSE\n    ELSE has_function_privilege(current_user,\n      to_regprocedure('emilia_gate_evidence.append_record(text,text,text,text,jsonb,text)'), 'EXECUTE') END AS can_append";
        readHead: "SELECT head_seq AS seq, head_hash AS hash\nFROM emilia_gate_evidence.heads\nWHERE tenant_id = $1 AND gate_id = $2 AND stream_id = $3";
        getById: "SELECT seq, record_id, prev_hash, hash, record\nFROM emilia_gate_evidence.records\nWHERE tenant_id = $1 AND gate_id = $2 AND stream_id = $3 AND record_id = $4";
        readAll: "SELECT seq, record_id, prev_hash, hash, record\nFROM emilia_gate_evidence.records\nWHERE tenant_id = $1 AND gate_id = $2 AND stream_id = $3\nORDER BY seq ASC";
        snapshot: "SELECT\n  COALESCE((\n    SELECT jsonb_agg(jsonb_build_object(\n      'seq', r.seq,\n      'record_id', r.record_id,\n      'prev_hash', r.prev_hash,\n      'hash', r.hash,\n      'record', r.record\n    ) ORDER BY r.seq ASC)\n    FROM emilia_gate_evidence.records r\n    WHERE r.tenant_id = $1 AND r.gate_id = $2 AND r.stream_id = $3\n  ), '[]'::jsonb) AS record_rows,\n  (\n    SELECT CASE WHEN h.head_seq = -1 THEN NULL ELSE jsonb_build_object(\n      'seq', h.head_seq, 'hash', h.head_hash\n    ) END\n    FROM emilia_gate_evidence.heads h\n    WHERE h.tenant_id = $1 AND h.gate_id = $2 AND h.stream_id = $3\n  ) AS head";
        appendIfHead: "SELECT emilia_gate_evidence.append_record($1, $2, $3, $4, $5::jsonb, $6) AS appended";
    }>;
    EVIDENCE_SCHEMA: string;
    EVIDENCE_RECORDS_TABLE: string;
    EVIDENCE_HEADS_TABLE: string;
    EVIDENCE_APPEND_FUNCTION: string;
    PG_EVIDENCE_VERSION: string;
};
export default postgresEvidence;
//# sourceMappingURL=evidence-postgres.d.ts.map