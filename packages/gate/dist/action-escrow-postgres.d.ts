export declare const ACTION_ESCROW_PG_STORE_VERSION = "EP-ACTION-ESCROW-PG-STORE-v1";
export declare const ACTION_ESCROW_STATE_TABLE = "ep_action_escrow_state";
export declare const ACTION_ESCROW_EVENT_TABLE = "ep_action_escrow_state_events";
export declare const ACTION_ESCROW_MAX_STATE_BYTES: number;
export declare const ACTION_ESCROW_STATE_DDL = "CREATE TABLE IF NOT EXISTS ep_action_escrow_state (\n  agreement_key TEXT PRIMARY KEY,\n  revision      BIGINT NOT NULL CHECK (revision >= 0),\n  record_json   TEXT NOT NULL,\n  updated_at    BIGINT NOT NULL,\nCHECK (octet_length(record_json) <= 4194304)\n);\nCREATE TABLE IF NOT EXISTS ep_action_escrow_state_events (\n  agreement_key     TEXT NOT NULL,\n  revision          BIGINT NOT NULL CHECK (revision >= 0),\n  previous_revision BIGINT NULL,\n  record_json       TEXT NOT NULL,\n  record_digest     TEXT NOT NULL CHECK (record_digest ~ '^sha256:[0-9a-f]{64}$'),\n  recorded_at       BIGINT NOT NULL,\n  PRIMARY KEY (agreement_key, revision),\n  CHECK (\n    (revision = 0 AND previous_revision IS NULL)\n    OR previous_revision = revision - 1\n  ),\n  CHECK (octet_length(record_json) <= 4194304)\n);\nREVOKE ALL ON ep_action_escrow_state FROM PUBLIC;\nREVOKE ALL ON ep_action_escrow_state_events FROM PUBLIC;\nREVOKE UPDATE, DELETE, TRUNCATE ON ep_action_escrow_state_events FROM PUBLIC;";
/**
 * @param {string} roleName
 */
export declare function actionEscrowRuntimeGrantDdl(roleName: any): string;
export declare const ACTION_ESCROW_STATE_SQL: Readonly<{
    health: "SELECT\n  to_regclass('public.ep_action_escrow_state') IS NOT NULL AS table_ready,\n  to_regclass('public.ep_action_escrow_state_events') IS NOT NULL AS event_table_ready,\n  CASE WHEN to_regclass('public.ep_action_escrow_state') IS NULL THEN FALSE\n    ELSE has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state'), 'SELECT')\n      AND has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state'), 'INSERT')\n      AND has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state'), 'UPDATE') END AS can_use,\n  CASE WHEN to_regclass('public.ep_action_escrow_state_events') IS NULL THEN FALSE\n    ELSE has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state_events'), 'SELECT')\n      AND has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state_events'), 'INSERT') END AS can_append_history,\n  CASE WHEN to_regclass('public.ep_action_escrow_state') IS NULL THEN TRUE\n    ELSE (SELECT relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)\n      FROM pg_class WHERE oid = to_regclass('public.ep_action_escrow_state')) END AS owns_state_table,\n  CASE WHEN to_regclass('public.ep_action_escrow_state_events') IS NULL THEN TRUE\n    ELSE (SELECT relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)\n      FROM pg_class WHERE oid = to_regclass('public.ep_action_escrow_state_events')) END AS owns_event_table,\n  CASE WHEN to_regclass('public.ep_action_escrow_state') IS NULL THEN TRUE\n    ELSE has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state'), 'DELETE')\n      OR has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state'), 'TRUNCATE') END AS can_destroy_state,\n  CASE WHEN to_regclass('public.ep_action_escrow_state_events') IS NULL THEN TRUE\n    ELSE has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state_events'), 'UPDATE')\n      OR has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state_events'), 'DELETE')\n      OR has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state_events'), 'TRUNCATE') END AS can_mutate_history";
    read: "SELECT revision, record_json FROM ep_action_escrow_state WHERE agreement_key = $1";
    history: "SELECT revision, previous_revision, record_json, record_digest, recorded_at\nFROM ep_action_escrow_state_events\nWHERE agreement_key = $1\nORDER BY revision ASC";
    create: "WITH installed AS (\n  INSERT INTO ep_action_escrow_state (agreement_key, revision, record_json, updated_at)\n  VALUES ($1, 0, $2, $3)\n  ON CONFLICT (agreement_key) DO NOTHING\n  RETURNING agreement_key, revision, record_json, updated_at\n), journaled AS (\n  INSERT INTO ep_action_escrow_state_events\n    (agreement_key, revision, previous_revision, record_json, record_digest, recorded_at)\n  SELECT agreement_key, revision, NULL, record_json, $4, updated_at\n  FROM installed\n  RETURNING revision\n)\nSELECT revision FROM journaled";
    compareAndSwap: "WITH installed AS (\nUPDATE ep_action_escrow_state\nSET revision = $3, record_json = $4, updated_at = $5\nWHERE agreement_key = $1 AND revision = $2 AND updated_at <= $5\nRETURNING agreement_key, revision, record_json, updated_at\n), journaled AS (\n  INSERT INTO ep_action_escrow_state_events\n    (agreement_key, revision, previous_revision, record_json, record_digest, recorded_at)\n  SELECT agreement_key, revision, $2, record_json, $6, updated_at\n  FROM installed\n  RETURNING revision\n)\nSELECT revision FROM journaled";
}>;
export declare function createActionEscrowPostgresStore({ query, now, }?: {
    query?: (text: string, params: any[]) => Promise<{
        rowCount: number;
        rows?: any[];
    }>;
    now?: number | (() => number);
}): Readonly<{
    version: "EP-ACTION-ESCROW-PG-STORE-v1";
    durable: true;
    atomicExpectedRevisionCas: true;
    linearizableReads: true;
    monotonicRevisions: true;
    nonExpiring: true;
    maxStateBytes: number;
    health(): Promise<{
        ok: boolean;
        version: string;
    }>;
    read: (key: any) => Promise<{
        revision: number;
        value: any;
    } | null>;
    readHistory(key: any): Promise<any>;
    compareAndSwap(key: any, expectedRevision: any, value: any): Promise<{
        applied: boolean;
        revision: any;
    }>;
}>;
declare const _default: {
    ACTION_ESCROW_PG_STORE_VERSION: string;
    ACTION_ESCROW_STATE_TABLE: string;
    ACTION_ESCROW_EVENT_TABLE: string;
    ACTION_ESCROW_MAX_STATE_BYTES: number;
    ACTION_ESCROW_STATE_DDL: string;
    actionEscrowRuntimeGrantDdl: typeof actionEscrowRuntimeGrantDdl;
    ACTION_ESCROW_STATE_SQL: Readonly<{
        health: "SELECT\n  to_regclass('public.ep_action_escrow_state') IS NOT NULL AS table_ready,\n  to_regclass('public.ep_action_escrow_state_events') IS NOT NULL AS event_table_ready,\n  CASE WHEN to_regclass('public.ep_action_escrow_state') IS NULL THEN FALSE\n    ELSE has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state'), 'SELECT')\n      AND has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state'), 'INSERT')\n      AND has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state'), 'UPDATE') END AS can_use,\n  CASE WHEN to_regclass('public.ep_action_escrow_state_events') IS NULL THEN FALSE\n    ELSE has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state_events'), 'SELECT')\n      AND has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state_events'), 'INSERT') END AS can_append_history,\n  CASE WHEN to_regclass('public.ep_action_escrow_state') IS NULL THEN TRUE\n    ELSE (SELECT relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)\n      FROM pg_class WHERE oid = to_regclass('public.ep_action_escrow_state')) END AS owns_state_table,\n  CASE WHEN to_regclass('public.ep_action_escrow_state_events') IS NULL THEN TRUE\n    ELSE (SELECT relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)\n      FROM pg_class WHERE oid = to_regclass('public.ep_action_escrow_state_events')) END AS owns_event_table,\n  CASE WHEN to_regclass('public.ep_action_escrow_state') IS NULL THEN TRUE\n    ELSE has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state'), 'DELETE')\n      OR has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state'), 'TRUNCATE') END AS can_destroy_state,\n  CASE WHEN to_regclass('public.ep_action_escrow_state_events') IS NULL THEN TRUE\n    ELSE has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state_events'), 'UPDATE')\n      OR has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state_events'), 'DELETE')\n      OR has_table_privilege(current_user, to_regclass('public.ep_action_escrow_state_events'), 'TRUNCATE') END AS can_mutate_history";
        read: "SELECT revision, record_json FROM ep_action_escrow_state WHERE agreement_key = $1";
        history: "SELECT revision, previous_revision, record_json, record_digest, recorded_at\nFROM ep_action_escrow_state_events\nWHERE agreement_key = $1\nORDER BY revision ASC";
        create: "WITH installed AS (\n  INSERT INTO ep_action_escrow_state (agreement_key, revision, record_json, updated_at)\n  VALUES ($1, 0, $2, $3)\n  ON CONFLICT (agreement_key) DO NOTHING\n  RETURNING agreement_key, revision, record_json, updated_at\n), journaled AS (\n  INSERT INTO ep_action_escrow_state_events\n    (agreement_key, revision, previous_revision, record_json, record_digest, recorded_at)\n  SELECT agreement_key, revision, NULL, record_json, $4, updated_at\n  FROM installed\n  RETURNING revision\n)\nSELECT revision FROM journaled";
        compareAndSwap: "WITH installed AS (\nUPDATE ep_action_escrow_state\nSET revision = $3, record_json = $4, updated_at = $5\nWHERE agreement_key = $1 AND revision = $2 AND updated_at <= $5\nRETURNING agreement_key, revision, record_json, updated_at\n), journaled AS (\n  INSERT INTO ep_action_escrow_state_events\n    (agreement_key, revision, previous_revision, record_json, record_digest, recorded_at)\n  SELECT agreement_key, revision, $2, record_json, $6, updated_at\n  FROM installed\n  RETURNING revision\n)\nSELECT revision FROM journaled";
    }>;
    createActionEscrowPostgresStore: typeof createActionEscrowPostgresStore;
};
export default _default;
//# sourceMappingURL=action-escrow-postgres.d.ts.map