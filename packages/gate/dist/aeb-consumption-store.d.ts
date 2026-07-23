import type { AebDurableConsumptionStore } from '@emilia-protocol/verify/aeb-adapter-contract';
export declare const AEB_PG_CONSUMPTION_STORE_VERSION = "EP-GATE-AEB-PG-CONSUMPTION-v1";
export declare const AEB_CONSUMPTION_OPERATION_TABLE = "ep_aeb_consumption_operations";
export declare const AEB_CONSUMPTION_REPLAY_TABLE = "ep_aeb_consumption_replay_fences";
export declare const AEB_CONSUMPTION_EXECUTOR_ROLE = "ep_aeb_executor";
export declare const AEB_CONSUMPTION_RECOVERY_ROLE = "ep_aeb_recovery";
export declare const AEB_CONSUMPTION_OWNER_ROLE = "ep_aeb_store_owner";
/** Exact schema required by createPostgresAebDurableConsumptionStore(). */
export declare const AEB_CONSUMPTION_DDL = "CREATE TABLE IF NOT EXISTS ep_aeb_consumption_operations (\n  tenant_id        TEXT NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 512),\n  relying_party_id TEXT NOT NULL CHECK (octet_length(relying_party_id) BETWEEN 1 AND 512),\n  operation_key    TEXT NOT NULL CHECK (octet_length(operation_key) BETWEEN 1 AND 4096),\n  state            TEXT NOT NULL CHECK (state IN ('RESERVED', 'CONSUMED')),\n  owner_token      TEXT NULL CHECK (owner_token IS NULL OR octet_length(owner_token) BETWEEN 16 AND 512),\n  reserved_at      TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),\n  consumed_at      TIMESTAMPTZ NULL,\n  PRIMARY KEY (tenant_id, relying_party_id, operation_key),\n  CHECK (\n    (state = 'RESERVED' AND owner_token IS NOT NULL AND consumed_at IS NULL)\n    OR (state = 'CONSUMED' AND owner_token IS NULL AND consumed_at IS NOT NULL)\n  )\n);\nCREATE TABLE IF NOT EXISTS ep_aeb_consumption_replay_fences (\n  tenant_id        TEXT NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 512),\n  relying_party_id TEXT NOT NULL CHECK (octet_length(relying_party_id) BETWEEN 1 AND 512),\n  replay_key       TEXT NOT NULL CHECK (octet_length(replay_key) BETWEEN 1 AND 4096),\n  operation_key    TEXT NOT NULL CHECK (octet_length(operation_key) BETWEEN 1 AND 4096),\n  reserved_at      TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),\n  PRIMARY KEY (tenant_id, relying_party_id, replay_key),\n  FOREIGN KEY (tenant_id, relying_party_id, operation_key)\n    REFERENCES ep_aeb_consumption_operations (tenant_id, relying_party_id, operation_key)\n    ON DELETE CASCADE\n);\nCREATE INDEX IF NOT EXISTS ep_aeb_consumption_replay_fences_operation_idx\n  ON ep_aeb_consumption_replay_fences (tenant_id, relying_party_id, operation_key);\nDO $roles$\nBEGIN\n  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ep_aeb_executor') THEN\n    CREATE ROLE ep_aeb_executor NOLOGIN\n      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n  END IF;\n  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ep_aeb_recovery') THEN\n    CREATE ROLE ep_aeb_recovery NOLOGIN\n      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n  END IF;\n  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ep_aeb_store_owner') THEN\n    CREATE ROLE ep_aeb_store_owner NOLOGIN\n      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n  END IF;\nEND\n$roles$;\nGRANT ep_aeb_store_owner TO CURRENT_USER;\nCREATE SCHEMA IF NOT EXISTS ep_aeb_private;\nREVOKE ALL ON SCHEMA ep_aeb_private FROM PUBLIC, anon, authenticated, service_role;\nCREATE TABLE IF NOT EXISTS ep_aeb_private.tenant_principals (\n  principal_name NAME NOT NULL,\n  tenant_id TEXT NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 512),\n  can_execute BOOLEAN NOT NULL DEFAULT FALSE,\n  can_recover BOOLEAN NOT NULL DEFAULT FALSE,\n  PRIMARY KEY (principal_name, tenant_id),\n  CHECK (can_execute OR can_recover)\n);\nALTER SCHEMA ep_aeb_private OWNER TO ep_aeb_store_owner;\nALTER TABLE ep_aeb_private.tenant_principals OWNER TO ep_aeb_store_owner;\nALTER TABLE ep_aeb_consumption_operations OWNER TO ep_aeb_store_owner;\nALTER TABLE ep_aeb_consumption_replay_fences OWNER TO ep_aeb_store_owner;\nALTER TABLE ep_aeb_private.tenant_principals ENABLE ROW LEVEL SECURITY;\nALTER TABLE ep_aeb_private.tenant_principals FORCE ROW LEVEL SECURITY;\nALTER TABLE ep_aeb_consumption_operations ENABLE ROW LEVEL SECURITY;\nALTER TABLE ep_aeb_consumption_operations FORCE ROW LEVEL SECURITY;\nALTER TABLE ep_aeb_consumption_replay_fences ENABLE ROW LEVEL SECURITY;\nALTER TABLE ep_aeb_consumption_replay_fences FORCE ROW LEVEL SECURITY;\nDROP POLICY IF EXISTS ep_aeb_principals_owner_only ON ep_aeb_private.tenant_principals;\nCREATE POLICY ep_aeb_principals_owner_only ON ep_aeb_private.tenant_principals\n  TO ep_aeb_store_owner USING (TRUE) WITH CHECK (TRUE);\nDROP POLICY IF EXISTS ep_aeb_operations_owner_only ON ep_aeb_consumption_operations;\nCREATE POLICY ep_aeb_operations_owner_only ON ep_aeb_consumption_operations\n  TO ep_aeb_store_owner USING (TRUE) WITH CHECK (TRUE);\nDROP POLICY IF EXISTS ep_aeb_replay_owner_only ON ep_aeb_consumption_replay_fences;\nCREATE POLICY ep_aeb_replay_owner_only ON ep_aeb_consumption_replay_fences\n  TO ep_aeb_store_owner USING (TRUE) WITH CHECK (TRUE);\nREVOKE ALL ON ep_aeb_private.tenant_principals FROM PUBLIC, anon, authenticated, service_role,\n  ep_aeb_executor, ep_aeb_recovery;\nREVOKE ALL ON ep_aeb_consumption_operations FROM PUBLIC, anon, authenticated, service_role,\n  ep_aeb_executor, ep_aeb_recovery;\nREVOKE ALL ON ep_aeb_consumption_replay_fences FROM PUBLIC, anon, authenticated, service_role,\n  ep_aeb_executor, ep_aeb_recovery;\nCREATE OR REPLACE FUNCTION ep_aeb_private.assert_tenant_principal(\n  p_tenant_id TEXT, p_recovery BOOLEAN\n) RETURNS VOID\nLANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = ''\nAS $fn$\nDECLARE v_role_ok BOOLEAN; v_binding_ok BOOLEAN;\nBEGIN\n  v_role_ok := CASE WHEN p_recovery\n    THEN pg_catalog.pg_has_role(SESSION_USER, 'ep_aeb_recovery', 'MEMBER')\n    ELSE pg_catalog.pg_has_role(SESSION_USER, 'ep_aeb_executor', 'MEMBER')\n  END;\n  SELECT EXISTS (\n    SELECT 1 FROM ep_aeb_private.tenant_principals AS principals\n    WHERE principals.principal_name = SESSION_USER\n      AND principals.tenant_id = p_tenant_id\n      AND CASE WHEN p_recovery THEN principals.can_recover ELSE principals.can_execute END\n  ) INTO v_binding_ok;\n  IF v_role_ok IS NOT TRUE OR v_binding_ok IS NOT TRUE THEN\n    RAISE EXCEPTION 'AEB_TENANT_PRINCIPAL_REFUSED' USING ERRCODE = '42501';\n  END IF;\nEND\n$fn$;\nCREATE OR REPLACE FUNCTION ep_aeb_private.reserve_operation(\n  p_tenant_id TEXT, p_relying_party_id TEXT, p_operation_key TEXT, p_owner_token TEXT\n) RETURNS TABLE(operation_key TEXT)\nLANGUAGE plpgsql SECURITY DEFINER SET search_path = ''\nAS $fn$\nBEGIN\n  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);\n  RETURN QUERY INSERT INTO public.ep_aeb_consumption_operations\n    (tenant_id, relying_party_id, operation_key, state, owner_token)\n    VALUES (p_tenant_id, p_relying_party_id, p_operation_key, 'RESERVED', p_owner_token)\n    ON CONFLICT ON CONSTRAINT ep_aeb_consumption_operations_pkey DO NOTHING\n    RETURNING ep_aeb_consumption_operations.operation_key;\nEND\n$fn$;\nCREATE OR REPLACE FUNCTION ep_aeb_private.has_replay_fence(\n  p_tenant_id TEXT, p_relying_party_id TEXT, p_replay_key TEXT\n) RETURNS TABLE(fenced BOOLEAN)\nLANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = ''\nAS $fn$\nBEGIN\n  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);\n  RETURN QUERY SELECT EXISTS (\n    SELECT 1\n    FROM public.ep_aeb_consumption_replay_fences AS fences\n    WHERE fences.tenant_id = p_tenant_id\n      AND fences.relying_party_id = p_relying_party_id\n      AND fences.replay_key = p_replay_key\n  );\nEND\n$fn$;\nCREATE OR REPLACE FUNCTION ep_aeb_private.reserve_replay_keys(\n  p_tenant_id TEXT, p_relying_party_id TEXT, p_operation_key TEXT, p_replay_keys TEXT[]\n) RETURNS TABLE(replay_key TEXT)\nLANGUAGE plpgsql SECURITY DEFINER SET search_path = ''\nAS $fn$\nBEGIN\n  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);\n  RETURN QUERY INSERT INTO public.ep_aeb_consumption_replay_fences\n    (tenant_id, relying_party_id, replay_key, operation_key)\n    SELECT p_tenant_id, p_relying_party_id, requested.replay_key, p_operation_key\n    FROM pg_catalog.unnest(p_replay_keys) AS requested(replay_key)\n    ORDER BY requested.replay_key\n    ON CONFLICT ON CONSTRAINT ep_aeb_consumption_replay_fences_pkey DO NOTHING\n    RETURNING ep_aeb_consumption_replay_fences.replay_key;\nEND\n$fn$;\nCREATE OR REPLACE FUNCTION ep_aeb_private.commit_operation(\n  p_tenant_id TEXT, p_relying_party_id TEXT, p_operation_key TEXT, p_owner_token TEXT\n) RETURNS TABLE(operation_key TEXT)\nLANGUAGE plpgsql SECURITY DEFINER SET search_path = ''\nAS $fn$\nBEGIN\n  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);\n  RETURN QUERY UPDATE public.ep_aeb_consumption_operations\n    SET state = 'CONSUMED', owner_token = NULL, consumed_at = pg_catalog.transaction_timestamp()\n    WHERE tenant_id = p_tenant_id AND relying_party_id = p_relying_party_id\n      AND ep_aeb_consumption_operations.operation_key = p_operation_key\n      AND state = 'RESERVED' AND owner_token = p_owner_token\n    RETURNING ep_aeb_consumption_operations.operation_key;\nEND\n$fn$;\nCREATE OR REPLACE FUNCTION ep_aeb_private.claim_operation(\n  p_tenant_id TEXT, p_relying_party_id TEXT, p_operation_key TEXT, p_owner_token TEXT\n) RETURNS TABLE(operation_key TEXT)\nLANGUAGE plpgsql SECURITY DEFINER SET search_path = ''\nAS $fn$\nBEGIN\n  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, TRUE);\n  RETURN QUERY UPDATE public.ep_aeb_consumption_operations\n    SET owner_token = p_owner_token\n    WHERE tenant_id = p_tenant_id AND relying_party_id = p_relying_party_id\n      AND ep_aeb_consumption_operations.operation_key = p_operation_key\n      AND state = 'RESERVED'\n    RETURNING ep_aeb_consumption_operations.operation_key;\nEND\n$fn$;\nCREATE OR REPLACE FUNCTION ep_aeb_private.release_operation(\n  p_tenant_id TEXT, p_relying_party_id TEXT, p_operation_key TEXT, p_owner_token TEXT\n) RETURNS TABLE(operation_key TEXT)\nLANGUAGE plpgsql SECURITY DEFINER SET search_path = ''\nAS $fn$\nBEGIN\n  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);\n  RETURN QUERY DELETE FROM public.ep_aeb_consumption_operations\n    WHERE tenant_id = p_tenant_id AND relying_party_id = p_relying_party_id\n      AND ep_aeb_consumption_operations.operation_key = p_operation_key\n      AND state = 'RESERVED' AND owner_token = p_owner_token\n    RETURNING ep_aeb_consumption_operations.operation_key;\nEND\n$fn$;\nALTER FUNCTION ep_aeb_private.assert_tenant_principal(TEXT, BOOLEAN)\n  OWNER TO ep_aeb_store_owner;\nALTER FUNCTION ep_aeb_private.reserve_operation(TEXT, TEXT, TEXT, TEXT)\n  OWNER TO ep_aeb_store_owner;\nALTER FUNCTION ep_aeb_private.has_replay_fence(TEXT, TEXT, TEXT)\n  OWNER TO ep_aeb_store_owner;\nALTER FUNCTION ep_aeb_private.reserve_replay_keys(TEXT, TEXT, TEXT, TEXT[])\n  OWNER TO ep_aeb_store_owner;\nALTER FUNCTION ep_aeb_private.commit_operation(TEXT, TEXT, TEXT, TEXT)\n  OWNER TO ep_aeb_store_owner;\nALTER FUNCTION ep_aeb_private.claim_operation(TEXT, TEXT, TEXT, TEXT)\n  OWNER TO ep_aeb_store_owner;\nALTER FUNCTION ep_aeb_private.release_operation(TEXT, TEXT, TEXT, TEXT)\n  OWNER TO ep_aeb_store_owner;\nREVOKE ALL ON ALL FUNCTIONS IN SCHEMA ep_aeb_private\n  FROM PUBLIC, anon, authenticated, service_role;\nGRANT USAGE ON SCHEMA ep_aeb_private TO ep_aeb_executor, ep_aeb_recovery;\nGRANT EXECUTE ON FUNCTION ep_aeb_private.has_replay_fence(TEXT, TEXT, TEXT),\n  ep_aeb_private.reserve_operation(TEXT, TEXT, TEXT, TEXT),\n  ep_aeb_private.reserve_replay_keys(TEXT, TEXT, TEXT, TEXT[]),\n  ep_aeb_private.commit_operation(TEXT, TEXT, TEXT, TEXT),\n  ep_aeb_private.release_operation(TEXT, TEXT, TEXT, TEXT)\n  TO ep_aeb_executor;\nGRANT EXECUTE ON FUNCTION ep_aeb_private.claim_operation(TEXT, TEXT, TEXT, TEXT)\n  TO ep_aeb_recovery;\nREVOKE ep_aeb_store_owner FROM CURRENT_USER;";
/** Exact statements issued by the store, exported for audit and deterministic fakes. */
export declare const AEB_CONSUMPTION_SQL: Readonly<{
    hasReplayFence: "SELECT fenced FROM ep_aeb_private.has_replay_fence($1::text, $2::text, $3::text)";
    reserveOperation: "SELECT operation_key FROM ep_aeb_private.reserve_operation($1::text, $2::text, $3::text, $4::text)";
    reserveReplayKeys: "SELECT replay_key FROM ep_aeb_private.reserve_replay_keys($1::text, $2::text, $3::text, $4::text[])";
    commitOperation: "SELECT operation_key FROM ep_aeb_private.commit_operation($1::text, $2::text, $3::text, $4::text)";
    claimOperation: "SELECT operation_key FROM ep_aeb_private.claim_operation($1::text, $2::text, $3::text, $4::text)";
    releaseOperation: "SELECT operation_key FROM ep_aeb_private.release_operation($1::text, $2::text, $3::text, $4::text)";
}>;
type QueryResult = {
    rowCount: number | null;
    rows?: Record<string, unknown>[];
};
export type AebConsumptionPgClient = {
    query: (text: string, params?: any[]) => Promise<QueryResult>;
    release: () => void;
};
export type AebConsumptionPgPool = {
    connect: () => Promise<AebConsumptionPgClient>;
};
export interface PostgresAebDurableConsumptionStoreOptions {
    /** Pool authenticated as a tenant-bound member of ep_aeb_executor. */
    pool?: AebConsumptionPgPool;
    /** Distinct pool authenticated as a tenant-bound member of ep_aeb_recovery. */
    recoveryPool?: AebConsumptionPgPool;
    tenantId?: string;
    relyingPartyId?: string;
    /** Must return an unpredictable opaque string in production. */
    ownerTokenFactory?: () => string;
    /** Verify a caller credential bound to the exact reservation being claimed. */
    authorizeRecoveryClaim?: AebRecoveryClaimAuthorizer;
}
export interface AebRecoveryClaimAuthorization {
    authorization: unknown;
    tenantId: string;
    relyingPartyId: string;
    operationKey: string;
    requiredState: 'RESERVED';
}
export type AebRecoveryClaimAuthorizer = (claim: Readonly<AebRecoveryClaimAuthorization>) => boolean | Promise<boolean>;
export interface PostgresAebDurableConsumptionStore extends AebDurableConsumptionStore {
    recoveryClaimSupported: true;
    /**
     * Authenticated pre-reservation observation for one exact native replay key.
     * A true result includes both RESERVED and CONSUMED fences. Atomic reserve
     * remains the race-closing operation.
     */
    hasReplayFence(replayKey: string): Promise<boolean>;
    /**
     * Rotate ownership of an existing RESERVED row after external authorization.
     * The stored and replacement owner tokens are never returned or passed to
     * the authorizer.
     */
    claimReservation(key: string, authorization: unknown): Promise<boolean>;
}
/**
 * Create the durable AEB store consumed by authorizeAebExecutionDurable().
 * The pool must return a pinned node-postgres-style client for each transaction.
 */
export declare function createPostgresAebDurableConsumptionStore({ pool, recoveryPool, tenantId, relyingPartyId, ownerTokenFactory, authorizeRecoveryClaim, }?: PostgresAebDurableConsumptionStoreOptions): PostgresAebDurableConsumptionStore;
declare const _default: {
    AEB_PG_CONSUMPTION_STORE_VERSION: string;
    AEB_CONSUMPTION_OPERATION_TABLE: string;
    AEB_CONSUMPTION_REPLAY_TABLE: string;
    AEB_CONSUMPTION_EXECUTOR_ROLE: string;
    AEB_CONSUMPTION_RECOVERY_ROLE: string;
    AEB_CONSUMPTION_DDL: string;
    AEB_CONSUMPTION_SQL: Readonly<{
        hasReplayFence: "SELECT fenced FROM ep_aeb_private.has_replay_fence($1::text, $2::text, $3::text)";
        reserveOperation: "SELECT operation_key FROM ep_aeb_private.reserve_operation($1::text, $2::text, $3::text, $4::text)";
        reserveReplayKeys: "SELECT replay_key FROM ep_aeb_private.reserve_replay_keys($1::text, $2::text, $3::text, $4::text[])";
        commitOperation: "SELECT operation_key FROM ep_aeb_private.commit_operation($1::text, $2::text, $3::text, $4::text)";
        claimOperation: "SELECT operation_key FROM ep_aeb_private.claim_operation($1::text, $2::text, $3::text, $4::text)";
        releaseOperation: "SELECT operation_key FROM ep_aeb_private.release_operation($1::text, $2::text, $3::text, $4::text)";
    }>;
    createPostgresAebDurableConsumptionStore: typeof createPostgresAebDurableConsumptionStore;
};
export default _default;
//# sourceMappingURL=aeb-consumption-store.d.ts.map