// SPDX-License-Identifier: Apache-2.0
/**
 * PostgreSQL custody for AEB operation consumption and native replay fences.
 *
 * A reservation installs the operation key and every native replay key in one
 * pinned transaction. Logical conflicts roll the transaction back; database
 * errors propagate so callers fail closed. Commit and release are fenced by an
 * opaque per-reservation token retained only by the store instance that won.
 * A different instance (for example after a restart) takes ownership of a
 * RESERVED row only through claimReservation(), which requires the separate
 * recovery pool and an authorized recovery claim. state() is an authenticated
 * durable read, which the direct-native consequence boundary requires.
 *
 * Ownership is per store instance and per key, so two callers in one process
 * that reserve the same key share one owner token. The native consequence
 * boundary therefore writes only keys that include its boundary ID and
 * attempt ID, which no other attempt can produce. The composed boundary's
 * evaluation reservation is keyed by the evaluation; it closes or commits that
 * row for an attempt only while the attempt's own holder row, keyed by the
 * evaluation reservation, the boundary ID, and the attempt ID, is still
 * RESERVED.
 *
 * Every recovery claim must carry a scope naming the claimed row. A claim
 * without one is refused before the authorizer runs
 * (`recovery_claim_scope_required`).
 */
import crypto from 'node:crypto';
import type {
  AebConsumptionState,
  AebDurableConsumptionStore,
  AebReservationResult,
} from '@emilia-protocol/verify/aeb-adapter-contract';
import {
  consequenceBoundaryRecoveryAttemptIdentity,
  consequenceBoundaryRecoveryClaimKey,
  consequenceBoundaryRecoveryClaimMarkerKey,
} from './consequence-boundary.js';

export const AEB_PG_CONSUMPTION_STORE_VERSION = 'EP-GATE-AEB-PG-CONSUMPTION-v1';
export const AEB_CONSUMPTION_OPERATION_TABLE = 'ep_aeb_consumption_operations';
export const AEB_CONSUMPTION_REPLAY_TABLE = 'ep_aeb_consumption_replay_fences';
export const AEB_CONSUMPTION_EXECUTOR_ROLE = 'ep_aeb_executor';
export const AEB_CONSUMPTION_RECOVERY_ROLE = 'ep_aeb_recovery';
export const AEB_CONSUMPTION_OWNER_ROLE = 'ep_aeb_store_owner';

/** Exact schema required by createPostgresAebDurableConsumptionStore(). */
export const AEB_CONSUMPTION_DDL = `CREATE TABLE IF NOT EXISTS ${AEB_CONSUMPTION_OPERATION_TABLE} (
  tenant_id        TEXT NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 512),
  relying_party_id TEXT NOT NULL CHECK (octet_length(relying_party_id) BETWEEN 1 AND 512),
  operation_key    TEXT NOT NULL CHECK (octet_length(operation_key) BETWEEN 1 AND 4096),
  state            TEXT NOT NULL CHECK (state IN ('RESERVED', 'CONSUMED', 'RELEASED_NOT_ENTERED')),
  owner_token      TEXT NULL CHECK (owner_token IS NULL OR octet_length(owner_token) BETWEEN 16 AND 512),
  reserved_at      TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
  consumed_at      TIMESTAMPTZ NULL,
  released_at      TIMESTAMPTZ NULL,
  PRIMARY KEY (tenant_id, relying_party_id, operation_key),
  CONSTRAINT ep_aeb_consumption_operations_lifecycle_check CHECK (
    (state = 'RESERVED' AND owner_token IS NOT NULL AND consumed_at IS NULL AND released_at IS NULL)
    OR (state = 'CONSUMED' AND owner_token IS NULL AND consumed_at IS NOT NULL AND released_at IS NULL)
    OR (state = 'RELEASED_NOT_ENTERED' AND owner_token IS NULL AND consumed_at IS NULL
        AND released_at IS NOT NULL)
  )
);
-- Forward migration for a table created before the terminal released-not-entered
-- state existed. Every step is idempotent, so re-running the whole DDL is safe.
ALTER TABLE ${AEB_CONSUMPTION_OPERATION_TABLE}
  ADD COLUMN IF NOT EXISTS released_at TIMESTAMPTZ NULL;
ALTER TABLE ${AEB_CONSUMPTION_OPERATION_TABLE}
  DROP CONSTRAINT IF EXISTS ep_aeb_consumption_operations_state_check;
ALTER TABLE ${AEB_CONSUMPTION_OPERATION_TABLE}
  ADD CONSTRAINT ep_aeb_consumption_operations_state_check
  CHECK (state IN ('RESERVED', 'CONSUMED', 'RELEASED_NOT_ENTERED'));
ALTER TABLE ${AEB_CONSUMPTION_OPERATION_TABLE}
  DROP CONSTRAINT IF EXISTS ep_aeb_consumption_operations_check;
ALTER TABLE ${AEB_CONSUMPTION_OPERATION_TABLE}
  DROP CONSTRAINT IF EXISTS ep_aeb_consumption_operations_lifecycle_check;
ALTER TABLE ${AEB_CONSUMPTION_OPERATION_TABLE}
  ADD CONSTRAINT ep_aeb_consumption_operations_lifecycle_check CHECK (
    (state = 'RESERVED' AND owner_token IS NOT NULL AND consumed_at IS NULL AND released_at IS NULL)
    OR (state = 'CONSUMED' AND owner_token IS NULL AND consumed_at IS NOT NULL AND released_at IS NULL)
    OR (state = 'RELEASED_NOT_ENTERED' AND owner_token IS NULL AND consumed_at IS NULL
        AND released_at IS NOT NULL)
  );
CREATE TABLE IF NOT EXISTS ${AEB_CONSUMPTION_REPLAY_TABLE} (
  tenant_id        TEXT NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 512),
  relying_party_id TEXT NOT NULL CHECK (octet_length(relying_party_id) BETWEEN 1 AND 512),
  replay_key       TEXT NOT NULL CHECK (octet_length(replay_key) BETWEEN 1 AND 4096),
  operation_key    TEXT NOT NULL CHECK (octet_length(operation_key) BETWEEN 1 AND 4096),
  reserved_at      TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (tenant_id, relying_party_id, replay_key),
  FOREIGN KEY (tenant_id, relying_party_id, operation_key)
    REFERENCES ${AEB_CONSUMPTION_OPERATION_TABLE} (tenant_id, relying_party_id, operation_key)
    ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ${AEB_CONSUMPTION_REPLAY_TABLE}_operation_idx
  ON ${AEB_CONSUMPTION_REPLAY_TABLE} (tenant_id, relying_party_id, operation_key);
DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '${AEB_CONSUMPTION_EXECUTOR_ROLE}') THEN
    CREATE ROLE ${AEB_CONSUMPTION_EXECUTOR_ROLE} NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '${AEB_CONSUMPTION_RECOVERY_ROLE}') THEN
    CREATE ROLE ${AEB_CONSUMPTION_RECOVERY_ROLE} NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '${AEB_CONSUMPTION_OWNER_ROLE}') THEN
    CREATE ROLE ${AEB_CONSUMPTION_OWNER_ROLE} NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$roles$;
GRANT ${AEB_CONSUMPTION_OWNER_ROLE} TO CURRENT_USER;
CREATE SCHEMA IF NOT EXISTS ep_aeb_private;
REVOKE ALL ON SCHEMA ep_aeb_private FROM PUBLIC, anon, authenticated, service_role;
CREATE TABLE IF NOT EXISTS ep_aeb_private.tenant_principals (
  principal_name NAME NOT NULL,
  tenant_id TEXT NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 512),
  can_execute BOOLEAN NOT NULL DEFAULT FALSE,
  can_recover BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (principal_name, tenant_id),
  CHECK (can_execute OR can_recover)
);
ALTER SCHEMA ep_aeb_private OWNER TO ${AEB_CONSUMPTION_OWNER_ROLE};
ALTER TABLE ep_aeb_private.tenant_principals OWNER TO ${AEB_CONSUMPTION_OWNER_ROLE};
ALTER TABLE ${AEB_CONSUMPTION_OPERATION_TABLE} OWNER TO ${AEB_CONSUMPTION_OWNER_ROLE};
ALTER TABLE ${AEB_CONSUMPTION_REPLAY_TABLE} OWNER TO ${AEB_CONSUMPTION_OWNER_ROLE};
ALTER TABLE ep_aeb_private.tenant_principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE ep_aeb_private.tenant_principals FORCE ROW LEVEL SECURITY;
ALTER TABLE ${AEB_CONSUMPTION_OPERATION_TABLE} ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${AEB_CONSUMPTION_OPERATION_TABLE} FORCE ROW LEVEL SECURITY;
ALTER TABLE ${AEB_CONSUMPTION_REPLAY_TABLE} ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${AEB_CONSUMPTION_REPLAY_TABLE} FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ep_aeb_principals_owner_only ON ep_aeb_private.tenant_principals;
CREATE POLICY ep_aeb_principals_owner_only ON ep_aeb_private.tenant_principals
  TO ${AEB_CONSUMPTION_OWNER_ROLE} USING (TRUE) WITH CHECK (TRUE);
DROP POLICY IF EXISTS ep_aeb_operations_owner_only ON ${AEB_CONSUMPTION_OPERATION_TABLE};
CREATE POLICY ep_aeb_operations_owner_only ON ${AEB_CONSUMPTION_OPERATION_TABLE}
  TO ${AEB_CONSUMPTION_OWNER_ROLE} USING (TRUE) WITH CHECK (TRUE);
DROP POLICY IF EXISTS ep_aeb_replay_owner_only ON ${AEB_CONSUMPTION_REPLAY_TABLE};
CREATE POLICY ep_aeb_replay_owner_only ON ${AEB_CONSUMPTION_REPLAY_TABLE}
  TO ${AEB_CONSUMPTION_OWNER_ROLE} USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON ep_aeb_private.tenant_principals FROM PUBLIC, anon, authenticated, service_role,
  ${AEB_CONSUMPTION_EXECUTOR_ROLE}, ${AEB_CONSUMPTION_RECOVERY_ROLE};
REVOKE ALL ON ${AEB_CONSUMPTION_OPERATION_TABLE} FROM PUBLIC, anon, authenticated, service_role,
  ${AEB_CONSUMPTION_EXECUTOR_ROLE}, ${AEB_CONSUMPTION_RECOVERY_ROLE};
REVOKE ALL ON ${AEB_CONSUMPTION_REPLAY_TABLE} FROM PUBLIC, anon, authenticated, service_role,
  ${AEB_CONSUMPTION_EXECUTOR_ROLE}, ${AEB_CONSUMPTION_RECOVERY_ROLE};
CREATE OR REPLACE FUNCTION ep_aeb_private.assert_tenant_principal(
  p_tenant_id TEXT, p_recovery BOOLEAN
) RETURNS VOID
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = ''
AS $fn$
DECLARE v_role_ok BOOLEAN; v_binding_ok BOOLEAN;
BEGIN
  v_role_ok := CASE WHEN p_recovery
    THEN pg_catalog.pg_has_role(SESSION_USER, '${AEB_CONSUMPTION_RECOVERY_ROLE}', 'MEMBER')
    ELSE pg_catalog.pg_has_role(SESSION_USER, '${AEB_CONSUMPTION_EXECUTOR_ROLE}', 'MEMBER')
  END;
  SELECT EXISTS (
    SELECT 1 FROM ep_aeb_private.tenant_principals AS principals
    WHERE principals.principal_name = SESSION_USER
      AND principals.tenant_id = p_tenant_id
      AND CASE WHEN p_recovery THEN principals.can_recover ELSE principals.can_execute END
  ) INTO v_binding_ok;
  IF v_role_ok IS NOT TRUE OR v_binding_ok IS NOT TRUE THEN
    RAISE EXCEPTION 'AEB_TENANT_PRINCIPAL_REFUSED' USING ERRCODE = '42501';
  END IF;
END
$fn$;
CREATE OR REPLACE FUNCTION ep_aeb_private.reserve_operation(
  p_tenant_id TEXT, p_relying_party_id TEXT, p_operation_key TEXT, p_owner_token TEXT
) RETURNS TABLE(operation_key TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);
  RETURN QUERY INSERT INTO public.${AEB_CONSUMPTION_OPERATION_TABLE}
    (tenant_id, relying_party_id, operation_key, state, owner_token)
    VALUES (p_tenant_id, p_relying_party_id, p_operation_key, 'RESERVED', p_owner_token)
    ON CONFLICT ON CONSTRAINT ep_aeb_consumption_operations_pkey DO NOTHING
    RETURNING ${AEB_CONSUMPTION_OPERATION_TABLE}.operation_key;
END
$fn$;
CREATE OR REPLACE FUNCTION ep_aeb_private.has_replay_fence(
  p_tenant_id TEXT, p_relying_party_id TEXT, p_replay_key TEXT
) RETURNS TABLE(fenced BOOLEAN)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);
  RETURN QUERY SELECT EXISTS (
    SELECT 1
    FROM public.${AEB_CONSUMPTION_REPLAY_TABLE} AS fences
    WHERE fences.tenant_id = p_tenant_id
      AND fences.relying_party_id = p_relying_party_id
      AND fences.replay_key = p_replay_key
  );
END
$fn$;
-- Authenticated durable read of one exact operation row. AVAILABLE means no
-- row exists. Lets a caller distinguish a lost write acknowledgement from a
-- write that never happened without granting table reads.
CREATE OR REPLACE FUNCTION ep_aeb_private.operation_state(
  p_tenant_id TEXT, p_relying_party_id TEXT, p_operation_key TEXT
) RETURNS TABLE(state TEXT)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);
  RETURN QUERY SELECT COALESCE((
    SELECT operations.state
    FROM public.${AEB_CONSUMPTION_OPERATION_TABLE} AS operations
    WHERE operations.tenant_id = p_tenant_id
      AND operations.relying_party_id = p_relying_party_id
      AND operations.operation_key = p_operation_key
  ), 'AVAILABLE');
END
$fn$;
CREATE OR REPLACE FUNCTION ep_aeb_private.reserve_replay_keys(
  p_tenant_id TEXT, p_relying_party_id TEXT, p_operation_key TEXT, p_replay_keys TEXT[]
) RETURNS TABLE(replay_key TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);
  RETURN QUERY INSERT INTO public.${AEB_CONSUMPTION_REPLAY_TABLE}
    (tenant_id, relying_party_id, replay_key, operation_key)
    SELECT p_tenant_id, p_relying_party_id, requested.replay_key, p_operation_key
    FROM pg_catalog.unnest(p_replay_keys) AS requested(replay_key)
    ORDER BY requested.replay_key
    ON CONFLICT ON CONSTRAINT ep_aeb_consumption_replay_fences_pkey DO NOTHING
    RETURNING ${AEB_CONSUMPTION_REPLAY_TABLE}.replay_key;
END
$fn$;
CREATE OR REPLACE FUNCTION ep_aeb_private.commit_operation(
  p_tenant_id TEXT, p_relying_party_id TEXT, p_operation_key TEXT, p_owner_token TEXT
) RETURNS TABLE(operation_key TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);
  RETURN QUERY UPDATE public.${AEB_CONSUMPTION_OPERATION_TABLE}
    SET state = 'CONSUMED', owner_token = NULL, consumed_at = pg_catalog.transaction_timestamp()
    WHERE tenant_id = p_tenant_id AND relying_party_id = p_relying_party_id
      AND ${AEB_CONSUMPTION_OPERATION_TABLE}.operation_key = p_operation_key
      AND state = 'RESERVED' AND owner_token = p_owner_token
    RETURNING ${AEB_CONSUMPTION_OPERATION_TABLE}.operation_key;
END
$fn$;
CREATE OR REPLACE FUNCTION ep_aeb_private.claim_operation(
  p_tenant_id TEXT, p_relying_party_id TEXT, p_operation_key TEXT, p_owner_token TEXT
) RETURNS TABLE(operation_key TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, TRUE);
  RETURN QUERY UPDATE public.${AEB_CONSUMPTION_OPERATION_TABLE}
    SET owner_token = p_owner_token
    WHERE tenant_id = p_tenant_id AND relying_party_id = p_relying_party_id
      AND ${AEB_CONSUMPTION_OPERATION_TABLE}.operation_key = p_operation_key
      AND state = 'RESERVED'
    RETURNING ${AEB_CONSUMPTION_OPERATION_TABLE}.operation_key;
END
$fn$;
CREATE OR REPLACE FUNCTION ep_aeb_private.release_operation(
  p_tenant_id TEXT, p_relying_party_id TEXT, p_operation_key TEXT, p_owner_token TEXT
) RETURNS TABLE(operation_key TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);
  RETURN QUERY DELETE FROM public.${AEB_CONSUMPTION_OPERATION_TABLE}
    WHERE tenant_id = p_tenant_id AND relying_party_id = p_relying_party_id
      AND ${AEB_CONSUMPTION_OPERATION_TABLE}.operation_key = p_operation_key
      AND state = 'RESERVED' AND owner_token = p_owner_token
    RETURNING ${AEB_CONSUMPTION_OPERATION_TABLE}.operation_key;
END
$fn$;
-- Terminal released-not-entered marker. The row is kept so the byte-identical
-- operation key can never be reserved again, the owner token is dropped so no
-- late commit can reopen it, and the native replay fences that reference this
-- row are kept because the ON DELETE CASCADE never fires.
CREATE OR REPLACE FUNCTION ep_aeb_private.release_terminal_operation(
  p_tenant_id TEXT, p_relying_party_id TEXT, p_operation_key TEXT, p_owner_token TEXT
) RETURNS TABLE(operation_key TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);
  RETURN QUERY
    WITH transitioned AS (
      UPDATE public.${AEB_CONSUMPTION_OPERATION_TABLE}
        SET state = 'RELEASED_NOT_ENTERED', owner_token = NULL,
            released_at = pg_catalog.transaction_timestamp()
        WHERE tenant_id = p_tenant_id AND relying_party_id = p_relying_party_id
          AND ${AEB_CONSUMPTION_OPERATION_TABLE}.operation_key = p_operation_key
          AND state = 'RESERVED' AND owner_token = p_owner_token
        RETURNING ${AEB_CONSUMPTION_OPERATION_TABLE}.operation_key
    )
    SELECT transitioned.operation_key FROM transitioned
    UNION ALL
    SELECT existing.operation_key
      FROM public.${AEB_CONSUMPTION_OPERATION_TABLE} AS existing
      WHERE NOT EXISTS (SELECT 1 FROM transitioned)
        AND existing.tenant_id = p_tenant_id
        AND existing.relying_party_id = p_relying_party_id
        AND existing.operation_key = p_operation_key
        AND existing.state = 'RELEASED_NOT_ENTERED';
END
$fn$;
ALTER FUNCTION ep_aeb_private.assert_tenant_principal(TEXT, BOOLEAN)
  OWNER TO ${AEB_CONSUMPTION_OWNER_ROLE};
ALTER FUNCTION ep_aeb_private.reserve_operation(TEXT, TEXT, TEXT, TEXT)
  OWNER TO ${AEB_CONSUMPTION_OWNER_ROLE};
ALTER FUNCTION ep_aeb_private.has_replay_fence(TEXT, TEXT, TEXT)
  OWNER TO ${AEB_CONSUMPTION_OWNER_ROLE};
ALTER FUNCTION ep_aeb_private.operation_state(TEXT, TEXT, TEXT)
  OWNER TO ${AEB_CONSUMPTION_OWNER_ROLE};
ALTER FUNCTION ep_aeb_private.reserve_replay_keys(TEXT, TEXT, TEXT, TEXT[])
  OWNER TO ${AEB_CONSUMPTION_OWNER_ROLE};
ALTER FUNCTION ep_aeb_private.commit_operation(TEXT, TEXT, TEXT, TEXT)
  OWNER TO ${AEB_CONSUMPTION_OWNER_ROLE};
ALTER FUNCTION ep_aeb_private.claim_operation(TEXT, TEXT, TEXT, TEXT)
  OWNER TO ${AEB_CONSUMPTION_OWNER_ROLE};
ALTER FUNCTION ep_aeb_private.release_operation(TEXT, TEXT, TEXT, TEXT)
  OWNER TO ${AEB_CONSUMPTION_OWNER_ROLE};
ALTER FUNCTION ep_aeb_private.release_terminal_operation(TEXT, TEXT, TEXT, TEXT)
  OWNER TO ${AEB_CONSUMPTION_OWNER_ROLE};
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ep_aeb_private
  FROM PUBLIC, anon, authenticated, service_role;
GRANT USAGE ON SCHEMA ep_aeb_private TO ${AEB_CONSUMPTION_EXECUTOR_ROLE}, ${AEB_CONSUMPTION_RECOVERY_ROLE};
GRANT EXECUTE ON FUNCTION ep_aeb_private.has_replay_fence(TEXT, TEXT, TEXT),
  ep_aeb_private.reserve_operation(TEXT, TEXT, TEXT, TEXT),
  ep_aeb_private.reserve_replay_keys(TEXT, TEXT, TEXT, TEXT[]),
  ep_aeb_private.commit_operation(TEXT, TEXT, TEXT, TEXT),
  ep_aeb_private.release_operation(TEXT, TEXT, TEXT, TEXT),
  ep_aeb_private.release_terminal_operation(TEXT, TEXT, TEXT, TEXT)
  TO ${AEB_CONSUMPTION_EXECUTOR_ROLE};
GRANT EXECUTE ON FUNCTION ep_aeb_private.claim_operation(TEXT, TEXT, TEXT, TEXT)
  TO ${AEB_CONSUMPTION_RECOVERY_ROLE};
GRANT EXECUTE ON FUNCTION ep_aeb_private.operation_state(TEXT, TEXT, TEXT)
  TO ${AEB_CONSUMPTION_EXECUTOR_ROLE};
REVOKE ${AEB_CONSUMPTION_OWNER_ROLE} FROM CURRENT_USER;`;

/** Exact statements issued by the store, exported for audit and deterministic fakes. */
export const AEB_CONSUMPTION_SQL = Object.freeze({
  hasReplayFence: `SELECT fenced FROM ep_aeb_private.has_replay_fence($1::text, $2::text, $3::text)`,
  operationState: `SELECT state FROM ep_aeb_private.operation_state($1::text, $2::text, $3::text)`,
  reserveOperation: `SELECT operation_key FROM ep_aeb_private.reserve_operation($1::text, $2::text, $3::text, $4::text)`,
  reserveReplayKeys: `SELECT replay_key FROM ep_aeb_private.reserve_replay_keys($1::text, $2::text, $3::text, $4::text[])`,
  commitOperation: `SELECT operation_key FROM ep_aeb_private.commit_operation($1::text, $2::text, $3::text, $4::text)`,
  claimOperation: `SELECT operation_key FROM ep_aeb_private.claim_operation($1::text, $2::text, $3::text, $4::text)`,
  releaseOperation: `SELECT operation_key FROM ep_aeb_private.release_operation($1::text, $2::text, $3::text, $4::text)`,
  releaseTerminalOperation: `SELECT operation_key FROM ep_aeb_private.release_terminal_operation($1::text, $2::text, $3::text, $4::text)`,
});

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
  /**
   * Verify a caller credential for the reservation being claimed. The store
   * runs it only for a claim whose scope names exactly `operationKey`
   * (consequenceBoundaryRecoveryClaimKey()), so one credential bound to the
   * attempt authorizes every reservation that attempt holds: bind it to
   * `attemptIdentity` (the boundary kind, the boundary ID, and the attempt
   * ID) together with `tenantId` and `relyingPartyId`. Never bind it to
   * `scope.attemptId` alone, which attempts on two boundaries can share, to
   * `scope.recoveryOperationKey` alone, which every attempt with the same
   * operation ID and action (native) or the same evaluation (composed)
   * shares, or to `operationKey`, or restart reconciliation cannot finish in
   * one call.
   */
  authorizeRecoveryClaim?: AebRecoveryClaimAuthorizer;
}

/**
 * Which attempt a recovery claim is for. The consequence boundary supplies it
 * from custody it has already authenticated through its attempt store. The
 * store refuses a claim whose key is not the row this scope names
 * (consequenceBoundaryRecoveryClaimKey()), and a claim on a row shared by
 * several attempts (the composed evaluation reservation) unless the scope's
 * attempt still holds its action-fence holder row, so an authorizer binds one
 * credential to the attempt instead of to each row key.
 */
export interface AebRecoveryClaimScope {
  /**
   * Which consequence boundary wrote the attempt. A `native` scope derives
   * only native rows and a `composed` scope only composed rows, so equal
   * attempt IDs on the two boundaries never name each other's rows.
   */
  boundary: 'native' | 'composed';
  /**
   * The `boundary_id` of the boundary that wrote the attempt. Every
   * attempt-derived row key includes it, so two boundaries of the same kind
   * that share a consumption store never name each other's rows, even with
   * identical attempt IDs.
   */
  boundaryId: string;
  /**
   * Boundary attempt whose reservation is being claimed. Attempt IDs are
   * unique per attempt store: it refuses a second reservation of one ID.
   */
  attemptId: string;
  /**
   * Caller operation identifier the attempt carried. It is caller-asserted:
   * the store checks that the scope names the claimed row, but no row key is
   * derived from `operationId`, so an authorizer must not rely on it.
   */
  operationId: string;
  /**
   * Operation identity the attempt's row keys are derived from: the native
   * boundary's nativeConsequenceBoundaryReservationKey() value, or the
   * composed boundary's AEB evaluation reservation key. Other attempts with
   * the same operation ID and action, or the same evaluation, share it, so it
   * is not a binding for a credential.
   */
  recoveryOperationKey: string;
  /** Which of the attempt's reservations `operationKey` names. */
  reservation: 'operation' | 'native-authority' | 'action-fence-holder';
}

export interface AebRecoveryClaimAuthorization {
  authorization: unknown;
  tenantId: string;
  relyingPartyId: string;
  /** Exact store row being claimed; the scope names exactly this row. */
  operationKey: string;
  requiredState: 'RESERVED';
  /**
   * The attempt identity to bind a credential to:
   * consequenceBoundaryRecoveryAttemptIdentity(scope),
   * `native:<boundaryId>:<attemptId>` or `composed:<boundaryId>:<attemptId>`.
   */
  attemptIdentity: string;
  /**
   * The validated scope. Every member except `operationId` is checked
   * against the claimed row; `operationId` is caller-asserted.
   */
  scope: Readonly<AebRecoveryClaimScope>;
}

/**
 * Why claimReservationResult() refused a claim. Every reason except
 * `recovery_claim_unauthorized` and `recovery_claim_row_not_reserved` is
 * decided before the authorizer runs.
 */
export type AebRecoveryClaimRefusal =
  | 'recovery_claim_scope_required'
  | 'recovery_claim_scope_invalid'
  | 'recovery_claim_key_mismatch'
  | 'recovery_claim_owner_marker_absent'
  | 'recovery_claim_already_owned'
  | 'recovery_claim_unauthorized'
  | 'recovery_claim_row_not_reserved';

export type AebRecoveryClaimResult =
  | { claimed: true }
  | { claimed: false; reason: AebRecoveryClaimRefusal };

export type AebRecoveryClaimAuthorizer = (
  claim: Readonly<AebRecoveryClaimAuthorization>,
) => boolean | Promise<boolean>;

export interface PostgresAebDurableConsumptionStore extends AebDurableConsumptionStore {
  terminalRelease: true;
  recoveryClaimSupported: true;
  /**
   * Mark an owned RESERVED row permanently RELEASED_NOT_ENTERED after an
   * authoritative serialized non-entry. The row is never deleted, so the same
   * operation key is unreservable forever and its native replay fences survive.
   * A retry converges to true when the exact row is already terminal, covering
   * a committed transaction whose acknowledgement was lost.
   */
  releaseTerminal(key: string): Promise<boolean>;
  /**
   * Authenticated pre-reservation observation for one exact native replay key.
   * A true result includes both RESERVED and CONSUMED fences. Atomic reserve
   * remains the race-closing operation.
   */
  hasReplayFence(replayKey: string): Promise<boolean>;
  /**
   * Authenticated durable read of one operation row: AVAILABLE when no row
   * exists, otherwise RESERVED, CONSUMED, or RELEASED_NOT_ENTERED. Database
   * errors and malformed answers throw, so callers treat them as unknown.
   */
  state(key: string): Promise<AebConsumptionState>;
  /**
   * Rotate ownership of an existing RESERVED row after external authorization.
   * The stored and replacement owner tokens are never returned or passed to
   * the authorizer. `scope` is required and must name exactly `key`
   * (consequenceBoundaryRecoveryClaimKey()); for the composed evaluation
   * reservation the scope's attempt must still hold its fence holder row.
   * Otherwise the claim is refused before the authorizer runs. The validated
   * scope and its attempt identity are passed to the authorizer. Same as
   * claimReservationResult(), reduced to whether the claim succeeded.
   */
  claimReservation(
    key: string,
    authorization: unknown,
    scope?: AebRecoveryClaimScope,
  ): Promise<boolean>;
  /**
   * claimReservation() with the refusal reason. Scope problems are refusals,
   * never throws; database errors still reject so callers fail closed.
   */
  claimReservationResult(
    key: string,
    authorization: unknown,
    scope?: AebRecoveryClaimScope,
  ): Promise<AebRecoveryClaimResult>;
}

const BEGIN_WRITE = 'BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE';
const COMMIT = 'COMMIT';
const ROLLBACK = 'ROLLBACK';

class ReservationConflict extends Error {
  readonly result: Exclude<AebReservationResult, 'RESERVED'>;

  constructor(result: Exclude<AebReservationResult, 'RESERVED'>) {
    super(result);
    this.result = result;
  }
}

function defaultOwnerToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function assertText(
  value: unknown,
  label: string,
  maximumBytes: number,
): asserts value is string {
  if (typeof value !== 'string'
      || Buffer.byteLength(value, 'utf8') < 1
      || Buffer.byteLength(value, 'utf8') > maximumBytes
      || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new TypeError(`AEB consumption ${label} is invalid`);
  }
}

function assertOwnerToken(value: unknown): asserts value is string {
  if (typeof value !== 'string'
      || Buffer.byteLength(value, 'utf8') < 16
      || Buffer.byteLength(value, 'utf8') > 512
      || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new TypeError('AEB consumption ownerTokenFactory must return an opaque string of 16 to 512 bytes');
  }
}

const RECOVERY_CLAIM_RESERVATIONS = new Set(['operation', 'native-authority', 'action-fence-holder']);

const RECOVERY_CLAIM_BOUNDARIES = new Set(['native', 'composed']);

/** Same grammar as the boundaries' `boundary_id`. */
const RECOVERY_CLAIM_BOUNDARY_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;

function validText(value: unknown, maximumBytes: number): value is string {
  return typeof value === 'string'
    && Buffer.byteLength(value, 'utf8') >= 1
    && Buffer.byteLength(value, 'utf8') <= maximumBytes
    && !/[\u0000-\u001f\u007f]/.test(value);
}

/**
 * Copy a caller scope through data descriptors only; no getter ever runs.
 * Null for anything that is not a well-formed scope.
 */
function recoveryClaimScope(value: unknown): Readonly<AebRecoveryClaimScope> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  let descriptors: PropertyDescriptorMap;
  try {
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return null;
  }
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key !== 'string' || !Object.hasOwn(descriptors[key as string], 'value'))) {
    return null;
  }
  const record: Record<string, unknown> = {};
  for (const key of keys as string[]) record[key] = descriptors[key].value;
  if (Object.keys(record).sort().join(',')
      !== 'attemptId,boundary,boundaryId,operationId,recoveryOperationKey,reservation'
      || !RECOVERY_CLAIM_BOUNDARIES.has(record.boundary as string)
      || typeof record.boundaryId !== 'string'
      || !RECOVERY_CLAIM_BOUNDARY_ID.test(record.boundaryId)
      || !RECOVERY_CLAIM_RESERVATIONS.has(record.reservation as string)
      || !validText(record.attemptId, 512)
      || !validText(record.operationId, 512)
      || !validText(record.recoveryOperationKey, 4096)) {
    return null;
  }
  return Object.freeze({
    boundary: record.boundary as AebRecoveryClaimScope['boundary'],
    boundaryId: record.boundaryId as string,
    attemptId: record.attemptId as string,
    operationId: record.operationId as string,
    recoveryOperationKey: record.recoveryOperationKey as string,
    reservation: record.reservation as AebRecoveryClaimScope['reservation'],
  });
}

function exactRowCount(result: QueryResult, operation: string) {
  if (!result
      || !Number.isSafeInteger(result.rowCount)
      || (result.rowCount as number) < 0) {
    throw new Error(`${operation}: malformed PostgreSQL result`);
  }
  return result.rowCount as number;
}

/**
 * Create the durable AEB store consumed by authorizeAebExecutionDurable().
 * The pool must return a pinned node-postgres-style client for each transaction.
 */
export function createPostgresAebDurableConsumptionStore({
  pool,
  recoveryPool,
  tenantId,
  relyingPartyId,
  ownerTokenFactory = defaultOwnerToken,
  authorizeRecoveryClaim,
}: PostgresAebDurableConsumptionStoreOptions = {}): PostgresAebDurableConsumptionStore {
  if (!pool || typeof pool.connect !== 'function') {
    throw new TypeError('createPostgresAebDurableConsumptionStore requires an ep_aeb_executor pg pool');
  }
  if (!recoveryPool || typeof recoveryPool.connect !== 'function' || recoveryPool === pool) {
    throw new TypeError('AEB consumption requires a distinct ep_aeb_recovery pg pool');
  }
  assertText(tenantId, 'tenantId', 512);
  assertText(relyingPartyId, 'relyingPartyId', 512);
  if (typeof ownerTokenFactory !== 'function') {
    throw new TypeError('AEB consumption ownerTokenFactory must be a function');
  }
  if (typeof authorizeRecoveryClaim !== 'function') {
    throw new TypeError('AEB consumption requires an authorizeRecoveryClaim callback');
  }

  async function transaction<T>(
    activePool: AebConsumptionPgPool,
    work: (client: AebConsumptionPgClient) => Promise<T>,
  ): Promise<T> {
    const client = await activePool.connect();
    if (!client || typeof client.query !== 'function' || typeof client.release !== 'function') {
      throw new TypeError('AEB consumption pg pool returned an invalid client');
    }
    let began = false;
    try {
      await client.query(BEGIN_WRITE);
      began = true;
      const result = await work(client);
      await client.query(COMMIT);
      began = false;
      return result;
    } catch (error) {
      if (began) {
        try {
          await client.query(ROLLBACK);
        } catch (rollbackError) {
          throw new AggregateError(
            [error, rollbackError],
            'AEB consumption transaction and rollback both failed',
          );
        }
      }
      throw error;
    } finally {
      client.release();
    }
  }

  const ownedReservations = new Map<string, string>();

  const store: PostgresAebDurableConsumptionStore = {
    durable: true,
    ownershipFenced: true,
    permanentConsumption: true,
    atomicReplayFenced: true,
    terminalRelease: true,
    recoveryClaimSupported: true,

    async hasReplayFence(replayKey): Promise<boolean> {
      assertText(replayKey, 'native replay key', 4096);
      const client = await pool.connect();
      if (!client || typeof client.query !== 'function' || typeof client.release !== 'function') {
        throw new TypeError('AEB consumption pg pool returned an invalid client');
      }
      try {
        const result = await client.query(AEB_CONSUMPTION_SQL.hasReplayFence, [
          tenantId, relyingPartyId, replayKey,
        ]);
        const rows = exactRowCount(result, 'lookup replay fence');
        const fenced = result.rows?.[0]?.fenced;
        if (rows !== 1 || result.rows?.length !== 1 || typeof fenced !== 'boolean') {
          throw new Error('lookup replay fence: malformed PostgreSQL result');
        }
        return fenced;
      } finally {
        client.release();
      }
    },

    async state(key): Promise<AebConsumptionState> {
      assertText(key, 'operation key', 4096);
      const client = await pool.connect();
      if (!client || typeof client.query !== 'function' || typeof client.release !== 'function') {
        throw new TypeError('AEB consumption pg pool returned an invalid client');
      }
      try {
        const result = await client.query(AEB_CONSUMPTION_SQL.operationState, [
          tenantId, relyingPartyId, key,
        ]);
        const rows = exactRowCount(result, 'read operation state');
        const state = result.rows?.[0]?.state;
        if (rows !== 1 || result.rows?.length !== 1
            || (state !== 'AVAILABLE' && state !== 'RESERVED'
              && state !== 'CONSUMED' && state !== 'RELEASED_NOT_ENTERED')) {
          throw new Error('read operation state: malformed PostgreSQL result');
        }
        return state;
      } finally {
        client.release();
      }
    },

    async reserve(key, replayKeys = []): Promise<AebReservationResult> {
      assertText(key, 'operation key', 4096);
      if (!Array.isArray(replayKeys)) {
        throw new TypeError('AEB consumption replay keys must be an array');
      }
      for (const replayKey of replayKeys) assertText(replayKey, 'native replay key', 4096);
      // Stable lock acquisition order avoids crossed replay-key insert order
      // becoming a preventable PostgreSQL deadlock under concurrency.
      const uniqueReplayKeys = [...new Set(replayKeys)].sort();
      const ownerToken = ownerTokenFactory();
      assertOwnerToken(ownerToken);

      try {
        await transaction(pool, async (client) => {
          const operationRows = exactRowCount(
            await client.query(AEB_CONSUMPTION_SQL.reserveOperation, [
              tenantId, relyingPartyId, key, ownerToken,
            ]),
            'reserve operation',
          );
          if (operationRows === 0) throw new ReservationConflict('CONSUMPTION_CONFLICT');
          if (operationRows !== 1) throw new Error('reserve operation: unexpected PostgreSQL row count');

          const replayRows = exactRowCount(
            await client.query(AEB_CONSUMPTION_SQL.reserveReplayKeys, [
              tenantId, relyingPartyId, key, uniqueReplayKeys,
            ]),
            'reserve native replay keys',
          );
          if (replayRows !== uniqueReplayKeys.length) {
            throw new ReservationConflict('NATIVE_REPLAY_CONFLICT');
          }
        });
      } catch (error) {
        if (error instanceof ReservationConflict) return error.result;
        throw error;
      }

      ownedReservations.set(key, ownerToken);
      return 'RESERVED';
    },

    async claimReservationResult(key, authorization, scope): Promise<AebRecoveryClaimResult> {
      assertText(key, 'operation key', 4096);
      const refuse = (reason: AebRecoveryClaimRefusal): AebRecoveryClaimResult => (
        Object.freeze({ claimed: false as const, reason })
      );
      // Every claim names the row it is for. Gate always passes a scope; a
      // claim without one is refused before the authorizer can see it.
      if (scope === undefined) return refuse('recovery_claim_scope_required');
      const claimScope = recoveryClaimScope(scope);
      if (!claimScope) return refuse('recovery_claim_scope_invalid');
      // Recovery is a restart boundary, not an in-place owner rotation. The
      // base AEB store API fences ownership by store instance (commit/release
      // take only the operation key), so replacing a token already owned by
      // this instance would let its stale caller inherit the new token.
      if (ownedReservations.has(key)) return refuse('recovery_claim_already_owned');
      // A scope names exactly one row: the one the boundaries derive from it,
      // for its boundary kind. A credential bound to one attempt identity
      // cannot claim another row.
      if (consequenceBoundaryRecoveryClaimKey(claimScope) !== key) {
        return refuse('recovery_claim_key_mismatch');
      }
      // A row shared by every attempt of one evaluation is claimable for an
      // attempt only while that attempt's own holder row marks it as the
      // current owner.
      const marker = consequenceBoundaryRecoveryClaimMarkerKey(claimScope);
      if (marker !== null && await store.state(marker) !== 'RESERVED') {
        return refuse('recovery_claim_owner_marker_absent');
      }
      const claim: Readonly<AebRecoveryClaimAuthorization> = Object.freeze({
        authorization,
        tenantId,
        relyingPartyId,
        operationKey: key,
        requiredState: 'RESERVED' as const,
        attemptIdentity: consequenceBoundaryRecoveryAttemptIdentity(claimScope)!,
        scope: claimScope,
      });
      if (await authorizeRecoveryClaim(claim) !== true) return refuse('recovery_claim_unauthorized');

      const ownerToken = ownerTokenFactory();
      assertOwnerToken(ownerToken);
      const changed = await transaction(recoveryPool, async (client) => {
        const rows = exactRowCount(
          await client.query(AEB_CONSUMPTION_SQL.claimOperation, [
            tenantId, relyingPartyId, key, ownerToken,
          ]),
          'claim operation',
        );
        if (rows > 1) throw new Error('claim operation: unexpected PostgreSQL row count');
        return rows === 1;
      });
      if (!changed) return refuse('recovery_claim_row_not_reserved');
      ownedReservations.set(key, ownerToken);
      return Object.freeze({ claimed: true as const });
    },

    async claimReservation(key, authorization, scope): Promise<boolean> {
      return (await store.claimReservationResult(key, authorization, scope)).claimed;
    },

    async commit(key): Promise<boolean> {
      assertText(key, 'operation key', 4096);
      const ownerToken = ownedReservations.get(key);
      if (ownerToken === undefined) return false;
      const changed = await transaction(pool, async (client) => {
        const rows = exactRowCount(
          await client.query(AEB_CONSUMPTION_SQL.commitOperation, [
            tenantId, relyingPartyId, key, ownerToken,
          ]),
          'commit operation',
        );
        if (rows > 1) throw new Error('commit operation: unexpected PostgreSQL row count');
        return rows === 1;
      });
      ownedReservations.delete(key);
      return changed;
    },

    async release(key): Promise<boolean> {
      assertText(key, 'operation key', 4096);
      const ownerToken = ownedReservations.get(key);
      if (ownerToken === undefined) return false;
      const changed = await transaction(pool, async (client) => {
        const rows = exactRowCount(
          await client.query(AEB_CONSUMPTION_SQL.releaseOperation, [
            tenantId, relyingPartyId, key, ownerToken,
          ]),
          'release operation',
        );
        if (rows > 1) throw new Error('release operation: unexpected PostgreSQL row count');
        return rows === 1;
      });
      ownedReservations.delete(key);
      return changed;
    },

    async releaseTerminal(key): Promise<boolean> {
      assertText(key, 'operation key', 4096);
      const ownerToken = ownedReservations.get(key);
      if (ownerToken === undefined) return false;
      const changed = await transaction(pool, async (client) => {
        const rows = exactRowCount(
          await client.query(AEB_CONSUMPTION_SQL.releaseTerminalOperation, [
            tenantId, relyingPartyId, key, ownerToken,
          ]),
          'release operation terminally',
        );
        if (rows > 1) {
          throw new Error('release operation terminally: unexpected PostgreSQL row count');
        }
        return rows === 1;
      });
      ownedReservations.delete(key);
      return changed;
    },
  };

  return Object.freeze(store);
}

export default {
  AEB_PG_CONSUMPTION_STORE_VERSION,
  AEB_CONSUMPTION_OPERATION_TABLE,
  AEB_CONSUMPTION_REPLAY_TABLE,
  AEB_CONSUMPTION_EXECUTOR_ROLE,
  AEB_CONSUMPTION_RECOVERY_ROLE,
  AEB_CONSUMPTION_DDL,
  AEB_CONSUMPTION_SQL,
  createPostgresAebDurableConsumptionStore,
};
