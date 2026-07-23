// SPDX-License-Identifier: Apache-2.0
/**
 * PostgreSQL custody for AEB operation consumption and native replay fences.
 *
 * A reservation installs the operation key and every native replay key in one
 * pinned transaction. Logical conflicts roll the transaction back; database
 * errors propagate so callers fail closed. Commit and release are fenced by an
 * opaque per-reservation token retained only by the store instance that won.
 */
import crypto from 'node:crypto';
import type {
  AebDurableConsumptionStore,
  AebReservationResult,
} from '@emilia-protocol/verify/aeb-adapter-contract';

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
  state            TEXT NOT NULL CHECK (state IN ('RESERVED', 'CONSUMED')),
  owner_token      TEXT NULL CHECK (owner_token IS NULL OR octet_length(owner_token) BETWEEN 16 AND 512),
  reserved_at      TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
  consumed_at      TIMESTAMPTZ NULL,
  PRIMARY KEY (tenant_id, relying_party_id, operation_key),
  CHECK (
    (state = 'RESERVED' AND owner_token IS NOT NULL AND consumed_at IS NULL)
    OR (state = 'CONSUMED' AND owner_token IS NULL AND consumed_at IS NOT NULL)
  )
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
ALTER FUNCTION ep_aeb_private.assert_tenant_principal(TEXT, BOOLEAN)
  OWNER TO ${AEB_CONSUMPTION_OWNER_ROLE};
ALTER FUNCTION ep_aeb_private.reserve_operation(TEXT, TEXT, TEXT, TEXT)
  OWNER TO ${AEB_CONSUMPTION_OWNER_ROLE};
ALTER FUNCTION ep_aeb_private.reserve_replay_keys(TEXT, TEXT, TEXT, TEXT[])
  OWNER TO ${AEB_CONSUMPTION_OWNER_ROLE};
ALTER FUNCTION ep_aeb_private.commit_operation(TEXT, TEXT, TEXT, TEXT)
  OWNER TO ${AEB_CONSUMPTION_OWNER_ROLE};
ALTER FUNCTION ep_aeb_private.claim_operation(TEXT, TEXT, TEXT, TEXT)
  OWNER TO ${AEB_CONSUMPTION_OWNER_ROLE};
ALTER FUNCTION ep_aeb_private.release_operation(TEXT, TEXT, TEXT, TEXT)
  OWNER TO ${AEB_CONSUMPTION_OWNER_ROLE};
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ep_aeb_private
  FROM PUBLIC, anon, authenticated, service_role;
GRANT USAGE ON SCHEMA ep_aeb_private TO ${AEB_CONSUMPTION_EXECUTOR_ROLE}, ${AEB_CONSUMPTION_RECOVERY_ROLE};
GRANT EXECUTE ON FUNCTION ep_aeb_private.reserve_operation(TEXT, TEXT, TEXT, TEXT),
  ep_aeb_private.reserve_replay_keys(TEXT, TEXT, TEXT, TEXT[]),
  ep_aeb_private.commit_operation(TEXT, TEXT, TEXT, TEXT),
  ep_aeb_private.release_operation(TEXT, TEXT, TEXT, TEXT)
  TO ${AEB_CONSUMPTION_EXECUTOR_ROLE};
GRANT EXECUTE ON FUNCTION ep_aeb_private.claim_operation(TEXT, TEXT, TEXT, TEXT)
  TO ${AEB_CONSUMPTION_RECOVERY_ROLE};
REVOKE ${AEB_CONSUMPTION_OWNER_ROLE} FROM CURRENT_USER;`;

/** Exact statements issued by the store, exported for audit and deterministic fakes. */
export const AEB_CONSUMPTION_SQL = Object.freeze({
  reserveOperation: `SELECT operation_key FROM ep_aeb_private.reserve_operation($1::text, $2::text, $3::text, $4::text)`,
  reserveReplayKeys: `SELECT replay_key FROM ep_aeb_private.reserve_replay_keys($1::text, $2::text, $3::text, $4::text[])`,
  commitOperation: `SELECT operation_key FROM ep_aeb_private.commit_operation($1::text, $2::text, $3::text, $4::text)`,
  claimOperation: `SELECT operation_key FROM ep_aeb_private.claim_operation($1::text, $2::text, $3::text, $4::text)`,
  releaseOperation: `SELECT operation_key FROM ep_aeb_private.release_operation($1::text, $2::text, $3::text, $4::text)`,
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

export type AebRecoveryClaimAuthorizer = (
  claim: Readonly<AebRecoveryClaimAuthorization>,
) => boolean | Promise<boolean>;

export interface PostgresAebDurableConsumptionStore extends AebDurableConsumptionStore {
  recoveryClaimSupported: true;
  /**
   * Rotate ownership of an existing RESERVED row after external authorization.
   * The stored and replacement owner tokens are never returned or passed to
   * the authorizer.
   */
  claimReservation(key: string, authorization: unknown): Promise<boolean>;
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
    recoveryClaimSupported: true,

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

    async claimReservation(key, authorization): Promise<boolean> {
      assertText(key, 'operation key', 4096);
      // Recovery is a restart boundary, not an in-place owner rotation. The
      // base AEB store API fences ownership by store instance (commit/release
      // take only the operation key), so replacing a token already owned by
      // this instance would let its stale caller inherit the new token.
      if (ownedReservations.has(key)) return false;
      const claim = Object.freeze({
        authorization,
        tenantId,
        relyingPartyId,
        operationKey: key,
        requiredState: 'RESERVED' as const,
      });
      if (await authorizeRecoveryClaim(claim) !== true) return false;

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
      if (changed) ownedReservations.set(key, ownerToken);
      return changed;
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
