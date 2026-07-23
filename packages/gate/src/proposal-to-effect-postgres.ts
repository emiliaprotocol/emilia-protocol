// SPDX-License-Identifier: Apache-2.0
/**
 * PostgreSQL custody for Proposal-to-Effect consequence attempts.
 *
 * The application issues an opaque owner capability and sends only its keyed
 * digest to PostgreSQL. The database owns state-transition atomicity, terminal
 * immutability, and the exact attempt/provider-evidence join.
 */

import crypto from 'node:crypto';
import type {
  AuthenticatedProviderEvidenceBinding,
  ConsequenceAttemptBinding,
  ConsequenceAttemptOwnerHandle,
  ConsequenceAttemptReference,
  ConsequenceAttemptState,
  ProposalToEffectConsequenceAttemptStore,
} from './proposal-to-effect.js';

type AebDigest = ConsequenceAttemptBinding['request_digest'];
type QueryRow = Record<string, unknown>;

const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const OWNER_PATTERN = /^pto-owner:v1:[A-Za-z0-9_-]{43}$/;
const OWNER_DOMAIN = 'EMILIA-PROPOSAL-TO-EFFECT-POSTGRES-v1:OWNER\0';
const ATTEMPT_DOMAIN = 'EMILIA-PROPOSAL-TO-EFFECT-POSTGRES-v1:ATTEMPT\0';
const EVIDENCE_DOMAIN = 'EMILIA-PROPOSAL-TO-EFFECT-POSTGRES-v1:EVIDENCE\0';
const OWNER_BYTES = 32;
const DEFAULT_LEASE_SECONDS = 30;
const MAX_LEASE_SECONDS = 300;

const STATES = new Set<ConsequenceAttemptState>([
  'RESERVED',
  'INVOKING',
  'INDETERMINATE',
  'COMMITTED',
  'RELEASED',
  'ESCALATED',
]);
const TERMINAL_STATES = new Set<ConsequenceAttemptState>([
  'COMMITTED',
  'RELEASED',
  'ESCALATED',
]);

export interface ProposalToEffectPostgresQueryResult {
  rowCount: number | null;
  rows: unknown[];
}

export interface ProposalToEffectPostgresClient {
  query(
    text: string,
    params?: readonly unknown[],
  ): Promise<ProposalToEffectPostgresQueryResult>;
  /** Passing an error discards an ambiguously committed pooled connection. */
  release(error?: Error): void;
}

export interface ProposalToEffectPostgresPool {
  connect(): Promise<ProposalToEffectPostgresClient>;
}

export interface ProposalToEffectAttemptDigests {
  operation_digest: AebDigest;
  action_digest: AebDigest;
  config_digest: AebDigest;
}

export interface ProposalToEffectPostgresAttemptLookup {
  tenant_id: string;
  provider_id: string;
  provider_account_id: string;
  environment: string;
  request_digest: AebDigest;
}

export interface ProposalToEffectPostgresAttemptReference {
  tenant_id: string;
  provider_id: string;
  provider_account_id: string;
  environment: string;
  attempt_id: string;
  request_digest: AebDigest;
}

export interface ProposalToEffectPostgresAttemptSnapshot
  extends ProposalToEffectPostgresAttemptReference, ProposalToEffectAttemptDigests {
  attempt_digest: AebDigest;
  state: ConsequenceAttemptState;
  evidence_digest: AebDigest | null;
  last_heartbeat_at: string;
  lease_expires_at: string;
  lease_stale: boolean;
}

export interface ProposalToEffectPostgresRecoveryAuthorization
  extends ProposalToEffectPostgresAttemptSnapshot {
  owner_generation: number;
}

export type ProposalToEffectPostgresRecoveryResult =
  | {
    recovered: true;
    owner: ConsequenceAttemptOwnerHandle;
    state: 'RESERVED' | 'INDETERMINATE';
  }
  | {
    recovered: false;
    reason:
      | 'attempt_not_found'
      | 'attempt_not_stale'
      | 'recovery_not_authorized'
      | 'recovery_conflict'
      | 'terminal_state_immutable';
  };

export interface ProposalToEffectPostgresStore
  extends ProposalToEffectConsequenceAttemptStore {
  /**
   * Rediscover an attempt after a lost response using only the exact,
   * server-derived provider tuple and request digest. This neither executes
   * nor rotates custody and returns no owner or operational state.
   */
  lookup(
    input: ProposalToEffectPostgresAttemptLookup,
  ): Promise<ProposalToEffectPostgresAttemptReference | null>;
  /**
   * Read operational saga state by its complete durable namespace and request
   * digest. Owner material is deliberately absent.
   */
  read(
    input: ProposalToEffectPostgresAttemptReference,
  ): Promise<ProposalToEffectPostgresAttemptSnapshot | null>;
  /**
   * Renew nonterminal custody. The owner digest and database lease jointly
   * fence stale workers; the opaque owner never crosses the SQL boundary.
   */
  heartbeat(input: ConsequenceAttemptReference): Promise<boolean>;
  /**
   * Rotate ownership after restart only after the configured server callback
   * authorizes the exact stored tenant/attempt/request binding. INVOKING is
   * conservatively claimed as INDETERMINATE.
   */
  recover(
    input: ProposalToEffectPostgresAttemptReference,
  ): Promise<ProposalToEffectPostgresRecoveryResult>;
}

export interface CreateProposalToEffectPostgresStoreOptions {
  /** Least-privilege executor connection; it must not hold the recovery role. */
  pool: ProposalToEffectPostgresPool;
  /** Separately credentialed recovery connection; must differ from pool. */
  recovery_pool: ProposalToEffectPostgresPool;
  /** Server-held key copied at construction; minimum 256 bits. */
  owner_hmac_sha256_key: Uint8Array;
  /**
   * Resolve the digests not carried by ConsequenceAttemptBinding from
   * server-controlled canonical request custody.
   */
  resolve_binding_digests(
    binding: Readonly<ConsequenceAttemptBinding>,
  ): Promise<ProposalToEffectAttemptDigests> | ProposalToEffectAttemptDigests;
  /**
   * Explicit server authorization for restart ownership rotation. This
   * callback never receives the old owner token or its keyed digest.
   */
  authorize_recovery(
    authorization: Readonly<ProposalToEffectPostgresRecoveryAuthorization>,
  ): Promise<boolean> | boolean;
  /** Injectable only for deterministic tests; production defaults to crypto.randomBytes. */
  random_bytes?: (size: number) => Uint8Array;
  /** Database-enforced lease duration. Defaults to 30 seconds, max 5 minutes. */
  lease_seconds?: number;
}

/**
 * Install under a dedicated non-login owner. Runtime roles should receive only
 * schema USAGE plus EXECUTE on the RPCs they need; no table privilege is
 * required or intended. Keep recover_attempt limited to the server role that
 * runs authorize_recovery.
 */
export const PROPOSAL_TO_EFFECT_POSTGRES_DDL = String.raw`
CREATE SCHEMA IF NOT EXISTS proposal_to_effect_private;
REVOKE ALL ON SCHEMA proposal_to_effect_private FROM PUBLIC;

DO $roles$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'proposal_to_effect_executor'
  ) THEN
    CREATE ROLE proposal_to_effect_executor NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'proposal_to_effect_recovery'
  ) THEN
    CREATE ROLE proposal_to_effect_recovery NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$roles$;

CREATE TABLE IF NOT EXISTS proposal_to_effect_private.tenant_principals (
  principal_name NAME NOT NULL,
  tenant_id TEXT COLLATE "C" NOT NULL
    CHECK (tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$'),
  can_execute BOOLEAN NOT NULL DEFAULT FALSE,
  can_recover BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  PRIMARY KEY (principal_name, tenant_id),
  CHECK (can_execute OR can_recover)
);

CREATE TABLE IF NOT EXISTS proposal_to_effect_private.consequence_attempts (
  tenant_id TEXT COLLATE "C" NOT NULL
    CHECK (tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$'),
  provider_id TEXT COLLATE "C" NOT NULL
    CHECK (provider_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$'),
  provider_account_id TEXT COLLATE "C" NOT NULL
    CHECK (provider_account_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$'),
  environment TEXT COLLATE "C" NOT NULL
    CHECK (environment ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$'),
  attempt_id TEXT COLLATE "C" NOT NULL
    CHECK (attempt_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$'),
  operation_digest TEXT COLLATE "C" NOT NULL
    CHECK (operation_digest ~ '^sha256:[a-f0-9]{64}$'),
  request_digest TEXT COLLATE "C" NOT NULL
    CHECK (request_digest ~ '^sha256:[a-f0-9]{64}$'),
  action_digest TEXT COLLATE "C" NOT NULL
    CHECK (action_digest ~ '^sha256:[a-f0-9]{64}$'),
  config_digest TEXT COLLATE "C" NOT NULL
    CHECK (config_digest ~ '^sha256:[a-f0-9]{64}$'),
  attempt_digest TEXT COLLATE "C" NOT NULL
    CHECK (attempt_digest ~ '^sha256:[a-f0-9]{64}$'),
  owner_digest TEXT COLLATE "C" NOT NULL UNIQUE
    CHECK (owner_digest ~ '^sha256:[a-f0-9]{64}$'),
  owner_generation BIGINT NOT NULL DEFAULT 0 CHECK (owner_generation >= 0),
  state TEXT COLLATE "C" NOT NULL DEFAULT 'RESERVED'
    CHECK (state IN (
      'RESERVED', 'INVOKING', 'INDETERMINATE',
      'COMMITTED', 'RELEASED', 'ESCALATED'
    )),
  evidence_digest TEXT COLLATE "C"
    CHECK (evidence_digest IS NULL OR evidence_digest ~ '^sha256:[a-f0-9]{64}$'),
  evidence_binding_digest TEXT COLLATE "C"
    CHECK (
      evidence_binding_digest IS NULL
      OR evidence_binding_digest ~ '^sha256:[a-f0-9]{64}$'
    ),
  last_heartbeat_at TIMESTAMPTZ NOT NULL,
  lease_expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (
    tenant_id, provider_id, provider_account_id, environment, attempt_id
  ),
  UNIQUE (
    tenant_id, provider_id, provider_account_id, environment, operation_digest
  ),
  UNIQUE (
    tenant_id, provider_id, provider_account_id, environment, request_digest
  ),
  UNIQUE (
    tenant_id, provider_id, provider_account_id, environment, attempt_digest
  ),
  UNIQUE (
    tenant_id, provider_id, provider_account_id, environment,
    attempt_id, attempt_digest
  ),
  CHECK (
    (evidence_digest IS NULL AND evidence_binding_digest IS NULL)
    OR
    (evidence_digest IS NOT NULL AND evidence_binding_digest IS NOT NULL)
  ),
  CHECK (created_at <= updated_at),
  CHECK (created_at <= last_heartbeat_at),
  CHECK (last_heartbeat_at < lease_expires_at)
);

CREATE TABLE IF NOT EXISTS proposal_to_effect_private.provider_evidence (
  tenant_id TEXT COLLATE "C" NOT NULL,
  provider_id TEXT COLLATE "C" NOT NULL,
  provider_account_id TEXT COLLATE "C" NOT NULL,
  environment TEXT COLLATE "C" NOT NULL,
  attempt_id TEXT COLLATE "C" NOT NULL,
  attempt_digest TEXT COLLATE "C" NOT NULL
    CHECK (attempt_digest ~ '^sha256:[a-f0-9]{64}$'),
  operation_id TEXT COLLATE "C" NOT NULL
    CHECK (operation_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$'),
  caid TEXT COLLATE "C" NOT NULL
    CHECK (caid ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$'),
  action_digest TEXT COLLATE "C" NOT NULL
    CHECK (action_digest ~ '^sha256:[a-f0-9]{64}$'),
  evidence_id TEXT COLLATE "C" NOT NULL
    CHECK (evidence_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$'),
  observed_at TIMESTAMPTZ NOT NULL,
  outcome TEXT COLLATE "C" NOT NULL
    CHECK (outcome IN ('COMMITTED', 'NOT_COMMITTED', 'ESCALATED')),
  evidence_digest TEXT COLLATE "C" NOT NULL
    CHECK (evidence_digest ~ '^sha256:[a-f0-9]{64}$'),
  evidence_binding_digest TEXT COLLATE "C" NOT NULL
    CHECK (evidence_binding_digest ~ '^sha256:[a-f0-9]{64}$'),
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  PRIMARY KEY (
    tenant_id, provider_id, provider_account_id, environment, evidence_digest
  ),
  UNIQUE (
    tenant_id, provider_id, provider_account_id, environment, evidence_id
  ),
  UNIQUE (
    tenant_id, provider_id, provider_account_id, environment,
    evidence_binding_digest
  ),
  FOREIGN KEY (
    tenant_id, provider_id, provider_account_id, environment,
    attempt_id, attempt_digest
  ) REFERENCES proposal_to_effect_private.consequence_attempts (
    tenant_id, provider_id, provider_account_id, environment,
    attempt_id, attempt_digest
  ) ON DELETE RESTRICT
);

ALTER TABLE proposal_to_effect_private.tenant_principals
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposal_to_effect_private.tenant_principals
  FORCE ROW LEVEL SECURITY;
ALTER TABLE proposal_to_effect_private.consequence_attempts
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposal_to_effect_private.consequence_attempts
  FORCE ROW LEVEL SECURITY;
ALTER TABLE proposal_to_effect_private.provider_evidence
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposal_to_effect_private.provider_evidence
  FORCE ROW LEVEL SECURITY;

DO $ddl$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_policies
    WHERE schemaname = 'proposal_to_effect_private'
      AND tablename = 'tenant_principals'
      AND policyname = 'proposal_to_effect_principals_owner_only'
  ) THEN
    CREATE POLICY proposal_to_effect_principals_owner_only
      ON proposal_to_effect_private.tenant_principals
      USING (
        CURRENT_USER = (
          SELECT tableowner
          FROM pg_catalog.pg_tables
          WHERE schemaname = 'proposal_to_effect_private'
            AND tablename = 'tenant_principals'
        )
      )
      WITH CHECK (
        CURRENT_USER = (
          SELECT tableowner
          FROM pg_catalog.pg_tables
          WHERE schemaname = 'proposal_to_effect_private'
            AND tablename = 'tenant_principals'
        )
      );
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_policies
    WHERE schemaname = 'proposal_to_effect_private'
      AND tablename = 'consequence_attempts'
      AND policyname = 'proposal_to_effect_owner_only'
  ) THEN
    CREATE POLICY proposal_to_effect_owner_only
      ON proposal_to_effect_private.consequence_attempts
      USING (
        CURRENT_USER = (
          SELECT tableowner
          FROM pg_catalog.pg_tables
          WHERE schemaname = 'proposal_to_effect_private'
            AND tablename = 'consequence_attempts'
        )
      )
      WITH CHECK (
        CURRENT_USER = (
          SELECT tableowner
          FROM pg_catalog.pg_tables
          WHERE schemaname = 'proposal_to_effect_private'
            AND tablename = 'consequence_attempts'
        )
      );
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_policies
    WHERE schemaname = 'proposal_to_effect_private'
      AND tablename = 'provider_evidence'
      AND policyname = 'proposal_to_effect_evidence_owner_only'
  ) THEN
    CREATE POLICY proposal_to_effect_evidence_owner_only
      ON proposal_to_effect_private.provider_evidence
      USING (
        CURRENT_USER = (
          SELECT tableowner
          FROM pg_catalog.pg_tables
          WHERE schemaname = 'proposal_to_effect_private'
            AND tablename = 'provider_evidence'
        )
      )
      WITH CHECK (
        CURRENT_USER = (
          SELECT tableowner
          FROM pg_catalog.pg_tables
          WHERE schemaname = 'proposal_to_effect_private'
            AND tablename = 'provider_evidence'
        )
      );
  END IF;
END
$ddl$;

REVOKE ALL ON TABLE proposal_to_effect_private.tenant_principals FROM PUBLIC;
REVOKE ALL ON TABLE proposal_to_effect_private.consequence_attempts FROM PUBLIC;
REVOKE ALL ON TABLE proposal_to_effect_private.provider_evidence FROM PUBLIC;

CREATE OR REPLACE FUNCTION proposal_to_effect_private.assert_tenant_principal(
  p_tenant_id TEXT,
  p_recovery BOOLEAN
)
RETURNS VOID
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_role_ok BOOLEAN;
  v_binding_ok BOOLEAN;
BEGIN
  v_role_ok := CASE
    WHEN p_recovery IS TRUE THEN pg_catalog.pg_has_role(
      SESSION_USER, 'proposal_to_effect_recovery', 'MEMBER'
    )
    WHEN p_recovery IS FALSE THEN pg_catalog.pg_has_role(
      SESSION_USER, 'proposal_to_effect_executor', 'MEMBER'
    )
    ELSE pg_catalog.pg_has_role(
      SESSION_USER, 'proposal_to_effect_executor', 'MEMBER'
    ) OR pg_catalog.pg_has_role(
      SESSION_USER, 'proposal_to_effect_recovery', 'MEMBER'
    )
  END;
  SELECT EXISTS (
    SELECT 1
    FROM proposal_to_effect_private.tenant_principals AS principals
    WHERE principals.principal_name = SESSION_USER
      AND principals.tenant_id = p_tenant_id
      AND CASE
        WHEN p_recovery IS TRUE THEN principals.can_recover
        WHEN p_recovery IS FALSE THEN principals.can_execute
        ELSE principals.can_execute OR principals.can_recover
      END
  ) INTO v_binding_ok;
  IF v_role_ok IS NOT TRUE OR v_binding_ok IS NOT TRUE THEN
    RAISE EXCEPTION 'PTE_TENANT_PRINCIPAL_REFUSED'
      USING ERRCODE = '42501';
  END IF;
END
$fn$;

CREATE OR REPLACE FUNCTION proposal_to_effect_private.guard_attempt_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $fn$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'PTE_ATTEMPT_DELETE_REFUSED';
  END IF;
  IF OLD.state IN ('COMMITTED', 'RELEASED', 'ESCALATED') THEN
    RAISE EXCEPTION 'PTE_TERMINAL_ATTEMPT_IMMUTABLE';
  END IF;
  IF ROW(
    NEW.tenant_id, NEW.provider_id, NEW.provider_account_id, NEW.environment,
    NEW.attempt_id, NEW.operation_digest, NEW.request_digest,
    NEW.action_digest, NEW.config_digest, NEW.attempt_digest, NEW.created_at
  ) IS DISTINCT FROM ROW(
    OLD.tenant_id, OLD.provider_id, OLD.provider_account_id, OLD.environment,
    OLD.attempt_id, OLD.operation_digest, OLD.request_digest,
    OLD.action_digest, OLD.config_digest, OLD.attempt_digest, OLD.created_at
  ) THEN
    RAISE EXCEPTION 'PTE_ATTEMPT_BINDING_IMMUTABLE';
  END IF;
  IF NEW.updated_at < OLD.updated_at
     OR NEW.last_heartbeat_at < OLD.last_heartbeat_at
     OR NEW.lease_expires_at < OLD.lease_expires_at
     OR NEW.last_heartbeat_at >= NEW.lease_expires_at THEN
    RAISE EXCEPTION 'PTE_LEASE_REWIND_REFUSED';
  END IF;

  IF NEW.owner_generation = OLD.owner_generation THEN
    IF NEW.owner_digest IS DISTINCT FROM OLD.owner_digest OR NOT (
      (OLD.state = NEW.state)
      OR
      (OLD.state = 'RESERVED' AND NEW.state = 'INVOKING')
      OR (OLD.state = 'INVOKING' AND NEW.state = 'INDETERMINATE')
      OR (
        OLD.state = 'INDETERMINATE'
        AND NEW.state IN ('COMMITTED', 'RELEASED', 'ESCALATED')
      )
    ) THEN
      RAISE EXCEPTION 'PTE_ATTEMPT_TRANSITION_REFUSED';
    END IF;
    IF ROW(NEW.evidence_digest, NEW.evidence_binding_digest)
       IS DISTINCT FROM ROW(OLD.evidence_digest, OLD.evidence_binding_digest)
       AND NOT (
         OLD.state = 'INDETERMINATE'
         AND NEW.state IN ('COMMITTED', 'RELEASED', 'ESCALATED')
         AND OLD.evidence_digest IS NULL
         AND OLD.evidence_binding_digest IS NULL
         AND NEW.evidence_digest IS NOT NULL
         AND NEW.evidence_binding_digest IS NOT NULL
       ) THEN
      RAISE EXCEPTION 'PTE_ATTEMPT_EVIDENCE_REBIND_REFUSED';
    END IF;
  ELSIF NEW.owner_generation = OLD.owner_generation + 1 THEN
    IF NEW.owner_digest IS NOT DISTINCT FROM OLD.owner_digest
       OR ROW(NEW.evidence_digest, NEW.evidence_binding_digest)
          IS DISTINCT FROM ROW(OLD.evidence_digest, OLD.evidence_binding_digest)
       OR NOT (
         (OLD.state = 'RESERVED' AND NEW.state = 'RESERVED')
         OR (OLD.state = 'INVOKING' AND NEW.state = 'INDETERMINATE')
         OR (OLD.state = 'INDETERMINATE' AND NEW.state = 'INDETERMINATE')
       ) THEN
      RAISE EXCEPTION 'PTE_ATTEMPT_RECOVERY_REFUSED';
    END IF;
  ELSE
    RAISE EXCEPTION 'PTE_OWNER_GENERATION_REFUSED';
  END IF;
  RETURN NEW;
END
$fn$;

DROP TRIGGER IF EXISTS proposal_to_effect_attempt_guard
  ON proposal_to_effect_private.consequence_attempts;
CREATE TRIGGER proposal_to_effect_attempt_guard
BEFORE UPDATE OR DELETE ON proposal_to_effect_private.consequence_attempts
FOR EACH ROW EXECUTE FUNCTION proposal_to_effect_private.guard_attempt_mutation();

CREATE OR REPLACE FUNCTION proposal_to_effect_private.guard_evidence_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $fn$
BEGIN
  RAISE EXCEPTION 'PTE_PROVIDER_EVIDENCE_IMMUTABLE';
END
$fn$;

DROP TRIGGER IF EXISTS proposal_to_effect_evidence_guard
  ON proposal_to_effect_private.provider_evidence;
CREATE TRIGGER proposal_to_effect_evidence_guard
BEFORE UPDATE OR DELETE ON proposal_to_effect_private.provider_evidence
FOR EACH ROW EXECUTE FUNCTION proposal_to_effect_private.guard_evidence_mutation();

CREATE OR REPLACE FUNCTION proposal_to_effect_private.reserve_attempt(
  p_tenant_id TEXT,
  p_provider_id TEXT,
  p_provider_account_id TEXT,
  p_environment TEXT,
  p_attempt_id TEXT,
  p_operation_digest TEXT,
  p_request_digest TEXT,
  p_action_digest TEXT,
  p_config_digest TEXT,
  p_attempt_digest TEXT,
  p_owner_digest TEXT,
  p_lease_seconds INTEGER
)
RETURNS TABLE(applied BOOLEAN, reason TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_count BIGINT;
  v_now TIMESTAMPTZ;
BEGIN
  PERFORM proposal_to_effect_private.assert_tenant_principal(p_tenant_id, FALSE);
  IF p_lease_seconds < 1 OR p_lease_seconds > 300 THEN
    RAISE EXCEPTION 'PTE_LEASE_DURATION_REFUSED'
      USING ERRCODE = '22023';
  END IF;
  v_now := pg_catalog.clock_timestamp();
  INSERT INTO proposal_to_effect_private.consequence_attempts (
    tenant_id, provider_id, provider_account_id, environment, attempt_id,
    operation_digest, request_digest, action_digest, config_digest,
    attempt_digest, owner_digest, last_heartbeat_at, lease_expires_at,
    created_at, updated_at
  ) VALUES (
    p_tenant_id, p_provider_id, p_provider_account_id, p_environment, p_attempt_id,
    p_operation_digest, p_request_digest, p_action_digest, p_config_digest,
    p_attempt_digest, p_owner_digest, v_now,
    v_now + pg_catalog.make_interval(secs => p_lease_seconds),
    v_now, v_now
  )
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  IF v_count = 1 THEN
    RETURN QUERY SELECT TRUE, NULL::TEXT;
  ELSIF EXISTS (
    SELECT 1
    FROM proposal_to_effect_private.consequence_attempts
    WHERE tenant_id = p_tenant_id
      AND provider_id = p_provider_id
      AND provider_account_id = p_provider_account_id
      AND environment = p_environment
      AND attempt_id = p_attempt_id
      AND operation_digest = p_operation_digest
      AND request_digest = p_request_digest
      AND action_digest = p_action_digest
      AND config_digest = p_config_digest
      AND attempt_digest = p_attempt_digest
      AND owner_digest = p_owner_digest
      AND owner_generation = 0
      AND state = 'RESERVED'
  ) THEN
    -- idempotent_reservation: the original COMMIT may have succeeded.
    RETURN QUERY SELECT TRUE, NULL::TEXT;
  ELSIF EXISTS (
    SELECT 1
    FROM proposal_to_effect_private.consequence_attempts
    WHERE tenant_id = p_tenant_id
      AND provider_id = p_provider_id
      AND provider_account_id = p_provider_account_id
      AND environment = p_environment
      AND attempt_id = p_attempt_id
  ) THEN
    RETURN QUERY SELECT FALSE, 'attempt_exists'::TEXT;
  ELSE
    RETURN QUERY SELECT FALSE, 'binding_conflict'::TEXT;
  END IF;
END
$fn$;

CREATE OR REPLACE FUNCTION proposal_to_effect_private.transition_attempt(
  p_tenant_id TEXT,
  p_attempt_id TEXT,
  p_owner_digest TEXT,
  p_expected_state TEXT,
  p_next_state TEXT,
  p_lease_seconds INTEGER
)
RETURNS TABLE(applied BOOLEAN, reason TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_count BIGINT;
  v_now TIMESTAMPTZ;
BEGIN
  PERFORM proposal_to_effect_private.assert_tenant_principal(p_tenant_id, FALSE);
  IF p_lease_seconds < 1 OR p_lease_seconds > 300 THEN
    RAISE EXCEPTION 'PTE_LEASE_DURATION_REFUSED'
      USING ERRCODE = '22023';
  END IF;
  v_now := pg_catalog.clock_timestamp();
  UPDATE proposal_to_effect_private.consequence_attempts
  SET state = p_next_state,
      last_heartbeat_at = v_now,
      lease_expires_at = v_now + pg_catalog.make_interval(secs => p_lease_seconds),
      updated_at = v_now
  WHERE tenant_id = p_tenant_id
    AND attempt_id = p_attempt_id
    AND owner_digest = p_owner_digest
    AND state = p_expected_state
    AND (
      (p_expected_state = 'RESERVED' AND p_next_state = 'INVOKING')
      OR (p_expected_state = 'INVOKING' AND p_next_state = 'INDETERMINATE')
      OR (
        p_expected_state = 'INDETERMINATE'
        AND p_next_state IN ('COMMITTED', 'RELEASED', 'ESCALATED')
      )
    );
  GET DIAGNOSTICS v_count = ROW_COUNT;
  IF v_count = 1 THEN
    RETURN QUERY SELECT TRUE, NULL::TEXT;
  ELSIF EXISTS (
    SELECT 1
    FROM proposal_to_effect_private.consequence_attempts
    WHERE tenant_id = p_tenant_id
      AND attempt_id = p_attempt_id
      AND owner_digest = p_owner_digest
      AND state = p_next_state
  ) THEN
    -- idempotent_transition: retry after an ambiguous COMMIT.
    RETURN QUERY SELECT TRUE, NULL::TEXT;
  ELSE
    RETURN QUERY SELECT FALSE, NULL::TEXT;
  END IF;
END
$fn$;

CREATE OR REPLACE FUNCTION proposal_to_effect_private.heartbeat_attempt(
  p_tenant_id TEXT,
  p_attempt_id TEXT,
  p_owner_digest TEXT,
  p_lease_seconds INTEGER
)
RETURNS TABLE(applied BOOLEAN, reason TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_count BIGINT;
  v_now TIMESTAMPTZ;
BEGIN
  PERFORM proposal_to_effect_private.assert_tenant_principal(p_tenant_id, FALSE);
  IF p_lease_seconds < 1 OR p_lease_seconds > 300 THEN
    RAISE EXCEPTION 'PTE_LEASE_DURATION_REFUSED'
      USING ERRCODE = '22023';
  END IF;
  v_now := pg_catalog.clock_timestamp();
  UPDATE proposal_to_effect_private.consequence_attempts
  SET last_heartbeat_at = v_now,
      lease_expires_at = v_now + pg_catalog.make_interval(secs => p_lease_seconds),
      updated_at = v_now
  WHERE tenant_id = p_tenant_id
    AND attempt_id = p_attempt_id
    AND owner_digest = p_owner_digest
    AND state IN ('RESERVED', 'INVOKING', 'INDETERMINATE');
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN QUERY SELECT v_count = 1, NULL::TEXT;
END
$fn$;

CREATE OR REPLACE FUNCTION proposal_to_effect_private.reconcile_attempt(
  p_tenant_id TEXT,
  p_provider_id TEXT,
  p_provider_account_id TEXT,
  p_environment TEXT,
  p_attempt_id TEXT,
  p_owner_digest TEXT,
  p_operation_digest TEXT,
  p_request_digest TEXT,
  p_action_digest TEXT,
  p_config_digest TEXT,
  p_attempt_digest TEXT,
  p_operation_id TEXT,
  p_caid TEXT,
  p_next_state TEXT,
  p_evidence_id TEXT,
  p_observed_at TIMESTAMPTZ,
  p_outcome TEXT,
  p_evidence_digest TEXT,
  p_evidence_binding_digest TEXT
)
RETURNS TABLE(applied BOOLEAN, reason TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_attempt_digest TEXT;
BEGIN
  PERFORM proposal_to_effect_private.assert_tenant_principal(p_tenant_id, FALSE);
  IF NOT (
    (p_outcome = 'COMMITTED' AND p_next_state = 'COMMITTED')
    OR (p_outcome = 'NOT_COMMITTED' AND p_next_state = 'RELEASED')
    OR (p_outcome = 'ESCALATED' AND p_next_state = 'ESCALATED')
  ) THEN
    RETURN QUERY SELECT FALSE, NULL::TEXT;
    RETURN;
  END IF;
  BEGIN
    UPDATE proposal_to_effect_private.consequence_attempts
    SET state = p_next_state,
        evidence_digest = p_evidence_digest,
        evidence_binding_digest = p_evidence_binding_digest,
        updated_at = pg_catalog.clock_timestamp()
    WHERE tenant_id = p_tenant_id
      AND provider_id = p_provider_id
      AND provider_account_id = p_provider_account_id
      AND environment = p_environment
      AND attempt_id = p_attempt_id
      AND owner_digest = p_owner_digest
      AND operation_digest = p_operation_digest
      AND request_digest = p_request_digest
      AND action_digest = p_action_digest
      AND config_digest = p_config_digest
      AND attempt_digest = p_attempt_digest
      AND state = 'INDETERMINATE'
    RETURNING attempt_digest INTO v_attempt_digest;
    IF v_attempt_digest IS NOT NULL THEN
      INSERT INTO proposal_to_effect_private.provider_evidence (
        tenant_id, provider_id, provider_account_id, environment,
        attempt_id, attempt_digest, operation_id, caid, action_digest,
        evidence_id, observed_at, outcome,
        evidence_digest, evidence_binding_digest
      ) VALUES (
        p_tenant_id, p_provider_id, p_provider_account_id, p_environment,
        p_attempt_id, p_attempt_digest, p_operation_id, p_caid, p_action_digest,
        p_evidence_id, p_observed_at, p_outcome,
        p_evidence_digest, p_evidence_binding_digest
      );
      RETURN QUERY SELECT TRUE, NULL::TEXT;
      RETURN;
    END IF;
  EXCEPTION
    WHEN unique_violation OR foreign_key_violation OR check_violation THEN
      v_attempt_digest := NULL;
  END;
  IF EXISTS (
    SELECT 1
    FROM proposal_to_effect_private.consequence_attempts AS attempts
    JOIN proposal_to_effect_private.provider_evidence AS evidence
      USING (
        tenant_id, provider_id, provider_account_id, environment,
        attempt_id, attempt_digest
      )
    WHERE attempts.tenant_id = p_tenant_id
      AND attempts.provider_id = p_provider_id
      AND attempts.provider_account_id = p_provider_account_id
      AND attempts.environment = p_environment
      AND attempts.attempt_id = p_attempt_id
      AND attempts.owner_digest = p_owner_digest
      AND attempts.operation_digest = p_operation_digest
      AND attempts.request_digest = p_request_digest
      AND attempts.action_digest = p_action_digest
      AND attempts.config_digest = p_config_digest
      AND attempts.attempt_digest = p_attempt_digest
      AND attempts.state = p_next_state
      AND attempts.evidence_digest = p_evidence_digest
      AND attempts.evidence_binding_digest = p_evidence_binding_digest
      AND evidence.operation_id = p_operation_id
      AND evidence.caid = p_caid
      AND evidence.action_digest = p_action_digest
      AND evidence.evidence_id = p_evidence_id
      AND evidence.observed_at = p_observed_at
      AND evidence.outcome = p_outcome
      AND evidence.evidence_digest = p_evidence_digest
      AND evidence.evidence_binding_digest = p_evidence_binding_digest
  ) THEN
    -- idempotent_reconciliation: retry after an ambiguous COMMIT.
    RETURN QUERY SELECT TRUE, NULL::TEXT;
  ELSE
    RETURN QUERY SELECT FALSE, NULL::TEXT;
  END IF;
END
$fn$;

CREATE OR REPLACE FUNCTION proposal_to_effect_private.read_attempt(
  p_tenant_id TEXT,
  p_provider_id TEXT,
  p_provider_account_id TEXT,
  p_environment TEXT,
  p_attempt_id TEXT,
  p_request_digest TEXT
)
RETURNS TABLE(
  tenant_id TEXT,
  provider_id TEXT,
  provider_account_id TEXT,
  environment TEXT,
  attempt_id TEXT,
  operation_digest TEXT,
  request_digest TEXT,
  action_digest TEXT,
  config_digest TEXT,
  attempt_digest TEXT,
  state TEXT,
  evidence_digest TEXT,
  owner_generation BIGINT,
  last_heartbeat_at TEXT,
  lease_expires_at TEXT,
  lease_stale BOOLEAN
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $fn$
BEGIN
  PERFORM proposal_to_effect_private.assert_tenant_principal(p_tenant_id, NULL);
  RETURN QUERY SELECT
    attempts.tenant_id,
    attempts.provider_id,
    attempts.provider_account_id,
    attempts.environment,
    attempts.attempt_id,
    attempts.operation_digest,
    attempts.request_digest,
    attempts.action_digest,
    attempts.config_digest,
    attempts.attempt_digest,
    attempts.state,
    attempts.evidence_digest,
    attempts.owner_generation,
    pg_catalog.to_char(
      attempts.last_heartbeat_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    ),
    pg_catalog.to_char(
      attempts.lease_expires_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    ),
    attempts.lease_expires_at <= pg_catalog.clock_timestamp()
  FROM proposal_to_effect_private.consequence_attempts AS attempts
  WHERE attempts.tenant_id = p_tenant_id
    AND attempts.provider_id = p_provider_id
    AND attempts.provider_account_id = p_provider_account_id
    AND attempts.environment = p_environment
    AND attempts.attempt_id = p_attempt_id
    AND attempts.request_digest = p_request_digest;
END
$fn$;

CREATE OR REPLACE FUNCTION proposal_to_effect_private.recover_attempt(
  p_tenant_id TEXT,
  p_provider_id TEXT,
  p_provider_account_id TEXT,
  p_environment TEXT,
  p_attempt_id TEXT,
  p_request_digest TEXT,
  p_attempt_digest TEXT,
  p_owner_generation BIGINT,
  p_expected_state TEXT,
  p_expected_lease_expires_at TIMESTAMPTZ,
  p_next_owner_digest TEXT,
  p_lease_seconds INTEGER
)
RETURNS TABLE(applied BOOLEAN, reason TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_count BIGINT;
  v_now TIMESTAMPTZ;
BEGIN
  PERFORM proposal_to_effect_private.assert_tenant_principal(p_tenant_id, TRUE);
  IF p_lease_seconds < 1 OR p_lease_seconds > 300 THEN
    RAISE EXCEPTION 'PTE_LEASE_DURATION_REFUSED'
      USING ERRCODE = '22023';
  END IF;
  v_now := pg_catalog.clock_timestamp();
  UPDATE proposal_to_effect_private.consequence_attempts
  SET owner_digest = p_next_owner_digest,
      owner_generation = owner_generation + 1,
      state = CASE
        WHEN state = 'RESERVED' THEN 'RESERVED'
        ELSE 'INDETERMINATE'
      END,
      last_heartbeat_at = v_now,
      lease_expires_at = v_now + pg_catalog.make_interval(secs => p_lease_seconds),
      updated_at = v_now
  WHERE tenant_id = p_tenant_id
    AND provider_id = p_provider_id
    AND provider_account_id = p_provider_account_id
    AND environment = p_environment
    AND attempt_id = p_attempt_id
    AND request_digest = p_request_digest
    AND attempt_digest = p_attempt_digest
    AND owner_generation = p_owner_generation
    AND state = p_expected_state
    AND state IN ('RESERVED', 'INVOKING', 'INDETERMINATE')
    AND lease_expires_at = p_expected_lease_expires_at
    AND lease_expires_at <= pg_catalog.clock_timestamp();
  GET DIAGNOSTICS v_count = ROW_COUNT;
  IF v_count = 1 THEN
    RETURN QUERY SELECT TRUE, NULL::TEXT;
  ELSIF EXISTS (
    SELECT 1
    FROM proposal_to_effect_private.consequence_attempts
    WHERE tenant_id = p_tenant_id
      AND provider_id = p_provider_id
      AND provider_account_id = p_provider_account_id
      AND environment = p_environment
      AND attempt_id = p_attempt_id
      AND request_digest = p_request_digest
      AND attempt_digest = p_attempt_digest
      AND owner_generation = p_owner_generation + 1
      AND owner_digest = p_next_owner_digest
      AND state = CASE
        WHEN p_expected_state = 'RESERVED' THEN 'RESERVED'
        ELSE 'INDETERMINATE'
      END
  ) THEN
    -- idempotent_recovery: retry after an ambiguous COMMIT.
    RETURN QUERY SELECT TRUE, NULL::TEXT;
  ELSIF EXISTS (
    SELECT 1
    FROM proposal_to_effect_private.consequence_attempts
    WHERE tenant_id = p_tenant_id
      AND provider_id = p_provider_id
      AND provider_account_id = p_provider_account_id
      AND environment = p_environment
      AND attempt_id = p_attempt_id
      AND request_digest = p_request_digest
      AND attempt_digest = p_attempt_digest
      AND owner_generation = p_owner_generation
      AND state = p_expected_state
      AND lease_expires_at = p_expected_lease_expires_at
      AND lease_expires_at > pg_catalog.clock_timestamp()
  ) THEN
    RETURN QUERY SELECT FALSE, 'attempt_not_stale'::TEXT;
  ELSE
    RETURN QUERY SELECT FALSE, 'recovery_conflict'::TEXT;
  END IF;
END
$fn$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA proposal_to_effect_private FROM PUBLIC;

GRANT USAGE ON SCHEMA proposal_to_effect_private
  TO proposal_to_effect_executor, proposal_to_effect_recovery;
GRANT EXECUTE ON FUNCTION proposal_to_effect_private.reserve_attempt(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER
) TO proposal_to_effect_executor;
GRANT EXECUTE ON FUNCTION proposal_to_effect_private.transition_attempt(
  TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER
) TO proposal_to_effect_executor;
GRANT EXECUTE ON FUNCTION proposal_to_effect_private.heartbeat_attempt(
  TEXT, TEXT, TEXT, INTEGER
) TO proposal_to_effect_executor;
GRANT EXECUTE ON FUNCTION proposal_to_effect_private.reconcile_attempt(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
  TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TEXT, TEXT, TEXT
) TO proposal_to_effect_executor;
GRANT EXECUTE ON FUNCTION proposal_to_effect_private.read_attempt(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) TO proposal_to_effect_executor, proposal_to_effect_recovery;
GRANT EXECUTE ON FUNCTION proposal_to_effect_private.recover_attempt(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, TIMESTAMPTZ,
  TEXT, INTEGER
) TO proposal_to_effect_recovery;
`;

export const PROPOSAL_TO_EFFECT_POSTGRES_SQL = Object.freeze({
  reserve: `SELECT * FROM proposal_to_effect_private.reserve_attempt(
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
  )`,
  transition: `SELECT * FROM proposal_to_effect_private.transition_attempt(
    $1, $2, $3, $4, $5, $6
  )`,
  heartbeat: `SELECT * FROM proposal_to_effect_private.heartbeat_attempt(
    $1, $2, $3, $4
  )`,
  reconcile: `SELECT * FROM proposal_to_effect_private.reconcile_attempt(
    $1, $2, $3, $4, $5, $6, $7, $8, $9,
    $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
  )`,
  lookup: `SELECT * FROM proposal_to_effect_private.lookup_attempt(
    $1, $2, $3, $4, $5
  )`,
  read: `SELECT * FROM proposal_to_effect_private.read_attempt(
    $1, $2, $3, $4, $5, $6
  )`,
  recover: `SELECT * FROM proposal_to_effect_private.recover_attempt(
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
  )`,
});

function isRecord(value: unknown): value is QueryRow {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: QueryRow, expected: readonly string[]): boolean {
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => typeof key !== 'string') || actual.length !== expected.length) {
    return false;
  }
  const names = new Set(actual as string[]);
  return expected.every((key) => names.has(key));
}

function assertIdentifier(value: unknown, name: string): asserts value is string {
  if (typeof value !== 'string' || !IDENTIFIER_PATTERN.test(value)) {
    throw new TypeError(`${name} is invalid`);
  }
}

function assertDigest(value: unknown, name: string): asserts value is AebDigest {
  if (typeof value !== 'string' || !DIGEST_PATTERN.test(value)) {
    throw new TypeError(`${name} is invalid`);
  }
}

function assertInstant(value: unknown, name: string): asserts value is string {
  if (typeof value !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3,6}Z$/.test(value)) {
    throw new TypeError(`${name} is invalid`);
  }
  const parsed = Date.parse(value);
  const millisecondInstant = value.replace(/\.(\d{3})\d{0,3}Z$/, '.$1Z');
  if (!Number.isFinite(parsed)
      || new Date(parsed).toISOString() !== millisecondInstant) {
    throw new TypeError(`${name} is invalid`);
  }
}

function assertOwner(value: unknown): asserts value is ConsequenceAttemptOwnerHandle {
  if (typeof value !== 'string' || !OWNER_PATTERN.test(value)) {
    throw new TypeError('consequence attempt owner is invalid');
  }
}

function assertBinding(value: unknown): asserts value is ConsequenceAttemptBinding {
  if (!isRecord(value) || !hasExactKeys(value, [
    'tenant_id',
    'provider_id',
    'provider_account_id',
    'environment',
    'attempt_id',
    'request_digest',
  ])) {
    throw new TypeError('consequence attempt binding is invalid');
  }
  assertIdentifier(value.tenant_id, 'tenant_id');
  assertIdentifier(value.provider_id, 'provider_id');
  assertIdentifier(value.provider_account_id, 'provider_account_id');
  assertIdentifier(value.environment, 'environment');
  assertIdentifier(value.attempt_id, 'attempt_id');
  assertDigest(value.request_digest, 'request_digest');
}

function assertAttemptReference(
  value: unknown,
): asserts value is ProposalToEffectPostgresAttemptReference {
  if (!isRecord(value) || !hasExactKeys(value, [
    'tenant_id',
    'provider_id',
    'provider_account_id',
    'environment',
    'attempt_id',
    'request_digest',
  ])) {
    throw new TypeError('consequence attempt reference is invalid');
  }
  assertBinding(value);
}

function assertAttemptLookup(
  value: unknown,
): asserts value is ProposalToEffectPostgresAttemptLookup {
  if (!isRecord(value) || !hasExactKeys(value, [
    'tenant_id',
    'provider_id',
    'provider_account_id',
    'environment',
    'request_digest',
  ])) {
    throw new TypeError('consequence attempt lookup is invalid');
  }
  assertIdentifier(value.tenant_id, 'lookup tenant_id');
  assertIdentifier(value.provider_id, 'lookup provider_id');
  assertIdentifier(value.provider_account_id, 'lookup provider_account_id');
  assertIdentifier(value.environment, 'lookup environment');
  assertDigest(value.request_digest, 'lookup request_digest');
}

function assertResolvedDigests(value: unknown): asserts value is ProposalToEffectAttemptDigests {
  if (!isRecord(value) || !hasExactKeys(value, [
    'operation_digest',
    'action_digest',
    'config_digest',
  ])) {
    throw new TypeError('resolved consequence attempt digests are invalid');
  }
  assertDigest(value.operation_digest, 'operation_digest');
  assertDigest(value.action_digest, 'action_digest');
  assertDigest(value.config_digest, 'config_digest');
}

function cloneBinding(binding: ConsequenceAttemptBinding): ConsequenceAttemptBinding {
  return {
    tenant_id: binding.tenant_id,
    provider_id: binding.provider_id,
    provider_account_id: binding.provider_account_id,
    environment: binding.environment,
    attempt_id: binding.attempt_id,
    request_digest: binding.request_digest,
  };
}

function sha256(domain: string, value: QueryRow): AebDigest {
  return `sha256:${crypto.createHash('sha256')
    .update(domain)
    .update(JSON.stringify(value))
    .digest('hex')}` as AebDigest;
}

export function proposalToEffectAttemptDigest(
  binding: ConsequenceAttemptBinding,
  digests: ProposalToEffectAttemptDigests,
): AebDigest {
  assertBinding(binding);
  assertResolvedDigests(digests);
  return sha256(ATTEMPT_DOMAIN, {
    tenant_id: binding.tenant_id,
    provider_id: binding.provider_id,
    provider_account_id: binding.provider_account_id,
    environment: binding.environment,
    attempt_id: binding.attempt_id,
    operation_digest: digests.operation_digest,
    request_digest: binding.request_digest,
    action_digest: digests.action_digest,
    config_digest: digests.config_digest,
  });
}

function evidenceBindingDigest(
  attemptDigest: AebDigest,
  evidence: AuthenticatedProviderEvidenceBinding,
): AebDigest {
  return sha256(EVIDENCE_DOMAIN, {
    attempt_digest: attemptDigest,
    operation_id: evidence.operation_id,
    caid: evidence.caid,
    action_digest: evidence.action_digest,
    evidence_id: evidence.evidence_id,
    observed_at: evidence.observed_at,
    outcome: evidence.outcome,
    evidence_digest: evidence.evidence_digest,
  });
}

function parseOwnerGeneration(value: unknown): number {
  const parsed = typeof value === 'number'
    ? value
    : typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value)
      ? Number(value)
      : NaN;
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error('malformed Postgres result: owner_generation');
  }
  return parsed;
}

function assertResultEnvelope(
  result: ProposalToEffectPostgresQueryResult,
  operation: string,
): void {
  if (!result || !Array.isArray(result.rows)
      || (result.rowCount !== null
        && (!Number.isSafeInteger(result.rowCount) || result.rowCount < 0))) {
    throw new Error(`malformed Postgres result: ${operation}`);
  }
}

function parseApplied(
  result: ProposalToEffectPostgresQueryResult,
  operation: string,
): { applied: boolean; reason: string | null } {
  assertResultEnvelope(result, operation);
  if (result.rowCount !== 1 || result.rows.length !== 1 || !isRecord(result.rows[0])
      || !hasExactKeys(result.rows[0], ['applied', 'reason'])
      || typeof result.rows[0].applied !== 'boolean'
      || (result.rows[0].reason !== null && typeof result.rows[0].reason !== 'string')
      || (result.rows[0].applied && result.rows[0].reason !== null)) {
    throw new Error(`malformed Postgres result: ${operation}`);
  }
  return {
    applied: result.rows[0].applied,
    reason: result.rows[0].reason,
  };
}

function parseSnapshot(
  result: ProposalToEffectPostgresQueryResult,
  input: ProposalToEffectPostgresAttemptReference,
): (ProposalToEffectPostgresRecoveryAuthorization & { owner_generation: number }) | null {
  assertResultEnvelope(result, 'read');
  if (result.rowCount === 0 && result.rows.length === 0) return null;
  const row = result.rows[0];
  if (result.rowCount !== 1 || result.rows.length !== 1 || !isRecord(row)
      || !hasExactKeys(row, [
        'tenant_id',
        'provider_id',
        'provider_account_id',
        'environment',
        'attempt_id',
        'operation_digest',
        'request_digest',
        'action_digest',
        'config_digest',
        'attempt_digest',
        'state',
        'evidence_digest',
        'owner_generation',
        'last_heartbeat_at',
        'lease_expires_at',
        'lease_stale',
      ])) {
    throw new Error('malformed Postgres result: read');
  }
  assertIdentifier(row.tenant_id, 'read tenant_id');
  assertIdentifier(row.provider_id, 'read provider_id');
  assertIdentifier(row.provider_account_id, 'read provider_account_id');
  assertIdentifier(row.environment, 'read environment');
  assertIdentifier(row.attempt_id, 'read attempt_id');
  assertDigest(row.operation_digest, 'read operation_digest');
  assertDigest(row.request_digest, 'read request_digest');
  assertDigest(row.action_digest, 'read action_digest');
  assertDigest(row.config_digest, 'read config_digest');
  assertDigest(row.attempt_digest, 'read attempt_digest');
  if (typeof row.state !== 'string' || !STATES.has(row.state as ConsequenceAttemptState)) {
    throw new Error('malformed Postgres result: read state');
  }
  if (row.evidence_digest !== null) {
    assertDigest(row.evidence_digest, 'read evidence_digest');
  }
  assertInstant(row.last_heartbeat_at, 'read last_heartbeat_at');
  assertInstant(row.lease_expires_at, 'read lease_expires_at');
  if (typeof row.lease_stale !== 'boolean'
      || Date.parse(row.last_heartbeat_at) >= Date.parse(row.lease_expires_at)) {
    throw new Error('malformed Postgres result: read lease');
  }
  if (row.tenant_id !== input.tenant_id
      || row.provider_id !== input.provider_id
      || row.provider_account_id !== input.provider_account_id
      || row.environment !== input.environment
      || row.attempt_id !== input.attempt_id
      || row.request_digest !== input.request_digest) {
    throw new Error('malformed Postgres result: read binding');
  }
  return {
    tenant_id: row.tenant_id,
    provider_id: row.provider_id,
    provider_account_id: row.provider_account_id,
    environment: row.environment,
    attempt_id: row.attempt_id,
    operation_digest: row.operation_digest,
    request_digest: row.request_digest,
    action_digest: row.action_digest,
    config_digest: row.config_digest,
    attempt_digest: row.attempt_digest,
    state: row.state as ConsequenceAttemptState,
    evidence_digest: row.evidence_digest,
    owner_generation: parseOwnerGeneration(row.owner_generation),
    last_heartbeat_at: row.last_heartbeat_at,
    lease_expires_at: row.lease_expires_at,
    lease_stale: row.lease_stale,
  };
}

function parseLookup(
  result: ProposalToEffectPostgresQueryResult,
  input: ProposalToEffectPostgresAttemptLookup,
): ProposalToEffectPostgresAttemptReference | null {
  assertResultEnvelope(result, 'lookup');
  if (result.rowCount === 0 && result.rows.length === 0) return null;
  const row = result.rows[0];
  if (result.rowCount !== 1 || result.rows.length !== 1 || !isRecord(row)
      || !hasExactKeys(row, [
        'tenant_id',
        'provider_id',
        'provider_account_id',
        'environment',
        'attempt_id',
        'request_digest',
      ])) {
    throw new Error('malformed Postgres result: lookup');
  }
  assertIdentifier(row.tenant_id, 'lookup tenant_id');
  assertIdentifier(row.provider_id, 'lookup provider_id');
  assertIdentifier(row.provider_account_id, 'lookup provider_account_id');
  assertIdentifier(row.environment, 'lookup environment');
  assertIdentifier(row.attempt_id, 'lookup attempt_id');
  assertDigest(row.request_digest, 'lookup request_digest');
  if (row.tenant_id !== input.tenant_id
      || row.provider_id !== input.provider_id
      || row.provider_account_id !== input.provider_account_id
      || row.environment !== input.environment
      || row.request_digest !== input.request_digest) {
    throw new Error('malformed Postgres result: lookup binding');
  }
  return {
    tenant_id: row.tenant_id,
    provider_id: row.provider_id,
    provider_account_id: row.provider_account_id,
    environment: row.environment,
    attempt_id: row.attempt_id,
    request_digest: row.request_digest,
  };
}

function transitionAllowed(expected: string, next: string): boolean {
  return (expected === 'RESERVED' && next === 'INVOKING')
    || (expected === 'INVOKING' && next === 'INDETERMINATE')
    || (expected === 'INDETERMINATE'
      && (next === 'COMMITTED' || next === 'RELEASED' || next === 'ESCALATED'));
}

function terminalStateFor(
  outcome: AuthenticatedProviderEvidenceBinding['outcome'],
): 'COMMITTED' | 'RELEASED' | 'ESCALATED' {
  return outcome === 'COMMITTED'
    ? 'COMMITTED'
    : outcome === 'NOT_COMMITTED'
      ? 'RELEASED'
      : 'ESCALATED';
}

class AmbiguousPostgresCommitError extends Error {
  constructor(operation: string, cause: unknown) {
    super(`proposal-to-effect ${operation} COMMIT acknowledgement is ambiguous`, {
      cause,
    });
    this.name = 'AmbiguousPostgresCommitError';
  }
}

/**
 * Build the owner-fenced store consumed by createProposalToEffect(), plus
 * operational read/recovery methods for restart-safe saga repair.
 */
export function createProposalToEffectPostgresStore(
  options: CreateProposalToEffectPostgresStoreOptions,
): ProposalToEffectPostgresStore {
  if (!isRecord(options)
      || !options.pool
      || typeof options.pool.connect !== 'function'
      || !options.recovery_pool
      || typeof options.recovery_pool.connect !== 'function'
      || options.recovery_pool === options.pool
      || !(options.owner_hmac_sha256_key instanceof Uint8Array)
      || options.owner_hmac_sha256_key.byteLength < 32
      || typeof options.resolve_binding_digests !== 'function'
      || typeof options.authorize_recovery !== 'function'
      || (options.random_bytes !== undefined && typeof options.random_bytes !== 'function')
      || (options.lease_seconds !== undefined
        && (!Number.isSafeInteger(options.lease_seconds)
          || options.lease_seconds < 1
          || options.lease_seconds > MAX_LEASE_SECONDS))) {
    throw new TypeError('createProposalToEffectPostgresStore configuration is invalid');
  }
  const pool = options.pool;
  const recoveryPool = options.recovery_pool;
  const ownerKey = Buffer.from(options.owner_hmac_sha256_key);
  const randomBytes = options.random_bytes ?? ((size: number) => crypto.randomBytes(size));
  const leaseSeconds = options.lease_seconds ?? DEFAULT_LEASE_SECONDS;

  async function transaction<T>(
    selectedPool: ProposalToEffectPostgresPool,
    readOnly: boolean,
    operation: string,
    work: (client: ProposalToEffectPostgresClient) => Promise<T>,
  ): Promise<T> {
    const client = await selectedPool.connect();
    if (!client || typeof client.query !== 'function' || typeof client.release !== 'function') {
      throw new TypeError('proposal-to-effect pg pool returned an invalid client');
    }
    let began = false;
    let discardError: Error | undefined;
    try {
      await client.query(readOnly
        ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'
        : 'BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE');
      began = true;
      const value = await work(client);
      try {
        await client.query('COMMIT');
        began = false;
      } catch (error) {
        began = false;
        discardError = error instanceof Error
          ? error
          : new Error('unknown PostgreSQL COMMIT failure');
        throw new AmbiguousPostgresCommitError(operation, error);
      }
      return value;
    } catch (error) {
      if (began) {
        try {
          await client.query('ROLLBACK');
        } catch (rollbackError) {
          throw new AggregateError(
            [error, rollbackError],
            'proposal-to-effect transaction and rollback both failed',
          );
        }
      }
      throw error;
    } finally {
      client.release(discardError);
    }
  }

  async function retryAmbiguousCommit<T>(
    selectedPool: ProposalToEffectPostgresPool,
    readOnly: boolean,
    operation: string,
    work: (client: ProposalToEffectPostgresClient) => Promise<T>,
  ): Promise<T> {
    try {
      return await transaction(selectedPool, readOnly, operation, work);
    } catch (error) {
      if (!(error instanceof AmbiguousPostgresCommitError)) throw error;
      return transaction(selectedPool, readOnly, operation, work);
    }
  }

  function issueOwner(): ConsequenceAttemptOwnerHandle {
    const bytes = randomBytes(OWNER_BYTES);
    if (!(bytes instanceof Uint8Array) || bytes.byteLength !== OWNER_BYTES) {
      throw new TypeError('proposal-to-effect owner entropy source is invalid');
    }
    return (
      `pto-owner:v1:${Buffer.from(bytes).toString('base64url')}`
    ) as ConsequenceAttemptOwnerHandle;
  }

  function ownerDigest(owner: ConsequenceAttemptOwnerHandle): AebDigest {
    return `sha256:${crypto.createHmac('sha256', ownerKey)
      .update(OWNER_DOMAIN)
      .update(owner)
      .digest('hex')}` as AebDigest;
  }

  async function resolveDigests(
    attemptBinding: ConsequenceAttemptBinding,
  ): Promise<ProposalToEffectAttemptDigests> {
    const resolved = await options.resolve_binding_digests(
      Object.freeze(cloneBinding(attemptBinding)),
    );
    assertResolvedDigests(resolved);
    return {
      operation_digest: resolved.operation_digest,
      action_digest: resolved.action_digest,
      config_digest: resolved.config_digest,
    };
  }

  async function readInternal(
    selectedPool: ProposalToEffectPostgresPool,
    input: ProposalToEffectPostgresAttemptReference,
  ): Promise<ProposalToEffectPostgresRecoveryAuthorization | null> {
    return retryAmbiguousCommit(selectedPool, true, 'read', async (client) => parseSnapshot(
      await client.query(PROPOSAL_TO_EFFECT_POSTGRES_SQL.read, [
        input.tenant_id,
        input.provider_id,
        input.provider_account_id,
        input.environment,
        input.attempt_id,
        input.request_digest,
      ]),
      input,
    ));
  }

  const store: ProposalToEffectPostgresStore = {
    durable: true,
    ownershipFenced: true,
    compareAndSwap: true,
    atomicEvidenceBinding: true,

    async reserve(attemptBinding) {
      assertBinding(attemptBinding);
      const digests = await resolveDigests(attemptBinding);
      const attemptDigest = proposalToEffectAttemptDigest(attemptBinding, digests);
      const owner = issueOwner();
      const result = await retryAmbiguousCommit(pool, false, 'reserve', async (client) => parseApplied(
        await client.query(PROPOSAL_TO_EFFECT_POSTGRES_SQL.reserve, [
          attemptBinding.tenant_id,
          attemptBinding.provider_id,
          attemptBinding.provider_account_id,
          attemptBinding.environment,
          attemptBinding.attempt_id,
          digests.operation_digest,
          attemptBinding.request_digest,
          digests.action_digest,
          digests.config_digest,
          attemptDigest,
          ownerDigest(owner),
          leaseSeconds,
        ]),
        'reserve',
      ));
      if (!result.applied) {
        return {
          reserved: false,
          reason: result.reason === 'attempt_exists' || result.reason === 'binding_conflict'
            ? result.reason
            : 'attempt_conflict',
        };
      }
      return { reserved: true, owner };
    },

    async transition(input) {
      if (!isRecord(input) || !hasExactKeys(input, [
        'tenant_id',
        'attempt_id',
        'owner',
        'expected_state',
        'next_state',
      ])) {
        throw new TypeError('consequence attempt transition is invalid');
      }
      assertIdentifier(input.tenant_id, 'transition tenant_id');
      assertIdentifier(input.attempt_id, 'transition attempt_id');
      assertOwner(input.owner);
      if (typeof input.expected_state !== 'string'
          || typeof input.next_state !== 'string'
          || !transitionAllowed(input.expected_state, input.next_state)) {
        throw new TypeError('consequence attempt state transition is invalid');
      }
      const result = await retryAmbiguousCommit(pool, false, 'transition', async (client) => parseApplied(
        await client.query(PROPOSAL_TO_EFFECT_POSTGRES_SQL.transition, [
          input.tenant_id,
          input.attempt_id,
          ownerDigest(input.owner),
          input.expected_state,
          input.next_state,
          leaseSeconds,
        ]),
        'transition',
      ));
      return result.applied;
    },

    async heartbeat(input) {
      if (!isRecord(input) || !hasExactKeys(input, [
        'tenant_id',
        'attempt_id',
        'owner',
      ])) {
        throw new TypeError('consequence attempt heartbeat is invalid');
      }
      assertIdentifier(input.tenant_id, 'heartbeat tenant_id');
      assertIdentifier(input.attempt_id, 'heartbeat attempt_id');
      assertOwner(input.owner);
      const result = await retryAmbiguousCommit(
        pool,
        false,
        'heartbeat',
        async (client) => parseApplied(
          await client.query(PROPOSAL_TO_EFFECT_POSTGRES_SQL.heartbeat, [
            input.tenant_id,
            input.attempt_id,
            ownerDigest(input.owner),
            leaseSeconds,
          ]),
          'heartbeat',
        ),
      );
      return result.applied;
    },

    async reconcile(input) {
      if (!isRecord(input) || !hasExactKeys(input, [
        'tenant_id',
        'attempt_id',
        'owner',
        'expected_state',
        'next_state',
        'evidence',
      ])) {
        throw new TypeError('consequence attempt reconciliation is invalid');
      }
      assertIdentifier(input.tenant_id, 'reconcile tenant_id');
      assertIdentifier(input.attempt_id, 'reconcile attempt_id');
      assertOwner(input.owner);
      if (input.expected_state !== 'INDETERMINATE'
          || !isRecord(input.evidence)
          || !hasExactKeys(input.evidence, [
            'tenant_id',
            'provider_id',
            'provider_account_id',
            'environment',
            'attempt_id',
            'request_digest',
            'operation_id',
            'caid',
            'action_digest',
            'evidence_id',
            'observed_at',
            'outcome',
            'evidence_digest',
          ])) {
        throw new TypeError('consequence attempt evidence binding is invalid');
      }
      assertBinding({
        tenant_id: input.evidence.tenant_id,
        provider_id: input.evidence.provider_id,
        provider_account_id: input.evidence.provider_account_id,
        environment: input.evidence.environment,
        attempt_id: input.evidence.attempt_id,
        request_digest: input.evidence.request_digest,
      });
      assertIdentifier(input.evidence.operation_id, 'evidence operation_id');
      assertIdentifier(input.evidence.caid, 'evidence caid');
      assertDigest(input.evidence.action_digest, 'evidence action_digest');
      assertIdentifier(input.evidence.evidence_id, 'evidence_id');
      assertDigest(input.evidence.evidence_digest, 'evidence_digest');
      if (typeof input.evidence.observed_at !== 'string'
          || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(
            input.evidence.observed_at,
          )
          || !Number.isFinite(Date.parse(input.evidence.observed_at))
          || !['COMMITTED', 'NOT_COMMITTED', 'ESCALATED'].includes(input.evidence.outcome)
          || input.tenant_id !== input.evidence.tenant_id
          || input.attempt_id !== input.evidence.attempt_id
          || input.next_state !== terminalStateFor(input.evidence.outcome)) {
        throw new TypeError('consequence attempt evidence binding is invalid');
      }
      const attemptBinding: ConsequenceAttemptBinding = {
        tenant_id: input.evidence.tenant_id,
        provider_id: input.evidence.provider_id,
        provider_account_id: input.evidence.provider_account_id,
        environment: input.evidence.environment,
        attempt_id: input.evidence.attempt_id,
        request_digest: input.evidence.request_digest,
      };
      const digests = await resolveDigests(attemptBinding);
      if (input.evidence.action_digest !== digests.action_digest) {
        throw new TypeError('consequence attempt evidence binding is invalid');
      }
      const attemptDigest = proposalToEffectAttemptDigest(attemptBinding, digests);
      const providerEvidence = input.evidence as AuthenticatedProviderEvidenceBinding;
      const result = await retryAmbiguousCommit(pool, false, 'reconcile', async (client) => parseApplied(
        await client.query(PROPOSAL_TO_EFFECT_POSTGRES_SQL.reconcile, [
          attemptBinding.tenant_id,
          attemptBinding.provider_id,
          attemptBinding.provider_account_id,
          attemptBinding.environment,
          attemptBinding.attempt_id,
          ownerDigest(input.owner),
          digests.operation_digest,
          attemptBinding.request_digest,
          digests.action_digest,
          digests.config_digest,
          attemptDigest,
          providerEvidence.operation_id,
          providerEvidence.caid,
          input.next_state,
          providerEvidence.evidence_id,
          providerEvidence.observed_at,
          providerEvidence.outcome,
          providerEvidence.evidence_digest,
          evidenceBindingDigest(attemptDigest, providerEvidence),
        ]),
        'reconcile',
      ));
      return result.applied;
    },

    async lookup(input) {
      assertAttemptLookup(input);
      return retryAmbiguousCommit(pool, true, 'lookup', async (client) => parseLookup(
        await client.query(PROPOSAL_TO_EFFECT_POSTGRES_SQL.lookup, [
          input.tenant_id,
          input.provider_id,
          input.provider_account_id,
          input.environment,
          input.request_digest,
        ]),
        input,
      ));
    },

    async read(input) {
      assertAttemptReference(input);
      const snapshot = await readInternal(pool, input);
      if (!snapshot) return null;
      const { owner_generation: _ownerGeneration, ...operational } = snapshot;
      return operational;
    },

    async recover(input) {
      assertAttemptReference(input);
      const snapshot = await readInternal(recoveryPool, input);
      if (!snapshot) return { recovered: false, reason: 'attempt_not_found' };
      if (TERMINAL_STATES.has(snapshot.state)) {
        return { recovered: false, reason: 'terminal_state_immutable' };
      }
      if (!snapshot.lease_stale) {
        return { recovered: false, reason: 'attempt_not_stale' };
      }
      const authorized = await options.authorize_recovery(Object.freeze({
        ...snapshot,
      }));
      if (authorized !== true) {
        return { recovered: false, reason: 'recovery_not_authorized' };
      }
      const owner = issueOwner();
      const recovered = await retryAmbiguousCommit(
        recoveryPool,
        false,
        'recover',
        async (client) => parseApplied(
        await client.query(PROPOSAL_TO_EFFECT_POSTGRES_SQL.recover, [
          input.tenant_id,
          input.provider_id,
          input.provider_account_id,
          input.environment,
          input.attempt_id,
          input.request_digest,
          snapshot.attempt_digest,
          snapshot.owner_generation,
          snapshot.state,
          snapshot.lease_expires_at,
          ownerDigest(owner),
          leaseSeconds,
        ]),
        'recover',
        ),
      );
      if (!recovered.applied) {
        return {
          recovered: false,
          reason: recovered.reason === 'attempt_not_stale'
            ? 'attempt_not_stale'
            : 'recovery_conflict',
        };
      }
      return {
        recovered: true,
        owner,
        state: snapshot.state === 'RESERVED' ? 'RESERVED' : 'INDETERMINATE',
      };
    },
  };

  return Object.freeze(store);
}

export default {
  PROPOSAL_TO_EFFECT_POSTGRES_DDL,
  PROPOSAL_TO_EFFECT_POSTGRES_SQL,
  proposalToEffectAttemptDigest,
  createProposalToEffectPostgresStore,
};
