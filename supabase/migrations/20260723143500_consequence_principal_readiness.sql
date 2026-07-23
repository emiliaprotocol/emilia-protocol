-- SPDX-License-Identifier: Apache-2.0
-- Consequence-control database principal separation and readiness contract.
--
-- This migration is intentionally forward-only. It refuses to apply if an
-- existing tenant binding already combines execute and recover authority.
-- Runtime readiness then proves the actual SESSION_USER, exact tenant binding,
-- mutually exclusive group-role membership, narrow RPC grants, and required
-- schema objects for both the AEB and Proposal-to-Effect stores.

DO $preflight$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM ep_aeb_private.tenant_principals
    WHERE can_execute AND can_recover
  ) THEN
    RAISE EXCEPTION 'AEB_PRINCIPAL_CAPABILITY_OVERLAP_PRESENT'
      USING ERRCODE = '23514';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM proposal_to_effect_private.tenant_principals
    WHERE can_execute AND can_recover
  ) THEN
    RAISE EXCEPTION 'PTE_PRINCIPAL_CAPABILITY_OVERLAP_PRESENT'
      USING ERRCODE = '23514';
  END IF;
END
$preflight$;

DO $constraints$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_constraint
    WHERE conrelid = 'ep_aeb_private.tenant_principals'::pg_catalog.regclass
      AND conname = 'ep_aeb_tenant_principal_one_capability'
  ) THEN
    ALTER TABLE ep_aeb_private.tenant_principals
      ADD CONSTRAINT ep_aeb_tenant_principal_one_capability
      CHECK (can_execute <> can_recover) NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_constraint
    WHERE conrelid =
      'proposal_to_effect_private.tenant_principals'::pg_catalog.regclass
      AND conname = 'proposal_to_effect_tenant_principal_one_capability'
  ) THEN
    ALTER TABLE proposal_to_effect_private.tenant_principals
      ADD CONSTRAINT proposal_to_effect_tenant_principal_one_capability
      CHECK (can_execute <> can_recover) NOT VALID;
  END IF;
END
$constraints$;

ALTER TABLE ep_aeb_private.tenant_principals
  VALIDATE CONSTRAINT ep_aeb_tenant_principal_one_capability;
ALTER TABLE proposal_to_effect_private.tenant_principals
  VALIDATE CONSTRAINT proposal_to_effect_tenant_principal_one_capability;

CREATE OR REPLACE FUNCTION ep_aeb_private.principal_readiness(
  p_tenant_id TEXT,
  p_expected_recovery BOOLEAN
)
RETURNS TABLE(
  principal_name TEXT,
  expected_recovery BOOLEAN,
  tenant_binding_ok BOOLEAN,
  role_membership_ok BOOLEAN,
  opposite_role_absent BOOLEAN,
  rpc_grants_ok BOOLEAN,
  schema_objects_ok BOOLEAN,
  schema_contract TEXT
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_execute_member BOOLEAN;
  v_recovery_member BOOLEAN;
  v_tenant_binding_ok BOOLEAN;
  v_rpc_grants_ok BOOLEAN;
  v_schema_objects_ok BOOLEAN;
BEGIN
  v_execute_member := pg_catalog.pg_has_role(
    SESSION_USER, 'ep_aeb_executor', 'MEMBER'
  );
  v_recovery_member := pg_catalog.pg_has_role(
    SESSION_USER, 'ep_aeb_recovery', 'MEMBER'
  );

  SELECT
    pg_catalog.count(*) = 1
    AND COALESCE(
      pg_catalog.bool_and(
        principals.can_execute = NOT p_expected_recovery
        AND principals.can_recover = p_expected_recovery
      ),
      FALSE
    )
  INTO v_tenant_binding_ok
  FROM ep_aeb_private.tenant_principals AS principals
  WHERE principals.principal_name = SESSION_USER
    AND principals.tenant_id = p_tenant_id;

  IF p_expected_recovery THEN
    SELECT
      COALESCE(pg_catalog.bool_and(
        pg_catalog.has_function_privilege(
          SESSION_USER,
          pg_catalog.to_regprocedure(required.signature),
          'EXECUTE'
        )
      ), FALSE)
      AND NOT COALESCE(pg_catalog.bool_or(
        pg_catalog.has_function_privilege(
          SESSION_USER,
          pg_catalog.to_regprocedure(forbidden.signature),
          'EXECUTE'
        )
      ), FALSE)
    INTO v_rpc_grants_ok
    FROM pg_catalog.unnest(ARRAY[
      'ep_aeb_private.claim_operation(text,text,text,text)'
    ]) AS required(signature)
    CROSS JOIN pg_catalog.unnest(ARRAY[
      'ep_aeb_private.reserve_operation(text,text,text,text)',
      'ep_aeb_private.reserve_replay_keys(text,text,text,text[])',
      'ep_aeb_private.commit_operation(text,text,text,text)',
      'ep_aeb_private.release_operation(text,text,text,text)',
      'ep_aeb_private.has_replay_fence(text,text,text)',
      'ep_aeb_private.get_status_head(text,text,text,text,text,text)',
      'ep_aeb_private.compare_and_advance_status_head(text,text,text,text,text,text,text,text,bigint,text,text,timestamptz,timestamptz,text)'
    ]) AS forbidden(signature);
  ELSE
    SELECT
      COALESCE(pg_catalog.bool_and(
        pg_catalog.has_function_privilege(
          SESSION_USER,
          pg_catalog.to_regprocedure(required.signature),
          'EXECUTE'
        )
      ), FALSE)
      AND NOT COALESCE(pg_catalog.bool_or(
        pg_catalog.has_function_privilege(
          SESSION_USER,
          pg_catalog.to_regprocedure(forbidden.signature),
          'EXECUTE'
        )
      ), FALSE)
    INTO v_rpc_grants_ok
    FROM pg_catalog.unnest(ARRAY[
      'ep_aeb_private.reserve_operation(text,text,text,text)',
      'ep_aeb_private.reserve_replay_keys(text,text,text,text[])',
      'ep_aeb_private.commit_operation(text,text,text,text)',
      'ep_aeb_private.release_operation(text,text,text,text)',
      'ep_aeb_private.has_replay_fence(text,text,text)',
      'ep_aeb_private.get_status_head(text,text,text,text,text,text)',
      'ep_aeb_private.compare_and_advance_status_head(text,text,text,text,text,text,text,text,bigint,text,text,timestamptz,timestamptz,text)'
    ]) AS required(signature)
    CROSS JOIN pg_catalog.unnest(ARRAY[
      'ep_aeb_private.claim_operation(text,text,text,text)'
    ]) AS forbidden(signature);
  END IF;

  v_rpc_grants_ok := v_rpc_grants_ok
    AND NOT pg_catalog.has_table_privilege(
      SESSION_USER, 'ep_aeb_private.tenant_principals', 'SELECT'
    )
    AND NOT pg_catalog.has_table_privilege(
      SESSION_USER, 'public.ep_aeb_consumption_operations', 'SELECT'
    )
    AND NOT pg_catalog.has_table_privilege(
      SESSION_USER, 'public.ep_aeb_consumption_replay_fences', 'SELECT'
    )
    AND NOT pg_catalog.has_table_privilege(
      SESSION_USER, 'public.ep_aeb_status_heads', 'SELECT'
    );

  SELECT
    pg_catalog.to_regclass('public.ep_aeb_consumption_operations') IS NOT NULL
    AND pg_catalog.to_regclass(
      'public.ep_aeb_consumption_replay_fences'
    ) IS NOT NULL
    AND pg_catalog.to_regclass('public.ep_aeb_status_heads') IS NOT NULL
    AND pg_catalog.to_regprocedure(
      'ep_aeb_private.has_replay_fence(text,text,text)'
    ) IS NOT NULL
    AND pg_catalog.to_regprocedure(
      'ep_aeb_private.get_status_head(text,text,text,text,text,text)'
    ) IS NOT NULL
    AND pg_catalog.to_regprocedure(
      'ep_aeb_private.compare_and_advance_status_head(text,text,text,text,text,text,text,text,bigint,text,text,timestamptz,timestamptz,text)'
    ) IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM pg_catalog.pg_constraint
      WHERE conrelid =
        'ep_aeb_private.tenant_principals'::pg_catalog.regclass
        AND conname = 'ep_aeb_tenant_principal_one_capability'
        AND convalidated
    )
    AND (
      SELECT relrowsecurity AND relforcerowsecurity
      FROM pg_catalog.pg_class
      WHERE oid = 'public.ep_aeb_consumption_operations'::pg_catalog.regclass
    )
    AND (
      SELECT relrowsecurity AND relforcerowsecurity
      FROM pg_catalog.pg_class
      WHERE oid =
        'public.ep_aeb_consumption_replay_fences'::pg_catalog.regclass
    )
    AND (
      SELECT relrowsecurity AND relforcerowsecurity
      FROM pg_catalog.pg_class
      WHERE oid = 'public.ep_aeb_status_heads'::pg_catalog.regclass
    )
    AND EXISTS (
      SELECT 1 FROM pg_catalog.pg_roles
      WHERE rolname = 'ep_aeb_executor'
        AND NOT rolcanlogin AND NOT rolbypassrls
    )
    AND EXISTS (
      SELECT 1 FROM pg_catalog.pg_roles
      WHERE rolname = 'ep_aeb_recovery'
        AND NOT rolcanlogin AND NOT rolbypassrls
    )
  INTO v_schema_objects_ok;

  RETURN QUERY SELECT
    SESSION_USER::TEXT,
    p_expected_recovery,
    v_tenant_binding_ok,
    CASE WHEN p_expected_recovery
      THEN v_recovery_member
      ELSE v_execute_member
    END,
    CASE WHEN p_expected_recovery
      THEN NOT v_execute_member
      ELSE NOT v_recovery_member
    END,
    v_rpc_grants_ok,
    v_schema_objects_ok,
    '20260723143500'::TEXT;
END
$fn$;

ALTER FUNCTION ep_aeb_private.principal_readiness(TEXT, BOOLEAN)
  OWNER TO ep_aeb_store_owner;
REVOKE ALL ON FUNCTION ep_aeb_private.principal_readiness(TEXT, BOOLEAN)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION ep_aeb_private.principal_readiness(TEXT, BOOLEAN)
  TO ep_aeb_executor, ep_aeb_recovery;

CREATE OR REPLACE FUNCTION proposal_to_effect_private.principal_readiness(
  p_tenant_id TEXT,
  p_expected_recovery BOOLEAN
)
RETURNS TABLE(
  principal_name TEXT,
  expected_recovery BOOLEAN,
  tenant_binding_ok BOOLEAN,
  role_membership_ok BOOLEAN,
  opposite_role_absent BOOLEAN,
  rpc_grants_ok BOOLEAN,
  schema_objects_ok BOOLEAN,
  schema_contract TEXT
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_execute_member BOOLEAN;
  v_recovery_member BOOLEAN;
  v_tenant_binding_ok BOOLEAN;
  v_rpc_grants_ok BOOLEAN;
  v_schema_objects_ok BOOLEAN;
BEGIN
  v_execute_member := pg_catalog.pg_has_role(
    SESSION_USER, 'proposal_to_effect_executor', 'MEMBER'
  );
  v_recovery_member := pg_catalog.pg_has_role(
    SESSION_USER, 'proposal_to_effect_recovery', 'MEMBER'
  );

  SELECT
    pg_catalog.count(*) = 1
    AND COALESCE(
      pg_catalog.bool_and(
        principals.can_execute = NOT p_expected_recovery
        AND principals.can_recover = p_expected_recovery
      ),
      FALSE
    )
  INTO v_tenant_binding_ok
  FROM proposal_to_effect_private.tenant_principals AS principals
  WHERE principals.principal_name = SESSION_USER
    AND principals.tenant_id = p_tenant_id;

  IF p_expected_recovery THEN
    SELECT
      COALESCE(pg_catalog.bool_and(
        pg_catalog.has_function_privilege(
          SESSION_USER,
          pg_catalog.to_regprocedure(required.signature),
          'EXECUTE'
        )
      ), FALSE)
      AND NOT COALESCE(pg_catalog.bool_or(
        pg_catalog.has_function_privilege(
          SESSION_USER,
          pg_catalog.to_regprocedure(forbidden.signature),
          'EXECUTE'
        )
      ), FALSE)
    INTO v_rpc_grants_ok
    FROM pg_catalog.unnest(ARRAY[
      'proposal_to_effect_private.lookup_attempt(text,text,text,text,text)',
      'proposal_to_effect_private.read_attempt(text,text,text,text,text,text)',
      'proposal_to_effect_private.recover_attempt(text,text,text,text,text,text,text,bigint,text,timestamptz,text,integer)'
    ]) AS required(signature)
    CROSS JOIN pg_catalog.unnest(ARRAY[
      'proposal_to_effect_private.reserve_attempt(text,text,text,text,text,text,text,text,text,text,text,integer)',
      'proposal_to_effect_private.transition_attempt(text,text,text,text,text,integer)',
      'proposal_to_effect_private.heartbeat_attempt(text,text,text,integer)',
      'proposal_to_effect_private.reconcile_attempt(text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,timestamptz,text,text,text)'
    ]) AS forbidden(signature);
  ELSE
    SELECT
      COALESCE(pg_catalog.bool_and(
        pg_catalog.has_function_privilege(
          SESSION_USER,
          pg_catalog.to_regprocedure(required.signature),
          'EXECUTE'
        )
      ), FALSE)
      AND NOT COALESCE(pg_catalog.bool_or(
        pg_catalog.has_function_privilege(
          SESSION_USER,
          pg_catalog.to_regprocedure(forbidden.signature),
          'EXECUTE'
        )
      ), FALSE)
    INTO v_rpc_grants_ok
    FROM pg_catalog.unnest(ARRAY[
      'proposal_to_effect_private.lookup_attempt(text,text,text,text,text)',
      'proposal_to_effect_private.reserve_attempt(text,text,text,text,text,text,text,text,text,text,text,integer)',
      'proposal_to_effect_private.transition_attempt(text,text,text,text,text,integer)',
      'proposal_to_effect_private.heartbeat_attempt(text,text,text,integer)',
      'proposal_to_effect_private.reconcile_attempt(text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,timestamptz,text,text,text)',
      'proposal_to_effect_private.read_attempt(text,text,text,text,text,text)'
    ]) AS required(signature)
    CROSS JOIN pg_catalog.unnest(ARRAY[
      'proposal_to_effect_private.recover_attempt(text,text,text,text,text,text,text,bigint,text,timestamptz,text,integer)'
    ]) AS forbidden(signature);
  END IF;

  v_rpc_grants_ok := v_rpc_grants_ok
    AND NOT pg_catalog.has_table_privilege(
      SESSION_USER,
      'proposal_to_effect_private.tenant_principals',
      'SELECT'
    )
    AND NOT pg_catalog.has_table_privilege(
      SESSION_USER,
      'proposal_to_effect_private.consequence_attempts',
      'SELECT'
    )
    AND NOT pg_catalog.has_table_privilege(
      SESSION_USER,
      'proposal_to_effect_private.provider_evidence',
      'SELECT'
    );

  SELECT
    pg_catalog.to_regclass(
      'proposal_to_effect_private.consequence_attempts'
    ) IS NOT NULL
    AND pg_catalog.to_regclass(
      'proposal_to_effect_private.provider_evidence'
    ) IS NOT NULL
    AND pg_catalog.to_regprocedure(
      'proposal_to_effect_private.lookup_attempt(text,text,text,text,text)'
    ) IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM pg_catalog.pg_constraint
      WHERE conrelid =
        'proposal_to_effect_private.tenant_principals'::pg_catalog.regclass
        AND conname = 'proposal_to_effect_tenant_principal_one_capability'
        AND convalidated
    )
    AND EXISTS (
      SELECT 1
      FROM pg_catalog.pg_class AS indexes
      JOIN pg_catalog.pg_index
        ON pg_index.indexrelid = indexes.oid
      WHERE indexes.relname =
        'proposal_to_effect_provider_evidence_attempt_fk_idx'
        AND pg_index.indisvalid
        AND pg_index.indisready
    )
    AND (
      SELECT relrowsecurity AND relforcerowsecurity
      FROM pg_catalog.pg_class
      WHERE oid =
        'proposal_to_effect_private.consequence_attempts'::pg_catalog.regclass
    )
    AND (
      SELECT relrowsecurity AND relforcerowsecurity
      FROM pg_catalog.pg_class
      WHERE oid =
        'proposal_to_effect_private.provider_evidence'::pg_catalog.regclass
    )
    AND EXISTS (
      SELECT 1 FROM pg_catalog.pg_roles
      WHERE rolname = 'proposal_to_effect_executor'
        AND NOT rolcanlogin AND NOT rolbypassrls
    )
    AND EXISTS (
      SELECT 1 FROM pg_catalog.pg_roles
      WHERE rolname = 'proposal_to_effect_recovery'
        AND NOT rolcanlogin AND NOT rolbypassrls
    )
  INTO v_schema_objects_ok;

  RETURN QUERY SELECT
    SESSION_USER::TEXT,
    p_expected_recovery,
    v_tenant_binding_ok,
    CASE WHEN p_expected_recovery
      THEN v_recovery_member
      ELSE v_execute_member
    END,
    CASE WHEN p_expected_recovery
      THEN NOT v_execute_member
      ELSE NOT v_recovery_member
    END,
    v_rpc_grants_ok,
    v_schema_objects_ok,
    '20260723150000'::TEXT;
END
$fn$;

DO $owner$
DECLARE
  v_owner NAME;
BEGIN
  SELECT tableowner
  INTO STRICT v_owner
  FROM pg_catalog.pg_tables
  WHERE schemaname = 'proposal_to_effect_private'
    AND tablename = 'tenant_principals';
  EXECUTE pg_catalog.format(
    'ALTER FUNCTION proposal_to_effect_private.principal_readiness(TEXT, BOOLEAN) OWNER TO %I',
    v_owner
  );
END
$owner$;

REVOKE ALL ON FUNCTION
  proposal_to_effect_private.principal_readiness(TEXT, BOOLEAN)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION
  proposal_to_effect_private.principal_readiness(TEXT, BOOLEAN)
  TO proposal_to_effect_executor, proposal_to_effect_recovery;

COMMENT ON FUNCTION ep_aeb_private.principal_readiness(TEXT, BOOLEAN) IS
  'Fail-closed tenant principal, role, RPC-grant, and schema readiness proof for consequence-control startup.';
COMMENT ON FUNCTION
  proposal_to_effect_private.principal_readiness(TEXT, BOOLEAN) IS
  'Fail-closed tenant principal, role, RPC-grant, and schema readiness proof for consequence-control startup.';
