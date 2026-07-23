-- SPDX-License-Identifier: Apache-2.0
-- Durable AEB operation-consumption and native-protocol replay fences.
--
-- The table shape mirrors packages/gate/src/aeb-consumption-store.ts. One
-- transaction reserves the EMILIA operation key and every native replay unit;
-- any collision rolls the entire reservation back. Consumed rows and replay
-- fences remain terminal. Only the server-side service role may reach them.

CREATE TABLE IF NOT EXISTS ep_aeb_consumption_operations (
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

CREATE TABLE IF NOT EXISTS ep_aeb_consumption_replay_fences (
  tenant_id        TEXT NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 512),
  relying_party_id TEXT NOT NULL CHECK (octet_length(relying_party_id) BETWEEN 1 AND 512),
  replay_key       TEXT NOT NULL CHECK (octet_length(replay_key) BETWEEN 1 AND 4096),
  operation_key    TEXT NOT NULL CHECK (octet_length(operation_key) BETWEEN 1 AND 4096),
  reserved_at      TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (tenant_id, relying_party_id, replay_key),
  FOREIGN KEY (tenant_id, relying_party_id, operation_key)
    REFERENCES ep_aeb_consumption_operations (tenant_id, relying_party_id, operation_key)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ep_aeb_consumption_replay_fences_operation_idx
  ON ep_aeb_consumption_replay_fences (tenant_id, relying_party_id, operation_key);

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ep_aeb_executor') THEN
    CREATE ROLE ep_aeb_executor NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ep_aeb_recovery') THEN
    CREATE ROLE ep_aeb_recovery NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ep_aeb_store_owner') THEN
    CREATE ROLE ep_aeb_store_owner NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$roles$;

GRANT ep_aeb_store_owner TO CURRENT_USER;

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

ALTER SCHEMA ep_aeb_private OWNER TO ep_aeb_store_owner;
ALTER TABLE ep_aeb_private.tenant_principals OWNER TO ep_aeb_store_owner;
ALTER TABLE public.ep_aeb_consumption_operations OWNER TO ep_aeb_store_owner;
ALTER TABLE public.ep_aeb_consumption_replay_fences OWNER TO ep_aeb_store_owner;

ALTER TABLE ep_aeb_private.tenant_principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE ep_aeb_private.tenant_principals FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ep_aeb_consumption_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ep_aeb_consumption_operations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ep_aeb_consumption_replay_fences ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ep_aeb_consumption_replay_fences FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS ep_aeb_principals_owner_only ON ep_aeb_private.tenant_principals;
CREATE POLICY ep_aeb_principals_owner_only ON ep_aeb_private.tenant_principals
  TO ep_aeb_store_owner USING (TRUE) WITH CHECK (TRUE);
DROP POLICY IF EXISTS ep_aeb_operations_owner_only ON public.ep_aeb_consumption_operations;
CREATE POLICY ep_aeb_operations_owner_only ON public.ep_aeb_consumption_operations
  TO ep_aeb_store_owner USING (TRUE) WITH CHECK (TRUE);
DROP POLICY IF EXISTS ep_aeb_replay_owner_only ON public.ep_aeb_consumption_replay_fences;
CREATE POLICY ep_aeb_replay_owner_only ON public.ep_aeb_consumption_replay_fences
  TO ep_aeb_store_owner USING (TRUE) WITH CHECK (TRUE);

REVOKE ALL ON ep_aeb_private.tenant_principals
  FROM PUBLIC, anon, authenticated, service_role, ep_aeb_executor, ep_aeb_recovery;
REVOKE ALL ON public.ep_aeb_consumption_operations
  FROM PUBLIC, anon, authenticated, service_role, ep_aeb_executor, ep_aeb_recovery;
REVOKE ALL ON public.ep_aeb_consumption_replay_fences
  FROM PUBLIC, anon, authenticated, service_role, ep_aeb_executor, ep_aeb_recovery;

CREATE OR REPLACE FUNCTION ep_aeb_private.assert_tenant_principal(
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
  v_role_ok := CASE WHEN p_recovery
    THEN pg_catalog.pg_has_role(SESSION_USER, 'ep_aeb_recovery', 'MEMBER')
    ELSE pg_catalog.pg_has_role(SESSION_USER, 'ep_aeb_executor', 'MEMBER')
  END;
  SELECT EXISTS (
    SELECT 1
    FROM ep_aeb_private.tenant_principals AS principals
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
)
RETURNS TABLE(operation_key TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);
  RETURN QUERY INSERT INTO public.ep_aeb_consumption_operations (
    tenant_id, relying_party_id, operation_key, state, owner_token
  ) VALUES (
    p_tenant_id, p_relying_party_id, p_operation_key, 'RESERVED', p_owner_token
  )
  ON CONFLICT ON CONSTRAINT ep_aeb_consumption_operations_pkey DO NOTHING
  RETURNING ep_aeb_consumption_operations.operation_key;
END
$fn$;

CREATE OR REPLACE FUNCTION ep_aeb_private.reserve_replay_keys(
  p_tenant_id TEXT, p_relying_party_id TEXT, p_operation_key TEXT, p_replay_keys TEXT[]
)
RETURNS TABLE(replay_key TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);
  RETURN QUERY INSERT INTO public.ep_aeb_consumption_replay_fences (
    tenant_id, relying_party_id, replay_key, operation_key
  )
  SELECT p_tenant_id, p_relying_party_id, requested.replay_key, p_operation_key
  FROM pg_catalog.unnest(p_replay_keys) AS requested(replay_key)
  ORDER BY requested.replay_key
  ON CONFLICT ON CONSTRAINT ep_aeb_consumption_replay_fences_pkey DO NOTHING
  RETURNING ep_aeb_consumption_replay_fences.replay_key;
END
$fn$;

CREATE OR REPLACE FUNCTION ep_aeb_private.commit_operation(
  p_tenant_id TEXT, p_relying_party_id TEXT, p_operation_key TEXT, p_owner_token TEXT
)
RETURNS TABLE(operation_key TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);
  RETURN QUERY UPDATE public.ep_aeb_consumption_operations
    SET state = 'CONSUMED', owner_token = NULL,
        consumed_at = pg_catalog.transaction_timestamp()
    WHERE tenant_id = p_tenant_id
      AND relying_party_id = p_relying_party_id
      AND ep_aeb_consumption_operations.operation_key = p_operation_key
      AND state = 'RESERVED'
      AND owner_token = p_owner_token
    RETURNING ep_aeb_consumption_operations.operation_key;
END
$fn$;

CREATE OR REPLACE FUNCTION ep_aeb_private.claim_operation(
  p_tenant_id TEXT, p_relying_party_id TEXT, p_operation_key TEXT, p_owner_token TEXT
)
RETURNS TABLE(operation_key TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, TRUE);
  RETURN QUERY UPDATE public.ep_aeb_consumption_operations
    SET owner_token = p_owner_token
    WHERE tenant_id = p_tenant_id
      AND relying_party_id = p_relying_party_id
      AND ep_aeb_consumption_operations.operation_key = p_operation_key
      AND state = 'RESERVED'
    RETURNING ep_aeb_consumption_operations.operation_key;
END
$fn$;

CREATE OR REPLACE FUNCTION ep_aeb_private.release_operation(
  p_tenant_id TEXT, p_relying_party_id TEXT, p_operation_key TEXT, p_owner_token TEXT
)
RETURNS TABLE(operation_key TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);
  RETURN QUERY DELETE FROM public.ep_aeb_consumption_operations
    WHERE tenant_id = p_tenant_id
      AND relying_party_id = p_relying_party_id
      AND ep_aeb_consumption_operations.operation_key = p_operation_key
      AND state = 'RESERVED'
      AND owner_token = p_owner_token
    RETURNING ep_aeb_consumption_operations.operation_key;
END
$fn$;

ALTER FUNCTION ep_aeb_private.assert_tenant_principal(TEXT, BOOLEAN)
  OWNER TO ep_aeb_store_owner;
ALTER FUNCTION ep_aeb_private.reserve_operation(TEXT, TEXT, TEXT, TEXT)
  OWNER TO ep_aeb_store_owner;
ALTER FUNCTION ep_aeb_private.reserve_replay_keys(TEXT, TEXT, TEXT, TEXT[])
  OWNER TO ep_aeb_store_owner;
ALTER FUNCTION ep_aeb_private.commit_operation(TEXT, TEXT, TEXT, TEXT)
  OWNER TO ep_aeb_store_owner;
ALTER FUNCTION ep_aeb_private.claim_operation(TEXT, TEXT, TEXT, TEXT)
  OWNER TO ep_aeb_store_owner;
ALTER FUNCTION ep_aeb_private.release_operation(TEXT, TEXT, TEXT, TEXT)
  OWNER TO ep_aeb_store_owner;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ep_aeb_private
  FROM PUBLIC, anon, authenticated, service_role;
GRANT USAGE ON SCHEMA ep_aeb_private TO ep_aeb_executor, ep_aeb_recovery;
GRANT EXECUTE ON FUNCTION ep_aeb_private.reserve_operation(TEXT, TEXT, TEXT, TEXT),
  ep_aeb_private.reserve_replay_keys(TEXT, TEXT, TEXT, TEXT[]),
  ep_aeb_private.commit_operation(TEXT, TEXT, TEXT, TEXT),
  ep_aeb_private.release_operation(TEXT, TEXT, TEXT, TEXT)
  TO ep_aeb_executor;
GRANT EXECUTE ON FUNCTION ep_aeb_private.claim_operation(TEXT, TEXT, TEXT, TEXT)
  TO ep_aeb_recovery;

REVOKE ep_aeb_store_owner FROM CURRENT_USER;

COMMENT ON TABLE ep_aeb_consumption_operations IS
  'Durable AEB execution authorization state. RPC-only; opaque ownership-fenced RESERVED to CONSUMED lifecycle.';
COMMENT ON TABLE ep_aeb_consumption_replay_fences IS
  'Durable native-protocol replay fences reserved atomically with AEB operations. RPC-only; consumed fences are permanent.';
