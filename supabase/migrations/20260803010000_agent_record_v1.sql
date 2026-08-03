-- SPDX-License-Identifier: Apache-2.0
-- Agent Record v1: one privacy-minimized operator observation of one verified,
-- signed Arena refusal reached through the exact Agent Adoption trial binding.
--
-- This is not identity, ownership, competence, safety, rank, score,
-- certification, marketplace state, or production authority. The only public
-- access path is exact opaque record_id lookup. There is no enumeration RPC.

DO $roles$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles
    WHERE rolname = 'agent_record_store_owner'
  ) THEN
    CREATE ROLE agent_record_store_owner NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$roles$;

DO $least_privilege_role$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = 'agent_record_store_owner'
      AND NOT role.rolcanlogin
      AND NOT role.rolsuper
      AND NOT role.rolcreatedb
      AND NOT role.rolcreaterole
      AND NOT role.rolreplication
      AND NOT role.rolbypassrls
  ) THEN
    RAISE EXCEPTION 'agent record owner must have least-privilege posture'
      USING ERRCODE = '42501';
  END IF;
END
$least_privilege_role$;

SELECT pg_catalog.set_config(
  'ep.agent_record_migration_role',
  CURRENT_USER,
  TRUE
);
GRANT agent_record_store_owner TO CURRENT_USER
  WITH INHERIT FALSE, SET TRUE;
GRANT USAGE, CREATE ON SCHEMA public TO agent_record_store_owner;

CREATE SCHEMA agent_record_private
  AUTHORIZATION agent_record_store_owner;
REVOKE ALL ON SCHEMA agent_record_private
  FROM PUBLIC, anon, authenticated, service_role;

GRANT USAGE ON SCHEMA extensions TO agent_record_store_owner;
GRANT EXECUTE ON FUNCTION extensions.digest(BYTEA, TEXT)
  TO agent_record_store_owner;
GRANT EXECUTE ON FUNCTION extensions.gen_random_bytes(INTEGER)
  TO agent_record_store_owner;

-- Creation rechecks the active adoption through its existing bounded RPC.
-- It can inspect only non-revoked Arena public projections, never sessions,
-- private keys, encrypted tokens, raw private attempts, or allowance profiles.
GRANT EXECUTE ON FUNCTION public.read_agent_adoption_session(UUID, TEXT)
  TO agent_record_store_owner;
GRANT SELECT (share_id, public_projection, revoked_at)
  ON TABLE public.arena_shares TO agent_record_store_owner;
CREATE POLICY arena_shares_agent_record_source_read
  ON public.arena_shares
  FOR SELECT
  TO agent_record_store_owner
  USING (revoked_at IS NULL);

SET ROLE agent_record_store_owner;

ALTER DEFAULT PRIVILEGES IN SCHEMA agent_record_private
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA agent_record_private
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE TABLE agent_record_private.records (
  record_id TEXT COLLATE "C" NOT NULL
    CHECK (record_id ~ '^agent_record_[0-9a-f]{40}$'),
  owner_token_hash TEXT COLLATE "C" NOT NULL UNIQUE
    CHECK (owner_token_hash ~ '^[0-9a-f]{64}$'),
  adoption_id UUID NOT NULL,
  bond_id UUID NOT NULL,
  bond_digest TEXT COLLATE "C" NOT NULL
    CHECK (bond_digest ~ '^sha256:[0-9a-f]{64}$'),
  arena_share_id TEXT COLLATE "C" NOT NULL UNIQUE
    CHECK (arena_share_id ~ '^arena_share_[0-9a-f]{40}$'),
  source_artifact_digest TEXT COLLATE "C" NOT NULL UNIQUE
    CHECK (source_artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
  action_digest TEXT COLLATE "C" NOT NULL
    CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$'),
  refusal_digest TEXT COLLATE "C" NOT NULL
    CHECK (refusal_digest ~ '^sha256:[0-9a-f]{64}$'),
  refused_at TIMESTAMPTZ NOT NULL,
  observed_at TIMESTAMPTZ NOT NULL,
  retention_expires_at TIMESTAMPTZ NOT NULL,
  public_projection JSONB NOT NULL CHECK (
    pg_catalog.jsonb_typeof(public_projection) = 'object'
    AND pg_catalog.pg_column_size(public_projection) <= 8192
    AND public_projection ->> '@version' =
      'EP-AGENT-RECORD-OBSERVATION-v1'
  ),
  PRIMARY KEY (record_id),
  CHECK (refusal_digest = source_artifact_digest),
  CHECK (refused_at <= observed_at),
  CHECK (retention_expires_at = observed_at + INTERVAL '365 days')
);

CREATE TABLE agent_record_private.revocations (
  record_id TEXT COLLATE "C" NOT NULL,
  revocation_id UUID NOT NULL UNIQUE,
  revocation_nonce_hash TEXT COLLATE "C" NOT NULL UNIQUE
    CHECK (revocation_nonce_hash ~ '^[0-9a-f]{64}$'),
  revoked_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (record_id),
  FOREIGN KEY (record_id)
    REFERENCES agent_record_private.records (record_id)
    ON DELETE RESTRICT
);

CREATE INDEX agent_record_retention_idx
  ON agent_record_private.records (retention_expires_at, record_id);

ALTER TABLE agent_record_private.records
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_record_private.records
  FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_record_private.revocations
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_record_private.revocations
  FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_record_records_owner_only
  ON agent_record_private.records
  TO agent_record_store_owner USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY agent_record_revocations_owner_only
  ON agent_record_private.revocations
  TO agent_record_store_owner USING (TRUE) WITH CHECK (TRUE);

REVOKE ALL ON TABLE agent_record_private.records
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE agent_record_private.revocations
  FROM PUBLIC, anon, authenticated, service_role;

CREATE FUNCTION agent_record_private.token_hash(p_token TEXT)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
SECURITY DEFINER
SET search_path = ''
AS $agent_record_token_hash$
  SELECT pg_catalog.encode(
    extensions.digest(pg_catalog.convert_to(p_token, 'UTF8'), 'sha256'),
    'hex'
  );
$agent_record_token_hash$;

CREATE FUNCTION agent_record_private.iso_ms(p_value TIMESTAMPTZ)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
SECURITY DEFINER
SET search_path = ''
AS $agent_record_iso_ms$
  SELECT pg_catalog.to_char(
    p_value AT TIME ZONE 'UTC',
    'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
  );
$agent_record_iso_ms$;

CREATE FUNCTION agent_record_private.reject_immutable_record_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $agent_record_immutable$
BEGIN
  RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME
    USING ERRCODE = '55000';
END
$agent_record_immutable$;

CREATE TRIGGER agent_record_records_immutable_trigger
  BEFORE UPDATE OR DELETE ON agent_record_private.records
  FOR EACH ROW
  EXECUTE FUNCTION agent_record_private.reject_immutable_record_mutation();
CREATE TRIGGER agent_record_revocations_immutable_trigger
  BEFORE UPDATE OR DELETE ON agent_record_private.revocations
  FOR EACH ROW
  EXECUTE FUNCTION agent_record_private.reject_immutable_record_mutation();

CREATE FUNCTION public.create_agent_record(
  p_adoption_id UUID,
  p_adoption_session_token TEXT,
  p_record_id TEXT,
  p_bond_id UUID,
  p_bond_digest TEXT,
  p_arena_share_id TEXT,
  p_source_artifact_digest TEXT,
  p_action_digest TEXT,
  p_refusal_digest TEXT,
  p_refused_at TIMESTAMPTZ,
  p_observed_at TIMESTAMPTZ,
  p_retention_expires_at TIMESTAMPTZ,
  p_public_projection JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $create_agent_record$
DECLARE
  v_adoption JSONB;
  v_arena_projection JSONB;
  v_owner_token TEXT;
BEGIN
  IF p_adoption_id IS NULL
    OR p_adoption_session_token IS NULL
    OR p_adoption_session_token !~ '^eaa1_[0-9a-f]{64}$'
    OR p_record_id IS NULL
    OR p_record_id !~ '^agent_record_[0-9a-f]{40}$'
    OR p_bond_id IS NULL
    OR p_bond_digest IS NULL
    OR p_bond_digest !~ '^sha256:[0-9a-f]{64}$'
    OR p_arena_share_id IS NULL
    OR p_arena_share_id !~ '^arena_share_[0-9a-f]{40}$'
    OR p_source_artifact_digest IS NULL
    OR p_source_artifact_digest !~ '^sha256:[0-9a-f]{64}$'
    OR p_action_digest IS NULL
    OR p_action_digest !~ '^sha256:[0-9a-f]{64}$'
    OR p_refusal_digest IS NULL
    OR p_refusal_digest !~ '^sha256:[0-9a-f]{64}$'
    OR p_refusal_digest IS DISTINCT FROM p_source_artifact_digest
    OR p_refused_at IS NULL
    OR p_observed_at IS NULL
    OR p_retention_expires_at IS NULL
    OR p_refused_at > p_observed_at
    OR p_observed_at > pg_catalog.clock_timestamp() + INTERVAL '5 minutes'
    OR p_retention_expires_at IS DISTINCT FROM p_observed_at + INTERVAL '365 days'
    OR p_public_projection IS NULL
    OR pg_catalog.jsonb_typeof(p_public_projection) IS DISTINCT FROM 'object'
    OR pg_catalog.pg_column_size(p_public_projection) > 8192
  THEN
    RAISE EXCEPTION 'agent record creation input is invalid'
      USING ERRCODE = '22023';
  END IF;

  IF (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(p_public_projection)) <> 3
    OR p_public_projection ->> '@version' IS DISTINCT FROM
      'EP-AGENT-RECORD-OBSERVATION-v1'
    OR pg_catalog.jsonb_typeof(p_public_projection -> 'record') IS DISTINCT FROM 'object'
    OR pg_catalog.jsonb_typeof(p_public_projection -> 'signature') IS DISTINCT FROM 'object'
    OR (
      SELECT pg_catalog.count(*)
      FROM pg_catalog.jsonb_object_keys(p_public_projection -> 'record')
    ) <> 8
    OR (
      SELECT pg_catalog.count(*)
      FROM pg_catalog.jsonb_object_keys(p_public_projection -> 'record' -> 'bond')
    ) <> 2
    OR (
      SELECT pg_catalog.count(*)
      FROM pg_catalog.jsonb_object_keys(p_public_projection -> 'record' -> 'source')
    ) <> 3
    OR (
      SELECT pg_catalog.count(*)
      FROM pg_catalog.jsonb_object_keys(p_public_projection -> 'record' -> 'action')
    ) <> 1
    OR (
      SELECT pg_catalog.count(*)
      FROM pg_catalog.jsonb_object_keys(p_public_projection -> 'record' -> 'refusal')
    ) <> 2
    OR (
      SELECT pg_catalog.count(*)
      FROM pg_catalog.jsonb_object_keys(p_public_projection -> 'signature')
    ) <> 4
    OR p_public_projection -> 'record' ->> 'record_id' IS DISTINCT FROM p_record_id
    OR p_public_projection -> 'record' -> 'bond' ->> 'bond_id' IS DISTINCT FROM p_bond_id::TEXT
    OR p_public_projection -> 'record' -> 'bond' ->> 'bond_digest' IS DISTINCT FROM p_bond_digest
    OR p_public_projection -> 'record' -> 'source' ->> 'profile' IS DISTINCT FROM
      'EP-ACTION-REFUSAL-STATEMENT-v1'
    OR p_public_projection -> 'record' -> 'source' ->> 'arena_share_id' IS DISTINCT FROM
      p_arena_share_id
    OR p_public_projection -> 'record' -> 'source' ->> 'artifact_digest' IS DISTINCT FROM
      p_source_artifact_digest
    OR p_public_projection -> 'record' -> 'action' ->> 'action_digest' IS DISTINCT FROM
      p_action_digest
    OR p_public_projection -> 'record' -> 'refusal' ->> 'refusal_digest' IS DISTINCT FROM
      p_refusal_digest
    OR p_public_projection -> 'record' -> 'refusal' ->> 'refused_at' IS DISTINCT FROM
      agent_record_private.iso_ms(p_refused_at)
    OR p_public_projection -> 'record' ->> 'observed_at' IS DISTINCT FROM
      agent_record_private.iso_ms(p_observed_at)
    OR p_public_projection -> 'record' ->> 'retention_expires_at' IS DISTINCT FROM
      agent_record_private.iso_ms(p_retention_expires_at)
    OR p_public_projection -> 'record' ->> 'claim_boundary' IS DISTINCT FROM
        'one_operator_observation_of_one_verified_signed_arena_refusal_only'
    OR p_public_projection -> 'signature' ->> 'algorithm' IS DISTINCT FROM 'Ed25519'
    OR p_public_projection -> 'signature' ->> 'key_id' IS DISTINCT FROM 'ep-signing-key-1'
    OR p_public_projection -> 'signature' ->> 'key_source' IS DISTINCT FROM
        'operator-commit-signing-key'
    OR p_public_projection -> 'signature' ->> 'value' !~ '^[A-Za-z0-9_-]{86}$'
  THEN
    RAISE EXCEPTION 'agent record public projection is invalid'
      USING ERRCODE = '22023';
  END IF;

  v_adoption := public.read_agent_adoption_session(
    p_adoption_id,
    p_adoption_session_token
  );
  IF v_adoption ->> 'status' IS DISTINCT FROM 'active'
    OR v_adoption ->> 'adoption_id' IS DISTINCT FROM p_adoption_id::TEXT
    OR v_adoption ->> 'bond_count' IS DISTINCT FROM '1'
    OR v_adoption ->> 'latest_bond_id' IS DISTINCT FROM p_bond_id::TEXT
    OR v_adoption ->> 'bond_digest' IS DISTINCT FROM p_bond_digest
    OR v_adoption ->> 'latest_bond_digest' IS DISTINCT FROM p_bond_digest
  THEN
    RAISE EXCEPTION 'active adoption bond does not match agent record source'
      USING ERRCODE = '55000';
  END IF;

  SELECT share.public_projection
  INTO v_arena_projection
  FROM public.arena_shares AS share
  WHERE share.share_id = p_arena_share_id
    AND share.revoked_at IS NULL;
  IF NOT FOUND
    OR v_arena_projection ->> 'profile' IS DISTINCT FROM 'EP-ARENA-PUBLIC-REFUSAL-v1'
    OR v_arena_projection -> 'attempt' ->> 'decision' IS DISTINCT FROM 'refuse'
    OR v_arena_projection -> 'attempt' ->> 'action_digest' IS DISTINCT FROM p_action_digest
    OR v_arena_projection -> 'attempt' ->> 'created_at' IS DISTINCT FROM
      agent_record_private.iso_ms(p_refused_at)
    OR v_arena_projection ->> 'refusal_digest' IS DISTINCT FROM p_refusal_digest
    OR v_arena_projection -> 'refusal_artifact' ->> '@version' IS DISTINCT FROM
        'EP-ACTION-REFUSAL-STATEMENT-v1'
  THEN
    RAISE EXCEPTION 'Arena refusal source does not match agent record bindings'
      USING ERRCODE = '55000';
  END IF;

  v_owner_token := 'ear1_' ||
    pg_catalog.encode(extensions.gen_random_bytes(32), 'hex');
  INSERT INTO agent_record_private.records (
    record_id,
    owner_token_hash,
    adoption_id,
    bond_id,
    bond_digest,
    arena_share_id,
    source_artifact_digest,
    action_digest,
    refusal_digest,
    refused_at,
    observed_at,
    retention_expires_at,
    public_projection
  ) VALUES (
    p_record_id,
    agent_record_private.token_hash(v_owner_token),
    p_adoption_id,
    p_bond_id,
    p_bond_digest,
    p_arena_share_id,
    p_source_artifact_digest,
    p_action_digest,
    p_refusal_digest,
    p_refused_at,
    p_observed_at,
    p_retention_expires_at,
    p_public_projection
  );

  RETURN pg_catalog.jsonb_build_object(
    'record_id', p_record_id,
    'owner_token', v_owner_token,
    'created_at', agent_record_private.iso_ms(p_observed_at),
    'retention_expires_at', agent_record_private.iso_ms(p_retention_expires_at),
    'public_projection', p_public_projection
  );
END
$create_agent_record$;

CREATE FUNCTION public.revoke_agent_record(
  p_record_id TEXT,
  p_owner_token TEXT,
  p_revocation_nonce TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $revoke_agent_record$
DECLARE
  v_record agent_record_private.records%ROWTYPE;
  v_existing agent_record_private.revocations%ROWTYPE;
  v_revoked_at TIMESTAMPTZ;
BEGIN
  IF p_record_id IS NULL
    OR p_record_id !~ '^agent_record_[0-9a-f]{40}$'
    OR p_owner_token IS NULL
    OR p_owner_token !~ '^ear1_[0-9a-f]{64}$'
    OR p_revocation_nonce IS NULL
    OR p_revocation_nonce !~ '^earv1_[0-9a-f]{64}$'
  THEN
    RAISE EXCEPTION 'agent record owner credential is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT record.*
  INTO v_record
  FROM agent_record_private.records AS record
  WHERE record.record_id = p_record_id
    AND record.owner_token_hash = agent_record_private.token_hash(p_owner_token)
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'agent record not found'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT revocation.*
  INTO v_existing
  FROM agent_record_private.revocations AS revocation
  WHERE revocation.record_id = v_record.record_id;
  IF v_existing.revocation_id IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object(
      'record_id', v_record.record_id,
      'revoked', TRUE,
      'revoked_at', agent_record_private.iso_ms(v_existing.revoked_at)
    );
  END IF;

  v_revoked_at := pg_catalog.transaction_timestamp();
  INSERT INTO agent_record_private.revocations (
    record_id,
    revocation_id,
    revocation_nonce_hash,
    revoked_at
  ) VALUES (
    v_record.record_id,
    pg_catalog.gen_random_uuid(),
    agent_record_private.token_hash(p_revocation_nonce),
    v_revoked_at
  );

  RETURN pg_catalog.jsonb_build_object(
    'record_id', v_record.record_id,
    'revoked', TRUE,
    'revoked_at', agent_record_private.iso_ms(v_revoked_at)
  );
END
$revoke_agent_record$;

CREATE FUNCTION public.read_agent_record_public(p_record_id TEXT)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
SET statement_timeout = '2s'
AS $read_agent_record_public$
DECLARE
  v_public_projection JSONB;
BEGIN
  IF p_record_id IS NULL
    OR p_record_id !~ '^agent_record_[0-9a-f]{40}$'
  THEN
    RAISE EXCEPTION 'agent record not found'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT record.public_projection
  INTO v_public_projection
  FROM agent_record_private.records AS record
  WHERE record.record_id = p_record_id
    AND record.observed_at <= pg_catalog.clock_timestamp()
    AND record.retention_expires_at > pg_catalog.clock_timestamp()
    AND NOT EXISTS (
      SELECT 1
      FROM agent_record_private.revocations AS revocation
      WHERE revocation.record_id = record.record_id
    );
  IF NOT FOUND THEN
    RAISE EXCEPTION 'agent record not found'
      USING ERRCODE = 'P0002';
  END IF;

  RETURN pg_catalog.jsonb_build_object(
    'record_id', p_record_id,
    'public_projection', v_public_projection
  );
END
$read_agent_record_public$;

REVOKE ALL ON FUNCTION agent_record_private.token_hash(TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION agent_record_private.iso_ms(TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION agent_record_private.reject_immutable_record_mutation()
  FROM PUBLIC, anon, authenticated, service_role;

REVOKE ALL ON FUNCTION public.create_agent_record(UUID, TEXT, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, JSONB)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.create_agent_record(UUID, TEXT, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, JSONB)
  TO service_role;
REVOKE ALL ON FUNCTION public.revoke_agent_record(TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.revoke_agent_record(TEXT, TEXT, TEXT)
  TO service_role;
REVOKE ALL ON FUNCTION public.read_agent_record_public(TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.read_agent_record_public(TEXT)
  TO anon, authenticated, service_role;

COMMENT ON SCHEMA agent_record_private IS
  'RPC-only custody for minimal factual Agent Records and owner revocations.';
COMMENT ON TABLE agent_record_private.records IS
  'Immutable minimal bindings for one operator-observed signed Arena refusal; exact-id public projection expires after 365 days.';
COMMENT ON TABLE agent_record_private.revocations IS
  'Append-only terminal owner revocations; a revoked record is uniformly absent from public reads.';
COMMENT ON FUNCTION public.read_agent_record_public(TEXT) IS
  'Exact opaque Agent Record lookup only; unknown, expired, and revoked records all raise P0002.';

DO $restore_migration_role$
BEGIN
  EXECUTE pg_catalog.format(
    'SET ROLE %I',
    pg_catalog.current_setting('ep.agent_record_migration_role')
  );
END
$restore_migration_role$;
REVOKE CREATE ON SCHEMA public FROM agent_record_store_owner;
REVOKE agent_record_store_owner FROM CURRENT_USER;
