-- SPDX-License-Identifier: Apache-2.0
-- Agent Record v1: one privacy-minimized operator observation of one verified,
-- signed refusal reached through the exact Agent Adoption trial binding.
--
-- This is not identity, ownership, competence, safety, rank, score,
-- certification, marketplace state, or production authority. The only public
-- access path is exact opaque record_id lookup. There is no enumeration RPC.

SELECT pg_catalog.set_config(
  'ep.agent_record_migration_role',
  CURRENT_USER,
  TRUE
);

-- PostgreSQL 17 gives a non-superuser CREATEROLE caller an automatic ADMIN
-- membership in every role it creates. Create the permanent owner through a
-- disposable bootstrap role so dropping that bootstrap below removes the
-- automatic edge. The migration operator receives only temporary SET edges.
DO $roles$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles
    WHERE rolname = 'agent_record_store_owner'
  ) THEN
    RAISE EXCEPTION 'agent record owner already exists before migration'
      USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles
    WHERE rolname = 'agent_record_store_bootstrap'
  ) THEN
    RAISE EXCEPTION 'agent record bootstrap role already exists before migration'
      USING ERRCODE = '55000';
  END IF;

  CREATE ROLE agent_record_store_bootstrap NOLOGIN
    NOSUPERUSER NOCREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS;
  EXECUTE pg_catalog.format(
    'GRANT agent_record_store_bootstrap TO %I WITH INHERIT FALSE, SET TRUE GRANTED BY %I',
    pg_catalog.current_setting('ep.agent_record_migration_role'),
    pg_catalog.current_setting('ep.agent_record_migration_role')
  );
  EXECUTE 'SET ROLE agent_record_store_bootstrap';
  CREATE ROLE agent_record_store_owner NOLOGIN
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  EXECUTE pg_catalog.format(
    'GRANT agent_record_store_owner TO %I WITH INHERIT FALSE, SET TRUE GRANTED BY agent_record_store_bootstrap',
    pg_catalog.current_setting('ep.agent_record_migration_role')
  );
  EXECUTE pg_catalog.format(
    'SET ROLE %I',
    pg_catalog.current_setting('ep.agent_record_migration_role')
  );
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

GRANT USAGE, CREATE ON SCHEMA public TO agent_record_store_owner;

CREATE SCHEMA agent_record_private
  AUTHORIZATION agent_record_store_owner;
GRANT USAGE ON SCHEMA extensions TO agent_record_store_owner;
GRANT EXECUTE ON FUNCTION extensions.digest(BYTEA, TEXT)
  TO agent_record_store_owner;

-- Creation rechecks the active adoption through its existing bounded RPC. The
-- read-only source RPC returns the signed refusal and digest-only bindings
-- needed for server verification. It never creates a share or returns raw
-- action parameters, an Arena token, a private key, or an allowance profile.
GRANT EXECUTE ON FUNCTION public.read_agent_adoption_session(UUID, TEXT)
  TO agent_record_store_owner;
GRANT SELECT ON TABLE public.arena_sessions, public.arena_attempts
  TO agent_record_store_owner;

-- The dedicated NOLOGIN owner may read only the Arena source tables through
-- explicit forced-RLS policies. No application role receives these policies,
-- and the source RPC below still requires the plaintext session credential.
CREATE POLICY agent_record_source_sessions_reader
  ON public.arena_sessions
  FOR SELECT
  TO agent_record_store_owner
  USING (TRUE);
CREATE POLICY agent_record_source_attempts_reader
  ON public.arena_attempts
  FOR SELECT
  TO agent_record_store_owner
  USING (TRUE);

CREATE FUNCTION public.read_agent_record_refusal_source(
  p_source_token TEXT,
  p_source_session_id TEXT,
  p_source_attempt_id TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $agent_record_refusal_source$
DECLARE
  v_attempt public.arena_attempts%ROWTYPE;
  v_session public.arena_sessions%ROWTYPE;
  v_source_commitment TEXT;
BEGIN
  IF p_source_token IS NULL
    OR p_source_token !~ '^ep_arena_[0-9a-f]{64}$'
    OR p_source_session_id IS NULL
    OR p_source_session_id !~ '^arena_session_[0-9a-f]{32}$'
    OR p_source_attempt_id IS NULL
    OR p_source_attempt_id !~ '^arena_attempt_[0-9a-f]{32}$'
  THEN
    RAISE EXCEPTION 'Agent Record refusal source input is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT attempt.*
  INTO v_attempt
  FROM public.arena_attempts AS attempt
  JOIN public.arena_sessions AS session
    ON session.id = attempt.session_row_id
  WHERE attempt.attempt_id = p_source_attempt_id
    AND session.session_id = p_source_session_id
    AND session.token_hash = pg_catalog.encode(
      extensions.digest(pg_catalog.convert_to(p_source_token, 'UTF8'), 'sha256'),
      'hex'
    );
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Agent Record refusal source not found'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT session.*
  INTO v_session
  FROM public.arena_sessions AS session
  WHERE session.id = v_attempt.session_row_id;
  IF v_session.status IS DISTINCT FROM 'active'
    OR v_session.expires_at <= pg_catalog.clock_timestamp()
    OR v_attempt.decision IS DISTINCT FROM 'refuse'
    OR v_attempt.evidence_status IS DISTINCT FROM 'complete'
    OR v_attempt.refusal_artifact IS NULL
    OR v_attempt.refusal_digest IS NULL
    OR v_attempt.refusal_digest !~ '^sha256:[0-9a-f]{64}$'
    OR v_attempt.action_digest !~ '^sha256:[0-9a-f]{64}$'
    OR pg_catalog.jsonb_typeof(v_attempt.refusal_artifact) IS DISTINCT FROM 'object'
    OR v_attempt.refusal_artifact ->> '@version' IS DISTINCT FROM
      'EP-ACTION-REFUSAL-STATEMENT-v1'
    OR v_attempt.refusal_artifact ->> 'refusal_id' IS DISTINCT FROM
      'refusal:' || v_attempt.attempt_id
    OR v_attempt.refusal_artifact ->> 'action_digest' IS DISTINCT FROM
      v_attempt.action_digest
    OR v_attempt.refusal_artifact ->> 'refused_at' IS DISTINCT FROM
      pg_catalog.to_char(
        v_attempt.created_at AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
      )
    OR v_attempt.refusal_artifact -> 'issuer' ->> 'id' IS DISTINCT FROM
      v_session.issuer_id
    OR v_attempt.refusal_artifact -> 'issuer' ->> 'key_id' IS DISTINCT FROM
      v_session.key_id
  THEN
    RAISE EXCEPTION 'Agent Record refusal source is invalid'
      USING ERRCODE = '55000';
  END IF;

  v_source_commitment := 'sha256:' || pg_catalog.encode(
    extensions.digest(
      pg_catalog.convert_to(
        'emilia-agent-record-private-refusal-source-v1',
        'UTF8'
      )
      || pg_catalog.decode('00', 'hex')
      || pg_catalog.convert_to(v_session.session_id, 'UTF8')
      || pg_catalog.decode('00', 'hex')
      || pg_catalog.convert_to(v_attempt.attempt_id, 'UTF8')
      || pg_catalog.decode('00', 'hex')
      || pg_catalog.convert_to(v_attempt.refusal_digest, 'UTF8'),
      'sha256'
    ),
    'hex'
  );

  RETURN pg_catalog.jsonb_build_object(
    'source_commitment', v_source_commitment,
    'source_artifact_digest', v_attempt.refusal_digest,
    'action_digest', v_attempt.action_digest,
    'refusal_digest', v_attempt.refusal_digest,
    'refused_at', pg_catalog.to_char(
      v_attempt.created_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
    ),
    'refusal_artifact', v_attempt.refusal_artifact,
    'issuer', pg_catalog.jsonb_build_object(
      'issuer_id', v_session.issuer_id,
      'key_id', v_session.key_id,
      'public_key', v_session.public_key
    )
  );
END
$agent_record_refusal_source$;
ALTER FUNCTION public.read_agent_record_refusal_source(TEXT, TEXT, TEXT)
  OWNER TO agent_record_store_owner;
REVOKE ALL ON FUNCTION public.read_agent_record_refusal_source(TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role, agent_record_store_owner;
GRANT EXECUTE ON FUNCTION public.read_agent_record_refusal_source(TEXT, TEXT, TEXT)
  TO service_role, agent_record_store_owner;

SET ROLE agent_record_store_owner;

REVOKE ALL ON SCHEMA agent_record_private
  FROM PUBLIC, anon, authenticated, service_role;

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
  source_commitment TEXT COLLATE "C" NOT NULL UNIQUE
    CHECK (source_commitment ~ '^sha256:[0-9a-f]{64}$'),
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

CREATE TABLE agent_record_private.creation_capability (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
  capability_hash TEXT COLLATE "C" NOT NULL UNIQUE
    CHECK (capability_hash ~ '^[0-9a-f]{64}$'),
  configured_by TEXT COLLATE "C" NOT NULL,
  configured_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE agent_record_private.trial_bindings (
  source_session_id TEXT COLLATE "C" PRIMARY KEY
    CHECK (source_session_id ~ '^arena_session_[0-9a-f]{32}$'),
  source_token_hash TEXT COLLATE "C" NOT NULL UNIQUE
    CHECK (source_token_hash ~ '^[0-9a-f]{64}$'),
  adoption_id UUID NOT NULL,
  bond_id UUID NOT NULL,
  bond_digest TEXT COLLATE "C" NOT NULL
    CHECK (bond_digest ~ '^sha256:[0-9a-f]{64}$'),
  source_expires_at TIMESTAMPTZ NOT NULL,
  bound_at TIMESTAMPTZ NOT NULL,
  CHECK (bound_at < source_expires_at)
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
ALTER TABLE agent_record_private.creation_capability
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_record_private.creation_capability
  FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_record_private.trial_bindings
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_record_private.trial_bindings
  FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_record_records_owner_only
  ON agent_record_private.records
  TO agent_record_store_owner USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY agent_record_revocations_owner_only
  ON agent_record_private.revocations
  TO agent_record_store_owner USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY agent_record_creation_capability_owner_only
  ON agent_record_private.creation_capability
  TO agent_record_store_owner USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY agent_record_trial_bindings_owner_only
  ON agent_record_private.trial_bindings
  TO agent_record_store_owner USING (TRUE) WITH CHECK (TRUE);

REVOKE ALL ON TABLE agent_record_private.records
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE agent_record_private.revocations
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE agent_record_private.creation_capability
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE agent_record_private.trial_bindings
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

CREATE FUNCTION agent_record_private.owner_record_id(p_owner_token TEXT)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
SECURITY DEFINER
SET search_path = ''
AS $agent_record_owner_record_id$
  SELECT CASE
    WHEN p_owner_token ~ '^ear1_[0-9a-f]{64}$' THEN
      'agent_record_' || pg_catalog.substr(
        pg_catalog.encode(
          extensions.digest(
            pg_catalog.convert_to(
              'emilia-agent-record-owner-token-v1',
              'UTF8'
            )
            || pg_catalog.decode('00', 'hex')
            || pg_catalog.convert_to(p_owner_token, 'UTF8'),
            'sha256'
          ),
          'hex'
        ),
        1,
        40
      )
    ELSE NULL
  END;
$agent_record_owner_record_id$;

CREATE FUNCTION agent_record_private.configure_creation_capability(
  p_creation_capability TEXT
)
RETURNS VOID
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $agent_record_configure_creation_capability$
BEGIN
  IF p_creation_capability IS NULL
    OR p_creation_capability !~ '^earc1_[0-9a-f]{64}$'
  THEN
    RAISE EXCEPTION 'Agent Record creation capability is invalid'
      USING ERRCODE = '22023';
  END IF;

  INSERT INTO agent_record_private.creation_capability (
    singleton,
    capability_hash,
    configured_by,
    configured_at
  ) VALUES (
    TRUE,
    agent_record_private.token_hash(p_creation_capability),
    SESSION_USER,
    pg_catalog.transaction_timestamp()
  )
  ON CONFLICT (singleton) DO UPDATE
  SET capability_hash = EXCLUDED.capability_hash,
      configured_by = EXCLUDED.configured_by,
      configured_at = EXCLUDED.configured_at;
END
$agent_record_configure_creation_capability$;

-- The migration operator must be able to provision and rotate the capability
-- after its temporary SET membership in the private owner has been revoked.
-- This wrapper is owned by the NOLOGIN store owner, returns no capability data,
-- and receives one exact direct EXECUTE grant below. Application roles remain
-- unable to configure the capability or execute the base creator.
CREATE FUNCTION public.configure_agent_record_creation_capability(
  p_creation_capability TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
SET statement_timeout = '2s'
AS $configure_agent_record_creation_capability$
BEGIN
  PERFORM agent_record_private.configure_creation_capability(
    p_creation_capability
  );
  RETURN TRUE;
END
$configure_agent_record_creation_capability$;

CREATE FUNCTION agent_record_private.creation_capability_matches(
  p_creation_capability TEXT
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $agent_record_creation_capability_matches$
  SELECT
    p_creation_capability IS NOT NULL
    AND p_creation_capability ~ '^earc1_[0-9a-f]{64}$'
    AND EXISTS (
      SELECT 1
      FROM agent_record_private.creation_capability AS capability
      WHERE capability.singleton
        AND capability.capability_hash =
          agent_record_private.token_hash(p_creation_capability)
    );
$agent_record_creation_capability_matches$;

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

-- Bind one active adoption bond to one plaintext-authenticated Arena session
-- before any public record can be created. The database stores only the token
-- hash. A service_role database credential can read Arena hashes, but cannot
-- manufacture this binding without both original bearer credentials.
CREATE FUNCTION public.bind_agent_record_trial_source(
  p_adoption_id UUID,
  p_adoption_session_token TEXT,
  p_bond_id UUID,
  p_bond_digest TEXT,
  p_source_session_id TEXT,
  p_source_token TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $bind_agent_record_trial_source$
DECLARE
  v_adoption JSONB;
  v_source public.arena_sessions%ROWTYPE;
  v_token_hash TEXT;
  v_existing agent_record_private.trial_bindings%ROWTYPE;
BEGIN
  IF p_adoption_id IS NULL
    OR p_adoption_session_token IS NULL
    OR p_adoption_session_token !~ '^eaa1_[0-9a-f]{64}$'
    OR p_bond_id IS NULL
    OR p_bond_digest IS NULL
    OR p_bond_digest !~ '^sha256:[0-9a-f]{64}$'
    OR p_source_session_id IS NULL
    OR p_source_session_id !~ '^arena_session_[0-9a-f]{32}$'
    OR p_source_token IS NULL
    OR p_source_token !~ '^ep_arena_[0-9a-f]{64}$'
  THEN
    RAISE EXCEPTION 'Agent Record trial binding input is invalid'
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
    RAISE EXCEPTION 'Agent Record trial adoption binding is invalid'
      USING ERRCODE = '55000';
  END IF;

  v_token_hash := agent_record_private.token_hash(p_source_token);
  SELECT session.*
  INTO v_source
  FROM public.arena_sessions AS session
  WHERE session.session_id = p_source_session_id
    AND session.token_hash = v_token_hash
    AND session.status = 'active'
    AND session.expires_at > pg_catalog.clock_timestamp();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Agent Record trial Arena binding is invalid'
      USING ERRCODE = 'P0002';
  END IF;

  INSERT INTO agent_record_private.trial_bindings (
    source_session_id,
    source_token_hash,
    adoption_id,
    bond_id,
    bond_digest,
    source_expires_at,
    bound_at
  ) VALUES (
    p_source_session_id,
    v_token_hash,
    p_adoption_id,
    p_bond_id,
    p_bond_digest,
    v_source.expires_at,
    pg_catalog.transaction_timestamp()
  )
  ON CONFLICT (source_session_id) DO NOTHING
  RETURNING * INTO v_existing;

  IF NOT FOUND THEN
    SELECT binding.*
    INTO v_existing
    FROM agent_record_private.trial_bindings AS binding
    WHERE binding.source_session_id = p_source_session_id
      AND binding.source_token_hash = v_token_hash
      AND binding.adoption_id = p_adoption_id
      AND binding.bond_id = p_bond_id
      AND binding.bond_digest = p_bond_digest
      AND binding.source_expires_at = v_source.expires_at;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Agent Record trial source was already bound'
        USING ERRCODE = '23505';
    END IF;
  END IF;

  RETURN TRUE;
END
$bind_agent_record_trial_source$;

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
CREATE TRIGGER agent_record_trial_bindings_immutable_trigger
  BEFORE UPDATE OR DELETE ON agent_record_private.trial_bindings
  FOR EACH ROW
  EXECUTE FUNCTION agent_record_private.reject_immutable_record_mutation();

CREATE FUNCTION public.create_agent_record(
  p_adoption_id UUID,
  p_adoption_session_token TEXT,
  p_record_id TEXT,
  p_owner_token TEXT,
  p_bond_id UUID,
  p_bond_digest TEXT,
  p_source_session_id TEXT,
  p_source_token TEXT,
  p_source_attempt_id TEXT,
  p_source_commitment TEXT,
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
  v_source JSONB;
  v_existing agent_record_private.records%ROWTYPE;
BEGIN
  IF p_adoption_id IS NULL
    OR p_adoption_session_token IS NULL
    OR p_adoption_session_token !~ '^eaa1_[0-9a-f]{64}$'
    OR p_record_id IS NULL
    OR p_record_id !~ '^agent_record_[0-9a-f]{40}$'
    OR p_owner_token IS NULL
    OR p_owner_token !~ '^ear1_[0-9a-f]{64}$'
    OR p_record_id IS DISTINCT FROM
      agent_record_private.owner_record_id(p_owner_token)
    OR p_bond_id IS NULL
    OR p_bond_digest IS NULL
    OR p_bond_digest !~ '^sha256:[0-9a-f]{64}$'
    OR p_source_session_id IS NULL
    OR p_source_session_id !~ '^arena_session_[0-9a-f]{32}$'
    OR p_source_token IS NULL
    OR p_source_token !~ '^ep_arena_[0-9a-f]{64}$'
    OR p_source_attempt_id IS NULL
    OR p_source_attempt_id !~ '^arena_attempt_[0-9a-f]{32}$'
    OR p_source_commitment IS NULL
    OR p_source_commitment !~ '^sha256:[0-9a-f]{64}$'
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
    OR p_retention_expires_at <= pg_catalog.clock_timestamp()
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
    ) <> 2
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
        'one_operator_observation_of_one_verified_signed_refusal_artifact_only'
    OR p_public_projection -> 'signature' ->> 'algorithm' IS DISTINCT FROM 'Ed25519'
    OR pg_catalog.jsonb_typeof(
      p_public_projection -> 'signature' -> 'key_id'
    ) IS DISTINCT FROM 'string'
    OR (COALESCE(
      p_public_projection -> 'signature' ->> 'key_id',
      ''
    ) COLLATE "C") !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$'
    OR p_public_projection -> 'signature' ->> 'key_id' IN (
      'constructor',
      'prototype'
    )
    OR p_public_projection -> 'signature' ->> 'key_source' IS DISTINCT FROM
        'operator-commit-signing-key'
    OR pg_catalog.jsonb_typeof(
      p_public_projection -> 'signature' -> 'value'
    ) IS DISTINCT FROM 'string'
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

  v_source := public.read_agent_record_refusal_source(
    p_source_token,
    p_source_session_id,
    p_source_attempt_id
  );
  IF v_source ->> 'source_commitment' IS DISTINCT FROM p_source_commitment
    OR v_source ->> 'source_artifact_digest' IS DISTINCT FROM
      p_source_artifact_digest
    OR v_source ->> 'action_digest' IS DISTINCT FROM p_action_digest
    OR v_source ->> 'refusal_digest' IS DISTINCT FROM p_refusal_digest
    OR v_source ->> 'refused_at' IS DISTINCT FROM
      agent_record_private.iso_ms(p_refused_at)
    OR v_source -> 'refusal_artifact' ->> '@version' IS DISTINCT FROM
        'EP-ACTION-REFUSAL-STATEMENT-v1'
    OR v_source -> 'refusal_artifact' ->> 'action_digest' IS DISTINCT FROM
      p_action_digest
  THEN
    RAISE EXCEPTION 'private refusal source does not match agent record bindings'
      USING ERRCODE = '55000';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM agent_record_private.trial_bindings AS binding
    WHERE binding.source_session_id = p_source_session_id
      AND binding.source_token_hash =
        agent_record_private.token_hash(p_source_token)
      AND binding.adoption_id = p_adoption_id
      AND binding.bond_id = p_bond_id
      AND binding.bond_digest = p_bond_digest
      AND binding.source_expires_at > pg_catalog.clock_timestamp()
  ) THEN
    RAISE EXCEPTION 'Agent Record trial source is not bound to this adoption'
      USING ERRCODE = '55000';
  END IF;

  INSERT INTO agent_record_private.records (
    record_id,
    owner_token_hash,
    adoption_id,
    bond_id,
    bond_digest,
    source_commitment,
    source_artifact_digest,
    action_digest,
    refusal_digest,
    refused_at,
    observed_at,
    retention_expires_at,
    public_projection
  ) VALUES (
    p_record_id,
    agent_record_private.token_hash(p_owner_token),
    p_adoption_id,
    p_bond_id,
    p_bond_digest,
    p_source_commitment,
    p_source_artifact_digest,
    p_action_digest,
    p_refusal_digest,
    p_refused_at,
    p_observed_at,
    p_retention_expires_at,
    p_public_projection
  )
  ON CONFLICT (record_id) DO NOTHING
  RETURNING * INTO v_existing;

  IF NOT FOUND THEN
    SELECT record.*
    INTO v_existing
    FROM agent_record_private.records AS record
    WHERE record.record_id = p_record_id
      AND record.owner_token_hash = agent_record_private.token_hash(p_owner_token)
      AND record.adoption_id = p_adoption_id
      AND record.bond_id = p_bond_id
      AND record.bond_digest = p_bond_digest
      AND record.source_commitment = p_source_commitment
      AND record.source_artifact_digest = p_source_artifact_digest
      AND record.action_digest = p_action_digest
      AND record.refusal_digest = p_refusal_digest
      AND record.refused_at = p_refused_at;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'agent record identifier was already consumed'
        USING ERRCODE = '23505';
    END IF;
  END IF;

  RETURN pg_catalog.jsonb_build_object(
    'record_id', v_existing.record_id,
    'created_at', agent_record_private.iso_ms(v_existing.observed_at),
    'retention_expires_at', agent_record_private.iso_ms(v_existing.retention_expires_at),
    'public_projection', v_existing.public_projection
  );
END
$create_agent_record$;

-- PostgreSQL does not natively verify Ed25519. The application verifies the
-- exact public projection before crossing this boundary, and only that signing
-- path holds the independent creation capability. General service_role access
-- cannot execute the base creator and cannot configure or read the capability.
CREATE FUNCTION public.create_agent_record_with_capability(
  p_adoption_id UUID,
  p_adoption_session_token TEXT,
  p_record_id TEXT,
  p_owner_token TEXT,
  p_bond_id UUID,
  p_bond_digest TEXT,
  p_source_session_id TEXT,
  p_source_token TEXT,
  p_source_attempt_id TEXT,
  p_source_commitment TEXT,
  p_source_artifact_digest TEXT,
  p_action_digest TEXT,
  p_refusal_digest TEXT,
  p_refused_at TIMESTAMPTZ,
  p_observed_at TIMESTAMPTZ,
  p_retention_expires_at TIMESTAMPTZ,
  p_public_projection JSONB,
  p_creation_capability TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $create_agent_record_with_capability$
BEGIN
  IF NOT agent_record_private.creation_capability_matches(
    p_creation_capability
  ) THEN
    RAISE EXCEPTION 'Agent Record creation capability is unavailable'
      USING ERRCODE = '42501';
  END IF;

  RETURN public.create_agent_record(
    p_adoption_id,
    p_adoption_session_token,
    p_record_id,
    p_owner_token,
    p_bond_id,
    p_bond_digest,
    p_source_session_id,
    p_source_token,
    p_source_attempt_id,
    p_source_commitment,
    p_source_artifact_digest,
    p_action_digest,
    p_refusal_digest,
    p_refused_at,
    p_observed_at,
    p_retention_expires_at,
    p_public_projection
  );
END
$create_agent_record_with_capability$;

CREATE FUNCTION public.check_agent_record_creation_capability(
  p_creation_capability TEXT
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
SET statement_timeout = '2s'
AS $check_agent_record_creation_capability$
  SELECT agent_record_private.creation_capability_matches(
    p_creation_capability
  );
$check_agent_record_creation_capability$;

CREATE FUNCTION public.check_agent_record_storage_contract()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
SET statement_timeout = '2s'
AS $check_agent_record_storage_contract$
  SELECT
    (
      SELECT pg_catalog.count(*) = 4
      FROM pg_catalog.pg_class AS class
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid = class.relnamespace
      WHERE namespace.nspname = 'agent_record_private'
        AND class.relname = ANY(ARRAY[
          'records',
          'revocations',
          'creation_capability',
          'trial_bindings'
        ])
        AND class.relkind = 'r'
        AND class.relrowsecurity
        AND class.relforcerowsecurity
        AND pg_catalog.has_table_privilege(
          'agent_record_store_owner',
          class.oid,
          'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
        )
        AND NOT pg_catalog.has_table_privilege(
          'service_role',
          class.oid,
          'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
        )
    )
    AND (
      SELECT pg_catalog.count(*) = 4
      FROM pg_catalog.pg_policies AS policy
      WHERE policy.schemaname = 'agent_record_private'
        AND policy.tablename = ANY(ARRAY[
          'records',
          'revocations',
          'creation_capability',
          'trial_bindings'
        ])
        AND policy.roles = ARRAY['agent_record_store_owner']::name[]
        AND policy.cmd = 'ALL'
        AND policy.qual = 'true'
        AND policy.with_check = 'true'
    )
    AND (
      SELECT pg_catalog.count(*) = 2
      FROM pg_catalog.pg_policies AS policy
      WHERE policy.schemaname = 'public'
        AND policy.tablename = ANY(ARRAY['arena_sessions', 'arena_attempts'])
        AND policy.roles = ARRAY['agent_record_store_owner']::name[]
        AND policy.cmd = 'SELECT'
        AND policy.qual = 'true'
    )
    AND (
      SELECT pg_catalog.count(*) = 3
      FROM pg_catalog.pg_trigger AS trigger
      WHERE trigger.tgname = ANY(ARRAY[
          'agent_record_records_immutable_trigger',
          'agent_record_revocations_immutable_trigger',
          'agent_record_trial_bindings_immutable_trigger'
        ])
        AND NOT trigger.tgisinternal
        AND trigger.tgenabled = 'O'
    );
$check_agent_record_storage_contract$;

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
    OR p_record_id IS DISTINCT FROM
      agent_record_private.owner_record_id(p_owner_token)
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
REVOKE ALL ON FUNCTION agent_record_private.owner_record_id(TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION agent_record_private.configure_creation_capability(TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION agent_record_private.creation_capability_matches(TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION agent_record_private.iso_ms(TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION agent_record_private.reject_immutable_record_mutation()
  FROM PUBLIC, anon, authenticated, service_role;

REVOKE ALL ON FUNCTION public.configure_agent_record_creation_capability(TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
DO $grant_agent_record_configurator$
BEGIN
  EXECUTE pg_catalog.format(
    'GRANT EXECUTE ON FUNCTION public.configure_agent_record_creation_capability(TEXT) TO %I',
    pg_catalog.current_setting('ep.agent_record_migration_role')
  );
END
$grant_agent_record_configurator$;
REVOKE ALL ON FUNCTION public.create_agent_record(UUID, TEXT, TEXT, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, JSONB)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.bind_agent_record_trial_source(UUID, TEXT, UUID, TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.bind_agent_record_trial_source(UUID, TEXT, UUID, TEXT, TEXT, TEXT)
  TO service_role;
REVOKE ALL ON FUNCTION public.create_agent_record_with_capability(UUID, TEXT, TEXT, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, JSONB, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.create_agent_record_with_capability(UUID, TEXT, TEXT, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, JSONB, TEXT)
  TO service_role;
REVOKE ALL ON FUNCTION public.check_agent_record_creation_capability(TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.check_agent_record_creation_capability(TEXT)
  TO service_role;
REVOKE ALL ON FUNCTION public.check_agent_record_storage_contract()
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.check_agent_record_storage_contract()
  TO service_role;
REVOKE ALL ON FUNCTION public.revoke_agent_record(TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.revoke_agent_record(TEXT, TEXT, TEXT)
  TO service_role;
REVOKE ALL ON FUNCTION public.read_agent_record_public(TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.read_agent_record_public(TEXT)
  TO service_role;

COMMENT ON SCHEMA agent_record_private IS
  'RPC-only custody for minimal factual Agent Records and owner revocations.';
COMMENT ON TABLE agent_record_private.records IS
  'Immutable digest-only bindings for one operator-observed signed refusal; exact-id public projection expires after 365 days.';
COMMENT ON TABLE agent_record_private.revocations IS
  'Append-only terminal owner revocations; a revoked record is uniformly absent from public reads.';
COMMENT ON TABLE agent_record_private.creation_capability IS
  'Forced-RLS hash and configuring session role for the independent application-only capability that gates irreversible Agent Record creation.';
COMMENT ON TABLE agent_record_private.trial_bindings IS
  'Immutable private relation between one plaintext-authenticated Arena session and the active adoption bond that provisioned it.';
COMMENT ON FUNCTION public.bind_agent_record_trial_source(UUID, TEXT, UUID, TEXT, TEXT, TEXT) IS
  'Binds one active adoption bond to one Arena session after independently authenticating both bearer credentials; stores no plaintext credential.';
COMMENT ON FUNCTION public.configure_agent_record_creation_capability(TEXT) IS
  'Directly granted migration-operator provisioning path; stores only the capability hash and caller audit identity and returns no capability data.';
COMMENT ON FUNCTION public.create_agent_record_with_capability(UUID, TEXT, TEXT, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, JSONB, TEXT) IS
  'Capability-gated application entry point; the application must verify the Ed25519 projection before invoking it. SQL shape validation is not signature verification.';
COMMENT ON FUNCTION public.check_agent_record_creation_capability(TEXT) IS
  'Readiness probe that returns only whether the supplied application capability matches the forced-RLS configured hash.';
COMMENT ON FUNCTION public.check_agent_record_storage_contract() IS
  'Readiness probe for forced RLS, private ACLs, source-reader policies, and immutable-table triggers; returns no record data.';
COMMENT ON FUNCTION public.read_agent_record_public(TEXT) IS
  'Server-only exact opaque Agent Record lookup; the public HTTP route verifies the operator signature and unknown, expired, and revoked records all raise P0002.';

DO $restore_migration_role$
BEGIN
  EXECUTE pg_catalog.format(
    'SET ROLE %I',
    pg_catalog.current_setting('ep.agent_record_migration_role')
  );
END
$restore_migration_role$;
REVOKE CREATE ON SCHEMA public FROM agent_record_store_owner;
DO $drop_agent_record_bootstrap$
BEGIN
  EXECUTE 'SET ROLE agent_record_store_bootstrap';
  EXECUTE pg_catalog.format(
    'REVOKE agent_record_store_owner FROM %I GRANTED BY agent_record_store_bootstrap',
    pg_catalog.current_setting('ep.agent_record_migration_role')
  );
  EXECUTE pg_catalog.format(
    'SET ROLE %I',
    pg_catalog.current_setting('ep.agent_record_migration_role')
  );
  EXECUTE pg_catalog.format(
    'REVOKE agent_record_store_bootstrap FROM %I GRANTED BY %I',
    pg_catalog.current_setting('ep.agent_record_migration_role'),
    pg_catalog.current_setting('ep.agent_record_migration_role')
  );
  DROP ROLE agent_record_store_bootstrap;
END
$drop_agent_record_bootstrap$;
