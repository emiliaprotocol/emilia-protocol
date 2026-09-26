-- SPDX-License-Identifier: Apache-2.0
-- Forward-only ACL repair for 20260803020000_agent_record_v1. The original
-- migration remains immutable.
--
-- 20260803020000 issued two privilege statements as the migration role on
-- functions owned by other roles:
--
--   1. REVOKE ALL / GRANT EXECUTE on public.read_agent_record_refusal_source,
--      immediately after transferring it to agent_record_store_owner; and
--   2. GRANT EXECUTE on public.read_agent_adoption_session, owned by
--      agent_adoption_store_owner, to agent_record_store_owner.
--
-- PostgreSQL performs a superuser's GRANT or REVOKE as the object owner. A
-- non-superuser that neither owns the object nor inherits its owner holds no
-- grant option on it, and because the migration role already held EXECUTE on
-- both functions (through PUBLIC or its inherited service_role membership),
-- PostgreSQL reduced every one of those statements to a WARNING instead of an
-- error. Supabase runs migrations as the non-superuser postgres role, so
-- production kept the default EXECUTE grants to PUBLIC, anon, and
-- authenticated on the refusal-source reader, and agent_record_store_owner
-- never received the EXECUTE on the adoption-session reader that
-- bind_agent_record_trial_source and create_agent_record call.
--
-- The adoption-session grant is repaired as its owner through the migration
-- role's existing ADMIN membership, the managed-role pattern the other private
-- stores already use.
--
-- The refusal-source reader cannot be repaired in place. 20260803020000
-- dropped its bootstrap role so that no role keeps ADMIN on
-- agent_record_store_owner, and therefore no non-superuser can act as that
-- owner. The migration role does own schema public (through
-- pg_database_owner), which lets it drop the function. It is recreated with a
-- byte-identical body under agent_record_source_reader, a dedicated NOLOGIN
-- role whose only authority is the Arena source read the function performs,
-- and its ACL is set while acting as that owner. Unlike
-- agent_record_store_owner, the migration role keeps ADMIN (without INHERIT or
-- SET) on the reader. That is the posture every other store owner has in
-- production, the reader can do nothing the migration role cannot already do,
-- and it lets a later forward migration correct this function without a
-- superuser. Every repaired privilege is asserted before the transaction
-- commits, so a silent no-op now fails the migration.

-- Supabase may execute with a managed migration role over a different wire
-- login. Remember the actual migration role so every restore and revoke below
-- addresses the same principal.
SELECT pg_catalog.set_config(
  'ep.agent_record_acl_repair_role',
  CURRENT_USER,
  TRUE
);

DO $preconditions$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS proc
    JOIN pg_catalog.pg_roles AS owner_role
      ON owner_role.oid = proc.proowner
    WHERE proc.oid = pg_catalog.to_regprocedure(
        'public.read_agent_record_refusal_source(text,text,text)'
      )
      AND owner_role.rolname = 'agent_record_store_owner'
      AND proc.prosecdef
      AND pg_catalog.md5(proc.prosrc) = '12d5b8bdfbe8d29b3c6edafbc27d7b32'
  ) THEN
    RAISE EXCEPTION
      'read_agent_record_refusal_source is not the 20260803020000 definition'
      USING ERRCODE = '55000';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS proc
    JOIN pg_catalog.pg_roles AS owner_role
      ON owner_role.oid = proc.proowner
    WHERE proc.oid = pg_catalog.to_regprocedure(
        'public.read_agent_adoption_session(uuid,text)'
      )
      AND owner_role.rolname = 'agent_adoption_store_owner'
  ) THEN
    RAISE EXCEPTION
      'read_agent_adoption_session is not owned by agent_adoption_store_owner'
      USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles
    WHERE rolname = 'agent_record_source_reader'
  ) THEN
    RAISE EXCEPTION 'agent record source reader already exists before migration'
      USING ERRCODE = '55000';
  END IF;
END
$preconditions$;

-- 1. The Agent Record owner calls the adoption-session reader from its
-- definer functions. Grant that EXECUTE as the adoption owner.
GRANT agent_adoption_store_owner TO CURRENT_USER
  WITH INHERIT FALSE, SET TRUE;
SET ROLE agent_adoption_store_owner;
GRANT EXECUTE ON FUNCTION public.read_agent_adoption_session(UUID, TEXT)
  TO agent_record_store_owner;
DO $restore_after_adoption_grant$
BEGIN
  EXECUTE pg_catalog.format(
    'SET ROLE %I',
    pg_catalog.current_setting('ep.agent_record_acl_repair_role')
  );
END
$restore_after_adoption_grant$;
REVOKE agent_adoption_store_owner FROM CURRENT_USER;

-- 2. Replace the refusal-source reader under an owner the migration role can
-- act as.
CREATE ROLE agent_record_source_reader NOLOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

GRANT USAGE ON SCHEMA extensions TO agent_record_source_reader;
GRANT EXECUTE ON FUNCTION extensions.digest(BYTEA, TEXT)
  TO agent_record_source_reader;
GRANT SELECT ON TABLE public.arena_sessions, public.arena_attempts
  TO agent_record_source_reader;
CREATE POLICY agent_record_source_reader_sessions
  ON public.arena_sessions
  FOR SELECT
  TO agent_record_source_reader
  USING (TRUE);
CREATE POLICY agent_record_source_reader_attempts
  ON public.arena_attempts
  FOR SELECT
  TO agent_record_source_reader
  USING (TRUE);
GRANT CREATE ON SCHEMA public TO agent_record_source_reader;

DROP FUNCTION public.read_agent_record_refusal_source(TEXT, TEXT, TEXT);

GRANT agent_record_source_reader TO CURRENT_USER
  WITH INHERIT FALSE, SET TRUE;
SET ROLE agent_record_source_reader;

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

REVOKE ALL ON FUNCTION public.read_agent_record_refusal_source(TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role, agent_record_source_reader;
GRANT EXECUTE ON FUNCTION public.read_agent_record_refusal_source(TEXT, TEXT, TEXT)
  TO service_role, agent_record_store_owner;
COMMENT ON FUNCTION public.read_agent_record_refusal_source(TEXT, TEXT, TEXT) IS
  'Server-only Arena refusal source for Agent Record creation; owned by the NOLOGIN agent_record_source_reader and executable only by service_role and agent_record_store_owner.';

DO $restore_after_source_reader$
BEGIN
  EXECUTE pg_catalog.format(
    'SET ROLE %I',
    pg_catalog.current_setting('ep.agent_record_acl_repair_role')
  );
END
$restore_after_source_reader$;
REVOKE agent_record_source_reader FROM CURRENT_USER;
REVOKE CREATE ON SCHEMA public FROM agent_record_source_reader;

DO $assert_repaired_privileges$
DECLARE
  v_source OID := pg_catalog.to_regprocedure(
    'public.read_agent_record_refusal_source(text,text,text)'
  );
  v_adoption OID := pg_catalog.to_regprocedure(
    'public.read_agent_adoption_session(uuid,text)'
  );
  v_source_acl TEXT[];
BEGIN
  IF v_source IS NULL OR NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS proc
    JOIN pg_catalog.pg_roles AS owner_role
      ON owner_role.oid = proc.proowner
    WHERE proc.oid = v_source
      AND owner_role.rolname = 'agent_record_source_reader'
      AND proc.prosecdef
      AND proc.provolatile = 's'
      AND proc.proconfig = ARRAY['search_path=""', 'row_security=on']
      AND pg_catalog.md5(proc.prosrc) = '12d5b8bdfbe8d29b3c6edafbc27d7b32'
  ) THEN
    RAISE EXCEPTION 'read_agent_record_refusal_source was not recreated exactly'
      USING ERRCODE = '55000';
  END IF;

  SELECT pg_catalog.array_agg(entry ORDER BY entry)
  INTO v_source_acl
  FROM (
    SELECT pg_catalog.format(
      '%s=%s%s',
      CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE grantee_role.rolname END,
      acl.privilege_type,
      CASE WHEN acl.is_grantable THEN '*' ELSE '' END
    ) AS entry
    FROM pg_catalog.pg_proc AS proc
    CROSS JOIN LATERAL pg_catalog.aclexplode(proc.proacl) AS acl
    LEFT JOIN pg_catalog.pg_roles AS grantee_role
      ON grantee_role.oid = acl.grantee
    WHERE proc.oid = v_source
  ) AS entries;
  IF v_source_acl IS DISTINCT FROM ARRAY[
    'agent_record_store_owner=EXECUTE',
    'service_role=EXECUTE'
  ] THEN
    RAISE EXCEPTION 'read_agent_record_refusal_source ACL is %', v_source_acl
      USING ERRCODE = '42501';
  END IF;

  IF pg_catalog.has_function_privilege('anon', v_source, 'EXECUTE')
    OR pg_catalog.has_function_privilege('authenticated', v_source, 'EXECUTE')
    OR NOT pg_catalog.has_function_privilege('service_role', v_source, 'EXECUTE')
    OR NOT pg_catalog.has_function_privilege(
      'agent_record_store_owner', v_source, 'EXECUTE'
    )
    OR NOT pg_catalog.has_function_privilege(
      'agent_record_store_owner', v_adoption, 'EXECUTE'
    )
    OR pg_catalog.has_function_privilege('anon', v_adoption, 'EXECUTE')
    OR pg_catalog.has_function_privilege('authenticated', v_adoption, 'EXECUTE')
  THEN
    RAISE EXCEPTION 'Agent Record reader EXECUTE privileges are not exact'
      USING ERRCODE = '42501';
  END IF;

  IF NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_roles AS role
      WHERE role.rolname = 'agent_record_source_reader'
        AND NOT role.rolcanlogin
        AND NOT role.rolsuper
        AND NOT role.rolcreatedb
        AND NOT role.rolcreaterole
        AND NOT role.rolreplication
        AND NOT role.rolbypassrls
    )
    OR NOT pg_catalog.has_table_privilege(
      'agent_record_source_reader', 'public.arena_sessions', 'SELECT'
    )
    OR NOT pg_catalog.has_table_privilege(
      'agent_record_source_reader', 'public.arena_attempts', 'SELECT'
    )
    OR pg_catalog.has_schema_privilege(
      'agent_record_source_reader', 'public', 'CREATE'
    )
    OR NOT pg_catalog.has_function_privilege(
      'agent_record_source_reader', 'extensions.digest(bytea,text)', 'EXECUTE'
    )
    -- The reader is a member of nothing, and nobody can SET ROLE to it or
    -- inherit its privileges.
    OR EXISTS (
      SELECT 1
      FROM pg_catalog.pg_auth_members AS membership
      JOIN pg_catalog.pg_roles AS reader
        ON reader.oid IN (membership.roleid, membership.member)
      WHERE reader.rolname = 'agent_record_source_reader'
        AND (
          membership.member = reader.oid
          OR membership.inherit_option
          OR membership.set_option
        )
    )
    -- The temporary SET edge on the adoption owner is gone again.
    OR EXISTS (
      SELECT 1
      FROM pg_catalog.pg_auth_members AS membership
      JOIN pg_catalog.pg_roles AS owner_role
        ON owner_role.oid = membership.roleid
      WHERE owner_role.rolname = 'agent_adoption_store_owner'
        AND (membership.inherit_option OR membership.set_option)
    )
  THEN
    RAISE EXCEPTION 'agent record source reader posture is not least privilege'
      USING ERRCODE = '42501';
  END IF;
END
$assert_repaired_privileges$;
