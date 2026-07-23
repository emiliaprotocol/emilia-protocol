-- SPDX-License-Identifier: Apache-2.0
-- Durable, relying-party-held EP-STATUS-v1 heads.
--
-- A candidate status is verified in the Gate process against the predecessor
-- returned by get_status_head(). Cryptographic verification happens outside a
-- database transaction. The compare-and-advance function then locks and
-- repeats the exact predecessor comparison atomically, so presenter fields
-- cannot substitute for the relying party's accepted head.

CREATE TABLE public.ep_aeb_status_heads (
  tenant_id                  TEXT NOT NULL
    CHECK (octet_length(tenant_id) BETWEEN 1 AND 512),
  relying_party_id           TEXT NOT NULL
    CHECK (octet_length(relying_party_id) BETWEEN 1 AND 512),
  target_type                TEXT NOT NULL
    CHECK (target_type IN ('receipt', 'commit', 'delegation')),
  target_id                  TEXT NOT NULL
    CHECK (octet_length(target_id) BETWEEN 1 AND 512),
  target_digest              TEXT NOT NULL
    CHECK (target_digest ~ '^sha256:[0-9a-f]{64}$'),
  target_usage               TEXT NOT NULL
    CHECK (target_usage IN ('authorization', 'execution', 'delegation')),
  status_digest              TEXT NOT NULL
    CHECK (status_digest ~ '^sha256:[0-9a-f]{64}$'),
  sequence                   BIGINT NOT NULL CHECK (sequence >= 0),
  status_state               TEXT NOT NULL CHECK (status_state IN ('not_revoked', 'revoked')),
  previous_status_digest     TEXT NULL
    CHECK (previous_status_digest IS NULL
      OR previous_status_digest ~ '^sha256:[0-9a-f]{64}$'),
  issued_at                  TIMESTAMPTZ NOT NULL,
  next_update                TIMESTAMPTZ NULL,
  status_json                TEXT NOT NULL
    CHECK (octet_length(status_json) BETWEEN 2 AND 1048576),
  predecessor_status_json    TEXT NULL
    CHECK (predecessor_status_json IS NULL
      OR octet_length(predecessor_status_json) BETWEEN 2 AND 1048576),
  accepted_at                TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (
    tenant_id,
    relying_party_id,
    target_type,
    target_id,
    target_digest,
    target_usage
  ),
  CHECK (
    (sequence = 0
      AND previous_status_digest IS NULL
      AND predecessor_status_json IS NULL)
    OR
    (sequence > 0
      AND previous_status_digest IS NOT NULL
      AND predecessor_status_json IS NOT NULL)
  ),
  CHECK (
    (status_state = 'not_revoked' AND next_update IS NOT NULL AND next_update > issued_at)
    OR
    (status_state = 'revoked' AND next_update IS NULL)
  )
);

GRANT ep_aeb_store_owner TO CURRENT_USER;

ALTER TABLE public.ep_aeb_status_heads OWNER TO ep_aeb_store_owner;
ALTER TABLE public.ep_aeb_status_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ep_aeb_status_heads FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS ep_aeb_status_heads_owner_only ON public.ep_aeb_status_heads;
CREATE POLICY ep_aeb_status_heads_owner_only ON public.ep_aeb_status_heads
  TO ep_aeb_store_owner USING (TRUE) WITH CHECK (TRUE);

REVOKE ALL ON public.ep_aeb_status_heads
  FROM PUBLIC, anon, authenticated, service_role, ep_aeb_executor, ep_aeb_recovery;

CREATE OR REPLACE FUNCTION ep_aeb_private.status_head_scope_lock(
  p_tenant_id TEXT,
  p_relying_party_id TEXT,
  p_target_type TEXT,
  p_target_id TEXT,
  p_target_digest TEXT,
  p_target_usage TEXT
)
RETURNS VOID
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(
      p_tenant_id || E'\x1f'
      || p_relying_party_id || E'\x1f'
      || p_target_type || E'\x1f'
      || p_target_id || E'\x1f'
      || p_target_digest || E'\x1f'
      || p_target_usage,
      0
    )
  );
END
$fn$;

CREATE OR REPLACE FUNCTION ep_aeb_private.get_status_head(
  p_tenant_id TEXT,
  p_relying_party_id TEXT,
  p_target_type TEXT,
  p_target_id TEXT,
  p_target_digest TEXT,
  p_target_usage TEXT
)
RETURNS TABLE(
  status_digest TEXT,
  sequence BIGINT,
  status_state TEXT,
  previous_status_digest TEXT,
  issued_at TEXT,
  next_update TEXT,
  status_json TEXT,
  predecessor_status_json TEXT
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);
  RETURN QUERY
    SELECT
      current_head.status_digest,
      current_head.sequence,
      current_head.status_state,
      current_head.previous_status_digest,
      pg_catalog.to_char(
        current_head.issued_at AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
      ),
      CASE WHEN current_head.next_update IS NULL THEN NULL
        ELSE pg_catalog.to_char(
          current_head.next_update AT TIME ZONE 'UTC',
          'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
        )
      END,
      current_head.status_json,
      current_head.predecessor_status_json
    FROM public.ep_aeb_status_heads AS current_head
    WHERE current_head.tenant_id = p_tenant_id
      AND current_head.relying_party_id = p_relying_party_id
      AND current_head.target_type = p_target_type
      AND current_head.target_id = p_target_id
      AND current_head.target_digest = p_target_digest
      AND current_head.target_usage = p_target_usage
    ;
END
$fn$;

CREATE OR REPLACE FUNCTION ep_aeb_private.compare_and_advance_status_head(
  p_tenant_id TEXT,
  p_relying_party_id TEXT,
  p_target_type TEXT,
  p_target_id TEXT,
  p_target_digest TEXT,
  p_target_usage TEXT,
  p_expected_status_digest TEXT,
  p_status_digest TEXT,
  p_sequence BIGINT,
  p_status_state TEXT,
  p_previous_status_digest TEXT,
  p_issued_at TIMESTAMPTZ,
  p_next_update TIMESTAMPTZ,
  p_status_json TEXT
)
RETURNS TABLE(accepted BOOLEAN, reason TEXT)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  current_head public.ep_aeb_status_heads%ROWTYPE;
  affected_rows BIGINT;
BEGIN
  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);
  PERFORM ep_aeb_private.status_head_scope_lock(
    p_tenant_id,
    p_relying_party_id,
    p_target_type,
    p_target_id,
    p_target_digest,
    p_target_usage
  );

  SELECT *
  INTO current_head
  FROM public.ep_aeb_status_heads AS stored
  WHERE stored.tenant_id = p_tenant_id
    AND stored.relying_party_id = p_relying_party_id
    AND stored.target_type = p_target_type
    AND stored.target_id = p_target_id
    AND stored.target_digest = p_target_digest
    AND stored.target_usage = p_target_usage
  FOR UPDATE;

  IF NOT FOUND THEN
    IF p_expected_status_digest IS NOT NULL
       OR p_sequence <> 0
       OR p_previous_status_digest IS NOT NULL THEN
      RETURN QUERY SELECT FALSE, 'head_conflict'::TEXT;
      RETURN;
    END IF;

    INSERT INTO public.ep_aeb_status_heads (
      tenant_id,
      relying_party_id,
      target_type,
      target_id,
      target_digest,
      target_usage,
      status_digest,
      sequence,
      status_state,
      previous_status_digest,
      issued_at,
      next_update,
      status_json,
      predecessor_status_json
    ) VALUES (
      p_tenant_id,
      p_relying_party_id,
      p_target_type,
      p_target_id,
      p_target_digest,
      p_target_usage,
      p_status_digest,
      p_sequence,
      p_status_state,
      p_previous_status_digest,
      p_issued_at,
      p_next_update,
      p_status_json,
      NULL
    )
    ON CONFLICT ON CONSTRAINT ep_aeb_status_heads_pkey DO NOTHING;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    IF affected_rows <> 1 THEN
      RETURN QUERY SELECT FALSE, 'head_conflict'::TEXT;
      RETURN;
    END IF;
    RETURN QUERY SELECT TRUE, NULL::TEXT;
    RETURN;
  END IF;

  IF current_head.status_digest = p_status_digest THEN
    IF p_expected_status_digest IS NOT DISTINCT FROM current_head.status_digest
       AND current_head.sequence = p_sequence
       AND current_head.status_state = p_status_state
       AND current_head.previous_status_digest IS NOT DISTINCT FROM p_previous_status_digest
       AND current_head.issued_at = p_issued_at
       AND current_head.next_update IS NOT DISTINCT FROM p_next_update
       AND current_head.status_json = p_status_json THEN
      RETURN QUERY SELECT TRUE, NULL::TEXT;
    ELSE
      RETURN QUERY SELECT FALSE, 'digest_reuse_conflict'::TEXT;
    END IF;
    RETURN;
  END IF;

  IF current_head.status_digest IS DISTINCT FROM p_expected_status_digest
     OR current_head.status_state = 'revoked'
     OR p_sequence <> current_head.sequence + 1
     OR p_previous_status_digest IS DISTINCT FROM current_head.status_digest
     OR p_issued_at <= current_head.issued_at THEN
    RETURN QUERY SELECT FALSE, 'head_conflict'::TEXT;
    RETURN;
  END IF;

  UPDATE public.ep_aeb_status_heads AS advancing
  SET
    status_digest = p_status_digest,
    sequence = p_sequence,
    status_state = p_status_state,
    previous_status_digest = p_previous_status_digest,
    issued_at = p_issued_at,
    next_update = p_next_update,
    status_json = p_status_json,
    predecessor_status_json = current_head.status_json,
    accepted_at = pg_catalog.transaction_timestamp()
  WHERE advancing.tenant_id = p_tenant_id
    AND advancing.relying_party_id = p_relying_party_id
    AND advancing.target_type = p_target_type
    AND advancing.target_id = p_target_id
    AND advancing.target_digest = p_target_digest
    AND advancing.target_usage = p_target_usage
    AND advancing.status_digest = p_expected_status_digest;
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RETURN QUERY SELECT FALSE, 'head_conflict'::TEXT;
    RETURN;
  END IF;
  RETURN QUERY SELECT TRUE, NULL::TEXT;
END
$fn$;

CREATE OR REPLACE FUNCTION ep_aeb_private.status_head_update_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'AEB_STATUS_HEAD_DELETE_REFUSED' USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
     OR OLD.relying_party_id IS DISTINCT FROM NEW.relying_party_id
     OR OLD.target_type IS DISTINCT FROM NEW.target_type
     OR OLD.target_id IS DISTINCT FROM NEW.target_id
     OR OLD.target_digest IS DISTINCT FROM NEW.target_digest
     OR OLD.target_usage IS DISTINCT FROM NEW.target_usage THEN
    RAISE EXCEPTION 'AEB_STATUS_HEAD_SCOPE_IMMUTABLE' USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.status_state = 'revoked'
     OR NEW.sequence <> OLD.sequence + 1
     OR NEW.previous_status_digest IS DISTINCT FROM OLD.status_digest
     OR NEW.predecessor_status_json IS DISTINCT FROM OLD.status_json
     OR NEW.issued_at <= OLD.issued_at THEN
    RAISE EXCEPTION 'AEB_STATUS_HEAD_ADVANCE_REFUSED' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER ep_aeb_status_heads_update_guard
BEFORE UPDATE OR DELETE ON public.ep_aeb_status_heads
FOR EACH ROW EXECUTE FUNCTION ep_aeb_private.status_head_update_guard();

ALTER FUNCTION ep_aeb_private.status_head_scope_lock(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT)
  OWNER TO ep_aeb_store_owner;
ALTER FUNCTION ep_aeb_private.get_status_head(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT)
  OWNER TO ep_aeb_store_owner;
ALTER FUNCTION ep_aeb_private.compare_and_advance_status_head(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT,
  TIMESTAMPTZ, TIMESTAMPTZ, TEXT
) OWNER TO ep_aeb_store_owner;
ALTER FUNCTION ep_aeb_private.status_head_update_guard()
  OWNER TO ep_aeb_store_owner;

REVOKE ALL ON FUNCTION ep_aeb_private.status_head_scope_lock(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) FROM PUBLIC, anon, authenticated, service_role, ep_aeb_executor, ep_aeb_recovery;
REVOKE ALL ON FUNCTION ep_aeb_private.get_status_head(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) FROM PUBLIC, anon, authenticated, service_role, ep_aeb_executor, ep_aeb_recovery;
REVOKE ALL ON FUNCTION ep_aeb_private.compare_and_advance_status_head(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT,
  TIMESTAMPTZ, TIMESTAMPTZ, TEXT
) FROM PUBLIC, anon, authenticated, service_role, ep_aeb_executor, ep_aeb_recovery;
REVOKE ALL ON FUNCTION ep_aeb_private.status_head_update_guard()
  FROM PUBLIC, anon, authenticated, service_role, ep_aeb_executor, ep_aeb_recovery;

GRANT USAGE ON SCHEMA ep_aeb_private TO ep_aeb_executor;
GRANT EXECUTE ON FUNCTION ep_aeb_private.get_status_head(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
), ep_aeb_private.compare_and_advance_status_head(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT,
  TIMESTAMPTZ, TIMESTAMPTZ, TEXT
) TO ep_aeb_executor;

COMMENT ON TABLE public.ep_aeb_status_heads IS
  'Relying-party-held accepted EP-STATUS-v1 heads, scoped by tenant, relying party, and exact target; RPC-only.';
COMMENT ON FUNCTION ep_aeb_private.get_status_head(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) IS
  'Return the authenticated accepted status predecessor for one exact scope.';
COMMENT ON FUNCTION ep_aeb_private.compare_and_advance_status_head(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT,
  TIMESTAMPTZ, TIMESTAMPTZ, TEXT
) IS
  'Atomically compare and advance an accepted status head after Gate-side cryptographic verification.';

REVOKE ep_aeb_store_owner FROM CURRENT_USER;
