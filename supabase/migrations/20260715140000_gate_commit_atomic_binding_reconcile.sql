-- Reconcile migration 134 into the timestamped production migration stream.
--
-- Some deployed environments were initialized from timestamped migrations and
-- therefore never recorded the local numeric migration. Keep this migration
-- idempotent so fresh environments can safely run both copies.

CREATE OR REPLACE FUNCTION public.consume_gate_ref_atomic(
  p_gate_ref TEXT,
  p_entity_id TEXT,
  p_action_type TEXT,
  p_binding_version TEXT,
  p_binding_hash TEXT
)
RETURNS SETOF public.consumed_gate_refs
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_commit public.commits;
  v_consumption public.consumed_gate_refs;
BEGIN
  IF p_gate_ref IS NULL OR p_entity_id IS NULL OR p_action_type IS NULL OR
     p_binding_version IS NULL OR p_binding_hash IS NULL THEN
    RAISE EXCEPTION 'GATE_ARGUMENT_MISSING' USING ERRCODE = 'P0001';
  END IF;

  SELECT * INTO v_commit
  FROM public.commits
  WHERE commit_id = p_gate_ref
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'GATE_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;

  -- Serialize use of commits under a kid with emergency revocation of that kid.
  PERFORM pg_advisory_xact_lock(hashtextextended('ep-commit-kid:' || v_commit.kid, 0));

  IF v_commit.entity_id IS DISTINCT FROM p_entity_id OR
     v_commit.action_type IS DISTINCT FROM p_action_type THEN
    RAISE EXCEPTION 'GATE_ACTION_MISMATCH' USING ERRCODE = 'P0003';
  END IF;

  IF v_commit.decision IS DISTINCT FROM 'allow' THEN
    RAISE EXCEPTION 'GATE_NOT_ALLOW' USING ERRCODE = 'P0004';
  END IF;

  IF v_commit.status IS DISTINCT FROM 'active' OR
     v_commit.expires_at IS NULL OR v_commit.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'GATE_NOT_ACTIVE' USING ERRCODE = 'P0005';
  END IF;

  IF EXISTS (SELECT 1 FROM public.revoked_commit_keys WHERE kid = v_commit.kid) THEN
    RAISE EXCEPTION 'GATE_SIGNING_KEY_REVOKED' USING ERRCODE = 'P0006';
  END IF;

  IF v_commit.scope->>'gate_binding_version' IS DISTINCT FROM p_binding_version OR
     v_commit.scope->>'gate_binding_hash' IS DISTINCT FROM p_binding_hash THEN
    RAISE EXCEPTION 'GATE_BINDING_MISMATCH' USING ERRCODE = 'P0007';
  END IF;

  INSERT INTO public.consumed_gate_refs (
    gate_ref,
    consumed_by_entity,
    consumed_for_action
  ) VALUES (
    p_gate_ref,
    p_entity_id,
    p_action_type
  )
  RETURNING * INTO v_consumption;

  RETURN NEXT v_consumption;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.consume_gate_ref_atomic(TEXT, TEXT, TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_gate_ref_atomic(TEXT, TEXT, TEXT, TEXT, TEXT)
  TO service_role;

COMMENT ON FUNCTION public.consume_gate_ref_atomic(TEXT, TEXT, TEXT, TEXT, TEXT) IS
  'Atomically locks, validates, and consumes one exact-action trust-gate allow commit. Refuses expiry, status changes, key revocation, binding substitution, and replay.';

CREATE OR REPLACE FUNCTION public.revoke_commit_key_atomic(
  p_kid TEXT,
  p_reason TEXT,
  p_revoked_by TEXT
)
RETURNS SETOF public.revoked_commit_keys
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_revocation public.revoked_commit_keys;
BEGIN
  IF p_kid IS NULL OR length(p_kid) = 0 OR p_revoked_by IS NULL OR length(p_revoked_by) = 0 THEN
    RAISE EXCEPTION 'COMMIT_KEY_REVOCATION_ARGUMENT_MISSING' USING ERRCODE = 'P0001';
  END IF;

  -- Same transaction-scoped lock as consume_gate_ref_atomic. Whichever
  -- operation obtains it first defines the linearization point.
  PERFORM pg_advisory_xact_lock(hashtextextended('ep-commit-kid:' || p_kid, 0));

  INSERT INTO public.revoked_commit_keys (kid, reason, revoked_by, revoked_at)
  VALUES (p_kid, p_reason, p_revoked_by, now())
  ON CONFLICT (kid) DO UPDATE
    SET reason = EXCLUDED.reason,
        revoked_by = EXCLUDED.revoked_by,
        revoked_at = LEAST(public.revoked_commit_keys.revoked_at, EXCLUDED.revoked_at)
  RETURNING * INTO v_revocation;

  RETURN NEXT v_revocation;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.revoke_commit_key_atomic(TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.revoke_commit_key_atomic(TEXT, TEXT, TEXT)
  TO service_role;

COMMENT ON FUNCTION public.revoke_commit_key_atomic(TEXT, TEXT, TEXT) IS
  'Records emergency commit-key revocation under the same advisory lock used by gate consumption, closing the revocation/use race.';
