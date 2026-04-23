-- 085_consume_atomic_mark_binding.sql
--
-- Audit-fix (HIGH): the JS consume.js path runs two operations across a
-- transaction boundary:
--   1. RPC consume_handshake_atomic (migration 080) — inserts handshake_consumptions
--   2. JS .update() on handshake_bindings.consumed_at
-- If #2 fails, #1 has already committed. consume.js throws BINDING_MARK_FAILED
-- but the two tables are now permanently divergent: handshake_consumptions has
-- the row, handshake_bindings.consumed_at is still NULL. The HARD GATE in
-- verify.js checks only the latter, so a racy verify can proceed even though
-- consumption has "succeeded."
--
-- Fix: move the UPDATE into the RPC. We already hold FOR UPDATE on the
-- handshake_bindings row (added in migration 080 line 63) so the mark is atomic
-- with the consumption insert. consume.js simply drops the follow-up call.

CREATE OR REPLACE FUNCTION consume_handshake_atomic(
  p_handshake_id   UUID,
  p_binding_hash   TEXT,
  p_consumed_by_type TEXT,
  p_consumed_by_id   TEXT,
  p_actor_entity_ref TEXT,
  p_consumed_by_action TEXT DEFAULT NULL
)
RETURNS SETOF handshake_consumptions
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_status TEXT;
  v_real_binding_hash TEXT;
  v_consumption handshake_consumptions;
BEGIN
  -- Lock the handshake row to prevent concurrent revocation between
  -- the status check and the consumption insert.
  SELECT status INTO v_status
  FROM handshakes
  WHERE handshake_id = p_handshake_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'HANDSHAKE_NOT_FOUND'
      USING ERRCODE = 'P0002',
            DETAIL  = 'handshake_id: ' || p_handshake_id::text;
  END IF;

  IF v_status != 'verified' THEN
    RAISE EXCEPTION 'INVALID_STATE_FOR_CONSUMPTION'
      USING ERRCODE = 'P0001',
            DETAIL  = 'current status: ' || v_status;
  END IF;

  -- Verify caller-supplied binding_hash against server truth, under FOR UPDATE.
  SELECT binding_hash INTO v_real_binding_hash
  FROM handshake_bindings
  WHERE handshake_id = p_handshake_id
  FOR UPDATE;

  IF v_real_binding_hash IS NULL THEN
    RAISE EXCEPTION 'BINDING_NOT_FOUND'
      USING ERRCODE = 'P0002',
            DETAIL  = 'handshake_id: ' || p_handshake_id::text;
  END IF;

  IF v_real_binding_hash IS DISTINCT FROM p_binding_hash THEN
    RAISE EXCEPTION 'BINDING_HASH_MISMATCH'
      USING ERRCODE = 'P0003',
            DETAIL  = format('expected server truth (length %s), got caller value (length %s)',
                             length(v_real_binding_hash),
                             length(coalesce(p_binding_hash, '')));
  END IF;

  -- Unique constraint on handshake_id prevents double-consumption.
  INSERT INTO handshake_consumptions (
    handshake_id,
    binding_hash,
    consumed_by_type,
    consumed_by_id,
    actor_entity_ref,
    consumed_by_action
  ) VALUES (
    p_handshake_id,
    v_real_binding_hash,
    p_consumed_by_type,
    p_consumed_by_id,
    p_actor_entity_ref,
    p_consumed_by_action
  )
  RETURNING * INTO v_consumption;

  -- Audit-fix (085): mark the binding inside the same transaction as the
  -- consumption insert. We already hold FOR UPDATE on this row above.
  -- Using consumed_at IS NULL guard in WHERE for idempotency safety (a
  -- migration-067-style concurrent row could already have it set; that's
  -- fine — the consumption row is the source of truth).
  UPDATE handshake_bindings
     SET consumed_at  = now(),
         consumed_by  = p_actor_entity_ref,
         consumed_for = p_consumed_by_type || ':' || p_consumed_by_id
   WHERE handshake_id = p_handshake_id
     AND consumed_at IS NULL;

  RETURN NEXT v_consumption;
END;
$$;

COMMENT ON FUNCTION consume_handshake_atomic IS
  'Atomically verify handshake status, binding_hash integrity, insert consumption '
  'record, AND mark handshake_bindings.consumed_at — all under one transaction '
  'with FOR UPDATE. Migration 085 pulled the binding-mark into the RPC so the '
  'consumption row and binding.consumed_at cannot diverge on JS-side failure.';
