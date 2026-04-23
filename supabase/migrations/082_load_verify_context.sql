-- 082_load_verify_context.sql
--
-- Audit-fix (H8): verify.js currently loads parties, presentations, and the
-- binding via three parallel Supabase queries. Under concurrent writes (a
-- late presentation arriving between reads, a binding being marked consumed,
-- a party verified_status flip), the three result sets can be mutually
-- inconsistent — e.g., the presentations set may lack a row for a party that
-- was just added, or include one for a binding that was just consumed.
-- Downstream reason_codes can then reflect a state that never actually
-- existed at any single moment.
--
-- Fix: a single read-only RPC that performs all three SELECTs inside one
-- default-isolation Postgres transaction. This gives a consistent snapshot
-- (default READ COMMITTED is sufficient for reads within a single transaction
-- with no intervening writes; for stronger guarantees set REPEATABLE READ).
-- The RPC also returns the handshakes row so the caller can drop a fourth
-- trip.
--
-- verify.js calls this RPC instead of three separate queries.

CREATE OR REPLACE FUNCTION load_verify_context(p_handshake_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_handshake JSONB;
  v_parties JSONB;
  v_presentations JSONB;
  v_binding JSONB;
BEGIN
  -- Inside a single implicit transaction, all four reads are consistent.
  SELECT to_jsonb(h) INTO v_handshake
  FROM handshakes h
  WHERE h.handshake_id = p_handshake_id;

  IF v_handshake IS NULL THEN
    RAISE EXCEPTION 'HANDSHAKE_NOT_FOUND'
      USING ERRCODE = 'P0002',
            DETAIL  = 'handshake_id: ' || p_handshake_id::text;
  END IF;

  SELECT coalesce(jsonb_agg(to_jsonb(p)), '[]'::JSONB) INTO v_parties
  FROM handshake_parties p
  WHERE p.handshake_id = p_handshake_id;

  SELECT coalesce(jsonb_agg(to_jsonb(pr)), '[]'::JSONB) INTO v_presentations
  FROM handshake_presentations pr
  WHERE pr.handshake_id = p_handshake_id;

  SELECT to_jsonb(b) INTO v_binding
  FROM handshake_bindings b
  WHERE b.handshake_id = p_handshake_id;

  RETURN jsonb_build_object(
    'handshake', v_handshake,
    'parties', v_parties,
    'presentations', v_presentations,
    'binding', v_binding
  );
END;
$$;

COMMENT ON FUNCTION load_verify_context IS
  'Atomic snapshot read of handshake + parties + presentations + binding. '
  'Replaces three parallel Supabase queries in verify.js to close the '
  'snapshot-consistency gap between reads. Raises P0002 HANDSHAKE_NOT_FOUND.';
