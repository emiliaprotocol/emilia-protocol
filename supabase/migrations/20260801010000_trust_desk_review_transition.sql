-- Trust Desk human review: atomic, named transition from awaiting_review.
-- Prevents concurrent approval/rejection requests from both acquiring the
-- same prepared engagement.

CREATE OR REPLACE FUNCTION public.compare_and_set_trust_desk_status_atomic(
  p_engagement_id TEXT,
  p_expected_status TEXT,
  p_new_status TEXT,
  p_extra JSONB DEFAULT '{}'::JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_row public.trust_desk_engagements%ROWTYPE;
  v_now TIMESTAMPTZ := clock_timestamp();
  v_history JSONB;
  v_next JSONB;
BEGIN
  IF p_extra IS NULL OR jsonb_typeof(p_extra) <> 'object' THEN
    RAISE EXCEPTION 'p_extra must be a JSON object' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO v_row
  FROM public.trust_desk_engagements
  WHERE engagement_id = p_engagement_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'not_found', 'record', NULL);
  END IF;

  -- The promoted status and full record must agree before a transition. A
  -- drifted row is never silently repaired at the authorization boundary.
  IF v_row.status IS DISTINCT FROM p_expected_status
     OR v_row.data->>'status' IS DISTINCT FROM p_expected_status THEN
    RETURN jsonb_build_object(
      'ok', false,
      'reason', 'status_mismatch',
      'record', v_row.data
    );
  END IF;

  v_history := COALESCE(v_row.data->'status_history', '[]'::JSONB)
    || jsonb_build_array(jsonb_build_object('status', p_new_status, 'at', v_now));
  v_next := v_row.data
    || p_extra
    || jsonb_build_object(
      'status', p_new_status,
      'status_history', v_history,
      'updated_at', v_now
    );

  UPDATE public.trust_desk_engagements
  SET status = p_new_status,
      slug = COALESCE(v_next->>'slug', slug),
      company = COALESCE(v_next#>>'{intake,company}', v_next->>'company', company),
      outcome = COALESCE(v_next->>'outcome', outcome),
      data = v_next
  WHERE engagement_id = p_engagement_id;

  RETURN jsonb_build_object('ok', true, 'reason', NULL, 'record', v_next);
END;
$$;

REVOKE ALL ON FUNCTION public.compare_and_set_trust_desk_status_atomic(TEXT, TEXT, TEXT, JSONB)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.compare_and_set_trust_desk_status_atomic(TEXT, TEXT, TEXT, JSONB)
  TO service_role;

COMMENT ON FUNCTION public.compare_and_set_trust_desk_status_atomic(TEXT, TEXT, TEXT, JSONB) IS
  'Atomically transitions one Trust Desk engagement from an exact expected status under a row lock.';
