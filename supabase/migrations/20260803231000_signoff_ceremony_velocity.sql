-- Atomic per-approver Class-A approval velocity control.

CREATE TABLE IF NOT EXISTS public.signoff_approval_velocity (
  organization_id TEXT NOT NULL,
  approver_id TEXT NOT NULL,
  window_started_at TIMESTAMPTZ NOT NULL,
  approval_count INTEGER NOT NULL CHECK (approval_count > 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
  PRIMARY KEY (organization_id, approver_id, window_started_at)
);

REVOKE ALL ON public.signoff_approval_velocity FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.signoff_approval_velocity TO service_role;

CREATE OR REPLACE FUNCTION public.consume_signoff_approval_velocity(
  p_organization_id TEXT,
  p_approver_id TEXT,
  p_max_approvals INTEGER,
  p_window_seconds INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_now TIMESTAMPTZ := pg_catalog.now();
  v_window TIMESTAMPTZ;
  v_count INTEGER;
BEGIN
  IF p_organization_id IS NULL OR octet_length(p_organization_id) NOT BETWEEN 1 AND 512
     OR p_approver_id IS NULL OR octet_length(p_approver_id) NOT BETWEEN 1 AND 512
     OR p_max_approvals NOT BETWEEN 1 AND 100
     OR p_window_seconds <> 3600
  THEN
    RAISE EXCEPTION 'signoff_velocity_input_invalid' USING ERRCODE = '22023';
  END IF;

  v_window := pg_catalog.date_trunc('hour', v_now);
  INSERT INTO public.signoff_approval_velocity (
    organization_id, approver_id, window_started_at, approval_count, updated_at
  ) VALUES (
    p_organization_id, p_approver_id, v_window, 1, v_now
  )
  ON CONFLICT (organization_id, approver_id, window_started_at)
  DO UPDATE SET
    approval_count = public.signoff_approval_velocity.approval_count + 1,
    updated_at = v_now
  WHERE public.signoff_approval_velocity.approval_count < p_max_approvals
  RETURNING approval_count INTO v_count;

  IF v_count IS NULL THEN
    RETURN pg_catalog.jsonb_build_object(
      'ok', false,
      'reason', 'approval_velocity_exceeded',
      'window_started_at', v_window,
      'retry_at', v_window + pg_catalog.make_interval(secs => p_window_seconds)
    );
  END IF;

  RETURN pg_catalog.jsonb_build_object(
    'ok', true,
    'approval_count', v_count,
    'max_approvals', p_max_approvals,
    'window_started_at', v_window
  );
END;
$$;

REVOKE ALL ON FUNCTION public.consume_signoff_approval_velocity(TEXT, TEXT, INTEGER, INTEGER)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_signoff_approval_velocity(TEXT, TEXT, INTEGER, INTEGER)
  TO service_role;
