-- ============================================================================
-- EMILIA Protocol — Signoff request race hardening
-- ============================================================================
--
-- The route's existing-event check is useful for a clear retry response, but
-- cannot serialize two requests that read the same receipt concurrently.
-- This index makes the insert authoritative:
--
--   * single-signoff events have no quorum approver and therefore share '';
--   * quorum fan-out keeps one row per distinct roster approver;
--   * a concurrent replay collides with either shape and raises SQLSTATE 23505.

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.audit_events
    WHERE event_type = 'guard.signoff.requested'
      AND target_type = 'trust_receipt'
    GROUP BY
      target_id,
      COALESCE(after_state #>> '{quorum,approver_id}', '')
    HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'signoff_request_duplicates_present'
      USING
        ERRCODE = '23505',
        HINT = 'Review and reconcile duplicate historical request evidence before retrying this migration.';
  END IF;
END;
$$;

CREATE UNIQUE INDEX IF NOT EXISTS guard_signoff_request_once
  ON public.audit_events (
    target_id,
    (COALESCE(after_state #>> '{quorum,approver_id}', ''))
  )
  WHERE event_type = 'guard.signoff.requested'
    AND target_type = 'trust_receipt';

COMMENT ON INDEX public.guard_signoff_request_once IS
  'Enforces one signoff-request operation per receipt while allowing one quorum '
  'fan-out row per distinct approver. Concurrent duplicates raise SQLSTATE 23505.';
