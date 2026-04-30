-- Migration 090: Recalculate emilia_scores after migration 007 (renamed from 007b)
--
-- Originally authored as 007b_recalculate_scores.sql — the supabase CLI
-- rejected the `b` suffix so it was never tracked. The data fix was applied
-- on prod historically (via Studio SQL) so this is a no-op for prod;
-- renamed and idempotent so fresh deploys also get the recalc.
--
-- Re-running has no harmful effect: it just recomputes emilia_score from
-- the current entities/receipts state. compute_emilia_score() is a pure
-- function of those tables.
--
-- Guarded against the function not existing yet (e.g., if migration 007's
-- compute_emilia_score creation hadn't run on a fresh deploy).

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_proc WHERE proname = 'compute_emilia_score'
  ) THEN
    UPDATE entities SET
      emilia_score = compute_emilia_score(id),
      updated_at = NOW()
    WHERE status = 'active' AND total_receipts > 0;
  END IF;
END $$;
