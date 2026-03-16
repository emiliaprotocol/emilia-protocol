-- ⚠️ SUPERSEDED: The is_entity_established() function in this file has been
-- replaced by the quality-gated version in 020_quality_gated_establishment.sql.
-- This migration is preserved for historical reference and for the
-- compute_emilia_score() function which is also updated in migration 020.
-- Canonical establishment logic: supabase/migrations/020_quality_gated_establishment.sql
--
-- ============================================================================
-- EMILIA Protocol — Migration 016: Provenance Weight in SQL
-- ============================================================================
-- Aligns SQL scoring functions with JS four-factor weighting.
-- Before: submitter × time × graph
-- After:  submitter × time × graph × provenance
-- ============================================================================

CREATE OR REPLACE FUNCTION compute_emilia_score(p_entity_id uuid)
RETURNS float AS
$fn$
DECLARE
  receipt RECORD;
  total_weight float := 0;
  weighted_sum float := 0;
  effective_evidence float := 0;
  raw_score float := 50;
  final_score float;
  provenance_w float;
BEGIN
  FOR receipt IN
    SELECT composite_score, submitter_established, submitter_score,
           graph_weight, provenance_tier, created_at
    FROM receipts
    WHERE entity_id = p_entity_id
    ORDER BY created_at DESC
    LIMIT 200
  LOOP
    -- Four-factor weight: submitter × time × graph × provenance
    DECLARE
      submitter_w float;
      time_w float;
      graph_w float;
      prov_w float;
      age_days float;
      w float;
    BEGIN
      -- Submitter weight
      IF receipt.submitter_established THEN
        submitter_w := GREATEST(0.1, COALESCE(receipt.submitter_score, 50) / 100.0);
      ELSE
        submitter_w := 0.1;
      END IF;

      -- Time decay (90-day half-life)
      age_days := GREATEST(0, EXTRACT(EPOCH FROM (NOW() - receipt.created_at)) / 86400.0);
      time_w := GREATEST(0.05, POWER(0.5, age_days / 90.0));

      -- Graph weight
      graph_w := COALESCE(receipt.graph_weight, 1.0);

      -- Provenance weight
      prov_w := CASE COALESCE(receipt.provenance_tier, 'self_attested')
        WHEN 'self_attested' THEN 0.3
        WHEN 'identified_signed' THEN 0.5
        WHEN 'bilateral' THEN 0.8
        WHEN 'platform_originated' THEN 0.9
        WHEN 'carrier_verified' THEN 0.95
        WHEN 'oracle_verified' THEN 1.0
        ELSE 0.3
      END;

      w := submitter_w * time_w * graph_w * prov_w;
      effective_evidence := effective_evidence + w;

      IF receipt.composite_score IS NOT NULL THEN
        weighted_sum := weighted_sum + (receipt.composite_score * w);
        total_weight := total_weight + w;
      END IF;
    END;
  END LOOP;

  -- Compute raw score
  IF total_weight > 0 THEN
    raw_score := weighted_sum / total_weight;
  END IF;

  -- Effective evidence dampening
  IF effective_evidence < 5.0 THEN
    final_score := 50 + (raw_score - 50) * (effective_evidence / 5.0);
  ELSE
    final_score := raw_score;
  END IF;

  RETURN ROUND(final_score::numeric, 1);
END;
$fn$
LANGUAGE plpgsql;

-- Update is_entity_established to use four-factor evidence
CREATE OR REPLACE FUNCTION is_entity_established(p_entity_id uuid)
RETURNS TABLE(established boolean, unique_submitters bigint, effective_evidence float, total_receipts bigint) AS
$fn$
DECLARE
  eff_ev float := 0;
  receipt RECORD;
BEGIN
  FOR receipt IN
    SELECT submitter_established, submitter_score, graph_weight,
           provenance_tier, created_at
    FROM receipts
    WHERE entity_id = p_entity_id
  LOOP
    DECLARE
      submitter_w float;
      time_w float;
      graph_w float;
      prov_w float;
      age_days float;
    BEGIN
      IF receipt.submitter_established THEN
        submitter_w := GREATEST(0.1, COALESCE(receipt.submitter_score, 50) / 100.0);
      ELSE
        submitter_w := 0.1;
      END IF;

      age_days := GREATEST(0, EXTRACT(EPOCH FROM (NOW() - receipt.created_at)) / 86400.0);
      time_w := GREATEST(0.05, POWER(0.5, age_days / 90.0));
      graph_w := COALESCE(receipt.graph_weight, 1.0);

      prov_w := CASE COALESCE(receipt.provenance_tier, 'self_attested')
        WHEN 'self_attested' THEN 0.3
        WHEN 'identified_signed' THEN 0.5
        WHEN 'bilateral' THEN 0.8
        WHEN 'platform_originated' THEN 0.9
        WHEN 'carrier_verified' THEN 0.95
        WHEN 'oracle_verified' THEN 1.0
        ELSE 0.3
      END;

      eff_ev := eff_ev + (submitter_w * time_w * graph_w * prov_w);
    END;
  END LOOP;

  RETURN QUERY
    SELECT
      (eff_ev >= 5.0 AND (SELECT COUNT(DISTINCT submitted_by) FROM receipts WHERE entity_id = p_entity_id) >= 3) AS established,
      (SELECT COUNT(DISTINCT submitted_by) FROM receipts WHERE entity_id = p_entity_id) AS unique_submitters,
      eff_ev AS effective_evidence,
      (SELECT COUNT(*) FROM receipts WHERE entity_id = p_entity_id) AS total_receipts;
END;
$fn$
LANGUAGE plpgsql;
