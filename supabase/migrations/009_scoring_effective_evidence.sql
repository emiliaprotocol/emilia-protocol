-- ============================================================================
-- EMILIA Protocol — Migration 009: Scoring with Effective Evidence + Graph Weight
-- Run AFTER migration 008
-- ============================================================================
-- Key fixes:
--   1. Dampening uses effective_count (sum of weights), not raw count
--   2. graph_weight column stored per receipt, used in scoring
-- ============================================================================

-- Add graph_weight column (fraud graph analysis result per receipt)
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS graph_weight FLOAT DEFAULT 1.0;

CREATE OR REPLACE FUNCTION compute_emilia_score(p_entity_id uuid)
RETURNS float AS
$body$
DECLARE
  v_score float;
  v_count integer;
  v_effective_count float;
  v_total_weight float;
  v_delivery_sum float;
  v_product_sum float;
  v_price_sum float;
  v_returns_sum float;
  v_satisfaction_sum float;
  v_delivery_weight float;
  v_product_weight float;
  v_price_weight float;
  v_returns_weight float;
  v_satisfaction_weight float;
  v_consistency float;
  v_composite_var float;
  r RECORD;
  v_receipt_weight float;
  v_submitter_weight float;
  v_time_weight float;
  v_age_days float;
BEGIN
  v_count := 0;
  v_effective_count := 0;
  v_delivery_sum := 0;
  v_delivery_weight := 0;
  v_product_sum := 0;
  v_product_weight := 0;
  v_price_sum := 0;
  v_price_weight := 0;
  v_returns_sum := 0;
  v_returns_weight := 0;
  v_satisfaction_sum := 0;
  v_satisfaction_weight := 0;

  FOR r IN
    SELECT delivery_accuracy, product_accuracy, price_integrity,
           return_processing, agent_satisfaction, composite_score,
           submitter_score, submitter_established, graph_weight, created_at
    FROM receipts
    WHERE entity_id = p_entity_id
    ORDER BY created_at DESC
    LIMIT 200
  LOOP
    v_count := v_count + 1;

    IF r.submitter_established = TRUE THEN
      v_submitter_weight := GREATEST(0.1, LEAST(1.0, COALESCE(r.submitter_score, 50) / 100.0));
    ELSE
      v_submitter_weight := 0.1;
    END IF;

    v_age_days := GREATEST(0, EXTRACT(EPOCH FROM (NOW() - r.created_at)) / 86400.0);
    v_time_weight := GREATEST(0.05, POWER(0.5, v_age_days / 90.0));

    -- Three-factor weight: submitter credibility × time decay × graph health
    v_receipt_weight := v_submitter_weight * v_time_weight * COALESCE(r.graph_weight, 1.0);
    v_effective_count := v_effective_count + v_receipt_weight;

    IF r.delivery_accuracy IS NOT NULL THEN
      v_delivery_sum := v_delivery_sum + r.delivery_accuracy * v_receipt_weight;
      v_delivery_weight := v_delivery_weight + v_receipt_weight;
    END IF;
    IF r.product_accuracy IS NOT NULL THEN
      v_product_sum := v_product_sum + r.product_accuracy * v_receipt_weight;
      v_product_weight := v_product_weight + v_receipt_weight;
    END IF;
    IF r.price_integrity IS NOT NULL THEN
      v_price_sum := v_price_sum + r.price_integrity * v_receipt_weight;
      v_price_weight := v_price_weight + v_receipt_weight;
    END IF;
    IF r.return_processing IS NOT NULL THEN
      v_returns_sum := v_returns_sum + r.return_processing * v_receipt_weight;
      v_returns_weight := v_returns_weight + v_receipt_weight;
    END IF;
    IF r.agent_satisfaction IS NOT NULL THEN
      v_satisfaction_sum := v_satisfaction_sum + r.agent_satisfaction * v_receipt_weight;
      v_satisfaction_weight := v_satisfaction_weight + v_receipt_weight;
    END IF;
  END LOOP;

  IF v_count = 0 THEN
    RETURN 50.0;
  END IF;

  v_score := 0;
  v_total_weight := 0;

  IF v_delivery_weight > 0 THEN
    v_score := v_score + (v_delivery_sum / v_delivery_weight) * 0.30;
    v_total_weight := v_total_weight + 0.30;
  END IF;
  IF v_product_weight > 0 THEN
    v_score := v_score + (v_product_sum / v_product_weight) * 0.25;
    v_total_weight := v_total_weight + 0.25;
  END IF;
  IF v_price_weight > 0 THEN
    v_score := v_score + (v_price_sum / v_price_weight) * 0.15;
    v_total_weight := v_total_weight + 0.15;
  END IF;
  IF v_returns_weight > 0 THEN
    v_score := v_score + (v_returns_sum / v_returns_weight) * 0.15;
    v_total_weight := v_total_weight + 0.15;
  END IF;
  IF v_satisfaction_weight > 0 THEN
    v_score := v_score + (v_satisfaction_sum / v_satisfaction_weight) * 0.10;
    v_total_weight := v_total_weight + 0.10;
  END IF;

  SELECT COALESCE(STDDEV(composite_score), 0)
  INTO v_composite_var
  FROM (
    SELECT composite_score FROM receipts
    WHERE entity_id = p_entity_id
    ORDER BY created_at DESC
    LIMIT 200
  ) sub
  WHERE composite_score IS NOT NULL;

  v_consistency := GREATEST(0, 100 - v_composite_var * 2);
  v_score := v_score + v_consistency * 0.05;
  v_total_weight := v_total_weight + 0.05;

  IF v_total_weight > 0 THEN
    v_score := v_score / v_total_weight;
  ELSE
    v_score := 50.0;
  END IF;

  -- CRITICAL: Dampen based on EFFECTIVE evidence, not raw count
  IF v_effective_count < 5.0 THEN
    v_score := 50.0 + (v_score - 50.0) * (v_effective_count / 5.0);
  END IF;

  RETURN ROUND(GREATEST(0, LEAST(100, v_score))::numeric, 1);
END;
$body$
LANGUAGE plpgsql STABLE;
