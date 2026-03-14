-- ============================================================================
-- EMILIA Protocol — Migration 007: Rewrite Scoring Engine
-- ============================================================================
-- The original compute_emilia_score() did a simple avg() — treating every
-- receipt equally. This made the protocol vulnerable to Sybil attacks where
-- throwaway entities could pump scores.
--
-- This rewrite adds:
--   1. Submitter weighting: unestablished submitters = 0.1x, established = score/100
--   2. Time decay: 90-day half-life, recent receipts matter more
--   3. Both factors multiply together for combined weight
-- ============================================================================

CREATE OR REPLACE FUNCTION compute_emilia_score(p_entity_id uuid)
RETURNS float AS $$
DECLARE
  v_score float;
  v_count integer;
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
  v_composite_mean float;
  v_composite_var float;
  r RECORD;
  v_receipt_weight float;
  v_submitter_weight float;
  v_time_weight float;
  v_age_days float;
BEGIN
  -- Initialize accumulators
  v_count := 0;
  v_delivery_sum := 0; v_delivery_weight := 0;
  v_product_sum := 0; v_product_weight := 0;
  v_price_sum := 0; v_price_weight := 0;
  v_returns_sum := 0; v_returns_weight := 0;
  v_satisfaction_sum := 0; v_satisfaction_weight := 0;

  -- Loop through recent receipts with weighting
  FOR r IN
    SELECT
      delivery_accuracy, product_accuracy, price_integrity,
      return_processing, agent_satisfaction, composite_score,
      submitter_score, submitter_established, created_at
    FROM receipts
    WHERE entity_id = p_entity_id
    ORDER BY created_at DESC
    LIMIT 200
  LOOP
    v_count := v_count + 1;

    -- Submitter weight: unestablished = 0.1, established = score/100
    IF r.submitter_established = TRUE THEN
      v_submitter_weight := GREATEST(0.1, LEAST(1.0, COALESCE(r.submitter_score, 50) / 100.0));
    ELSE
      v_submitter_weight := 0.1;
    END IF;

    -- Time decay: 90-day half-life, floor at 0.05
    v_age_days := GREATEST(0, EXTRACT(EPOCH FROM (NOW() - r.created_at)) / 86400.0);
    v_time_weight := GREATEST(0.05, POWER(0.5, v_age_days / 90.0));

    -- Combined weight
    v_receipt_weight := v_submitter_weight * v_time_weight;

    -- Accumulate weighted signals (skip nulls)
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

  -- No receipts
  IF v_count = 0 THEN
    RETURN 50.0;
  END IF;

  -- Compute weighted averages for each signal
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

  -- Consistency: low variance in composite scores = high consistency
  SELECT COALESCE(STDDEV(composite_score), 0)
  INTO v_composite_var
  FROM (
    SELECT composite_score FROM receipts
    WHERE entity_id = p_entity_id
    ORDER BY created_at DESC LIMIT 200
  ) sub
  WHERE composite_score IS NOT NULL;

  v_consistency := GREATEST(0, 100 - v_composite_var * 2);
  v_score := v_score + v_consistency * 0.05;
  v_total_weight := v_total_weight + 0.05;

  -- Normalize
  IF v_total_weight > 0 THEN
    v_score := v_score / v_total_weight;
  ELSE
    v_score := 50.0;
  END IF;

  -- New entity dampening: pull toward 50 until 5 receipts
  IF v_count < 5 THEN
    v_score := 50.0 + (v_score - 50.0) * (v_count::float / 5.0);
  END IF;

  RETURN ROUND(GREATEST(0, LEAST(100, v_score))::numeric, 1);
END;
$$ LANGUAGE plpgsql STABLE;

-- Also update avg columns on entities for the score breakdown display
CREATE OR REPLACE FUNCTION update_entity_score()
RETURNS trigger AS $$
DECLARE
  v_new_score float;
BEGIN
  v_new_score := compute_emilia_score(NEW.entity_id);

  UPDATE entities SET
    emilia_score = v_new_score,
    total_receipts = total_receipts + 1,
    successful_receipts = successful_receipts + CASE WHEN NEW.composite_score >= 70 THEN 1 ELSE 0 END,
    -- Update breakdown averages (simple avg for display — weighted score is in emilia_score)
    avg_delivery_accuracy = COALESCE((SELECT AVG(delivery_accuracy) FROM receipts WHERE entity_id = NEW.entity_id AND delivery_accuracy IS NOT NULL), avg_delivery_accuracy),
    avg_product_accuracy = COALESCE((SELECT AVG(product_accuracy) FROM receipts WHERE entity_id = NEW.entity_id AND product_accuracy IS NOT NULL), avg_product_accuracy),
    avg_price_integrity = COALESCE((SELECT AVG(price_integrity) FROM receipts WHERE entity_id = NEW.entity_id AND price_integrity IS NOT NULL), avg_price_integrity),
    avg_return_processing = COALESCE((SELECT AVG(return_processing) FROM receipts WHERE entity_id = NEW.entity_id AND return_processing IS NOT NULL), avg_return_processing),
    avg_agent_satisfaction = COALESCE((SELECT AVG(agent_satisfaction) FROM receipts WHERE entity_id = NEW.entity_id AND agent_satisfaction IS NOT NULL), avg_agent_satisfaction),
    score_consistency = GREATEST(0, 100 - COALESCE((SELECT STDDEV(composite_score) FROM receipts WHERE entity_id = NEW.entity_id), 0) * 2),
    updated_at = NOW()
  WHERE id = NEW.entity_id;

  -- Record score history
  INSERT INTO score_history (entity_id, score, total_receipts, receipt_id)
  SELECT NEW.entity_id, v_new_score, total_receipts, NEW.id
  FROM entities WHERE id = NEW.entity_id;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
