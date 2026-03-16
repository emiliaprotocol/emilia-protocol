-- ============================================================================
-- EMILIA Protocol — Migration 020: Quality-Gated Establishment
-- ============================================================================
-- Aligns SQL establishment logic with JS qualityGatedEvidence barrier.
-- Pure unestablished volume can no longer cross the establishment threshold.
-- ============================================================================

CREATE OR REPLACE FUNCTION is_entity_established(p_entity_id uuid)
RETURNS TABLE(established boolean, unique_submitters bigint, effective_evidence float, quality_gated_evidence float, total_receipts bigint) AS
$fn$
DECLARE
  eff_ev float := 0;
  established_ev float := 0;
  quality_gated_ev float;
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
      w float;
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

      w := submitter_w * time_w * graph_w * prov_w;
      eff_ev := eff_ev + w;

      IF receipt.submitter_established THEN
        established_ev := established_ev + w;
      END IF;
    END;
  END LOOP;

  -- Quality gate: cap unestablished contribution at 2.0
  quality_gated_ev := LEAST(
    eff_ev,
    established_ev + LEAST(GREATEST(eff_ev - established_ev, 0), 2.0)
  );

  RETURN QUERY
    SELECT
      (quality_gated_ev >= 5.0 AND (SELECT COUNT(DISTINCT submitted_by) FROM receipts WHERE entity_id = p_entity_id) >= 3) AS established,
      (SELECT COUNT(DISTINCT submitted_by) FROM receipts WHERE entity_id = p_entity_id) AS unique_submitters,
      eff_ev AS effective_evidence,
      quality_gated_ev AS quality_gated_evidence,
      (SELECT COUNT(*) FROM receipts WHERE entity_id = p_entity_id) AS total_receipts;
END;
$fn$
LANGUAGE plpgsql;

-- Also update compute_emilia_score to use quality-gated dampening
CREATE OR REPLACE FUNCTION compute_emilia_score(p_entity_id uuid)
RETURNS float AS
$fn$
DECLARE
  receipt RECORD;
  total_weight float := 0;
  weighted_sum float := 0;
  effective_evidence float := 0;
  established_evidence float := 0;
  quality_gated_ev float;
  raw_score float := 50;
  final_score float;
BEGIN
  FOR receipt IN
    SELECT composite_score, submitter_established, submitter_score,
           graph_weight, provenance_tier, created_at
    FROM receipts
    WHERE entity_id = p_entity_id
    ORDER BY created_at DESC
    LIMIT 200
  LOOP
    DECLARE
      submitter_w float;
      time_w float;
      graph_w float;
      prov_w float;
      age_days float;
      w float;
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

      w := submitter_w * time_w * graph_w * prov_w;
      effective_evidence := effective_evidence + w;

      IF receipt.submitter_established THEN
        established_evidence := established_evidence + w;
      END IF;

      IF receipt.composite_score IS NOT NULL THEN
        weighted_sum := weighted_sum + (receipt.composite_score * w);
        total_weight := total_weight + w;
      END IF;
    END;
  END LOOP;

  IF total_weight > 0 THEN
    raw_score := weighted_sum / total_weight;
  END IF;

  -- Quality-gated dampening (matches JS qualityGatedEvidence)
  quality_gated_ev := LEAST(
    effective_evidence,
    established_evidence + LEAST(GREATEST(effective_evidence - established_evidence, 0), 2.0)
  );

  IF quality_gated_ev < 5.0 THEN
    final_score := 50 + (raw_score - 50) * (quality_gated_ev / 5.0);
  ELSE
    final_score := raw_score;
  END IF;

  RETURN ROUND(final_score::numeric, 1);
END;
$fn$
LANGUAGE plpgsql;
