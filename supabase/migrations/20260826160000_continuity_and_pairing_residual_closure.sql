-- SPDX-License-Identifier: Apache-2.0
-- STRIX residual closure: successor-control proof, conserved continuity
-- transfer budgets, and atomic claim withdrawal. Mobile-pairing closure is
-- intentionally delivered by the following independently owned migration.

-- A continuity decision is the durable transfer-budget ledger. Backfill the
-- exact budget on existing approvals before making decision rows immutable.
UPDATE public.continuity_decisions AS decision
   SET allocation_rule =
     CASE
       WHEN pg_catalog.jsonb_typeof(decision.allocation_rule) = 'object'
         THEN decision.allocation_rule
       ELSE '{}'::JSONB
     END
     || pg_catalog.jsonb_build_object(
       'budget', COALESCE(claim.transfer_budget, 1.0),
       'old_entity_id', claim.old_entity_id,
       'new_entity_id', claim.new_entity_id,
       'ledger_version', 'EP-IX-TRANSFER-LEDGER-v1'
     )
  FROM public.continuity_claims AS claim
 WHERE claim.continuity_id = decision.continuity_id
   AND decision.decision IN ('approved_full', 'approved_partial');

CREATE UNIQUE INDEX IF NOT EXISTS ux_continuity_decisions_one_per_claim
  ON public.continuity_decisions (continuity_id);

DO $continuity_decision_budget_constraint$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM pg_catalog.pg_constraint
     WHERE conrelid = pg_catalog.to_regclass('public.continuity_decisions')
       AND conname = 'continuity_decisions_approval_budget_ledger'
  ) THEN
    ALTER TABLE public.continuity_decisions
      ADD CONSTRAINT continuity_decisions_approval_budget_ledger CHECK (
        CASE
          WHEN decision IN ('approved_full', 'approved_partial') THEN
            CASE
              WHEN pg_catalog.jsonb_typeof(allocation_rule) = 'object'
                AND pg_catalog.jsonb_typeof(allocation_rule -> 'budget') = 'number'
              THEN (allocation_rule ->> 'budget')::NUMERIC > 0
                AND (allocation_rule ->> 'budget')::NUMERIC <= 1.0
              ELSE FALSE
            END
          ELSE TRUE
        END
      );
  END IF;
END;
$continuity_decision_budget_constraint$;

CREATE OR REPLACE FUNCTION public.populate_continuity_decision_budget_ledger()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $continuity_decision_budget_ledger$
DECLARE
  v_claim public.continuity_claims%ROWTYPE;
BEGIN
  IF NEW.decision NOT IN ('approved_full', 'approved_partial') THEN
    RETURN NEW;
  END IF;

  SELECT claim.*
    INTO v_claim
    FROM public.continuity_claims AS claim
   WHERE claim.continuity_id = NEW.continuity_id
   FOR SHARE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'CONTINUITY_TRANSFER_LEDGER_CLAIM_NOT_FOUND'
      USING ERRCODE = '23503';
  END IF;
  IF v_claim.transfer_budget IS NULL
      OR v_claim.transfer_budget <= 0
      OR v_claim.transfer_budget > 1.0 THEN
    RAISE EXCEPTION 'CONTINUITY_TRANSFER_LEDGER_INVALID_BUDGET'
      USING ERRCODE = '23514';
  END IF;

  NEW.allocation_rule :=
    CASE
      WHEN pg_catalog.jsonb_typeof(NEW.allocation_rule) = 'object'
        THEN NEW.allocation_rule
      ELSE '{}'::JSONB
    END
    || pg_catalog.jsonb_build_object(
      'budget', v_claim.transfer_budget,
      'old_entity_id', v_claim.old_entity_id,
      'new_entity_id', v_claim.new_entity_id,
      'ledger_version', 'EP-IX-TRANSFER-LEDGER-v1'
    );
  RETURN NEW;
END;
$continuity_decision_budget_ledger$;

DROP TRIGGER IF EXISTS continuity_decision_budget_ledger
  ON public.continuity_decisions;
CREATE TRIGGER continuity_decision_budget_ledger
  BEFORE INSERT ON public.continuity_decisions
  FOR EACH ROW
  EXECUTE FUNCTION public.populate_continuity_decision_budget_ledger();

CREATE OR REPLACE FUNCTION public.reject_continuity_decision_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $continuity_decision_immutable$
BEGIN
  RAISE EXCEPTION
    'CONTINUITY_DECISION_IMMUTABILITY_VIOLATION: continuity decisions are append-only'
    USING ERRCODE = '55000';
END;
$continuity_decision_immutable$;

DROP TRIGGER IF EXISTS continuity_decisions_append_only
  ON public.continuity_decisions;
CREATE TRIGGER continuity_decisions_append_only
  BEFORE UPDATE OR DELETE ON public.continuity_decisions
  FOR EACH ROW
  EXECUTE FUNCTION public.reject_continuity_decision_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON TABLE public.continuity_decisions
  FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT, INSERT ON TABLE public.continuity_decisions TO service_role;
REVOKE ALL ON FUNCTION public.populate_continuity_decision_budget_ledger()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.reject_continuity_decision_mutation()
  FROM PUBLIC, anon, authenticated, service_role;

-- Preserve the complete dispute/audit implementation from 130000 as an
-- owner-only core, then put the successor-control proof in front of it. The
-- wrapper and core execute in one transaction, so failure of either audit
-- append rolls the filing back.
DO $rename_continuity_filing_core$
BEGIN
  IF pg_catalog.to_regprocedure(
       'public.file_continuity_claim_atomic(text,text,text,text,text,text,text,jsonb,numeric)'
     ) IS NOT NULL
     AND pg_catalog.to_regprocedure(
       'public.file_continuity_claim_atomic_pre_successor_proof(text,text,text,text,text,text,text,jsonb,numeric)'
     ) IS NULL THEN
    ALTER FUNCTION public.file_continuity_claim_atomic(
      TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, NUMERIC
    ) RENAME TO file_continuity_claim_atomic_pre_successor_proof;
  END IF;
END;
$rename_continuity_filing_core$;

REVOKE ALL ON FUNCTION public.file_continuity_claim_atomic_pre_successor_proof(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, NUMERIC
) FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.file_continuity_claim_atomic(
  p_continuity_id TEXT,
  p_principal_id TEXT,
  p_actor_entity_id TEXT,
  p_old_entity_id TEXT,
  p_new_entity_id TEXT,
  p_reason TEXT,
  p_continuity_mode TEXT DEFAULT 'linear',
  p_proofs JSONB DEFAULT '[]'::JSONB,
  p_transfer_budget NUMERIC DEFAULT 1.0
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $continuity_filing_successor_proof$
DECLARE
  v_principal public.principals%ROWTYPE;
  v_actor public.entities%ROWTYPE;
  v_old_entity public.entities%ROWTYPE;
  v_new_entity public.entities%ROWTYPE;
  v_result JSONB;
BEGIN
  IF p_actor_entity_id IS NULL OR pg_catalog.btrim(p_actor_entity_id) = '' THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Authenticated successor identity is required',
      'status', 400
    );
  END IF;
  IF p_new_entity_id IS NULL OR pg_catalog.btrim(p_new_entity_id) = '' THEN
    RETURN pg_catalog.jsonb_build_object('error', 'new_entity_id is required', 'status', 400);
  END IF;
  IF p_actor_entity_id IS DISTINCT FROM p_new_entity_id THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'The authenticated actor must be the successor continuity endpoint',
      'status', 403
    );
  END IF;

  -- Match the core lock order: old-identity serialization key, then principal
  -- and endpoint rows. Locks survive the owner-only core call below.
  SELECT endpoint.*
    INTO v_old_entity
    FROM public.entities AS endpoint
   WHERE endpoint.entity_id = p_old_entity_id;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('error', 'Continuity endpoint entity not found', 'status', 404);
  END IF;

  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('ep-continuity-dispute:' || v_old_entity.id::TEXT, 0)
  );

  SELECT principal.*
    INTO v_principal
    FROM public.principals AS principal
   WHERE principal.principal_id = p_principal_id
     AND principal.status = 'active'
   FOR SHARE;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('error', 'Principal not found', 'status', 404);
  END IF;

  PERFORM endpoint.id
    FROM public.entities AS endpoint
   WHERE endpoint.entity_id IN (
     p_actor_entity_id,
     p_old_entity_id,
     p_new_entity_id
   )
   ORDER BY endpoint.entity_id
   FOR SHARE;

  SELECT actor.*
    INTO v_actor
    FROM public.entities AS actor
   WHERE actor.entity_id = p_actor_entity_id
     AND actor.status = 'active';
  SELECT endpoint.*
    INTO v_old_entity
    FROM public.entities AS endpoint
   WHERE endpoint.entity_id = p_old_entity_id;
  SELECT endpoint.*
    INTO v_new_entity
    FROM public.entities AS endpoint
   WHERE endpoint.entity_id = p_new_entity_id
     AND endpoint.status = 'active';

  IF v_actor.id IS NULL OR v_new_entity.id IS NULL
      OR v_actor.id IS DISTINCT FROM v_new_entity.id THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Authenticated successor continuity endpoint is not active',
      'status', 403
    );
  END IF;
  IF v_actor.principal_id IS NULL
      OR v_actor.principal_id IS DISTINCT FROM v_principal.id
      OR v_new_entity.principal_id IS DISTINCT FROM v_principal.id THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Authenticated successor is not bound to the continuity subject principal',
      'status', 403
    );
  END IF;
  IF v_old_entity.id IS NULL
      OR v_old_entity.principal_id IS DISTINCT FROM v_principal.id THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Filing principal must control the old continuity endpoint',
      'status', 403
    );
  END IF;

  v_result := public.file_continuity_claim_atomic_pre_successor_proof(
    p_continuity_id,
    p_principal_id,
    p_actor_entity_id,
    p_old_entity_id,
    p_new_entity_id,
    p_reason,
    p_continuity_mode,
    p_proofs,
    p_transfer_budget
  );

  IF pg_catalog.jsonb_typeof(v_result) = 'object'
      AND v_result ? 'continuity' THEN
    INSERT INTO public.audit_events (
      event_type, actor_id, actor_type, target_type, target_id, action,
      before_state, after_state
    ) VALUES (
      'continuity.successor_control_verified',
      v_actor.entity_id,
      'entity',
      'continuity',
      p_continuity_id,
      'verify_successor_control',
      NULL,
      pg_catalog.jsonb_build_object(
        'successor_control', 'verified',
        'subject_principal', p_principal_id,
        'old_entity', p_old_entity_id,
        'new_entity', p_new_entity_id
      )
    );
  END IF;

  RETURN v_result;
END;
$continuity_filing_successor_proof$;

REVOKE ALL ON FUNCTION public.file_continuity_claim_atomic(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, NUMERIC
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.file_continuity_claim_atomic(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, NUMERIC
) TO service_role;

-- Preserve the already atomic resolution implementation as an owner-only core.
-- Approval now requires the immutable successor-control event above and spends
-- from the immutable decision ledger while holding the old identity's shared
-- advisory key and row lock.
DO $rename_continuity_resolution_core$
BEGIN
  IF pg_catalog.to_regprocedure(
       'public.resolve_continuity_atomic(text,text,jsonb,text)'
     ) IS NOT NULL
     AND pg_catalog.to_regprocedure(
       'public.resolve_continuity_atomic_pre_budget_conservation(text,text,jsonb,text)'
     ) IS NULL THEN
    ALTER FUNCTION public.resolve_continuity_atomic(TEXT, TEXT, JSONB, TEXT)
      RENAME TO resolve_continuity_atomic_pre_budget_conservation;
  END IF;
END;
$rename_continuity_resolution_core$;

REVOKE ALL ON FUNCTION public.resolve_continuity_atomic_pre_budget_conservation(
  TEXT, TEXT, JSONB, TEXT
) FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.resolve_continuity_atomic(
  p_continuity_id TEXT,
  p_decision TEXT,
  p_reasoning JSONB,
  p_operator_id TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $continuity_resolution_budget_conservation$
DECLARE
  v_claim_probe RECORD;
  v_claim public.continuity_claims%ROWTYPE;
  v_old_entity public.entities%ROWTYPE;
  v_new_entity public.entities%ROWTYPE;
  v_principal_public_id TEXT;
  v_allocated_budget NUMERIC := 0;
  v_requested_budget NUMERIC;
BEGIN
  -- Rejections remain available for legacy or malformed claims. Only an
  -- approval can transfer identity authority or consume the shared budget.
  IF p_decision NOT IN ('approved_full', 'approved_partial') THEN
    RETURN public.resolve_continuity_atomic_pre_budget_conservation(
      p_continuity_id, p_decision, p_reasoning, p_operator_id
    );
  END IF;

  SELECT claim.old_entity_id, claim.new_entity_id
    INTO v_claim_probe
    FROM public.continuity_claims AS claim
   WHERE claim.continuity_id = p_continuity_id;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('error', 'Continuity claim not found', 'status', 404);
  END IF;

  SELECT endpoint.*
    INTO v_old_entity
    FROM public.entities AS endpoint
   WHERE endpoint.entity_id = v_claim_probe.old_entity_id;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Continuity old endpoint entity not found',
      'status', 409
    );
  END IF;

  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('ep-continuity-dispute:' || v_old_entity.id::TEXT, 0)
  );

  SELECT claim.*
    INTO v_claim
    FROM public.continuity_claims AS claim
   WHERE claim.continuity_id = p_continuity_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('error', 'Continuity claim not found', 'status', 404);
  END IF;
  IF v_claim.old_entity_id <> v_claim_probe.old_entity_id
      OR v_claim.new_entity_id <> v_claim_probe.new_entity_id THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Continuity endpoint changed during resolution; retry required',
      'status', 409
    );
  END IF;

  PERFORM endpoint.id
    FROM public.entities AS endpoint
   WHERE endpoint.entity_id IN (v_claim.old_entity_id, v_claim.new_entity_id)
   ORDER BY endpoint.entity_id
   FOR UPDATE;
  SELECT endpoint.*
    INTO v_old_entity
    FROM public.entities AS endpoint
   WHERE endpoint.entity_id = v_claim.old_entity_id;
  SELECT endpoint.*
    INTO v_new_entity
    FROM public.entities AS endpoint
   WHERE endpoint.entity_id = v_claim.new_entity_id
     AND endpoint.status = 'active';
  SELECT principal.principal_id
    INTO v_principal_public_id
    FROM public.principals AS principal
   WHERE principal.id = v_claim.principal_id
     AND principal.status = 'active'
   FOR SHARE;

  IF v_old_entity.id IS NULL
      OR v_old_entity.principal_id IS DISTINCT FROM v_claim.principal_id
      OR v_new_entity.id IS NULL
      OR v_new_entity.principal_id IS DISTINCT FROM v_claim.principal_id
      OR v_principal_public_id IS NULL THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Continuity endpoint ownership is not currently proven',
      'status', 409
    );
  END IF;

  IF NOT EXISTS (
    SELECT 1
      FROM public.audit_events AS proof
     WHERE proof.event_type = 'continuity.successor_control_verified'
       AND proof.target_type = 'continuity'
       AND proof.target_id = v_claim.continuity_id
       AND proof.actor_type = 'entity'
       AND proof.actor_id = v_claim.new_entity_id
       AND proof.after_state ->> 'successor_control' = 'verified'
       AND proof.after_state ->> 'subject_principal' = v_principal_public_id
       AND proof.after_state ->> 'old_entity' = v_claim.old_entity_id
       AND proof.after_state ->> 'new_entity' = v_claim.new_entity_id
  ) THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Successor control was not proven by the authenticated successor',
      'status', 409
    );
  END IF;

  v_requested_budget := v_claim.transfer_budget;
  IF v_requested_budget IS NULL
      OR v_requested_budget <= 0
      OR v_requested_budget > 1.0 THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Continuity transfer budget is invalid',
      'status', 409
    );
  END IF;

  SELECT COALESCE(
           pg_catalog.sum((decision.allocation_rule ->> 'budget')::NUMERIC),
           0
         )
    INTO v_allocated_budget
    FROM public.continuity_decisions AS decision
    JOIN public.continuity_claims AS allocated_claim
      ON allocated_claim.continuity_id = decision.continuity_id
   WHERE allocated_claim.old_entity_id = v_claim.old_entity_id
     AND decision.decision IN ('approved_full', 'approved_partial');

  IF v_allocated_budget + v_requested_budget > 1.0 THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Continuity transfer budget exhausted for the old identity',
      'status', 409,
      'allocated_budget', v_allocated_budget,
      'requested_budget', v_requested_budget,
      'remaining_budget', GREATEST(0, 1.0 - v_allocated_budget)
    );
  END IF;

  RETURN public.resolve_continuity_atomic_pre_budget_conservation(
    p_continuity_id, p_decision, p_reasoning, p_operator_id
  );
END;
$continuity_resolution_budget_conservation$;

REVOKE ALL ON FUNCTION public.resolve_continuity_atomic(TEXT, TEXT, JSONB, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.resolve_continuity_atomic(TEXT, TEXT, JSONB, TEXT)
  TO service_role;

-- Withdrawal is a single database transaction: claim lock, authenticated
-- principal binding check, terminal transition, and append-only audit event.
CREATE OR REPLACE FUNCTION public.withdraw_continuity_claim_atomic(
  p_continuity_id TEXT,
  p_actor_entity_id TEXT,
  p_reason TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $continuity_withdrawal$
DECLARE
  v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
  v_claim public.continuity_claims%ROWTYPE;
  v_actor public.entities%ROWTYPE;
BEGIN
  IF p_continuity_id IS NULL OR pg_catalog.btrim(p_continuity_id) = '' THEN
    RETURN pg_catalog.jsonb_build_object('error', 'continuity_id is required', 'status', 400);
  END IF;
  IF p_actor_entity_id IS NULL OR pg_catalog.btrim(p_actor_entity_id) = '' THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Authenticated withdrawing actor identity is required',
      'status', 400
    );
  END IF;

  SELECT claim.*
    INTO v_claim
    FROM public.continuity_claims AS claim
   WHERE claim.continuity_id = p_continuity_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('error', 'Continuity claim not found', 'status', 404);
  END IF;

  SELECT actor.*
    INTO v_actor
    FROM public.entities AS actor
   WHERE actor.entity_id = p_actor_entity_id
     AND actor.status = 'active'
   FOR SHARE;
  IF NOT FOUND OR v_actor.principal_id IS NULL
      OR v_actor.principal_id IS DISTINCT FROM v_claim.principal_id THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Only an authenticated entity bound to the filing principal may withdraw this claim',
      'status', 403
    );
  END IF;

  IF v_claim.status NOT IN ('pending', 'under_challenge') THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', pg_catalog.format('Cannot withdraw claim in status %L', v_claim.status),
      'status', 409
    );
  END IF;

  UPDATE public.continuity_claims
     SET status = 'withdrawn',
         withdrawn_at = v_now,
         withdrawn_by = v_actor.entity_id,
         withdrawn_reason = NULLIF(pg_catalog.btrim(COALESCE(p_reason, '')), ''),
         updated_at = v_now
   WHERE id = v_claim.id;

  INSERT INTO public.audit_events (
    event_type, actor_id, actor_type, target_type, target_id, action,
    before_state, after_state
  ) VALUES (
    'continuity.withdrawn',
    v_actor.entity_id,
    'entity',
    'continuity',
    v_claim.continuity_id,
    'withdraw',
    pg_catalog.jsonb_build_object('status', v_claim.status),
    pg_catalog.jsonb_build_object(
      'status', 'withdrawn',
      'reason', NULLIF(pg_catalog.btrim(COALESCE(p_reason, '')), '')
    )
  );

  RETURN pg_catalog.jsonb_build_object(
    'continuity_id', v_claim.continuity_id,
    'status', 'withdrawn',
    'withdrawn_at', v_now
  );
END;
$continuity_withdrawal$;

REVOKE ALL ON FUNCTION public.withdraw_continuity_claim_atomic(TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.withdraw_continuity_claim_atomic(TEXT, TEXT, TEXT)
  TO service_role;

COMMENT ON FUNCTION public.file_continuity_claim_atomic(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, NUMERIC
) IS 'Files continuity only when the authenticated actor is the active, principal-bound successor endpoint; filing and proof audit are atomic.';
COMMENT ON FUNCTION public.resolve_continuity_atomic(TEXT, TEXT, JSONB, TEXT)
  IS 'Approves continuity only after immutable successor-control proof and under a conserved per-old-identity transfer-budget ledger.';
COMMENT ON FUNCTION public.withdraw_continuity_claim_atomic(TEXT, TEXT, TEXT)
  IS 'Atomically withdraws an unresolved continuity claim and appends its audit event.';
