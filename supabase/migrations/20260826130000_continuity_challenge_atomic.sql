-- SPDX-License-Identifier: Apache-2.0
-- Atomic EP-IX continuity filing, dispute reconciliation, challenge, and resolution.

ALTER TABLE public.entities
  ADD COLUMN IF NOT EXISTS is_operator BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN public.entities.is_operator IS
  'Server-managed global continuity adjudicator flag. Never sourced from a challenge request body.';

CREATE OR REPLACE FUNCTION public.is_active_continuity_dispute_status(p_status TEXT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = ''
AS $continuity_active_status$
  SELECT p_status IN ('open', 'under_review', 'appealed');
$continuity_active_status$;

REVOKE ALL ON FUNCTION public.is_active_continuity_dispute_status(TEXT)
  FROM PUBLIC, anon, authenticated, service_role;

-- Remove the actor/subject-conflating overload if it was ever installed by a
-- pre-release build of this migration. Only the actor-bound signature below
-- may remain executable.
DROP FUNCTION IF EXISTS public.file_continuity_claim_atomic(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, NUMERIC
);

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
AS $continuity_filing$
DECLARE
  v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
  v_principal public.principals%ROWTYPE;
  v_actor public.entities%ROWTYPE;
  v_old_entity public.entities%ROWTYPE;
  v_new_entity public.entities%ROWTYPE;
  v_claim public.continuity_claims%ROWTYPE;
  v_active_disputes BIGINT;
  v_challenge_deadline TIMESTAMPTZ;
  v_expires_at TIMESTAMPTZ;
BEGIN
  IF p_continuity_id IS NULL OR pg_catalog.btrim(p_continuity_id) = '' THEN
    RETURN pg_catalog.jsonb_build_object('error', 'continuity_id is required', 'status', 400);
  END IF;
  IF p_principal_id IS NULL OR pg_catalog.btrim(p_principal_id) = '' THEN
    RETURN pg_catalog.jsonb_build_object('error', 'principal_id is required', 'status', 400);
  END IF;
  IF p_actor_entity_id IS NULL OR pg_catalog.btrim(p_actor_entity_id) = '' THEN
    RETURN pg_catalog.jsonb_build_object('error', 'Authenticated actor identity is required', 'status', 400);
  END IF;
  IF p_old_entity_id IS NULL OR pg_catalog.btrim(p_old_entity_id) = '' THEN
    RETURN pg_catalog.jsonb_build_object('error', 'old_entity_id is required', 'status', 400);
  END IF;
  IF p_new_entity_id IS NULL OR pg_catalog.btrim(p_new_entity_id) = '' THEN
    RETURN pg_catalog.jsonb_build_object('error', 'new_entity_id is required', 'status', 400);
  END IF;
  IF p_old_entity_id = p_new_entity_id THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Continuity endpoints must identify two distinct entities',
      'status', 400
    );
  END IF;
  IF p_reason IS NULL OR pg_catalog.btrim(p_reason) = '' OR p_reason NOT IN (
    'key_rotation', 'infrastructure_migration', 'host_migration',
    'entity_rename', 'domain_change', 'publisher_transition',
    'merger_or_acquisition', 'recovery_after_compromise', 'fission'
  ) THEN
    RETURN pg_catalog.jsonb_build_object('error', 'Unsupported continuity reason', 'status', 400);
  END IF;
  IF p_continuity_mode IS NULL OR p_continuity_mode NOT IN ('linear', 'fission', 'merger') THEN
    RETURN pg_catalog.jsonb_build_object('error', 'Unsupported continuity mode', 'status', 400);
  END IF;
  IF p_proofs IS NULL OR pg_catalog.jsonb_typeof(p_proofs) <> 'array' THEN
    RETURN pg_catalog.jsonb_build_object('error', 'proofs must be an array', 'status', 400);
  END IF;
  IF p_transfer_budget IS NULL OR p_transfer_budget <= 0 OR p_transfer_budget > 1.0 THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'transfer_budget must be greater than 0 and no greater than 1.0',
      'status', 400
    );
  END IF;

  -- Probe the old endpoint only to select the serialization key. Its full row,
  -- and the new endpoint, are authoritatively re-read under locks below.
  SELECT endpoint.*
    INTO v_old_entity
    FROM public.entities AS endpoint
   WHERE endpoint.entity_id = p_old_entity_id;

  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('error', 'Continuity endpoint entity not found', 'status', 404);
  END IF;

  -- Acquire the dispute serialization key before endpoint row locks. Resolution
  -- uses this same order, preventing an endpoint-lock/advisory-lock cycle.
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

  -- Lock the actor and both endpoints together in one stable lexical order.
  -- No affected entity row is locked before the advisory key, and a delegate
  -- actor cannot invert endpoint lock order against a concurrent resolution.
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

  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('error', 'Authenticated filing actor not found', 'status', 403);
  END IF;
  IF v_actor.principal_id IS DISTINCT FROM v_principal.id
      AND v_actor.entity_id <> v_principal.principal_id THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Authenticated actor does not control the continuity subject principal',
      'status', 403
    );
  END IF;

  SELECT endpoint.*
    INTO v_old_entity
    FROM public.entities AS endpoint
   WHERE endpoint.entity_id = p_old_entity_id;

  SELECT endpoint.*
    INTO v_new_entity
    FROM public.entities AS endpoint
   WHERE endpoint.entity_id = p_new_entity_id;

  IF v_old_entity.id IS NULL OR v_new_entity.id IS NULL THEN
    RETURN pg_catalog.jsonb_build_object('error', 'Continuity endpoint entity not found', 'status', 404);
  END IF;
  IF v_old_entity.principal_id IS DISTINCT FROM v_principal.id THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Filing principal must control the old continuity endpoint',
      'status', 403
    );
  END IF;
  IF v_new_entity.principal_id IS NOT NULL
      AND v_new_entity.principal_id IS DISTINCT FROM v_principal.id THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'New continuity endpoint is already controlled by another principal',
      'status', 403
    );
  END IF;

  SELECT pg_catalog.count(*)
    INTO v_active_disputes
    FROM public.disputes AS dispute
   WHERE dispute.entity_id = v_old_entity.id
     AND public.is_active_continuity_dispute_status(dispute.status);

  IF v_active_disputes > 0 THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Continuity frozen: old entity has active disputes. Resolve disputes before claiming continuity.',
      'status', 409,
      'frozen', TRUE,
      'active_disputes', v_active_disputes
    );
  END IF;

  v_challenge_deadline := v_now + INTERVAL '7 days';
  v_expires_at := v_now + INTERVAL '30 days';

  INSERT INTO public.continuity_claims (
    continuity_id,
    principal_id,
    old_entity_id,
    new_entity_id,
    reason,
    continuity_mode,
    proofs,
    status,
    challenge_deadline,
    expires_at,
    transfer_budget
  ) VALUES (
    p_continuity_id,
    v_principal.id,
    p_old_entity_id,
    p_new_entity_id,
    p_reason,
    p_continuity_mode,
    p_proofs,
    'pending',
    v_challenge_deadline,
    v_expires_at,
    p_transfer_budget
  )
  RETURNING * INTO STRICT v_claim;

  INSERT INTO public.audit_events (
    event_type,
    actor_id,
    actor_type,
    target_type,
    target_id,
    action,
    before_state,
    after_state
  ) VALUES (
    'continuity.filed',
    v_actor.entity_id,
    'entity',
    'continuity',
    p_continuity_id,
    'file',
    NULL,
    pg_catalog.jsonb_build_object(
      'status', 'pending',
      'subject_principal', p_principal_id,
      'old_entity', p_old_entity_id,
      'new_entity', p_new_entity_id,
      'reason', p_reason
    )
  );

  RETURN pg_catalog.jsonb_build_object(
    'continuity', pg_catalog.to_jsonb(v_claim),
    'challenge_deadline', v_challenge_deadline,
    'expires_at', v_expires_at
  );
END;
$continuity_filing$;

REVOKE ALL ON FUNCTION public.file_continuity_claim_atomic(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, NUMERIC
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.file_continuity_claim_atomic(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, NUMERIC
) TO service_role;

CREATE OR REPLACE FUNCTION public.reconcile_continuity_for_entity(
  p_entity_id UUID,
  p_now TIMESTAMPTZ DEFAULT pg_catalog.transaction_timestamp()
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $continuity_reconcile$
DECLARE
  v_entity_id TEXT;
  v_claim RECORD;
  v_blocker_id TEXT;
  v_active_disputes BIGINT;
  v_frozen INTEGER := 0;
  v_repointed INTEGER := 0;
  v_unfrozen INTEGER := 0;
  v_restored_status TEXT;
  v_open_challenges BIGINT;
  v_now TIMESTAMPTZ := COALESCE(p_now, pg_catalog.transaction_timestamp());
BEGIN
  IF p_entity_id IS NULL THEN
    RAISE EXCEPTION 'CONTINUITY_DISPUTE_ENTITY_REQUIRED';
  END IF;

  -- This is the single serialization key for filing, active-dispute writes,
  -- resolution, and explicit reconciliation. Every caller takes it before a
  -- continuity-claim row lock, preventing advisory/row-lock inversion.
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('ep-continuity-dispute:' || p_entity_id::TEXT, 0)
  );

  SELECT entity.entity_id
    INTO v_entity_id
    FROM public.entities AS entity
   WHERE entity.id = p_entity_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'CONTINUITY_DISPUTE_ENTITY_NOT_FOUND';
  END IF;

  -- frozen_dispute_id stores a deterministic representative blocker. The
  -- complete active set is re-read on every dispute transition, so resolving
  -- one of several disputes can never unfreeze the claim prematurely.
  SELECT pg_catalog.count(*), pg_catalog.min(dispute.dispute_id)
    INTO v_active_disputes, v_blocker_id
    FROM public.disputes AS dispute
   WHERE dispute.entity_id = p_entity_id
     AND public.is_active_continuity_dispute_status(dispute.status);

  FOR v_claim IN
    SELECT
      claim.id,
      claim.continuity_id,
      claim.status,
      claim.expires_at,
      claim.frozen_due_to,
      claim.frozen_dispute_id
      FROM public.continuity_claims AS claim
     WHERE claim.old_entity_id = v_entity_id
       AND claim.status IN ('pending', 'under_challenge', 'frozen_pending_dispute')
     ORDER BY claim.continuity_id
     FOR UPDATE
  LOOP
    IF v_active_disputes > 0 AND v_claim.status <> 'frozen_pending_dispute' THEN
      UPDATE public.continuity_claims
         SET status = 'frozen_pending_dispute',
             frozen_due_to = v_blocker_id,
             frozen_dispute_id = v_blocker_id,
             updated_at = v_now
       WHERE id = v_claim.id;

      INSERT INTO public.audit_events (
        event_type, actor_id, actor_type, target_type, target_id, action,
        before_state, after_state
      ) VALUES (
        'continuity.frozen', 'system', 'system', 'continuity',
        v_claim.continuity_id, 'freeze',
        pg_catalog.jsonb_build_object('status', v_claim.status),
        pg_catalog.jsonb_build_object(
          'status', 'frozen_pending_dispute',
          'frozen_due_to', v_blocker_id,
          'active_disputes', v_active_disputes
        )
      );
      v_frozen := v_frozen + 1;
    ELSIF v_active_disputes > 0
        AND v_claim.frozen_dispute_id IS DISTINCT FROM v_blocker_id THEN
      UPDATE public.continuity_claims
         SET frozen_due_to = v_blocker_id,
             frozen_dispute_id = v_blocker_id,
             updated_at = v_now
       WHERE id = v_claim.id;

      INSERT INTO public.audit_events (
        event_type, actor_id, actor_type, target_type, target_id, action,
        before_state, after_state
      ) VALUES (
        'continuity.freeze_reconciled', 'system', 'system', 'continuity',
        v_claim.continuity_id, 'reconcile',
        pg_catalog.jsonb_build_object(
          'status', v_claim.status,
          'frozen_due_to', v_claim.frozen_dispute_id
        ),
        pg_catalog.jsonb_build_object(
          'status', 'frozen_pending_dispute',
          'frozen_due_to', v_blocker_id,
          'active_disputes', v_active_disputes
        )
      );
      v_repointed := v_repointed + 1;
    ELSIF v_active_disputes = 0
        AND v_claim.status = 'frozen_pending_dispute' THEN
      SELECT pg_catalog.count(*)
        INTO v_open_challenges
        FROM public.continuity_challenges AS challenge
       WHERE challenge.continuity_id = v_claim.continuity_id
         AND challenge.status IN ('open', 'reviewed');

      v_restored_status := CASE
        WHEN v_claim.expires_at IS NOT NULL AND v_claim.expires_at <= v_now
          THEN 'expired'
        WHEN v_open_challenges > 0
          THEN 'under_challenge'
        ELSE 'pending'
      END;

      UPDATE public.continuity_claims
         SET status = CASE
               WHEN v_claim.expires_at IS NOT NULL AND v_claim.expires_at <= v_now
                 THEN 'expired'
               WHEN v_open_challenges > 0
                 THEN 'under_challenge'
               ELSE 'pending'
             END,
             frozen_due_to = NULL,
             frozen_dispute_id = NULL,
             updated_at = v_now
       WHERE id = v_claim.id;

      INSERT INTO public.audit_events (
        event_type, actor_id, actor_type, target_type, target_id, action,
        before_state, after_state
      ) VALUES (
        'continuity.unfrozen', 'system', 'system', 'continuity',
        v_claim.continuity_id, 'unfreeze',
        pg_catalog.jsonb_build_object(
          'status', 'frozen_pending_dispute',
          'frozen_due_to', v_claim.frozen_dispute_id
        ),
        pg_catalog.jsonb_build_object(
          'status', v_restored_status,
          'active_disputes', 0
        )
      );
      v_unfrozen := v_unfrozen + 1;
    END IF;
  END LOOP;

  RETURN pg_catalog.jsonb_build_object(
    'entity_id', v_entity_id,
    'remaining_active_disputes', v_active_disputes,
    'blocker_dispute_id', v_blocker_id,
    'frozen', v_frozen,
    'repointed', v_repointed,
    'unfrozen', v_unfrozen
  );
END;
$continuity_reconcile$;

REVOKE ALL ON FUNCTION public.reconcile_continuity_for_entity(UUID, TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.reconcile_continuity_dispute_atomic(
  p_dispute_id TEXT,
  p_continuity_id TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $continuity_dispute_reconcile$
DECLARE
  v_dispute public.disputes%ROWTYPE;
  v_entity_id TEXT;
  v_claim public.continuity_claims%ROWTYPE;
  v_result JSONB;
BEGIN
  IF p_dispute_id IS NULL OR pg_catalog.btrim(p_dispute_id) = '' THEN
    RETURN pg_catalog.jsonb_build_object('error', 'dispute_id is required', 'status', 400);
  END IF;
  IF p_continuity_id IS NOT NULL AND pg_catalog.btrim(p_continuity_id) = '' THEN
    RETURN pg_catalog.jsonb_build_object('error', 'continuity_id must not be empty', 'status', 400);
  END IF;

  SELECT dispute.*
    INTO v_dispute
    FROM public.disputes AS dispute
   WHERE dispute.dispute_id = p_dispute_id
   FOR SHARE;

  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('error', 'Dispute not found', 'status', 404);
  END IF;

  SELECT entity.entity_id
    INTO v_entity_id
    FROM public.entities AS entity
   WHERE entity.id = v_dispute.entity_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'CONTINUITY_DISPUTE_ENTITY_NOT_FOUND';
  END IF;

  -- Validate an explicitly requested claim before any reconciliation mutation.
  IF p_continuity_id IS NOT NULL THEN
    SELECT claim.*
      INTO v_claim
      FROM public.continuity_claims AS claim
     WHERE claim.continuity_id = p_continuity_id;

    IF NOT FOUND THEN
      RETURN pg_catalog.jsonb_build_object('error', 'Continuity claim not found', 'status', 404);
    END IF;
    IF v_claim.old_entity_id <> v_entity_id THEN
      RETURN pg_catalog.jsonb_build_object(
        'error', 'Dispute does not govern the requested continuity claim',
        'status', 409
      );
    END IF;
  END IF;

  v_result := public.reconcile_continuity_for_entity(
    v_dispute.entity_id,
    pg_catalog.transaction_timestamp()
  );

  IF p_continuity_id IS NOT NULL THEN
    SELECT claim.*
      INTO STRICT v_claim
      FROM public.continuity_claims AS claim
     WHERE claim.continuity_id = p_continuity_id;

    v_result := v_result || pg_catalog.jsonb_build_object(
      'continuity_id', v_claim.continuity_id,
      'status', v_claim.status,
      'frozen_due_to', v_claim.frozen_dispute_id
    );
  END IF;

  RETURN v_result;
END;
$continuity_dispute_reconcile$;

REVOKE ALL ON FUNCTION public.reconcile_continuity_dispute_atomic(TEXT, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.reconcile_continuity_dispute_atomic(TEXT, TEXT)
  TO service_role;

CREATE OR REPLACE FUNCTION public.lock_continuity_dispute_entity()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $continuity_dispute_lock$
BEGIN
  -- Lock before the dispute row changes. An AFTER-only lock is too late: an
  -- uncommitted active row could otherwise exist while resolution holds this
  -- key, remain invisible to resolution's count, and reconcile only after the
  -- claim has become terminal. Entity moves acquire both keys in UUID order.
  IF TG_OP = 'UPDATE' AND OLD.entity_id IS DISTINCT FROM NEW.entity_id THEN
    IF OLD.entity_id::TEXT < NEW.entity_id::TEXT THEN
      PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('ep-continuity-dispute:' || OLD.entity_id::TEXT, 0)
      );
      PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('ep-continuity-dispute:' || NEW.entity_id::TEXT, 0)
      );
    ELSE
      PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('ep-continuity-dispute:' || NEW.entity_id::TEXT, 0)
      );
      PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('ep-continuity-dispute:' || OLD.entity_id::TEXT, 0)
      );
    END IF;
  ELSIF TG_OP = 'DELETE' THEN
    PERFORM pg_catalog.pg_advisory_xact_lock(
      pg_catalog.hashtextextended('ep-continuity-dispute:' || OLD.entity_id::TEXT, 0)
    );
  ELSE
    PERFORM pg_catalog.pg_advisory_xact_lock(
      pg_catalog.hashtextextended('ep-continuity-dispute:' || NEW.entity_id::TEXT, 0)
    );
  END IF;

  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$continuity_dispute_lock$;

REVOKE ALL ON FUNCTION public.lock_continuity_dispute_entity()
  FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION public.guard_active_dispute_continuity()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $continuity_dispute_guard$
BEGIN
  -- Reconcile affected entities in a deterministic UUID order when a dispute
  -- moves between entities. The helper acquires the shared advisory lock and
  -- reads the post-mutation dispute set because this is an AFTER trigger.
  IF TG_OP = 'UPDATE' AND OLD.entity_id IS DISTINCT FROM NEW.entity_id THEN
    IF OLD.entity_id::TEXT < NEW.entity_id::TEXT THEN
      PERFORM public.reconcile_continuity_for_entity(OLD.entity_id, pg_catalog.transaction_timestamp());
      PERFORM public.reconcile_continuity_for_entity(NEW.entity_id, pg_catalog.transaction_timestamp());
    ELSE
      PERFORM public.reconcile_continuity_for_entity(NEW.entity_id, pg_catalog.transaction_timestamp());
      PERFORM public.reconcile_continuity_for_entity(OLD.entity_id, pg_catalog.transaction_timestamp());
    END IF;
  ELSIF TG_OP = 'DELETE' THEN
    PERFORM public.reconcile_continuity_for_entity(OLD.entity_id, pg_catalog.transaction_timestamp());
  ELSE
    PERFORM public.reconcile_continuity_for_entity(NEW.entity_id, pg_catalog.transaction_timestamp());
  END IF;

  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$continuity_dispute_guard$;

REVOKE ALL ON FUNCTION public.guard_active_dispute_continuity()
  FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS continuity_dispute_entity_lock ON public.disputes;
CREATE TRIGGER continuity_dispute_entity_lock
BEFORE INSERT OR DELETE OR UPDATE OF status, entity_id ON public.disputes
FOR EACH ROW
EXECUTE FUNCTION public.lock_continuity_dispute_entity();

DROP TRIGGER IF EXISTS continuity_active_dispute_guard ON public.disputes;
CREATE TRIGGER continuity_active_dispute_guard
AFTER INSERT OR DELETE OR UPDATE OF status, entity_id ON public.disputes
FOR EACH ROW
EXECUTE FUNCTION public.guard_active_dispute_continuity();

-- Existing active disputes predate the triggers. Reconcile them immediately
-- in stable entity order so migration completion cannot leave a pending claim
-- beside an open, under-review, or appealed dispute. Re-running this block is
-- idempotent because already-correct blocker/status pairs do not emit writes.
DO $continuity_backfill$
DECLARE
  v_entity_id UUID;
BEGIN
  FOR v_entity_id IN
    SELECT DISTINCT dispute.entity_id
      FROM public.disputes AS dispute
     WHERE public.is_active_continuity_dispute_status(dispute.status)
     ORDER BY dispute.entity_id
  LOOP
    PERFORM public.reconcile_continuity_for_entity(
      v_entity_id,
      pg_catalog.transaction_timestamp()
    );
  END LOOP;
END;
$continuity_backfill$;

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
AS $continuity_resolution$
DECLARE
  v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
  v_claim_probe RECORD;
  v_claim public.continuity_claims%ROWTYPE;
  v_old_entity public.entities%ROWTYPE;
  v_new_entity public.entities%ROWTYPE;
  v_active_disputes BIGINT;
  v_reconciliation JSONB;
  v_transfer_policy TEXT;
  v_claim_status TEXT;
BEGIN
  IF p_continuity_id IS NULL OR pg_catalog.btrim(p_continuity_id) = '' THEN
    RETURN pg_catalog.jsonb_build_object('error', 'continuity_id is required', 'status', 400);
  END IF;
  IF p_decision IS NULL OR p_decision NOT IN ('approved_full', 'approved_partial', 'rejected', 'rejected_laundering') THEN
    RETURN pg_catalog.jsonb_build_object('error', 'Unsupported continuity decision', 'status', 400);
  END IF;
  IF p_reasoning IS NULL OR pg_catalog.jsonb_typeof(p_reasoning) <> 'array' THEN
    RETURN pg_catalog.jsonb_build_object('error', 'reasoning must be an array', 'status', 400);
  END IF;
  IF p_operator_id IS NULL OR pg_catalog.btrim(p_operator_id) = '' THEN
    RETURN pg_catalog.jsonb_build_object('error', 'Authenticated operator identity is required', 'status', 400);
  END IF;

  -- Probe only for the immutable old endpoint needed to choose the lock. The
  -- authoritative claim state is re-read FOR UPDATE after serialization.
  SELECT claim.old_entity_id, claim.new_entity_id
    INTO v_claim_probe
    FROM public.continuity_claims AS claim
   WHERE claim.continuity_id = p_continuity_id;

  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('error', 'Continuity claim not found', 'status', 404);
  END IF;

  SELECT entity.*
    INTO v_old_entity
    FROM public.entities AS entity
   WHERE entity.entity_id = v_claim_probe.old_entity_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'CONTINUITY_OLD_ENTITY_NOT_FOUND';
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
  IF v_claim.status IN (
    'approved_full', 'approved_partial', 'rejected', 'expired', 'withdrawn'
  ) THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', pg_catalog.format('Claim already resolved: %s', v_claim.status),
      'status', 409
    );
  END IF;

  -- Freeze endpoint ownership for the whole decision transaction. Both rows
  -- take exclusive row locks in stable public-id order after the claim lock;
  -- this avoids lock-upgrade cycles with inverse continuity resolutions.
  PERFORM endpoint.id
    FROM public.entities AS endpoint
   WHERE endpoint.entity_id IN (
     v_claim.old_entity_id,
     v_claim.new_entity_id
   )
   ORDER BY endpoint.entity_id
   FOR UPDATE;

  SELECT endpoint.*
    INTO v_old_entity
    FROM public.entities AS endpoint
   WHERE endpoint.entity_id = v_claim.old_entity_id;

  SELECT endpoint.*
    INTO v_new_entity
    FROM public.entities AS endpoint
   WHERE endpoint.entity_id = v_claim.new_entity_id;

  IF v_old_entity.id IS NULL OR v_new_entity.id IS NULL THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Continuity endpoint entity not found during resolution',
      'status', 409
    );
  END IF;
  IF v_old_entity.principal_id IS DISTINCT FROM v_claim.principal_id THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Old continuity endpoint ownership changed; resolution refused',
      'status', 409
    );
  END IF;
  IF v_new_entity.principal_id IS NOT NULL
      AND v_new_entity.principal_id IS DISTINCT FROM v_claim.principal_id THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'New continuity endpoint is controlled by another principal; resolution refused',
      'status', 409
    );
  END IF;

  SELECT pg_catalog.count(*)
    INTO v_active_disputes
    FROM public.disputes AS dispute
   WHERE dispute.entity_id = v_old_entity.id
     AND public.is_active_continuity_dispute_status(dispute.status);

  IF v_active_disputes > 0 THEN
    -- Heal any pre-migration non-frozen row while refusing resolution. This
    -- helper is re-entrant under the advisory lock and writes its audit in the
    -- same transaction.
    v_reconciliation := public.reconcile_continuity_for_entity(v_old_entity.id, v_now);
    RETURN pg_catalog.jsonb_build_object(
      'error', pg_catalog.format('Claim is frozen behind %s active dispute(s)', v_active_disputes),
      'status', 409,
      'frozen', TRUE,
      'active_disputes', v_active_disputes,
      'blocker_dispute_id', v_reconciliation ->> 'blocker_dispute_id'
    );
  END IF;

  v_transfer_policy := CASE p_decision
    WHEN 'approved_full' THEN 'full'
    WHEN 'approved_partial' THEN 'partial'
    WHEN 'rejected_laundering' THEN 'rejected_laundering'
    ELSE 'none'
  END;
  -- rejected_laundering is a decision and transfer-policy value; the claim
  -- state machine records the terminal status as rejected.
  v_claim_status := CASE
    WHEN p_decision = 'rejected_laundering' THEN 'rejected'
    ELSE p_decision
  END;

  INSERT INTO public.continuity_decisions (
    continuity_id,
    decision,
    transfer_policy,
    allocation_rule,
    reasoning,
    decided_by
  ) VALUES (
    p_continuity_id,
    p_decision,
    v_transfer_policy,
    CASE
      WHEN v_claim.continuity_mode = 'fission'
        THEN pg_catalog.jsonb_build_object('budget', COALESCE(v_claim.transfer_budget, 1.0))
      ELSE NULL
    END,
    p_reasoning,
    p_operator_id
  );

  UPDATE public.continuity_claims
     SET status = v_claim_status,
         transfer_policy = v_transfer_policy,
         frozen_due_to = NULL,
         frozen_dispute_id = NULL,
         updated_at = v_now
   WHERE id = v_claim.id;

  IF p_decision IN ('approved_full', 'approved_partial') THEN
    UPDATE public.entities
       SET principal_id = v_claim.principal_id,
           principal_linked_at = v_now
     WHERE id = v_new_entity.id
       AND (principal_id IS NULL OR principal_id = v_claim.principal_id);

    IF NOT FOUND THEN
      RAISE EXCEPTION 'CONTINUITY_NEW_ENTITY_NOT_FOUND';
    END IF;
  END IF;

  INSERT INTO public.audit_events (
    event_type, actor_id, actor_type, target_type, target_id, action,
    before_state, after_state
  ) VALUES (
    'continuity.resolved', p_operator_id, 'operator', 'continuity',
    p_continuity_id, 'resolve',
    pg_catalog.jsonb_build_object('status', v_claim.status),
    pg_catalog.jsonb_build_object(
      'status', v_claim_status,
      'decision', p_decision,
      'transfer_policy', v_transfer_policy
    )
  );

  RETURN pg_catalog.jsonb_build_object(
    'continuity_id', p_continuity_id,
    'decision', p_decision,
    'resolved_at', v_now
  );
END;
$continuity_resolution$;

REVOKE ALL ON FUNCTION public.resolve_continuity_atomic(TEXT, TEXT, JSONB, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.resolve_continuity_atomic(TEXT, TEXT, JSONB, TEXT)
  TO service_role;

CREATE OR REPLACE FUNCTION public.challenge_continuity_atomic(
  p_continuity_id TEXT,
  p_challenge_id TEXT,
  p_challenger_id TEXT,
  p_reason TEXT,
  p_evidence JSONB DEFAULT '{}'::JSONB,
  p_enterprise_admin_authorized BOOLEAN DEFAULT FALSE
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $continuity_challenge$
DECLARE
  v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
  v_claim public.continuity_claims%ROWTYPE;
  v_claim_principal public.principals%ROWTYPE;
  v_actor public.entities%ROWTYPE;
  v_old_entity public.entities%ROWTYPE;
  v_new_entity public.entities%ROWTYPE;
  v_challenge public.continuity_challenges%ROWTYPE;
  v_challenger_type TEXT;
  v_actor_type TEXT;
  v_open_challenges BIGINT;
BEGIN
  IF p_continuity_id IS NULL OR pg_catalog.btrim(p_continuity_id) = '' THEN
    RETURN pg_catalog.jsonb_build_object('error', 'continuity_id is required', 'status', 400);
  END IF;
  IF p_challenge_id IS NULL OR pg_catalog.btrim(p_challenge_id) = '' THEN
    RETURN pg_catalog.jsonb_build_object('error', 'challenge_id is required', 'status', 400);
  END IF;
  IF p_challenger_id IS NULL OR pg_catalog.btrim(p_challenger_id) = '' THEN
    RETURN pg_catalog.jsonb_build_object('error', 'Authenticated challenger identity is required', 'status', 400);
  END IF;
  IF p_reason IS NULL OR pg_catalog.btrim(p_reason) = '' THEN
    RETURN pg_catalog.jsonb_build_object('error', 'reason is required', 'status', 400);
  END IF;
  IF p_evidence IS NULL OR pg_catalog.jsonb_typeof(p_evidence) <> 'object' THEN
    RETURN pg_catalog.jsonb_build_object('error', 'evidence must be an object', 'status', 400);
  END IF;

  -- Every challenge for one claim serializes on the claim row before reading
  -- mutable state, counting challenges, or deriving a relationship-backed role.
  SELECT claim.*
    INTO v_claim
    FROM public.continuity_claims AS claim
   WHERE claim.continuity_id = p_continuity_id
   FOR UPDATE;

  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('error', 'Continuity claim not found', 'status', 404);
  END IF;
  IF v_claim.status NOT IN ('pending', 'under_challenge') THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', pg_catalog.format('Claim status is %L, not challengeable', v_claim.status),
      'status', 409
    );
  END IF;
  IF v_claim.challenge_deadline IS NOT NULL AND v_claim.challenge_deadline <= v_now THEN
    RETURN pg_catalog.jsonb_build_object('error', 'Challenge window has expired', 'status', 410);
  END IF;

  SELECT principal.*
    INTO v_claim_principal
    FROM public.principals AS principal
   WHERE principal.id = v_claim.principal_id
   FOR SHARE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'CONTINUITY_CLAIM_PRINCIPAL_NOT_FOUND';
  END IF;

  -- The actor is resolved from the authenticated entity id. No role string is
  -- accepted by this function, so the caller cannot choose an audit identity.
  SELECT actor.*
    INTO v_actor
    FROM public.entities AS actor
   WHERE actor.entity_id = p_challenger_id
     AND actor.status = 'active'
   FOR SHARE;

  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('error', 'Authenticated challenger entity not found', 'status', 403);
  END IF;

  SELECT endpoint.*
    INTO v_old_entity
    FROM public.entities AS endpoint
   WHERE endpoint.entity_id = v_claim.old_entity_id;

  SELECT endpoint.*
    INTO v_new_entity
    FROM public.entities AS endpoint
   WHERE endpoint.entity_id = v_claim.new_entity_id;

  -- Deny both ownership-graph delegates and the route identity that filed the
  -- claim. A filing identity may be represented by entity_id while its entity
  -- row is unlinked or linked to a different principal UUID.
  IF v_actor.principal_id = v_claim.principal_id
      OR v_actor.entity_id = v_claim_principal.principal_id THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Principal cannot challenge their own continuity claim',
      'status', 403
    );
  END IF;

  -- Derivation order is privilege first, then exact claim relationships.
  -- enterprise_admin_authorized is server-derived from the authenticated API
  -- key and is still constrained to an endpoint organization here.
  IF v_actor.is_operator THEN
    v_challenger_type := 'operator';
    v_actor_type := 'operator';
  ELSIF p_enterprise_admin_authorized
      AND v_actor.organization_id IS NOT NULL
      AND (
        v_actor.organization_id = v_old_entity.organization_id
        OR v_actor.organization_id = v_new_entity.organization_id
      ) THEN
    v_challenger_type := 'enterprise_admin';
    v_actor_type := 'entity';
  ELSIF v_actor.entity_id = v_claim.old_entity_id THEN
    -- This is principally a legacy-claim recovery path. Newly filed claims
    -- already require the filing principal to own both endpoints.
    v_challenger_type := 'old_entity_controller';
    v_actor_type := 'entity';
  ELSIF EXISTS (
    SELECT 1
      FROM public.disputes AS dispute
     WHERE dispute.filed_by = v_actor.id
       AND dispute.entity_id IN (v_old_entity.id, v_new_entity.id)
       AND (
         public.is_active_continuity_dispute_status(dispute.status)
         OR dispute.status = 'upheld'
       )
  ) THEN
    v_challenger_type := 'dispute_counterparty';
    v_actor_type := 'entity';
  ELSIF v_actor.principal_id IS NOT NULL AND EXISTS (
    SELECT 1
      FROM public.identity_bindings AS binding
     WHERE binding.principal_id = v_actor.principal_id
       AND binding.status = 'verified'
       AND (binding.expires_at IS NULL OR binding.expires_at > v_now)
       AND binding.binding_type IN (
         'domain_control', 'github_org', 'npm_publisher', 'chrome_store',
         'shopify_store', 'mcp_server', 'marketplace_account', 'enterprise_oidc'
       )
       AND pg_catalog.lower(binding.binding_target) IN (
         pg_catalog.lower(v_claim.old_entity_id),
         pg_catalog.lower(v_claim.new_entity_id),
         pg_catalog.lower(COALESCE(v_old_entity.website_url, '')),
         pg_catalog.lower(COALESCE(v_new_entity.website_url, ''))
       )
  ) THEN
    v_challenger_type := 'bound_host';
    v_actor_type := 'entity';
  ELSE
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Authenticated entity has no verified challenger relationship to this claim',
      'status', 403
    );
  END IF;

  SELECT pg_catalog.count(*)
    INTO v_open_challenges
    FROM public.continuity_challenges AS challenge
   WHERE challenge.continuity_id = p_continuity_id
     AND challenge.status IN ('open', 'reviewed');

  IF v_open_challenges >= 5 THEN
    RETURN pg_catalog.jsonb_build_object(
      'error', 'Maximum open challenges (5) already exist for this claim',
      'status', 429
    );
  END IF;

  INSERT INTO public.continuity_challenges (
    challenge_id,
    continuity_id,
    challenger_type,
    challenger_id,
    reason,
    evidence
  ) VALUES (
    p_challenge_id,
    p_continuity_id,
    v_challenger_type,
    v_actor.entity_id,
    p_reason,
    p_evidence
  )
  RETURNING * INTO STRICT v_challenge;

  IF v_claim.status = 'pending' THEN
    UPDATE public.continuity_claims
       SET status = 'under_challenge',
           updated_at = v_now
     WHERE id = v_claim.id
       AND status = 'pending';

    IF NOT FOUND THEN
      RAISE EXCEPTION 'CONTINUITY_CLAIM_STATE_RACE';
    END IF;
  END IF;

  INSERT INTO public.audit_events (
    event_type,
    actor_id,
    actor_type,
    target_type,
    target_id,
    action,
    before_state,
    after_state
  ) VALUES (
    'continuity.challenged',
    v_actor.entity_id,
    v_actor_type,
    'continuity',
    p_continuity_id,
    'challenge',
    pg_catalog.jsonb_build_object('status', v_claim.status),
    pg_catalog.jsonb_build_object(
      'status', 'under_challenge',
      'challenger_role', v_challenger_type
    )
  );

  RETURN pg_catalog.jsonb_build_object('challenge', pg_catalog.to_jsonb(v_challenge));
END;
$continuity_challenge$;

REVOKE ALL ON FUNCTION public.challenge_continuity_atomic(
  TEXT, TEXT, TEXT, TEXT, JSONB, BOOLEAN
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.challenge_continuity_atomic(
  TEXT, TEXT, TEXT, TEXT, JSONB, BOOLEAN
) TO service_role;
