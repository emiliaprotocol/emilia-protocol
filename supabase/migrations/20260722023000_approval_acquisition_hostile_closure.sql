-- EMILIA Protocol — EP-APPROVAL-v1 hostile-finding closure.
--
-- Forward-only expansion of 20260721171500. The committed migration remains
-- immutable. This migration separates the provider-entry boundary, preserves
-- indeterminate recovery across envelope-key retirement, scopes idempotency to
-- tenant/environment/logical request rather than a rotating API key, and binds
-- recovery to the exact append-only Guard evidence.

ALTER TABLE public.approval_acquisition_requests
  ADD COLUMN poll_token_key_id text;
UPDATE public.approval_acquisition_requests
SET poll_token_key_id = 'legacy-v1'
WHERE poll_token_key_id IS NULL;
ALTER TABLE public.approval_acquisition_requests
  ALTER COLUMN poll_token_key_id SET NOT NULL,
  ADD CONSTRAINT approval_acquisition_poll_token_key_id_check
    CHECK (poll_token_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$'),
  ADD CONSTRAINT approval_acquisition_poll_token_envelope_check
    CHECK (
      (poll_token_key_id = 'legacy-v1'
        AND poll_token_ciphertext ~ '^[A-Za-z0-9_-]+$'
        AND pg_catalog.char_length(poll_token_ciphertext) BETWEEN 16 AND 512)
      OR (poll_token_ciphertext ~ '^epat1[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+$'
        AND pg_catalog.char_length(poll_token_ciphertext) BETWEEN 24 AND 512)
    ),
  ADD COLUMN reconciliation_state text NOT NULL DEFAULT 'not_required',
  ADD COLUMN producer_key_id text,
  ADD COLUMN refusal_code text,
  ADD COLUMN indeterminate_at timestamptz,
  ADD COLUMN reconciled_at timestamptz,
  ADD COLUMN refused_at timestamptz;

-- Rows that completed under the original schema necessarily used the original
-- authenticated requester as their producer. Initializing rows have not yet
-- crossed the producer boundary and remain unbound until the boundary RPC.
UPDATE public.approval_acquisition_requests
SET producer_key_id = requester_key_id
WHERE status = 'pending';

DO $$
DECLARE
  v_constraint record;
BEGIN
  FOR v_constraint IN
    SELECT constraint_row.conname
    FROM pg_catalog.pg_constraint AS constraint_row
    WHERE constraint_row.conrelid = 'public.approval_acquisition_requests'::regclass
      AND (
        (constraint_row.contype = 'c'
          AND pg_catalog.pg_get_constraintdef(constraint_row.oid) LIKE '%status = ANY%')
        OR (constraint_row.contype = 'c'
          AND pg_catalog.pg_get_constraintdef(constraint_row.oid) LIKE '%status%'
          AND pg_catalog.pg_get_constraintdef(constraint_row.oid) LIKE '%receipt_id%')
        OR (constraint_row.contype = 'c'
          AND pg_catalog.pg_get_constraintdef(constraint_row.oid) LIKE '%receipt_action_hash%sha256%')
        OR (constraint_row.contype = 'u'
          AND pg_catalog.pg_get_constraintdef(constraint_row.oid)
            = 'UNIQUE (tenant_id, environment, requester_key_id, idempotency_digest)')
      )
  LOOP
    EXECUTE format(
      'ALTER TABLE public.approval_acquisition_requests DROP CONSTRAINT %I',
      v_constraint.conname
    );
  END LOOP;
END;
$$;

ALTER TABLE public.approval_acquisition_requests
  ADD CONSTRAINT approval_acquisition_producer_key_id_check
    CHECK (producer_key_id IS NULL OR pg_catalog.octet_length(producer_key_id) BETWEEN 1 AND 256),
  ADD CONSTRAINT approval_acquisition_status_check
    CHECK (status IN ('initializing', 'invoking', 'indeterminate', 'pending', 'refused')),
  ADD CONSTRAINT approval_acquisition_reconciliation_state_check
    CHECK (reconciliation_state IN ('not_required', 'required', 'reconciled')),
  ADD CONSTRAINT approval_acquisition_receipt_action_hash_check
    CHECK (receipt_action_hash IS NULL OR receipt_action_hash ~ '^[a-f0-9]{64}$'),
  ADD CONSTRAINT approval_acquisition_state_shape_check
    CHECK (
      (status = 'initializing'
        AND reconciliation_state = 'not_required'
        AND producer_key_id IS NULL
        AND receipt_id IS NULL AND signoff_id IS NULL AND receipt_action_hash IS NULL
        AND indeterminate_at IS NULL AND reconciled_at IS NULL
        AND refusal_code IS NULL AND refused_at IS NULL)
      OR (status = 'invoking'
        AND reconciliation_state = 'not_required'
        AND producer_key_id IS NOT NULL
        AND receipt_id IS NULL AND signoff_id IS NULL AND receipt_action_hash IS NULL
        AND indeterminate_at IS NULL AND reconciled_at IS NULL
        AND refusal_code IS NULL AND refused_at IS NULL)
      OR (status = 'indeterminate'
        AND reconciliation_state = 'required'
        AND producer_key_id IS NOT NULL
        AND receipt_id IS NULL AND signoff_id IS NULL AND receipt_action_hash IS NULL
        AND indeterminate_at IS NOT NULL AND reconciled_at IS NULL
        AND refusal_code IS NULL AND refused_at IS NULL)
      OR (status = 'pending'
        AND producer_key_id IS NOT NULL
        AND receipt_id IS NOT NULL AND signoff_id IS NOT NULL AND receipt_action_hash IS NOT NULL
        AND refusal_code IS NULL AND refused_at IS NULL
        AND (
          (reconciliation_state = 'not_required'
            AND indeterminate_at IS NULL AND reconciled_at IS NULL)
          OR (reconciliation_state = 'reconciled'
            AND indeterminate_at IS NOT NULL AND reconciled_at IS NOT NULL)
        ))
      OR (status = 'refused'
        AND reconciliation_state = 'not_required'
        AND producer_key_id IS NOT NULL
        AND receipt_id IS NULL AND signoff_id IS NULL AND receipt_action_hash IS NULL
        AND indeterminate_at IS NULL AND reconciled_at IS NULL
        AND refusal_code IS NOT NULL AND refused_at IS NOT NULL)
    );

CREATE UNIQUE INDEX approval_acquisition_logical_idempotency_active
  ON public.approval_acquisition_requests
    (tenant_id, environment, idempotency_digest)
  WHERE status <> 'refused';

REVOKE ALL ON FUNCTION public.reserve_approval_acquisition_request(
  text, uuid, text, text, text, text, text, text, text, jsonb, text,
  text, text, text, text, timestamptz
) FROM PUBLIC, anon, authenticated, service_role;
DROP FUNCTION public.reserve_approval_acquisition_request(
  text, uuid, text, text, text, text, text, text, text, jsonb, text,
  text, text, text, text, timestamptz
);

CREATE FUNCTION public.reserve_approval_acquisition_request(
  p_request_id text,
  p_tenant_id uuid,
  p_environment text,
  p_requester_key_id text,
  p_idempotency_digest text,
  p_request_digest text,
  p_challenge_hash text,
  p_action_hash text,
  p_action_caid text,
  p_action jsonb,
  p_approver_id text,
  p_poll_token_hash text,
  p_poll_token_key_id text,
  p_poll_token_ciphertext text,
  p_poll_token_iv text,
  p_poll_token_tag text,
  p_expires_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_row public.approval_acquisition_requests%ROWTYPE;
BEGIN
  INSERT INTO public.approval_acquisition_requests (
    request_id, tenant_id, environment, requester_key_id,
    idempotency_digest, request_digest, challenge_hash,
    action_hash, action_caid, action, approver_id,
    poll_token_hash, poll_token_key_id, poll_token_ciphertext,
    poll_token_iv, poll_token_tag, expires_at
  ) VALUES (
    p_request_id, p_tenant_id, p_environment, p_requester_key_id,
    p_idempotency_digest, p_request_digest, p_challenge_hash,
    p_action_hash, p_action_caid, p_action, p_approver_id,
    p_poll_token_hash, p_poll_token_key_id, p_poll_token_ciphertext,
    p_poll_token_iv, p_poll_token_tag, p_expires_at
  )
  ON CONFLICT (tenant_id, environment, idempotency_digest)
    WHERE status <> 'refused'
  DO NOTHING
  RETURNING * INTO v_row;

  IF FOUND THEN
    RETURN jsonb_build_object('outcome', 'created', 'request', to_jsonb(v_row));
  END IF;

  SELECT * INTO v_row
  FROM public.approval_acquisition_requests
  WHERE tenant_id = p_tenant_id
    AND environment = p_environment
    AND idempotency_digest = p_idempotency_digest
    AND status <> 'refused'
  ORDER BY created_at DESC
  LIMIT 1;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'approval_acquisition_reservation_lost'
      USING ERRCODE = '40001';
  END IF;
  IF v_row.request_digest <> p_request_digest THEN
    RETURN jsonb_build_object('outcome', 'conflict');
  END IF;
  RETURN jsonb_build_object('outcome', 'existing', 'request', to_jsonb(v_row));
END;
$$;

CREATE FUNCTION public.enter_approval_acquisition_boundary(
  p_request_id text,
  p_request_digest text,
  p_producer_key_id text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  UPDATE public.approval_acquisition_requests
  SET status = 'invoking',
      producer_key_id = p_producer_key_id,
      updated_at = statement_timestamp()
  WHERE request_id = p_request_id AND status = 'initializing'
    AND request_digest = p_request_digest
    AND EXISTS (
      SELECT 1
      FROM public.tenant_api_keys AS producer_key
      WHERE producer_key.key_id::text = p_producer_key_id
        AND producer_key.tenant_id = approval_acquisition_requests.tenant_id
        AND producer_key.environment = approval_acquisition_requests.environment
        AND producer_key.created_at <= statement_timestamp()
        AND (producer_key.expires_at IS NULL OR producer_key.expires_at > statement_timestamp())
        AND producer_key.revoked_at IS NULL
    );
  RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION public.complete_approval_acquisition_request(
  p_request_id text,
  p_request_digest text,
  p_receipt_id text,
  p_signoff_id text,
  p_receipt_action_hash text,
  p_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_row public.approval_acquisition_requests%ROWTYPE;
  v_created_count integer;
  v_request_count integer;
BEGIN
  SELECT * INTO v_row
  FROM public.approval_acquisition_requests
  WHERE request_id = p_request_id
  FOR UPDATE;

  IF NOT FOUND OR v_row.request_digest <> p_request_digest THEN
    RETURN false;
  END IF;
  IF v_row.status = 'pending' THEN
    RETURN v_row.receipt_id = p_receipt_id
      AND v_row.signoff_id = p_signoff_id
      AND v_row.receipt_action_hash = p_receipt_action_hash
      AND v_row.expires_at = LEAST(v_row.expires_at, p_expires_at);
  END IF;
  IF v_row.status <> 'invoking' OR p_receipt_action_hash !~ '^[a-f0-9]{64}$' THEN
    RETURN false;
  END IF;

  SELECT count(*) INTO v_created_count
  FROM public.audit_events AS event
  WHERE event.event_type = 'guard.trust_receipt.created'
    AND event.target_type = 'trust_receipt'
    AND event.target_id = p_receipt_id
    AND event.actor_id = 'ep:cloud-key:' || v_row.producer_key_id
    AND event.after_state ->> 'organization_id' = v_row.tenant_id::text
    AND event.after_state ->> 'action_type' = 'large_payment_release'
    AND event.after_state ->> 'action_hash' = p_receipt_action_hash
    AND event.after_state ->> 'acquisition_request_id' = v_row.request_id
    AND event.after_state ->> 'acquisition_request_digest' = v_row.request_digest
    AND event.after_state ->> 'acquisition_action_hash' = v_row.action_hash
    AND event.after_state ->> 'acquisition_action_caid' = v_row.action_caid
    AND event.after_state ->> 'acquisition_challenge_hash' = v_row.challenge_hash
    AND event.after_state ->> 'acquisition_tenant_id' = v_row.tenant_id::text
    AND event.after_state ->> 'acquisition_environment' = v_row.environment
    AND event.after_state #>> '{canonical_action,acquisition_scope,tenant_id}' = v_row.tenant_id::text
    AND event.after_state #>> '{canonical_action,acquisition_scope,environment}' = v_row.environment
    AND event.after_state #>> '{canonical_action,acquisition_scope,request_id}' = v_row.request_id
    AND event.after_state #>> '{canonical_action,acquisition_scope,request_digest}' = v_row.request_digest;

  SELECT count(*) INTO v_request_count
  FROM public.audit_events AS event
  WHERE event.event_type = 'guard.signoff.requested'
    AND event.target_type = 'trust_receipt'
    AND event.target_id = p_receipt_id
    AND event.actor_id = 'ep:cloud-key:' || v_row.producer_key_id
    AND event.after_state ->> 'signoff_id' = p_signoff_id
    AND event.after_state ->> 'approver_id' = v_row.approver_id
    AND event.after_state ->> 'action_hash' = p_receipt_action_hash
    AND event.after_state ->> 'acquisition_request_id' = v_row.request_id
    AND event.after_state ->> 'acquisition_request_digest' = v_row.request_digest
    AND event.after_state ->> 'acquisition_tenant_id' = v_row.tenant_id::text
    AND event.after_state ->> 'acquisition_environment' = v_row.environment;

  IF v_created_count <> 1 OR v_request_count <> 1 THEN
    RETURN false;
  END IF;

  UPDATE public.approval_acquisition_requests
  SET status = 'pending',
      reconciliation_state = 'not_required',
      receipt_id = p_receipt_id,
      signoff_id = p_signoff_id,
      receipt_action_hash = p_receipt_action_hash,
      expires_at = LEAST(expires_at, p_expires_at),
      updated_at = statement_timestamp()
  WHERE request_id = p_request_id AND status = 'invoking';
  RETURN FOUND;
END;
$$;

CREATE FUNCTION public.reconcile_approval_acquisition_request(
  p_request_id text,
  p_request_digest text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_row public.approval_acquisition_requests%ROWTYPE;
  v_created_count integer;
  v_request_count integer;
  v_receipt_id text;
  v_receipt_action_hash text;
  v_signoff_id text;
BEGIN
  SELECT * INTO v_row
  FROM public.approval_acquisition_requests
  WHERE request_id = p_request_id
  FOR UPDATE;

  IF NOT FOUND OR v_row.request_digest <> p_request_digest THEN
    RETURN jsonb_build_object('outcome', 'mismatch');
  END IF;
  IF v_row.status = 'pending' THEN
    RETURN jsonb_build_object('outcome', 'pending', 'request', to_jsonb(v_row));
  END IF;
  IF v_row.status = 'initializing' THEN
    RETURN jsonb_build_object('outcome', 'pre_boundary', 'request', to_jsonb(v_row));
  END IF;
  IF v_row.status = 'refused' THEN
    RETURN jsonb_build_object('outcome', 'refused', 'request', to_jsonb(v_row));
  END IF;
  IF v_row.status = 'invoking' THEN
    UPDATE public.approval_acquisition_requests
    SET status = 'indeterminate',
        reconciliation_state = 'required',
        indeterminate_at = COALESCE(indeterminate_at, statement_timestamp()),
        updated_at = statement_timestamp()
    WHERE request_id = p_request_id AND status = 'invoking'
    RETURNING * INTO v_row;
  END IF;

  SELECT count(*), min(event.target_id), min(event.after_state ->> 'action_hash')
  INTO v_created_count, v_receipt_id, v_receipt_action_hash
  FROM public.audit_events AS event
  WHERE event.event_type = 'guard.trust_receipt.created'
    AND event.target_type = 'trust_receipt'
    AND event.target_id ~ '^tr_[a-f0-9]{32}$'
    AND event.actor_id = 'ep:cloud-key:' || v_row.producer_key_id
    AND event.after_state ->> 'organization_id' = v_row.tenant_id::text
    AND event.after_state ->> 'action_type' = 'large_payment_release'
    AND event.after_state ->> 'action_hash' ~ '^[a-f0-9]{64}$'
    AND event.after_state ->> 'acquisition_request_id' = v_row.request_id
    AND event.after_state ->> 'acquisition_request_digest' = v_row.request_digest
    AND event.after_state ->> 'acquisition_action_hash' = v_row.action_hash
    AND event.after_state ->> 'acquisition_action_caid' = v_row.action_caid
    AND event.after_state ->> 'acquisition_challenge_hash' = v_row.challenge_hash
    AND event.after_state ->> 'acquisition_tenant_id' = v_row.tenant_id::text
    AND event.after_state ->> 'acquisition_environment' = v_row.environment
    AND event.after_state #>> '{canonical_action,acquisition_scope,tenant_id}' = v_row.tenant_id::text
    AND event.after_state #>> '{canonical_action,acquisition_scope,environment}' = v_row.environment
    AND event.after_state #>> '{canonical_action,acquisition_scope,request_id}' = v_row.request_id
    AND event.after_state #>> '{canonical_action,acquisition_scope,request_digest}' = v_row.request_digest;

  IF v_created_count <> 1 THEN
    RETURN jsonb_build_object('outcome', 'indeterminate', 'request', to_jsonb(v_row));
  END IF;

  SELECT count(*), min(event.after_state ->> 'signoff_id')
  INTO v_request_count, v_signoff_id
  FROM public.audit_events AS event
  WHERE event.event_type = 'guard.signoff.requested'
    AND event.target_type = 'trust_receipt'
    AND event.target_id = v_receipt_id
    AND event.actor_id = 'ep:cloud-key:' || v_row.producer_key_id
    AND event.after_state ->> 'signoff_id' ~ '^sig_[a-f0-9]{32}$'
    AND event.after_state ->> 'approver_id' = v_row.approver_id
    AND event.after_state ->> 'action_hash' = v_receipt_action_hash
    AND event.after_state ->> 'acquisition_request_id' = v_row.request_id
    AND event.after_state ->> 'acquisition_request_digest' = v_row.request_digest
    AND event.after_state ->> 'acquisition_tenant_id' = v_row.tenant_id::text
    AND event.after_state ->> 'acquisition_environment' = v_row.environment;

  IF v_request_count <> 1 THEN
    RETURN jsonb_build_object('outcome', 'indeterminate', 'request', to_jsonb(v_row));
  END IF;

  UPDATE public.approval_acquisition_requests
  SET status = 'pending',
      reconciliation_state = 'reconciled',
      receipt_id = v_receipt_id,
      signoff_id = v_signoff_id,
      receipt_action_hash = v_receipt_action_hash,
      reconciled_at = statement_timestamp(),
      updated_at = statement_timestamp()
  WHERE request_id = p_request_id AND status = 'indeterminate'
  RETURNING * INTO v_row;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'approval_acquisition_reconciliation_lost'
      USING ERRCODE = '40001';
  END IF;
  RETURN jsonb_build_object('outcome', 'reconciled', 'request', to_jsonb(v_row));
END;
$$;

CREATE FUNCTION public.refuse_approval_acquisition_request(
  p_request_id text,
  p_request_digest text,
  p_refusal_code text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_row public.approval_acquisition_requests%ROWTYPE;
  v_created_count integer;
BEGIN
  IF p_refusal_code !~ '^[a-z][a-z0-9_]{2,127}$' THEN
    RETURN false;
  END IF;
  SELECT * INTO v_row
  FROM public.approval_acquisition_requests
  WHERE request_id = p_request_id
  FOR UPDATE;
  IF NOT FOUND OR v_row.request_digest <> p_request_digest
      OR v_row.status NOT IN ('initializing', 'invoking') THEN
    RETURN false;
  END IF;

  SELECT count(*) INTO v_created_count
  FROM public.audit_events AS event
  WHERE event.event_type = 'guard.trust_receipt.created'
    AND event.after_state ->> 'acquisition_request_id' = v_row.request_id
    AND event.after_state ->> 'acquisition_request_digest' = v_row.request_digest;

  IF v_created_count = 0 THEN
    UPDATE public.approval_acquisition_requests
    SET status = 'refused',
        refusal_code = p_refusal_code,
        refused_at = statement_timestamp(),
        updated_at = statement_timestamp()
    WHERE request_id = p_request_id
      AND status IN ('initializing', 'invoking');
    RETURN FOUND;
  END IF;
  RETURN false;
END;
$$;

CREATE FUNCTION public.recover_approval_acquisition_poll_token(
  p_request_id text,
  p_request_digest text,
  p_tenant_id uuid,
  p_environment text,
  p_requester_key_id text,
  p_idempotency_digest text,
  p_previous_poll_token_hash text,
  p_previous_poll_token_key_id text,
  p_poll_token_hash text,
  p_poll_token_key_id text,
  p_poll_token_ciphertext text,
  p_poll_token_iv text,
  p_poll_token_tag text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  UPDATE public.approval_acquisition_requests
  SET poll_token_hash = p_poll_token_hash,
      poll_token_key_id = p_poll_token_key_id,
      poll_token_ciphertext = p_poll_token_ciphertext,
      poll_token_iv = p_poll_token_iv,
      poll_token_tag = p_poll_token_tag,
      updated_at = statement_timestamp()
  WHERE request_id = p_request_id
    AND request_digest = p_request_digest
    AND tenant_id = p_tenant_id
    AND environment = p_environment
    AND requester_key_id = p_requester_key_id
    AND idempotency_digest = p_idempotency_digest
    AND poll_token_hash = p_previous_poll_token_hash
    AND poll_token_key_id = p_previous_poll_token_key_id
    AND status IN ('initializing', 'invoking', 'indeterminate', 'pending');
  RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION public.reserve_approval_acquisition_request(
  text, uuid, text, text, text, text, text, text, text, jsonb, text,
  text, text, text, text, text, timestamptz
) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.enter_approval_acquisition_boundary(text, text, text)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.complete_approval_acquisition_request(
  text, text, text, text, text, timestamptz
) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.reconcile_approval_acquisition_request(text, text)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.refuse_approval_acquisition_request(text, text, text)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.recover_approval_acquisition_poll_token(
  text, text, uuid, text, text, text, text, text, text, text, text, text, text
) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.reserve_approval_acquisition_request(
  text, uuid, text, text, text, text, text, text, text, jsonb, text,
  text, text, text, text, text, timestamptz
) TO service_role;
GRANT EXECUTE ON FUNCTION public.enter_approval_acquisition_boundary(text, text, text)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.complete_approval_acquisition_request(
  text, text, text, text, text, timestamptz
) TO service_role;
GRANT EXECUTE ON FUNCTION public.reconcile_approval_acquisition_request(text, text)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.refuse_approval_acquisition_request(text, text, text)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.recover_approval_acquisition_poll_token(
  text, text, uuid, text, text, text, text, text, text, text, text, text, text
) TO service_role;

COMMENT ON INDEX public.approval_acquisition_logical_idempotency_active IS
  'One active EP-APPROVAL logical request per tenant/environment/idempotency digest; requester_key_id remains immutable authenticated actor provenance.';
