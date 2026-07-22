-- EMILIA Protocol — EP-APPROVAL-v1 durable acquisition envelope.
--
-- This table stores the idempotency reservation and a recoverable AES-GCM
-- ciphertext for the 192-bit poll capability. The plaintext poll token is
-- never persisted. Trust-receipt and Class-A decision evidence remain in the
-- append-only audit_events ledger; this table only joins the acquisition
-- protocol to that existing ceremony.

CREATE TABLE public.approval_acquisition_requests (
  request_id text PRIMARY KEY
    CHECK (request_id ~ '^apr_[a-f0-9]{32}$'),
  tenant_id uuid NOT NULL
    REFERENCES public.tenants(tenant_id) ON DELETE RESTRICT,
  environment text NOT NULL
    CHECK (char_length(environment) BETWEEN 1 AND 64),
  requester_key_id text NOT NULL
    CHECK (char_length(requester_key_id) BETWEEN 1 AND 256),
  idempotency_digest text NOT NULL
    CHECK (idempotency_digest ~ '^sha256:[a-f0-9]{64}$'),
  request_digest text NOT NULL
    CHECK (request_digest ~ '^sha256:[a-f0-9]{64}$'),
  challenge_hash text NOT NULL
    CHECK (challenge_hash ~ '^sha256:[a-f0-9]{64}$'),
  action_hash text NOT NULL
    CHECK (action_hash ~ '^sha256:[a-f0-9]{64}$'),
  action_caid text NOT NULL
    CHECK (action_caid ~ '^caid:1:payment[.]release[.]1:jcs-sha256:[A-Za-z0-9_-]{43}$'),
  action jsonb NOT NULL
    CHECK (jsonb_typeof(action) = 'object'),
  approver_id text NOT NULL
    CHECK (approver_id ~ '^[A-Za-z0-9:_.@-]{3,128}$'),
  poll_token_hash text NOT NULL
    CHECK (poll_token_hash ~ '^sha256:[a-f0-9]{64}$'),
  poll_token_ciphertext text NOT NULL
    CHECK (char_length(poll_token_ciphertext) BETWEEN 16 AND 512),
  poll_token_iv text NOT NULL
    CHECK (char_length(poll_token_iv) BETWEEN 16 AND 32),
  poll_token_tag text NOT NULL
    CHECK (char_length(poll_token_tag) BETWEEN 20 AND 32),
  status text NOT NULL DEFAULT 'initializing'
    CHECK (status IN ('initializing', 'pending')),
  receipt_id text,
  signoff_id text,
  receipt_action_hash text
    CHECK (receipt_action_hash IS NULL OR receipt_action_hash ~ '^sha256:[a-f0-9]{64}$'),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  UNIQUE (tenant_id, environment, requester_key_id, idempotency_digest),
  UNIQUE (poll_token_hash),
  CHECK (
    (status = 'initializing' AND receipt_id IS NULL AND signoff_id IS NULL)
    OR (status = 'pending' AND receipt_id IS NOT NULL AND signoff_id IS NOT NULL AND receipt_action_hash IS NOT NULL)
  )
);

-- The append-only receipt event is the durable recovery anchor. One cloud key
-- can append at most one receipt for an acquisition request id, so a retry
-- after a process crash recovers evidence instead of minting a duplicate.
CREATE UNIQUE INDEX guard_approval_acquisition_receipt_once
  ON public.audit_events (actor_id, ((after_state ->> 'acquisition_request_id')))
  WHERE event_type = 'guard.trust_receipt.created'
    AND after_state ? 'acquisition_request_id';

COMMENT ON TABLE public.approval_acquisition_requests IS
  'Service-only EP-APPROVAL-v1 idempotency and poll-capability envelope. Plaintext poll tokens are never stored.';

ALTER TABLE public.approval_acquisition_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.approval_acquisition_requests FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.approval_acquisition_requests
  FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON TABLE public.approval_acquisition_requests TO service_role;

CREATE OR REPLACE FUNCTION public.reserve_approval_acquisition_request(
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
    poll_token_hash, poll_token_ciphertext, poll_token_iv, poll_token_tag,
    expires_at
  ) VALUES (
    p_request_id, p_tenant_id, p_environment, p_requester_key_id,
    p_idempotency_digest, p_request_digest, p_challenge_hash,
    p_action_hash, p_action_caid, p_action, p_approver_id,
    p_poll_token_hash, p_poll_token_ciphertext, p_poll_token_iv, p_poll_token_tag,
    p_expires_at
  )
  ON CONFLICT (tenant_id, environment, requester_key_id, idempotency_digest) DO NOTHING
  RETURNING * INTO v_row;

  IF FOUND THEN
    RETURN jsonb_build_object('outcome', 'created', 'request', to_jsonb(v_row));
  END IF;

  SELECT * INTO v_row
  FROM public.approval_acquisition_requests
  WHERE tenant_id = p_tenant_id
    AND environment = p_environment
    AND requester_key_id = p_requester_key_id
    AND idempotency_digest = p_idempotency_digest;

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

  SELECT count(*) INTO v_created_count
  FROM public.audit_events AS event
  WHERE event.event_type = 'guard.trust_receipt.created'
    AND event.target_type = 'trust_receipt'
    AND event.target_id = p_receipt_id
    AND event.actor_id = 'ep:cloud-key:' || v_row.requester_key_id
    AND event.after_state ->> 'organization_id' = v_row.tenant_id::text
    AND event.after_state ->> 'action_type' = 'large_payment_release'
    AND event.after_state ->> 'action_hash' = p_receipt_action_hash
    AND event.after_state ->> 'acquisition_request_id' = v_row.request_id
    AND event.after_state ->> 'acquisition_request_digest' = v_row.request_digest
    AND event.after_state ->> 'acquisition_action_hash' = v_row.action_hash
    AND event.after_state ->> 'acquisition_action_caid' = v_row.action_caid
    AND event.after_state ->> 'acquisition_challenge_hash' = v_row.challenge_hash;

  SELECT count(*) INTO v_request_count
  FROM public.audit_events AS event
  WHERE event.event_type = 'guard.signoff.requested'
    AND event.target_type = 'trust_receipt'
    AND event.target_id = p_receipt_id
    AND event.actor_id = 'ep:cloud-key:' || v_row.requester_key_id
    AND event.after_state ->> 'signoff_id' = p_signoff_id
    AND event.after_state ->> 'approver_id' = v_row.approver_id
    AND event.after_state ->> 'action_hash' = p_receipt_action_hash
    AND event.after_state ->> 'acquisition_request_id' = v_row.request_id
    AND event.after_state ->> 'acquisition_request_digest' = v_row.request_digest;

  IF v_created_count <> 1 OR v_request_count <> 1 THEN
    RETURN false;
  END IF;

  UPDATE public.approval_acquisition_requests
  SET status = 'pending',
      receipt_id = p_receipt_id,
      signoff_id = p_signoff_id,
      receipt_action_hash = p_receipt_action_hash,
      expires_at = LEAST(expires_at, p_expires_at),
      updated_at = statement_timestamp()
  WHERE request_id = p_request_id AND status = 'initializing';
  RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION public.reserve_approval_acquisition_request(
  text, uuid, text, text, text, text, text, text, text, jsonb, text,
  text, text, text, text, timestamptz
) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.complete_approval_acquisition_request(
  text, text, text, text, text, timestamptz
) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.reserve_approval_acquisition_request(
  text, uuid, text, text, text, text, text, text, text, jsonb, text,
  text, text, text, text, timestamptz
) TO service_role;
GRANT EXECUTE ON FUNCTION public.complete_approval_acquisition_request(
  text, text, text, text, text, timestamptz
) TO service_role;
