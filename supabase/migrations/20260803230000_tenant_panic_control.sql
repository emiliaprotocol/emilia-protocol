-- Organization-wide panic control.
--
-- The same tenant row is locked by panic and trust-receipt consumption, making
-- the boundary linearizable: whichever transaction acquires the row first is
-- the last action allowed. A panic also permanently invalidates receipts minted
-- before it, even if an operator later reactivates the tenant.

CREATE TABLE IF NOT EXISTS public.tenant_control_events (
  event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES public.tenants(tenant_id),
  epoch BIGINT NOT NULL CHECK (epoch > 0),
  status TEXT NOT NULL CHECK (status IN ('suspended', 'active')),
  reason TEXT NOT NULL CHECK (octet_length(reason) BETWEEN 3 AND 500),
  actor_id TEXT NOT NULL CHECK (octet_length(actor_id) BETWEEN 1 AND 512),
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
  UNIQUE (tenant_id, epoch)
);

CREATE INDEX IF NOT EXISTS tenant_control_events_latest_idx
  ON public.tenant_control_events (tenant_id, epoch DESC);

REVOKE ALL ON public.tenant_control_events FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.tenant_control_events TO service_role;

CREATE OR REPLACE FUNCTION public.guard_tenant_control_events_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  RAISE EXCEPTION 'tenant_control_events_immutable' USING ERRCODE = 'check_violation';
END;
$$;

DROP TRIGGER IF EXISTS tenant_control_events_immutable_trigger
  ON public.tenant_control_events;
CREATE TRIGGER tenant_control_events_immutable_trigger
BEFORE UPDATE OR DELETE ON public.tenant_control_events
FOR EACH ROW EXECUTE FUNCTION public.guard_tenant_control_events_immutable();

CREATE OR REPLACE FUNCTION public.guard_panic_tenant(
  p_tenant_id UUID,
  p_actor_id TEXT,
  p_reason TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_status TEXT;
  v_epoch BIGINT;
  v_at TIMESTAMPTZ := pg_catalog.now();
BEGIN
  IF p_tenant_id IS NULL
     OR p_actor_id IS NULL OR btrim(p_actor_id) = '' OR octet_length(p_actor_id) > 512
     OR p_reason IS NULL OR octet_length(btrim(p_reason)) NOT BETWEEN 3 AND 500
  THEN
    RAISE EXCEPTION 'tenant_panic_input_invalid' USING ERRCODE = '22023';
  END IF;

  SELECT status INTO v_status
  FROM public.tenants
  WHERE tenant_id = p_tenant_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant_not_found' USING ERRCODE = 'P0002';
  END IF;
  IF v_status = 'archived' THEN
    RAISE EXCEPTION 'tenant_archived' USING ERRCODE = '55000';
  END IF;

  SELECT epoch INTO v_epoch
  FROM public.tenant_control_events
  WHERE tenant_id = p_tenant_id AND status = 'suspended'
  ORDER BY epoch DESC
  LIMIT 1;

  IF v_status = 'suspended' THEN
    RETURN pg_catalog.jsonb_build_object(
      'tenant_id', p_tenant_id,
      'status', 'suspended',
      'epoch', COALESCE(v_epoch, 0),
      'idempotent', true
    );
  END IF;

  SELECT COALESCE(max(epoch), 0) + 1 INTO v_epoch
  FROM public.tenant_control_events
  WHERE tenant_id = p_tenant_id;

  UPDATE public.tenants
  SET status = 'suspended', updated_at = v_at
  WHERE tenant_id = p_tenant_id;

  UPDATE public.tenant_api_keys
  SET revoked_at = COALESCE(revoked_at, v_at)
  WHERE tenant_id = p_tenant_id AND revoked_at IS NULL;

  INSERT INTO public.tenant_control_events (
    tenant_id, epoch, status, reason, actor_id, created_at
  ) VALUES (
    p_tenant_id, v_epoch, 'suspended', btrim(p_reason), p_actor_id, v_at
  );

  RETURN pg_catalog.jsonb_build_object(
    'tenant_id', p_tenant_id,
    'status', 'suspended',
    'epoch', v_epoch,
    'suspended_at', v_at,
    'idempotent', false
  );
END;
$$;

REVOKE ALL ON FUNCTION public.guard_panic_tenant(UUID, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.guard_panic_tenant(UUID, TEXT, TEXT)
  TO service_role;

CREATE OR REPLACE FUNCTION public.guard_receipt_tenant_panic()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_org TEXT;
  v_status TEXT;
  v_created_at TIMESTAMPTZ;
  v_latest_panic TIMESTAMPTZ;
BEGIN
  IF NEW.event_type <> 'guard.trust_receipt.consumed'
     OR NEW.target_type <> 'trust_receipt'
  THEN
    RETURN NEW;
  END IF;

  SELECT ae.after_state ->> 'organization_id', ae.created_at
  INTO v_org, v_created_at
  FROM public.audit_events ae
  WHERE ae.target_type = 'trust_receipt'
    AND ae.target_id = NEW.target_id
    AND ae.event_type = 'guard.trust_receipt.created'
  ORDER BY ae.created_at ASC
  LIMIT 1;

  -- Non-cloud organization identifiers retain their existing behavior.
  IF v_org IS NULL OR NOT pg_catalog.pg_input_is_valid(v_org, 'uuid') THEN
    RETURN NEW;
  END IF;

  SELECT status INTO v_status
  FROM public.tenants
  WHERE tenant_id = v_org::uuid
  FOR UPDATE;

  IF NOT FOUND THEN RETURN NEW; END IF;
  IF v_status <> 'active' THEN
    RAISE EXCEPTION 'tenant_execution_suspended' USING ERRCODE = '55000';
  END IF;

  SELECT max(created_at) INTO v_latest_panic
  FROM public.tenant_control_events
  WHERE tenant_id = v_org::uuid AND status = 'suspended';

  IF v_latest_panic IS NOT NULL AND v_created_at <= v_latest_panic THEN
    RAISE EXCEPTION 'tenant_panic_invalidated_receipt' USING ERRCODE = '55000';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS guard_receipt_tenant_panic_trigger
  ON public.audit_events;
CREATE TRIGGER guard_receipt_tenant_panic_trigger
BEFORE INSERT ON public.audit_events
FOR EACH ROW EXECUTE FUNCTION public.guard_receipt_tenant_panic();

REVOKE EXECUTE ON FUNCTION public.guard_receipt_tenant_panic()
  FROM PUBLIC, anon, authenticated;
