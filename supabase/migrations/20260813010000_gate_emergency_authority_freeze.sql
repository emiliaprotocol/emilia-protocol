-- Gate Emergency Authority Freeze, phase 1.
--
-- This migration adds the execution-control row that serializes reservation,
-- provider entry, freeze, and restore. Existing unbound operations remain
-- legacy paths; a control domain applies only when both binding columns are
-- captured atomically at reservation.

CREATE TABLE IF NOT EXISTS public.ep_gate_control_domains (
  control_domain_id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('active', 'frozen')),
  epoch BIGINT NOT NULL DEFAULT 1 CHECK (epoch > 0),
  frozen_at TIMESTAMPTZ,
  frozen_by_digest TEXT CHECK (frozen_by_digest ~ '^sha256:[0-9a-f]{64}$'),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
  CHECK (
    (status = 'active' AND frozen_at IS NULL AND frozen_by_digest IS NULL)
    OR
    (status = 'frozen' AND frozen_at IS NOT NULL AND frozen_by_digest IS NOT NULL)
  )
);

CREATE TABLE IF NOT EXISTS public.ep_gate_control_domain_events (
  operation_id TEXT NOT NULL,
  control_domain_id TEXT NOT NULL
    REFERENCES public.ep_gate_control_domains(control_domain_id),
  event_type TEXT NOT NULL CHECK (event_type IN ('freeze', 'restore')),
  epoch_at_event BIGINT NOT NULL CHECK (epoch_at_event > 0),
  action_digest TEXT NOT NULL CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$'),
  authority_instance_digest TEXT NOT NULL
    CHECK (authority_instance_digest ~ '^sha256:[0-9a-f]{64}$'),
  result JSONB NOT NULL,
  committed_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
  PRIMARY KEY (operation_id)
);

ALTER TABLE public.ep_capability_operations
  ADD COLUMN IF NOT EXISTS control_domain_id TEXT
    REFERENCES public.ep_gate_control_domains(control_domain_id),
  ADD COLUMN IF NOT EXISTS reserved_control_epoch BIGINT
    CHECK (reserved_control_epoch > 0);

ALTER TABLE public.ep_capability_operations
  DROP CONSTRAINT IF EXISTS ep_capability_operations_control_domain_binding_check;
ALTER TABLE public.ep_capability_operations
  ADD CONSTRAINT ep_capability_operations_control_domain_binding_check
  CHECK ((control_domain_id IS NULL) = (reserved_control_epoch IS NULL));

REVOKE ALL ON public.ep_gate_control_domains
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON public.ep_gate_control_domain_events
  FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.ep_gate_control_domains TO service_role;
GRANT SELECT, INSERT ON public.ep_gate_control_domain_events TO service_role;

CREATE OR REPLACE FUNCTION public.guard_control_domain_events_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  RAISE EXCEPTION 'control_domain_events_immutable'
    USING ERRCODE = 'check_violation';
END;
$$;

DROP TRIGGER IF EXISTS control_domain_events_immutable_trigger
  ON public.ep_gate_control_domain_events;
CREATE TRIGGER control_domain_events_immutable_trigger
BEFORE UPDATE OR DELETE ON public.ep_gate_control_domain_events
FOR EACH ROW EXECUTE FUNCTION public.guard_control_domain_events_immutable();

REVOKE EXECUTE ON FUNCTION public.guard_control_domain_events_immutable()
  FROM PUBLIC, anon, authenticated;
