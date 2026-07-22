-- Fortress reassertion for the approval-acquisition and evidence-readiness
-- service-only state introduced after the previous reconciliation migration.
--
-- These tables are readable only by service_role and mutable only through the
-- narrowly granted SECURITY DEFINER RPCs in their defining migrations.

ALTER TABLE public.approval_acquisition_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.approval_acquisition_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE public.guard_receipt_streams ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.guard_receipt_streams FORCE ROW LEVEL SECURITY;
ALTER TABLE public.guard_receipt_event_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.guard_receipt_event_bindings FORCE ROW LEVEL SECURITY;

REVOKE ALL PRIVILEGES ON TABLE public.approval_acquisition_requests
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL PRIVILEGES ON TABLE public.guard_receipt_streams
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL PRIVILEGES ON TABLE public.guard_receipt_event_bindings
  FROM PUBLIC, anon, authenticated, service_role;

GRANT SELECT ON TABLE public.approval_acquisition_requests TO service_role;
GRANT SELECT ON TABLE public.guard_receipt_streams TO service_role;
GRANT SELECT ON TABLE public.guard_receipt_event_bindings TO service_role;
