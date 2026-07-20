-- Fortress reassertion: harden audit_events as a server-only append-only
-- ledger. The suffix intentionally enrolls this forward migration in the
-- static fortress reconciliation audit.
--
-- RLS remains explicit even though Supabase service_role normally bypasses it.
-- ACLs are reset independently so no client-facing role can read or append
-- audit records, and service_role retains no mutation privilege.

ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "service_role_bypass" ON public.audit_events;
CREATE POLICY "service_role_bypass" ON public.audit_events
  FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

REVOKE ALL PRIVILEGES
  ON TABLE public.audit_events
  FROM PUBLIC, anon, authenticated;
REVOKE ALL PRIVILEGES
  ON TABLE public.audit_events
  FROM service_role;

GRANT SELECT, INSERT ON TABLE public.audit_events TO service_role;
