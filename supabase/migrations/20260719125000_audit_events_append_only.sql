-- Make the trust evidence timeline genuinely append-only.
--
-- audit_events has always been documented as the append-only log of
-- trust-changing actions, but unlike protocol_events/security_events it lacked
-- a database mutation trigger. The rollout verifier reads this timeline between
-- application-side cryptographic verification and its locked activation
-- transaction, so UPDATE/DELETE must be impossible even to service_role.

CREATE OR REPLACE FUNCTION public.reject_audit_event_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  RAISE EXCEPTION 'AUDIT_EVENT_IMMUTABILITY_VIOLATION: audit_events is append-only. Cannot % event %',
    TG_OP, OLD.id
    USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS audit_events_append_only ON public.audit_events;
CREATE TRIGGER audit_events_append_only
  BEFORE UPDATE OR DELETE ON public.audit_events
  FOR EACH ROW
  EXECUTE FUNCTION public.reject_audit_event_mutation();

REVOKE UPDATE, DELETE, TRUNCATE
  ON TABLE public.audit_events
  FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT, INSERT ON TABLE public.audit_events TO service_role;

REVOKE ALL ON FUNCTION public.reject_audit_event_mutation()
  FROM PUBLIC, anon, authenticated;
