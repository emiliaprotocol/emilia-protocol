-- 110_security_events_hash_chain.sql
--
-- Government/high-assurance security event ledger.
--
-- security_events is intentionally narrower than protocol_events: it records
-- security-relevant control events (receipt challenge/consume/replay/refusal,
-- key rotation, authority revocation, admin actions, incident response) with a
-- tamper-evident hash chain. It is append-only at the database layer.

CREATE TABLE IF NOT EXISTS security_events (
  event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  actor_id TEXT,
  tenant_id TEXT,
  target_type TEXT,
  target_id TEXT,
  correlation_id TEXT,
  previous_hash TEXT,
  payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  payload_hash TEXT NOT NULL,
  event_hash TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_security_events_tenant_time
  ON security_events (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_type_time
  ON security_events (event_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_target
  ON security_events (target_type, target_id, created_at DESC);

ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "service_role_bypass" ON security_events;
CREATE POLICY "service_role_bypass" ON security_events
  TO service_role USING (true) WITH CHECK (true);

CREATE OR REPLACE FUNCTION prevent_security_event_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'SECURITY_EVENT_IMMUTABILITY_VIOLATION: security_events is append-only. Cannot % event %',
    TG_OP, COALESCE(OLD.event_id::text, 'unknown');
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS enforce_security_events_no_update ON security_events;
CREATE TRIGGER enforce_security_events_no_update
  BEFORE UPDATE ON security_events
  FOR EACH ROW EXECUTE FUNCTION prevent_security_event_mutation();

DROP TRIGGER IF EXISTS enforce_security_events_no_delete ON security_events;
CREATE TRIGGER enforce_security_events_no_delete
  BEFORE DELETE ON security_events
  FOR EACH ROW EXECUTE FUNCTION prevent_security_event_mutation();

COMMENT ON TABLE security_events IS
  'Append-only, hash-chained security event ledger for government/high-assurance incident response and audit export.';
