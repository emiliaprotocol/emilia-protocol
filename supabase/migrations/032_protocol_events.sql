-- Protocol Events — Append-only truth store
-- All trust-changing state transitions are recorded here.
-- Current-state tables (receipts, commits, disputes) are projections of this log.

CREATE TABLE IF NOT EXISTS protocol_events (
  event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  aggregate_type TEXT NOT NULL CHECK (aggregate_type IN ('receipt', 'commit', 'dispute', 'report', 'delegation', 'entity')),
  aggregate_id TEXT NOT NULL,
  command_type TEXT NOT NULL,
  parent_event_hash TEXT,
  payload_json JSONB NOT NULL,
  payload_hash TEXT NOT NULL,
  actor_authority_id TEXT,
  signature TEXT,
  signed_at TIMESTAMPTZ,
  idempotency_key TEXT UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for common queries
CREATE INDEX idx_protocol_events_aggregate ON protocol_events (aggregate_type, aggregate_id, created_at);
CREATE INDEX idx_protocol_events_command ON protocol_events (command_type, created_at);
CREATE INDEX idx_protocol_events_idempotency ON protocol_events (idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX idx_protocol_events_created ON protocol_events (created_at);

-- Prevent updates and deletes (append-only enforcement)
CREATE OR REPLACE FUNCTION prevent_protocol_event_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'protocol_events is append-only: % operations are not allowed', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_append_only_update
  BEFORE UPDATE ON protocol_events
  FOR EACH ROW EXECUTE FUNCTION prevent_protocol_event_mutation();

CREATE TRIGGER enforce_append_only_delete
  BEFORE DELETE ON protocol_events
  FOR EACH ROW EXECUTE FUNCTION prevent_protocol_event_mutation();

-- Comment
COMMENT ON TABLE protocol_events IS 'Append-only event store. The truth source for all trust-changing state transitions. Current-state tables are projections.';
