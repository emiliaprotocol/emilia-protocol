CREATE TABLE IF NOT EXISTS commits (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  commit_id               TEXT NOT NULL UNIQUE,
  entity_id               TEXT NOT NULL,
  principal_id            TEXT,
  counterparty_entity_id  TEXT,
  delegation_id           TEXT,
  action_type             TEXT NOT NULL CHECK (action_type IN ('install', 'connect', 'delegate', 'transact')),
  decision                TEXT NOT NULL CHECK (decision IN ('allow', 'review', 'deny')),
  scope                   JSONB,
  max_value_usd           NUMERIC,
  context                 JSONB,
  policy_snapshot         JSONB,
  nonce                   TEXT NOT NULL UNIQUE,
  signature               TEXT NOT NULL,
  public_key              TEXT NOT NULL,
  expires_at              TIMESTAMPTZ NOT NULL,
  status                  TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired', 'fulfilled')),
  receipt_id              TEXT,
  revoked_reason          TEXT,
  revoked_at              TIMESTAMPTZ,
  fulfilled_at            TIMESTAMPTZ,
  evaluation_result       JSONB,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_commits_commit_id  ON commits (commit_id);
CREATE INDEX IF NOT EXISTS idx_commits_entity_id  ON commits (entity_id);
CREATE INDEX IF NOT EXISTS idx_commits_status     ON commits (status);
CREATE INDEX IF NOT EXISTS idx_commits_expires_at ON commits (expires_at);
ALTER TABLE commits ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_all" ON commits;
CREATE POLICY "service_role_all" ON commits FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE OR REPLACE FUNCTION prevent_protocol_event_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'protocol_events is append-only: % operations are not allowed', TG_OP;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS enforce_append_only_update ON protocol_events;
CREATE TRIGGER enforce_append_only_update BEFORE UPDATE ON protocol_events
  FOR EACH ROW EXECUTE FUNCTION prevent_protocol_event_mutation();
DROP TRIGGER IF EXISTS enforce_append_only_delete ON protocol_events;
CREATE TRIGGER enforce_append_only_delete BEFORE DELETE ON protocol_events
  FOR EACH ROW EXECUTE FUNCTION prevent_protocol_event_mutation();

CREATE OR REPLACE FUNCTION prevent_consumption_reversal()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS NULL THEN
    RAISE EXCEPTION 'CONSUMPTION_IRREVERSIBLE: Cannot clear consumed_at once set on binding %', OLD.id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS enforce_consumption_irreversible ON handshake_bindings;
CREATE TRIGGER enforce_consumption_irreversible BEFORE UPDATE ON handshake_bindings
  FOR EACH ROW EXECUTE FUNCTION prevent_consumption_reversal();

CREATE OR REPLACE FUNCTION prevent_handshake_event_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'EVENT_IMMUTABILITY_VIOLATION: handshake_events is append-only. Cannot % event %',
    TG_OP, COALESCE(OLD.event_id::text, 'unknown');
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS enforce_handshake_events_no_update ON handshake_events;
CREATE TRIGGER enforce_handshake_events_no_update BEFORE UPDATE ON handshake_events
  FOR EACH ROW EXECUTE FUNCTION prevent_handshake_event_mutation();
DROP TRIGGER IF EXISTS enforce_handshake_events_no_delete ON handshake_events;
CREATE TRIGGER enforce_handshake_events_no_delete BEFORE DELETE ON handshake_events
  FOR EACH ROW EXECUTE FUNCTION prevent_handshake_event_mutation();

CREATE OR REPLACE FUNCTION update_tenant_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS set_tenant_updated_at ON tenants;
CREATE TRIGGER set_tenant_updated_at BEFORE UPDATE ON tenants
  FOR EACH ROW EXECUTE FUNCTION update_tenant_updated_at();;
