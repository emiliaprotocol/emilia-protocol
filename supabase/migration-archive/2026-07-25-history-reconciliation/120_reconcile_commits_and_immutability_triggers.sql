-- 120_reconcile_commits_and_immutability_triggers.sql
--
-- Drift reconciliation surfaced by `npm run schema:reconcile`: migrations 029,
-- 032, 045, 046, 051 were journaled-as-applied but their objects never existed
-- in prod:
--   * commits table (029) — the commit feature (lib/commit.js) was broken
--   * 3 append-only immutability trigger functions + their triggers — meaning
--     protocol_events / handshake_events / handshake_bindings were NOT
--     DB-enforced tamper-evident in prod (a core EP integrity guarantee)
--   * update_tenant_updated_at (cosmetic)
--
-- Safe to apply: the app never UPDATE/DELETEs protocol_events or handshake_events
-- (verified by grep), so the mutation-blocking triggers are no-ops for normal
-- operation and only block tampering. prevent_consumption_reversal only blocks
-- clearing consumed_at (a tampering op). All function defs are verbatim from the
-- original migrations. commits gets service_role-only RLS (029 shipped none).

-- ── commits table (029) + RLS it lacked ─────────────────────────────────────
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

-- ── protocol_events append-only (032) ───────────────────────────────────────
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

-- ── consumption irreversibility (045) ───────────────────────────────────────
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

-- ── handshake_events append-only (046) ──────────────────────────────────────
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

-- ── tenants.updated_at (051, cosmetic) ──────────────────────────────────────
CREATE OR REPLACE FUNCTION update_tenant_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS set_tenant_updated_at ON tenants;
CREATE TRIGGER set_tenant_updated_at BEFORE UPDATE ON tenants
  FOR EACH ROW EXECUTE FUNCTION update_tenant_updated_at();
