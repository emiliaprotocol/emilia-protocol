-- EMILIA Protocol — Migration 024: Auto-Receipt Configuration
-- Adds opt-in columns for automatic receipt generation from MCP tool calls.
--
-- Design notes:
--   • auto_receipt_enabled is a simple boolean gate (default false = opt-out).
--   • auto_receipt_config carries the richer JSON payload so we avoid adding
--     new columns for every future privacy knob.
--   • The partial index keeps opted-in entity lookups fast without paying an
--     index storage cost for the (vast) majority of opted-out entities.

ALTER TABLE entities
  ADD COLUMN IF NOT EXISTS auto_receipt_enabled BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS auto_receipt_config  JSONB;

-- Fast lookup of all entities that have opted in to auto-receipt.
-- Partial index: only opted-in rows are indexed, keeping the index small.
CREATE INDEX IF NOT EXISTS idx_entities_auto_receipt
  ON entities (auto_receipt_enabled)
  WHERE auto_receipt_enabled = true;

-- -------------------------------------------------------------------------
-- Column documentation
-- -------------------------------------------------------------------------

COMMENT ON COLUMN entities.auto_receipt_enabled IS
  'Whether this entity has opted in to automatic receipt generation from MCP tool calls. '
  'Defaults to false (opt-out). Must be explicitly set to true by the entity owner.';

COMMENT ON COLUMN entities.auto_receipt_config IS
  'JSON config for auto-receipt privacy rules. '
  'Shape: { redact_fields: string[], privacy_mode: "standard" | "anonymous" }. '
  'redact_fields: additional field names to strip from receipt data beyond the protocol defaults. '
  'privacy_mode "anonymous": counterparty_id is one-way hashed before storage.';
