-- 097_aml_history.sql
--
-- Per-counterparty transfer history for AML structuring/velocity detection.
--
-- Before this table, structuring and velocity signals only fired when the
-- caller supplied recent_amounts — trusting the monitored system to report the
-- pattern it might be hiding. Now the guard adapter records every financial
-- precheck that names a counterparty, and looks the window up ITSELF when the
-- caller omits recent_amounts. Caller-supplied history is still accepted (a
-- core-banking system may have a longer view than EP).
--
-- Service-role-only (RLS on, no policy), like every other EP table.

CREATE TABLE IF NOT EXISTS aml_history (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id     TEXT NOT NULL,                 -- organization_id from the precheck
  counterparty  TEXT NOT NULL,                 -- normalized (lowercased, trimmed)
  amount        NUMERIC NOT NULL,
  currency      TEXT,
  action_type   TEXT,
  receipt_id    TEXT,                          -- the precheck receipt that recorded it
  occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The structuring/velocity window query: latest transfers for one
-- (tenant, counterparty), newest first.
CREATE INDEX IF NOT EXISTS idx_aml_history_window
  ON aml_history (tenant_id, counterparty, occurred_at DESC);

COMMENT ON TABLE aml_history IS
  'Per-counterparty transfer history recorded by the financial guard adapters; feeds AML structuring/velocity detection without trusting caller-supplied recent_amounts.';

ALTER TABLE aml_history ENABLE ROW LEVEL SECURITY;
