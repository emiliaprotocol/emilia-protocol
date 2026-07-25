-- 097_aml_history.sql — per-counterparty transfer history for AML
-- structuring/velocity detection. Service-role-only (RLS on, no policy).

CREATE TABLE IF NOT EXISTS aml_history (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  counterparty  TEXT NOT NULL,
  amount        NUMERIC NOT NULL,
  currency      TEXT,
  action_type   TEXT,
  receipt_id    TEXT,
  occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_aml_history_window
  ON aml_history (tenant_id, counterparty, occurred_at DESC);

COMMENT ON TABLE aml_history IS
  'Per-counterparty transfer history recorded by the financial guard adapters; feeds AML structuring/velocity detection without trusting caller-supplied recent_amounts.';

ALTER TABLE aml_history ENABLE ROW LEVEL SECURITY;;
