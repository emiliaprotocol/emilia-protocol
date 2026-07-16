BEGIN;

CREATE TABLE IF NOT EXISTS ep_gate_schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ep_gate_consumption (
  consumption_key TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  consumed_at BIGINT NOT NULL,
  expires_at BIGINT
);
CREATE INDEX IF NOT EXISTS ep_gate_consumption_expires_idx
  ON ep_gate_consumption (expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS ep_gate_actions (
  id TEXT PRIMARY KEY,
  record JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO ep_gate_schema_migrations (version)
  VALUES ('gate-e2e-v1') ON CONFLICT (version) DO NOTHING;

COMMIT;
