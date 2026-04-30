-- Migration 091: handshake_consumptions table (renamed from 042b)
--
-- Originally authored as 042b_handshake_consumptions.sql — the supabase
-- CLI rejected the `b` suffix so it was never tracked. The table exists
-- on prod (applied via Studio SQL historically; subsequent migrations
-- 047, 048, 074 reference it). Already uses IF NOT EXISTS so this rename
-- is purely a tracking fix — a no-op for prod, a real schema add for a
-- hypothetical fresh deploy.

CREATE TABLE IF NOT EXISTS handshake_consumptions (
  id BIGSERIAL PRIMARY KEY,
  handshake_id UUID NOT NULL REFERENCES handshakes(handshake_id),
  binding_hash TEXT NOT NULL,
  consumed_by_type TEXT NOT NULL,
  consumed_by_id TEXT NOT NULL,
  consumed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_entity_ref TEXT,
  CONSTRAINT uq_handshake_consumption UNIQUE (handshake_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_handshake_consumptions_binding
  ON handshake_consumptions (binding_hash);

COMMENT ON TABLE handshake_consumptions IS
  'One-time consumption records for handshake authorization artifacts';
COMMENT ON COLUMN handshake_consumptions.consumed_by_type IS
  'Type of downstream action that consumed this handshake';
COMMENT ON COLUMN handshake_consumptions.consumed_by_id IS
  'ID of the downstream artifact';
