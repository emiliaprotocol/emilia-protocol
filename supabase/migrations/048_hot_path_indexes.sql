-- ============================================================================
-- Hot-Path Indexes for 10M+ decisions/day
--
-- Section 1.2D of EP Scale Architecture.
-- These indexes support the critical write and read paths without
-- weakening invariants. They are additive — no schema changes.
-- ============================================================================

-- ============================================================================
-- Handshakes
-- ============================================================================

-- Handshake lookup by idempotency_key (duplicate detection on write path)
-- Note: uq_handshakes_idempotency_key (unique index) exists from 039,
--       idx_handshakes_idempotency (unique index) exists from 037.
--       Both cover this path. No additional index needed.

-- ============================================================================
-- Handshake Parties
-- ============================================================================

-- Party lookup by entity_ref (access control, listing)
-- Note: idx_handshake_parties_entity already exists from 035.
--       No additional index needed.

-- Party lookup by handshake + party_role (presentation/verification)
CREATE INDEX IF NOT EXISTS idx_handshake_parties_handshake_role
  ON handshake_parties(handshake_id, party_role);

-- ============================================================================
-- Handshake Consumptions
-- ============================================================================

-- Consumption lookup by binding_hash (one-time check)
-- Note: idx_handshake_consumptions_binding (unique) already exists from 042.
--       No additional index needed.

-- ============================================================================
-- Handshake Bindings
-- ============================================================================

-- Binding hash lookup for verification (already exists from 042_binding_material)
-- idx_handshake_bindings_binding_hash covers this.

-- Bindings: consumed_at IS NOT NULL for fast "is consumed?" checks
CREATE INDEX IF NOT EXISTS idx_bindings_consumed
  ON handshake_bindings(handshake_id) WHERE consumed_at IS NOT NULL;

-- Bindings: consumed_at IS NULL for fast "available bindings" queries
CREATE INDEX IF NOT EXISTS idx_bindings_unconsumed
  ON handshake_bindings(handshake_id) WHERE consumed_at IS NULL;

-- ============================================================================
-- Protocol Events
-- ============================================================================

-- Aggregate + time ordering (reconstruction, audit)
-- Note: idx_protocol_events_aggregate already exists from 032.
--       No additional index needed.

-- ============================================================================
-- Handshake Events
-- ============================================================================

-- Handshake + time ordering (reconstruction, audit)
-- Note: idx_handshake_events_handshake_created already exists from 037.
--       No additional index needed.

-- ============================================================================
-- Commits
-- ============================================================================

-- Hot lookup by entity_id + status for active commit queries
CREATE INDEX IF NOT EXISTS idx_commits_entity_status
  ON commits(entity_id, status) WHERE status = 'active';

-- ============================================================================
-- Receipts
-- ============================================================================

-- Entity + time for trust profile computation (scoring window queries)
-- Note: idx_receipts_entity covers (entity_id, created_at desc) from 001.
--       Adding a dedicated forward-order index for aggregation scans.
CREATE INDEX IF NOT EXISTS idx_receipts_entity_time
  ON receipts(entity_id, created_at);

-- ============================================================================
-- Summary
-- ============================================================================
-- New indexes added by this migration:
--   idx_handshake_parties_handshake_role  — composite lookup for verification
--   idx_bindings_consumed                 — partial index, consumed bindings
--   idx_bindings_unconsumed              — partial index, available bindings
--   idx_commits_entity_status            — active commits per entity
--   idx_receipts_entity_time             — scoring window scans
--
-- Indexes confirmed already present (not duplicated):
--   idx_handshake_parties_entity          — from 035
--   idx_handshake_consumptions_binding    — from 042
--   idx_handshake_bindings_binding_hash   — from 042_binding_material
--   idx_protocol_events_aggregate         — from 032
--   idx_handshake_events_handshake_created — from 037
--   uq_handshakes_idempotency_key        — from 039
--   idx_handshakes_idempotency           — from 037
