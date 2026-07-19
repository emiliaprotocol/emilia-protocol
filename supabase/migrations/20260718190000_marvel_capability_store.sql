-- SPDX-License-Identifier: Apache-2.0
-- Marvel durable capability store — forward migration for the Gate's
-- budget/spending state tables.
--
-- packages/gate/capability-receipt.js defines createPostgresCapabilityStore()
-- and the DDL for two tables (CAPABILITY_STATE_DDL), but shipping that code
-- does not create the tables in a database. This migration is that DDL, applied
-- as a tracked Supabase migration, plus the EP service-role security posture
-- (RLS enabled, no anon/authenticated/PUBLIC access) that every server-only
-- table in this project carries.
--
-- The table shape is copied VERBATIM from CAPABILITY_STATE_DDL so the durable
-- store's CAPABILITY_SQL (register / reserveState / commitState / insert /
-- commit operation) runs against exactly the schema it was written for. The
-- budget invariants (consumed + reserved <= budget) are enforced by that SQL
-- under a FOR UPDATE lock on the state row; the column CHECKs here are the
-- database-side floor (non-negative amounts, valid status, fingerprint shape).

CREATE TABLE IF NOT EXISTS ep_capability_state (
  capability_id TEXT PRIMARY KEY,
  capability_fingerprint TEXT NOT NULL CHECK (capability_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  budget_amount BIGINT NOT NULL CHECK (budget_amount >= 0),
  currency TEXT NOT NULL,
  consumed_amount BIGINT NOT NULL DEFAULT 0 CHECK (consumed_amount >= 0),
  reserved_amount BIGINT NOT NULL DEFAULT 0 CHECK (reserved_amount >= 0),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Compat hedge carried from CAPABILITY_STATE_DDL: a no-op on this fresh table
-- (the column is already present with its NOT NULL CHECK above), present so the
-- migration and the code's own DDL stay byte-aligned.
ALTER TABLE ep_capability_state ADD COLUMN IF NOT EXISTS capability_fingerprint TEXT;

CREATE TABLE IF NOT EXISTS ep_capability_operations (
  operation_id TEXT PRIMARY KEY,
  capability_id TEXT NOT NULL REFERENCES ep_capability_state(capability_id),
  amount BIGINT NOT NULL CHECK (amount > 0),
  currency TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('reserved', 'committed')),
  reservation_token TEXT NOT NULL,
  outcome TEXT,
  reserved_at TIMESTAMPTZ NOT NULL,
  committed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ep_capability_operations_capability_idx
  ON ep_capability_operations(capability_id);

-- ── Service-role-only security posture ───────────────────────────────────────
-- These tables hold spending/budget state reached only through the Gate's
-- server-side durable store (service_role). RLS is enabled with NO policy, so
-- anon/authenticated are denied every row; service_role bypasses RLS. The table
-- ACL is a separate Data-API gate (mig 113 precedent), so anon/authenticated/
-- PUBLIC are also revoked at the grant level. This mirrors SERVICE_ONLY_TABLES
-- in scripts/db-contract.manifest.mjs, to which both tables are added.
ALTER TABLE ep_capability_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE ep_capability_operations ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON ep_capability_state FROM anon, authenticated, PUBLIC;
REVOKE ALL ON ep_capability_operations FROM anon, authenticated, PUBLIC;
GRANT ALL ON ep_capability_state TO service_role;
GRANT ALL ON ep_capability_operations TO service_role;

COMMENT ON TABLE ep_capability_state IS
  'Marvel durable capability budget state (createPostgresCapabilityStore). Service-role only; RLS-enabled deny-all. One row per capability: budget/consumed/reserved under a FOR UPDATE lock.';
COMMENT ON TABLE ep_capability_operations IS
  'Marvel durable capability spend operations. Service-role only. reserved -> committed, keyed by operation_id, fenced by reservation_token.';
