-- 100_out_of_band_tables.sql
--
-- Captures three tables the app references that had no creating migration —
-- they existed only out-of-band on deployed databases. Migrations 072 and 076
-- already ALTER / add RLS for these and were guarded (to_regclass) so a
-- from-scratch replay skips them when absent; this migration creates them in
-- dependency order (after entities) so the replayed schema is complete and the
-- guards become moot on fresh DBs. Definitions captured verbatim from production
-- (information_schema + pg_get_constraintdef + pg_indexes) on 2026-06-20.
--
-- (policy_versions, also referenced in 072, intentionally NOT created — it does
-- not exist in production either, so 072's guard is the correct handling.)
--
-- Everything here is idempotent (IF NOT EXISTS / DROP POLICY IF EXISTS), so it is
-- a safe no-op on databases that already have these objects.

-- ── fraud_flags ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fraud_flags (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_id    uuid NOT NULL REFERENCES entities(id),
  submitted_by uuid NOT NULL REFERENCES entities(id),
  flags        text[] NOT NULL,
  detail       jsonb NOT NULL DEFAULT '{}'::jsonb,
  blocked      boolean NOT NULL DEFAULT false,
  reviewed     boolean NOT NULL DEFAULT false,
  reviewed_at  timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_fraud_flags_entity
  ON fraud_flags (entity_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fraud_flags_unreviewed
  ON fraud_flags (reviewed, created_at DESC) WHERE reviewed = false;
ALTER TABLE fraud_flags ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_bypass" ON fraud_flags;
CREATE POLICY "service_role_bypass" ON fraud_flags TO service_role USING (true) WITH CHECK (true);

-- ── partner_inquiries (public lead-capture form) ─────────────────────────────
CREATE TABLE IF NOT EXISTS partner_inquiries (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at    timestamptz NOT NULL DEFAULT now(),
  inquiry_type  text NOT NULL DEFAULT 'partner',
  name          text NOT NULL,
  email         text NOT NULL,
  organization  text,
  title         text,
  website       text,
  message       text,
  metadata_json jsonb,
  trust_surface text,
  timeline      text
);
CREATE INDEX IF NOT EXISTS idx_partner_inquiries_email ON partner_inquiries (email);
ALTER TABLE partner_inquiries ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_bypass" ON partner_inquiries;
CREATE POLICY "service_role_bypass" ON partner_inquiries TO service_role USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_insert" ON partner_inquiries;
CREATE POLICY "anon_insert" ON partner_inquiries FOR INSERT TO anon WITH CHECK (true);

-- ── investor_inquiries (public lead-capture form) ────────────────────────────
CREATE TABLE IF NOT EXISTS investor_inquiries (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at    timestamptz NOT NULL DEFAULT now(),
  inquiry_type  text NOT NULL DEFAULT 'investor',
  name          text NOT NULL,
  email         text NOT NULL,
  organization  text,
  title         text,
  website       text,
  message       text,
  metadata_json jsonb,
  why_emilia    text,
  help_offer    text
);
CREATE INDEX IF NOT EXISTS idx_investor_inquiries_email ON investor_inquiries (email);
ALTER TABLE investor_inquiries ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_bypass" ON investor_inquiries;
CREATE POLICY "service_role_bypass" ON investor_inquiries TO service_role USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_insert" ON investor_inquiries;
CREATE POLICY "anon_insert" ON investor_inquiries FOR INSERT TO anon WITH CHECK (true);
