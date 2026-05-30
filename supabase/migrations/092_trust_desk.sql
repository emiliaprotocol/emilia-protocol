-- 092_trust_desk.sql
-- AI Trust Desk — engagement state + published pages.
--
-- The file-based store (data/trust-desk/) works locally and for committed demo
-- pages, but Vercel's runtime filesystem is read-only, so the automated pipeline
-- needs a real backend to persist new engagements and published pages in prod.
-- Enable by setting TRUST_DESK_STORE=supabase. Service-role access only.

-- ── Engagements (pipeline state) ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS trust_desk_engagements (
  engagement_id   TEXT PRIMARY KEY,
  slug            TEXT,
  company         TEXT,
  status          TEXT NOT NULL DEFAULT 'intake_received',
  outcome         TEXT,
  -- Full engagement record (intake, status_history, verification, etc.) lives
  -- in `data` so the pipeline can evolve its shape without a migration. The
  -- promoted columns above exist only for indexing/querying.
  data            JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_td_eng_status  ON trust_desk_engagements (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_td_eng_slug    ON trust_desk_engagements (slug);

-- ── Published pages (the buyer-facing trust documents) ──────────────────────
CREATE TABLE IF NOT EXISTS trust_desk_pages (
  slug            TEXT PRIMARY KEY,
  engagement_id   TEXT,
  company         TEXT,
  -- `doc` is the full trust-page JSON (claims with stored signatures).
  doc             JSONB NOT NULL,
  -- `policies` = [{ doc_id, filename, content, content_hash }, ...]
  -- `answers`  = the questionnaire answers payload (content_hash source)
  -- Both are stored so the verify endpoint can re-derive content hashes.
  policies        JSONB NOT NULL DEFAULT '[]'::jsonb,
  answers         JSONB NOT NULL DEFAULT '{}'::jsonb,
  published_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at      TIMESTAMPTZ,
  monitor         JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_td_pages_expires ON trust_desk_pages (expires_at);

-- ── RLS: service-role only (no anon/public access) ──────────────────────────
ALTER TABLE trust_desk_engagements ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust_desk_pages       ENABLE ROW LEVEL SECURITY;

-- No policies are created → with RLS enabled, only the service role (which
-- bypasses RLS) can read/write. The buyer-facing verify endpoint and renderer
-- run server-side with the service client, so this is the intended posture.

-- updated_at touch trigger. search_path pinned to '' per Supabase advisor
-- (function_search_path_mutable); NOW() resolves via pg_catalog regardless.
CREATE OR REPLACE FUNCTION trust_desk_touch_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_td_eng_touch ON trust_desk_engagements;
CREATE TRIGGER trg_td_eng_touch BEFORE UPDATE ON trust_desk_engagements
  FOR EACH ROW EXECUTE FUNCTION trust_desk_touch_updated_at();

DROP TRIGGER IF EXISTS trg_td_pages_touch ON trust_desk_pages;
CREATE TRIGGER trg_td_pages_touch BEFORE UPDATE ON trust_desk_pages
  FOR EACH ROW EXECUTE FUNCTION trust_desk_touch_updated_at();
