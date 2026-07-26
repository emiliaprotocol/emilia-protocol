-- 092_trust_desk.sql — AI Trust Desk engagement state + published pages.
-- Service-role access only. Enable backend via TRUST_DESK_STORE=supabase.

CREATE TABLE IF NOT EXISTS trust_desk_engagements (
  engagement_id   TEXT PRIMARY KEY,
  slug            TEXT,
  company         TEXT,
  status          TEXT NOT NULL DEFAULT 'intake_received',
  outcome         TEXT,
  data            JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_td_eng_status ON trust_desk_engagements (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_td_eng_slug   ON trust_desk_engagements (slug);

CREATE TABLE IF NOT EXISTS trust_desk_pages (
  slug            TEXT PRIMARY KEY,
  engagement_id   TEXT,
  company         TEXT,
  doc             JSONB NOT NULL,
  policies        JSONB NOT NULL DEFAULT '[]'::jsonb,
  answers         JSONB NOT NULL DEFAULT '{}'::jsonb,
  published_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at      TIMESTAMPTZ,
  monitor         JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_td_pages_expires ON trust_desk_pages (expires_at);

ALTER TABLE trust_desk_engagements ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust_desk_pages       ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION trust_desk_touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_td_eng_touch ON trust_desk_engagements;
CREATE TRIGGER trg_td_eng_touch BEFORE UPDATE ON trust_desk_engagements
  FOR EACH ROW EXECUTE FUNCTION trust_desk_touch_updated_at();

DROP TRIGGER IF EXISTS trg_td_pages_touch ON trust_desk_pages;
CREATE TRIGGER trg_td_pages_touch BEFORE UPDATE ON trust_desk_pages
  FOR EACH ROW EXECUTE FUNCTION trust_desk_touch_updated_at();;
