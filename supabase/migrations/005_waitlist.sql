-- ============================================================================
-- EMILIA Protocol — Migration 005: Waitlist Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS waitlist (
  id              BIGSERIAL PRIMARY KEY,
  email           TEXT UNIQUE NOT NULL,
  claimed_number  INTEGER NOT NULL,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_waitlist_email ON waitlist (email);
CREATE INDEX IF NOT EXISTS idx_waitlist_claimed ON waitlist (claimed_number DESC);

ALTER TABLE waitlist ENABLE ROW LEVEL SECURITY;

CREATE POLICY "waitlist_insert" ON waitlist
  FOR INSERT WITH CHECK (true);

CREATE POLICY "waitlist_read" ON waitlist
  FOR SELECT USING (true);
