-- Migration 022: Operator applications
-- Stores applications from people who want to become EP dispute resolution operators.

CREATE TABLE IF NOT EXISTS operator_applications (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name          TEXT NOT NULL,
  email         TEXT NOT NULL UNIQUE,
  background    TEXT,
  motivation    TEXT,
  status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'waitlisted')),
  reviewed_by   TEXT,
  review_notes  TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  reviewed_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_operator_applications_status ON operator_applications(status);
CREATE INDEX IF NOT EXISTS idx_operator_applications_email ON operator_applications(email);

-- RLS: only service role can read/write operator applications
ALTER TABLE operator_applications ENABLE ROW LEVEL SECURITY;

-- No public read — applications are private until approved
CREATE POLICY "service_role_all" ON operator_applications
  FOR ALL USING (auth.role() = 'service_role');
