-- 031: Add unique constraint on normalized (lowercased) email for operator_applications.
-- Ensures no two applications share the same email address (case-insensitive).

CREATE UNIQUE INDEX IF NOT EXISTS idx_operator_applications_email_unique
  ON operator_applications (lower(email));
