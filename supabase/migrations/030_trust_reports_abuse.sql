-- Migration 030: Add abuse-detection support to trust_reports
--
-- The checkAbuse() function previously queried the `disputes` table for report
-- abuse detection, but human reports are stored in `trust_reports`. This migration
-- adds the columns and indexes needed for proper abuse detection on trust_reports.
--
-- Changes:
--   1. Add reporter_ip_hash column (truncated SHA-256 for privacy, not raw IP)
--   2. Add composite index on (entity_id, report_type, created_at) for repeated-report checks
--   3. Add index on (reporter_ip_hash, created_at) for IP-based throttling

-- 1. Add hashed IP column for privacy-preserving IP-based throttling
ALTER TABLE trust_reports
  ADD COLUMN IF NOT EXISTS reporter_ip_hash TEXT DEFAULT NULL;

COMMENT ON COLUMN trust_reports.reporter_ip_hash
  IS 'Truncated SHA-256 hash of reporter IP address. Used for abuse throttling, never stores raw IP.';

-- 2. Index for repeated-report abuse detection (same entity + same type within time window)
CREATE INDEX IF NOT EXISTS idx_trust_reports_entity_type_created
  ON trust_reports (entity_id, report_type, created_at);

-- 3. Index for IP-based flooding detection
CREATE INDEX IF NOT EXISTS idx_trust_reports_ip_hash_created
  ON trust_reports (reporter_ip_hash, created_at)
  WHERE reporter_ip_hash IS NOT NULL;
