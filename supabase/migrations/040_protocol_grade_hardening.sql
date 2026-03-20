-- EP Protocol-Grade Hardening (Delta Audit Fixes)
--
-- Fix 1: Transaction binding — action_hash + policy_hash on handshakes
-- Fix 4: Provably fail-closed issuer — issuer_status on presentations

-- ============================================================================
-- 1. Add action_hash and policy_hash to handshakes (transaction binding)
-- ============================================================================

ALTER TABLE handshakes
  ADD COLUMN IF NOT EXISTS action_hash TEXT,
  ADD COLUMN IF NOT EXISTS policy_hash TEXT;

COMMENT ON COLUMN handshakes.action_hash IS 'SHA-256 of canonical {action_type, resource_ref, intent_ref} at initiation — tamper detection at gate';
COMMENT ON COLUMN handshakes.policy_hash IS 'SHA-256 of policy.rules at initiation — detects policy modification between initiation and verification';

-- ============================================================================
-- 2. Add issuer_status to handshake_presentations (provably fail-closed)
-- ============================================================================
-- issuer_status records WHY the issuer was trusted or untrusted:
--   'self_asserted'           — no issuer_ref, trust deferred to policy
--   'authority_valid'         — issuer found in registry, non-revoked, within validity period
--   'authority_not_found'     — issuer_ref provided but not in registry (fail closed)
--   'authority_revoked'       — issuer found but status=revoked
--   'authority_expired'       — issuer found but past valid_to
--   'authority_not_yet_valid' — issuer found but before valid_from
--   'authority_table_missing' — authorities table does not exist (fail closed)

-- Note: authority_id and issuer_status columns may already exist from migration 038.
-- Using IF NOT EXISTS to be idempotent.

ALTER TABLE handshake_presentations
  ADD COLUMN IF NOT EXISTS issuer_status TEXT;

COMMENT ON COLUMN handshake_presentations.issuer_status IS 'Explicit trust reason for auditability: why the issuer was trusted or untrusted';
