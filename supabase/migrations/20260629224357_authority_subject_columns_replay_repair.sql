-- Fresh-replay repair for the authority-registry schema transition.
--
-- Migration 033 creates public.authorities with a narrow legacy role CHECK.
-- The next journaled migration, 20260629224358, uses CREATE TABLE IF NOT EXISTS
-- and immediately creates an index over subject columns. On a fresh database
-- the CREATE is a no-op, so those columns must exist before that migration
-- runs. This idempotent repair is deliberately timestamped immediately before
-- the journaled migration it repairs.

ALTER TABLE public.authorities
  ADD COLUMN IF NOT EXISTS organization_id TEXT,
  ADD COLUMN IF NOT EXISTS subject_type TEXT,
  ADD COLUMN IF NOT EXISTS subject_ref TEXT,
  ADD COLUMN IF NOT EXISTS assurance_class TEXT;

-- Drop only the legacy enum constraint created by migration 033. Never infer
-- a target from constraint text: a later role-dependent safety CHECK may be
-- semantically unrelated and must survive replay.
ALTER TABLE public.authorities
  DROP CONSTRAINT IF EXISTS authorities_role_check;

CREATE INDEX IF NOT EXISTS idx_authorities_subject
  ON public.authorities (
    subject_type,
    subject_ref,
    organization_id,
    status
  );
