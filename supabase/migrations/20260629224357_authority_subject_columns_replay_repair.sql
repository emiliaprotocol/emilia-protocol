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

DO $$
DECLARE
  v_constraint RECORD;
BEGIN
  FOR v_constraint IN
    SELECT c.conname
    FROM pg_catalog.pg_constraint c
    JOIN pg_catalog.pg_class t ON t.oid = c.conrelid
    JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = 'public'
      AND t.relname = 'authorities'
      AND c.contype = 'c'
      AND pg_catalog.pg_get_constraintdef(c.oid) ILIKE '%role%'
  LOOP
    EXECUTE pg_catalog.format(
      'ALTER TABLE public.authorities DROP CONSTRAINT %I',
      v_constraint.conname
    );
  END LOOP;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_authorities_subject
  ON public.authorities (
    subject_type,
    subject_ref,
    organization_id,
    status
  );
