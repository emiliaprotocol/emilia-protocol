-- Add explicit, signed revocation inheritance metadata to bounded capability
-- state. Existing rows without an explicit direct/cascade mode are quarantined;
-- this migration never guesses a mode from age, topology, or prior behavior.

BEGIN;

ALTER TABLE public.ep_capability_state
  ADD COLUMN IF NOT EXISTS revocation_mode TEXT,
  ADD COLUMN IF NOT EXISTS parent_capability_id TEXT,
  ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS revocation_state_ready BOOLEAN;

ALTER TABLE public.ep_capability_state
  DROP CONSTRAINT IF EXISTS ep_capability_state_revocation_mode_check,
  DROP CONSTRAINT IF EXISTS ep_capability_state_parent_capability_id_fkey;

ALTER TABLE public.ep_capability_state
  ADD CONSTRAINT ep_capability_state_revocation_mode_check
    CHECK (revocation_mode IS NULL OR revocation_mode IN ('direct', 'cascade')),
  ADD CONSTRAINT ep_capability_state_parent_capability_id_fkey
    FOREIGN KEY (parent_capability_id)
    REFERENCES public.ep_capability_state(capability_id);

-- A valid mode is evidence that the current runtime registered explicit
-- revocation metadata. NULL or unknown metadata is not upgraded by inference.
-- An already quarantined row remains quarantined even if a mode was populated
-- later; the safe recovery path is a freshly issued capability ID.
UPDATE public.ep_capability_state
  SET revocation_state_ready = CASE
    WHEN revocation_state_ready IS FALSE THEN FALSE
    WHEN revocation_mode IN ('direct', 'cascade') THEN TRUE
    ELSE FALSE
  END;

ALTER TABLE public.ep_capability_state
  ALTER COLUMN revocation_state_ready SET DEFAULT TRUE,
  ALTER COLUMN revocation_state_ready SET NOT NULL;

CREATE OR REPLACE FUNCTION public.ep_require_capability_revocation_metadata()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $capability_revocation_metadata_function$
BEGIN
  IF NEW.revocation_state_ready IS TRUE
     AND (
       NEW.revocation_mode IS NULL
       OR NEW.revocation_mode NOT IN ('direct', 'cascade')
     ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '55000',
      MESSAGE = 'capability revocation metadata is not ready',
      DETAIL = format('capability_id=%s', NEW.capability_id),
      HINT = 'Reissue the capability with an explicitly signed direct or cascade revocation mode.';
  END IF;

  RETURN NEW;
END
$capability_revocation_metadata_function$;

DROP TRIGGER IF EXISTS ep_capability_state_revocation_metadata_guard
  ON public.ep_capability_state;
CREATE TRIGGER ep_capability_state_revocation_metadata_guard
  BEFORE INSERT OR UPDATE OF revocation_mode, revocation_state_ready
  ON public.ep_capability_state
  FOR EACH ROW
  EXECUTE FUNCTION public.ep_require_capability_revocation_metadata();

-- Extend the existing direct-writer guard. A new operation can be admitted
-- only for a capability whose action fence and revocation lineage metadata are
-- both authoritative. Existing history remains available for reconciliation.
CREATE OR REPLACE FUNCTION public.ep_require_semantic_capability_fence()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $semantic_capability_fence_function$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM public.ep_capability_state AS capability_state
      WHERE capability_state.capability_id = NEW.capability_id
        AND capability_state.semantic_fence_ready IS TRUE
        AND capability_state.revocation_state_ready IS TRUE
        AND capability_state.revocation_mode IN ('direct', 'cascade')
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '55000',
      MESSAGE = 'capability semantic action fence or revocation lineage is not ready',
      DETAIL = format('capability_id=%s', NEW.capability_id),
      HINT = 'Issue a fresh capability with a new ID and an explicitly signed revocation mode; never infer a mode for legacy state.';
  END IF;

  RETURN NEW;
END
$semantic_capability_fence_function$;

DROP TRIGGER IF EXISTS ep_capability_operations_semantic_fence_guard
  ON public.ep_capability_operations;
CREATE TRIGGER ep_capability_operations_semantic_fence_guard
  BEFORE INSERT ON public.ep_capability_operations
  FOR EACH ROW
  EXECUTE FUNCTION public.ep_require_semantic_capability_fence();

-- The runtime records authenticated final non-entry after a provider-entry
-- uncertainty without restoring budget. The historical table constraint
-- admitted only executed reconciliation, so restore the full runtime contract.
ALTER TABLE public.ep_capability_operations
  DROP CONSTRAINT IF EXISTS ep_capability_operations_reconciliation_outcome_check;
ALTER TABLE public.ep_capability_operations
  ADD CONSTRAINT ep_capability_operations_reconciliation_outcome_check
  CHECK (
    reconciliation_outcome IS NULL
    OR reconciliation_outcome IN ('executed', 'not_entered')
  );

CREATE INDEX IF NOT EXISTS ep_capability_state_parent_idx
  ON public.ep_capability_state(parent_capability_id)
  WHERE parent_capability_id IS NOT NULL;

COMMENT ON COLUMN public.ep_capability_state.revocation_mode IS
  'Signed capability policy: direct revokes only this capability; cascade also blocks descendants through the complete registered parent lineage.';
COMMENT ON COLUMN public.ep_capability_state.parent_capability_id IS
  'Immediate signed delegation parent used for complete ancestor revocation traversal inside one authoritative atomic state domain.';
COMMENT ON COLUMN public.ep_capability_state.revoked_at IS
  'Authoritative revocation transition time. It blocks future reservations but never erases an already-owned provider-entry or reconciliation obligation.';
COMMENT ON COLUMN public.ep_capability_state.revocation_state_ready IS
  'FALSE permanently quarantines capability state whose signed revocation mode or lineage cannot be established. Recovery requires fresh issuance, not inference.';

COMMIT;
