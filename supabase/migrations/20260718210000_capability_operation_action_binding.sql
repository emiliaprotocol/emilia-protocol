-- SPDX-License-Identifier: Apache-2.0
-- Bind every durable capability reservation to the exact immutable action
-- snapshot evaluated by the Gate. Existing operation rows cannot be safely
-- reconstructed from budget data, so the migration fails closed if any
-- unbound rows exist instead of inventing evidence.

ALTER TABLE public.ep_capability_operations
  ADD COLUMN IF NOT EXISTS action_digest TEXT;

ALTER TABLE public.ep_capability_operations
  ADD COLUMN IF NOT EXISTS reconciliation_outcome TEXT,
  ADD COLUMN IF NOT EXISTS reconciliation_evidence_digest TEXT,
  ADD COLUMN IF NOT EXISTS reconciled_at TIMESTAMPTZ;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.ep_capability_operations
    WHERE action_digest IS NULL
  ) THEN
    RAISE EXCEPTION
      'ep_capability_operations contains unbound rows; reconcile them before adding the action-digest invariant';
  END IF;
END
$$;

ALTER TABLE public.ep_capability_operations
  ALTER COLUMN action_digest SET NOT NULL;

ALTER TABLE public.ep_capability_operations
  DROP CONSTRAINT IF EXISTS ep_capability_operations_action_digest_check;

ALTER TABLE public.ep_capability_operations
  ADD CONSTRAINT ep_capability_operations_action_digest_check
  CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$');

ALTER TABLE public.ep_capability_operations
  DROP CONSTRAINT IF EXISTS ep_capability_operations_reconciliation_outcome_check,
  DROP CONSTRAINT IF EXISTS ep_capability_operations_reconciliation_evidence_digest_check,
  DROP CONSTRAINT IF EXISTS ep_capability_operations_reconciliation_complete_check;

ALTER TABLE public.ep_capability_operations
  ADD CONSTRAINT ep_capability_operations_reconciliation_outcome_check
    CHECK (reconciliation_outcome IN ('executed')),
  ADD CONSTRAINT ep_capability_operations_reconciliation_evidence_digest_check
    CHECK (
      reconciliation_evidence_digest IS NULL
      OR reconciliation_evidence_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
  ADD CONSTRAINT ep_capability_operations_reconciliation_complete_check
    CHECK (
      (reconciliation_outcome IS NULL AND reconciliation_evidence_digest IS NULL AND reconciled_at IS NULL)
      OR
      (reconciliation_outcome IS NOT NULL AND reconciliation_evidence_digest IS NOT NULL AND reconciled_at IS NOT NULL)
    );

COMMENT ON COLUMN public.ep_capability_operations.action_digest IS
  'SHA-256 over the same immutable canonical action snapshot used for scope evaluation and effect execution.';
COMMENT ON COLUMN public.ep_capability_operations.reconciliation_evidence_digest IS
  'Digest of authenticated provider evidence that proved the terminal reconciliation outcome; raw evidence remains in the evidence system.';
