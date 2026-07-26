-- SPDX-License-Identifier: Apache-2.0
-- Retire the control-plane capability of public pilot credentials across the
-- entire credential population, including keys issued before the metadata
-- marker was introduced.

ALTER TABLE public.entities
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE public.api_keys
  ADD COLUMN IF NOT EXISTS revocation_reason TEXT DEFAULT NULL;

COMMENT ON COLUMN public.entities.metadata IS
  'Non-secret entity metadata. pilot_sandbox=true and scope=observe identify public observe-only pilot entities.';

-- Backfill the durable marker before revoking the historical bearer keys. The
-- route-generated identity shape is the legacy discriminator used by the
-- application guard during the migration window.
UPDATE public.entities
SET metadata = COALESCE(metadata, '{}'::jsonb)
  || jsonb_build_object('pilot_sandbox', true, 'scope', 'observe')
WHERE entity_type = 'agent'
  AND organization_id = entity_id
  AND display_name LIKE 'Pilot · %'
  AND description LIKE 'Observe-mode pilot sandbox for %'
  AND NOT (
    COALESCE(metadata, '{}'::jsonb)->>'pilot_sandbox' = 'true'
    AND COALESCE(metadata, '{}'::jsonb)->>'scope' = 'observe'
  );

-- Historical pilot keys are disposable observe-only credentials. Revoke all
-- of them so a stale key cannot authenticate during or after rollout; users can
-- provision a fresh sandbox key after the marker is in place.
UPDATE public.api_keys AS k
SET revoked_at = COALESCE(k.revoked_at, now()),
    revocation_reason = COALESCE(k.revocation_reason, 'legacy public pilot sandbox retired during observe-scope hardening')
FROM public.entities AS e
WHERE k.entity_id = e.id
  AND e.entity_type = 'agent'
  AND e.organization_id = e.entity_id
  AND e.display_name LIKE 'Pilot · %'
  AND e.description LIKE 'Observe-mode pilot sandbox for %'
  AND k.revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_entities_pilot_observe_scope
  ON public.entities ((metadata->>'pilot_sandbox'), (metadata->>'scope'))
  WHERE metadata->>'pilot_sandbox' = 'true'
    AND metadata->>'scope' = 'observe';
