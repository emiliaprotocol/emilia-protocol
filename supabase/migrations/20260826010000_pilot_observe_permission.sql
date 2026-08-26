-- SPDX-License-Identifier: Apache-2.0
-- Give currently active, server-marked public pilot keys the one explicit
-- capability accepted by the centralized request authorization floor.
--
-- Non-empty permission sets are deliberately untouched. The application
-- treats every pilot identity as deny-by-default outside the exact reviewed
-- Gov/Fin precheck routes, even if a stale row carries write or admin.

UPDATE public.api_keys AS k
SET permissions = '["observe"]'::jsonb
FROM public.entities AS e
WHERE k.entity_id = e.id
  AND k.revoked_at IS NULL
  AND COALESCE(k.permissions, '[]'::jsonb) = '[]'::jsonb
  AND e.metadata->>'pilot_sandbox' = 'true'
  AND e.metadata->>'scope' = 'observe';
