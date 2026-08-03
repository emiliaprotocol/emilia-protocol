-- EMILIA capability action-digest fence production preflight.
--
-- Run this read-only artifact with capability writers QUIESCED before applying
-- supabase/migrations/20260803010000_capability_action_digest_fence.sql.
-- It reports duplicate live rows without exposing reservation_token and exits
-- with SQLSTATE 23505 when reconciliation is required. It never changes data.

BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;

DO $capability_action_digest_table_contract$
BEGIN
  IF to_regclass('ep_capability_operations') IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = '42P01',
      MESSAGE = 'ep_capability_operations does not exist in the active search_path',
      HINT = 'Connect to the intended Gate database and schema before running this preflight.';
  END IF;
END
$capability_action_digest_table_contract$;

-- This result set is the operator reconciliation queue. It deliberately omits
-- reservation_token and groups only statuses covered by the proposed fence.
SELECT
  operation_namespace,
  action_digest,
  count(*) AS live_row_count,
  count(*) FILTER (WHERE status = 'reserved') AS reserved_count,
  count(*) FILTER (WHERE status = 'provider_entered') AS provider_entered_count,
  count(*) FILTER (WHERE status = 'committed') AS committed_count,
  jsonb_agg(
    jsonb_build_object(
      'operation_id', operation_id,
      'capability_id', capability_id,
      'status', status,
      'outcome', outcome,
      'reserved_at', reserved_at,
      'entry_deadline_at', entry_deadline_at,
      'provider_entry_at', provider_entry_at,
      'committed_at', committed_at,
      'reconciled_at', reconciled_at
    )
    ORDER BY reserved_at, operation_id
  ) AS rows_to_reconcile
FROM ep_capability_operations
WHERE status IN ('reserved', 'provider_entered', 'committed')
GROUP BY operation_namespace, action_digest
HAVING count(*) > 1
ORDER BY operation_namespace, action_digest;

DO $capability_action_digest_duplicate_guard$
DECLARE
  duplicate_group_count BIGINT;
BEGIN
  SELECT count(*)
    INTO duplicate_group_count
    FROM (
      SELECT operation_namespace, action_digest
        FROM ep_capability_operations
        WHERE status IN ('reserved', 'provider_entered', 'committed')
        GROUP BY operation_namespace, action_digest
        HAVING count(*) > 1
    ) AS duplicate_groups;

  IF duplicate_group_count > 0 THEN
    RAISE EXCEPTION USING
      ERRCODE = '23505',
      MESSAGE = format(
        'EMILIA capability action-digest preflight found %s duplicate live group(s)',
        duplicate_group_count
      ),
      DETAIL = 'The preceding result set is the reconciliation queue. This read-only preflight changed no rows.',
      HINT = 'Do not apply the unique-index migration until every group is resolved through an approved, evidence-preserving operator procedure.';
  END IF;
END
$capability_action_digest_duplicate_guard$;

COMMIT;
