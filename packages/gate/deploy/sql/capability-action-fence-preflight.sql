-- EMILIA capability action-digest fence production preflight.
--
-- Run this read-only artifact with capability writers QUIESCED before applying
-- supabase/migrations/20260803010000_capability_action_digest_fence.sql.
-- It supports the journaled historical table, where operation_namespace and
-- later lifecycle columns are absent. The only pre-migration namespace it uses
-- is the row's recorded capability_id, exactly matching the migration backfill.
-- The only pre-migration fence digest it uses is the recorded action_digest;
-- this preserves historical exact-action identity without inferring a broader
-- semantic equivalence that the row did not record.
-- It never changes data and never exposes reservation_token.

BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;

DO $capability_action_digest_table_contract$
DECLARE
  required_column_count INTEGER;
  unbound_operation_count BIGINT;
BEGIN
  IF pg_catalog.to_regclass('public.ep_capability_operations') IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = '42P01',
      MESSAGE = 'public.ep_capability_operations does not exist',
      HINT = 'Connect to the intended Gate database before running this preflight.';
  END IF;

  SELECT count(*)
    INTO required_column_count
    FROM pg_catalog.pg_attribute
    WHERE attrelid = 'public.ep_capability_operations'::pg_catalog.regclass
      AND attname = ANY(ARRAY[
        'operation_id',
        'capability_id',
        'action_digest',
        'status'
      ]::TEXT[])
      AND attnum > 0
      AND NOT attisdropped;

  IF required_column_count <> 4 THEN
    RAISE EXCEPTION USING
      ERRCODE = '55000',
      MESSAGE = 'public.ep_capability_operations is missing a required historical capability column',
      DETAIL = 'Required columns: operation_id, capability_id, action_digest, status.',
      HINT = 'Reconcile the schema against the journaled capability migrations before applying the action fence.';
  END IF;

  SELECT count(*)
    INTO unbound_operation_count
    FROM public.ep_capability_operations AS operations
    WHERE operations.capability_id IS NULL
       OR btrim(operations.capability_id) = ''
       OR (
         pg_catalog.to_jsonb(operations) ? 'operation_namespace'
         AND pg_catalog.to_jsonb(operations) ->> 'operation_namespace' IS NOT NULL
         AND btrim(
           pg_catalog.to_jsonb(operations) ->> 'operation_namespace'
         ) = ''
       )
       OR (
         pg_catalog.to_jsonb(operations) ? 'action_fence_digest'
         AND pg_catalog.to_jsonb(operations) ->> 'action_fence_digest' IS NOT NULL
         AND pg_catalog.to_jsonb(operations) ->> 'action_fence_digest'
           !~ '^sha256:[0-9a-f]{64}$'
       );

  IF unbound_operation_count > 0 THEN
    RAISE EXCEPTION USING
      ERRCODE = '23502',
      MESSAGE = format(
        'EMILIA capability action-digest preflight found %s unbound operation row(s)',
        unbound_operation_count
      ),
      DETAIL = 'No namespace or semantic fence was inferred for a blank binding or malformed recorded fence digest.',
      HINT = 'Bind each row from authoritative operation history before applying the migration.';
  END IF;
END
$capability_action_digest_table_contract$;

-- IF NOT EXISTS must never turn a same-named relation into deployment proof.
-- When the name is already present, require the complete index contract now;
-- a non-unique, invalid, differently keyed, included-column, or differently
-- predicated index is a closed deployment failure.
DO $capability_action_digest_existing_index_contract$
DECLARE
  named_relation OID;
  index_is_unique BOOLEAN;
  index_is_valid BOOLEAN;
  index_is_ready BOOLEAN;
  index_is_immediate BOOLEAN;
  index_is_exclusion BOOLEAN;
  index_nulls_not_distinct BOOLEAN;
  index_access_method TEXT;
  index_table OID;
  index_key_count INTEGER;
  index_attribute_count INTEGER;
  index_key_columns TEXT[];
  index_predicate TEXT;
  normalized_predicate TEXT;
BEGIN
  named_relation := pg_catalog.to_regclass(
    'public.ep_capability_operations_live_action_uniq'
  );
  IF named_relation IS NULL THEN
    RETURN;
  END IF;

  SELECT
      index_catalog.indisunique,
      index_catalog.indisvalid,
      index_catalog.indisready,
      index_catalog.indimmediate,
      index_catalog.indisexclusion,
      index_catalog.indnullsnotdistinct,
      access_method.amname,
      index_catalog.indrelid,
      index_catalog.indnkeyatts,
      index_catalog.indnatts,
      ARRAY(
        SELECT attribute_catalog.attname
          FROM unnest(index_catalog.indkey::SMALLINT[])
            WITH ORDINALITY AS key_column(attnum, ordinal)
          JOIN pg_catalog.pg_attribute AS attribute_catalog
            ON attribute_catalog.attrelid = index_catalog.indrelid
           AND attribute_catalog.attnum = key_column.attnum
          WHERE key_column.ordinal <= index_catalog.indnkeyatts
          ORDER BY key_column.ordinal
      ),
      pg_catalog.pg_get_expr(
        index_catalog.indpred,
        index_catalog.indrelid
      )
    INTO
      index_is_unique,
      index_is_valid,
      index_is_ready,
      index_is_immediate,
      index_is_exclusion,
      index_nulls_not_distinct,
      index_access_method,
      index_table,
      index_key_count,
      index_attribute_count,
      index_key_columns,
      index_predicate
    FROM pg_catalog.pg_index AS index_catalog
    JOIN pg_catalog.pg_class AS index_relation
      ON index_relation.oid = index_catalog.indexrelid
    JOIN pg_catalog.pg_am AS access_method
      ON access_method.oid = index_relation.relam
    WHERE index_catalog.indexrelid = named_relation;

  normalized_predicate := replace(
    regexp_replace(coalesce(index_predicate, ''), '\s+', '', 'g'),
    '::text',
    ''
  );

  IF index_is_unique IS DISTINCT FROM TRUE
     OR index_is_valid IS DISTINCT FROM TRUE
     OR index_is_ready IS DISTINCT FROM TRUE
     OR index_is_immediate IS DISTINCT FROM TRUE
     OR index_is_exclusion IS DISTINCT FROM FALSE
     OR index_nulls_not_distinct IS DISTINCT FROM FALSE
     OR index_access_method IS DISTINCT FROM 'btree'
     OR index_table IS DISTINCT FROM
       'public.ep_capability_operations'::pg_catalog.regclass::OID
     OR index_key_count IS DISTINCT FROM 2
     OR index_attribute_count IS DISTINCT FROM 2
     OR index_key_columns IS DISTINCT FROM
       ARRAY['operation_namespace', 'action_fence_digest']::TEXT[]
     OR normalized_predicate IS DISTINCT FROM
       '(status=ANY(ARRAY[''reserved'',''provider_entered'',''committed'']))' THEN
    RAISE EXCEPTION USING
      ERRCODE = '55000',
      MESSAGE = 'EMILIA capability action-digest fence index does not match its required contract',
      DETAIL = format(
        'unique=%s valid=%s ready=%s immediate=%s exclusion=%s nulls_not_distinct=%s method=%s table_oid=%s key_count=%s attribute_count=%s columns=%s predicate=%s',
        coalesce(index_is_unique::TEXT, '<missing>'),
        coalesce(index_is_valid::TEXT, '<missing>'),
        coalesce(index_is_ready::TEXT, '<missing>'),
        coalesce(index_is_immediate::TEXT, '<missing>'),
        coalesce(index_is_exclusion::TEXT, '<missing>'),
        coalesce(index_nulls_not_distinct::TEXT, '<missing>'),
        coalesce(index_access_method, '<missing>'),
        coalesce(index_table::TEXT, '<missing>'),
        coalesce(index_key_count::TEXT, '<missing>'),
        coalesce(index_attribute_count::TEXT, '<missing>'),
        coalesce(array_to_string(index_key_columns, ','), '<missing>'),
        coalesce(index_predicate, '<missing>')
      ),
      HINT = 'Do not continue. Remove or repair the conflicting relation only through a reviewed migration after preserving all operation history.';
  END IF;
END
$capability_action_digest_existing_index_contract$;

-- This result set is the operator reconciliation queue. to_jsonb makes optional
-- lifecycle fields safe on the historical table while still omitting the
-- reservation token. A missing operation_namespace resolves only to the exact
-- capability_id that the migration will backfill.
SELECT
  coalesce(
    pg_catalog.to_jsonb(operations) ->> 'operation_namespace',
    operations.capability_id
  ) AS operation_namespace,
  coalesce(
    pg_catalog.to_jsonb(operations) ->> 'action_fence_digest',
    operations.action_digest
  ) AS action_fence_digest,
  count(*) AS live_row_count,
  count(*) FILTER (WHERE operations.status = 'reserved') AS reserved_count,
  count(*) FILTER (WHERE operations.status = 'provider_entered') AS provider_entered_count,
  count(*) FILTER (WHERE operations.status = 'committed') AS committed_count,
  jsonb_agg(
    jsonb_build_object(
      'operation_id', operations.operation_id,
      'capability_id', operations.capability_id,
      'status', operations.status,
      'outcome', operations.outcome,
      'reserved_at', operations.reserved_at,
      'entry_deadline_at', pg_catalog.to_jsonb(operations) -> 'entry_deadline_at',
      'provider_entry_at', pg_catalog.to_jsonb(operations) -> 'provider_entry_at',
      'committed_at', operations.committed_at,
      'reconciled_at', pg_catalog.to_jsonb(operations) -> 'reconciled_at'
    )
    ORDER BY operations.reserved_at, operations.operation_id
  ) AS rows_to_reconcile
FROM public.ep_capability_operations AS operations
WHERE operations.status IN ('reserved', 'provider_entered', 'committed')
GROUP BY
  coalesce(
    pg_catalog.to_jsonb(operations) ->> 'operation_namespace',
    operations.capability_id
  ),
  coalesce(
    pg_catalog.to_jsonb(operations) ->> 'action_fence_digest',
    operations.action_digest
  )
HAVING count(*) > 1
ORDER BY operation_namespace, action_fence_digest;

DO $capability_action_digest_duplicate_guard$
DECLARE
  duplicate_group_count BIGINT;
BEGIN
  SELECT count(*)
    INTO duplicate_group_count
    FROM (
      SELECT
        coalesce(
          pg_catalog.to_jsonb(operations) ->> 'operation_namespace',
          operations.capability_id
        ) AS effective_operation_namespace,
        coalesce(
          pg_catalog.to_jsonb(operations) ->> 'action_fence_digest',
          operations.action_digest
        ) AS effective_action_fence_digest
        FROM public.ep_capability_operations AS operations
        WHERE operations.status IN ('reserved', 'provider_entered', 'committed')
        GROUP BY
          coalesce(
            pg_catalog.to_jsonb(operations) ->> 'operation_namespace',
            operations.capability_id
          ),
          coalesce(
            pg_catalog.to_jsonb(operations) ->> 'action_fence_digest',
            operations.action_digest
          )
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
