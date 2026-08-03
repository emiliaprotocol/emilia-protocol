-- EMILIA capability action-fence production preflight.
--
-- Run with every capability writer quiesced before applying
-- supabase/migrations/20260803010000_capability_action_digest_fence.sql.
-- This script is read-only, never exposes reservation_token, and supports both
-- the journaled historical schema and the migrated schema. A capability with
-- historical operations is permanently quarantined under that legacy ID. The
-- rollout never infers semantic equivalence from historical exact digests;
-- review may result only in a fresh capability with a new capability ID.

BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;

DO $capability_action_digest_table_contract$
DECLARE
  required_operation_column_count INTEGER;
  required_state_column_count INTEGER;
  unbound_operation_count BIGINT;
BEGIN
  IF pg_catalog.to_regclass('public.ep_capability_operations') IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = '42P01',
      MESSAGE = 'public.ep_capability_operations does not exist',
      HINT = 'Connect to the intended Gate database before running this preflight.';
  END IF;

  IF pg_catalog.to_regclass('public.ep_capability_state') IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = '42P01',
      MESSAGE = 'public.ep_capability_state does not exist',
      HINT = 'Reconcile the journaled capability migration chain before applying the action fence.';
  END IF;

  SELECT count(*)
    INTO required_operation_column_count
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

  SELECT count(*)
    INTO required_state_column_count
    FROM pg_catalog.pg_attribute
    WHERE attrelid = 'public.ep_capability_state'::pg_catalog.regclass
      AND attname = 'capability_id'
      AND attnum > 0
      AND NOT attisdropped;

  IF required_operation_column_count <> 4
     OR required_state_column_count <> 1 THEN
    RAISE EXCEPTION USING
      ERRCODE = '55000',
      MESSAGE = 'the capability schema is missing a required historical column',
      DETAIL = 'Required operation columns: operation_id, capability_id, action_digest, status. Required state column: capability_id.',
      HINT = 'Reconcile the schema against the journaled capability migrations before applying the action fence.';
  END IF;

  SELECT count(*)
    INTO unbound_operation_count
    FROM public.ep_capability_operations AS operations
    WHERE operations.capability_id IS NULL
       OR btrim(operations.capability_id) = ''
       OR operations.action_digest !~ '^sha256:[0-9a-f]{64}$'
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
       )
       OR (
         pg_catalog.to_jsonb(operations) ? 'release_evidence_digest'
         AND pg_catalog.to_jsonb(operations) ->> 'release_evidence_digest' IS NOT NULL
         AND pg_catalog.to_jsonb(operations) ->> 'release_evidence_digest'
           !~ '^sha256:[0-9a-f]{64}$'
       );

  IF unbound_operation_count > 0 THEN
    RAISE EXCEPTION USING
      ERRCODE = '23502',
      MESSAGE = format(
        'EMILIA capability action-digest preflight found %s unbound operation row(s)',
        unbound_operation_count
      ),
      DETAIL = 'This read-only preflight changed no rows and inferred no semantic evidence.',
      HINT = 'Bind each row from authoritative operation history before applying the migration.';
  END IF;
END
$capability_action_digest_table_contract$;

-- Legacy reserved rows are not safely migratable: the historical schema has no
-- provider-entry deadline and the plaintext owner token may no longer exist.
-- Print the affected rows without their reservation tokens, then fail closed.
SELECT
  operations.operation_id,
  operations.capability_id,
  operations.action_digest,
  operations.status,
  operations.reserved_at
FROM public.ep_capability_operations AS operations
WHERE operations.status = 'reserved'
  AND (
    NOT (pg_catalog.to_jsonb(operations) ? 'entry_deadline_at')
    OR pg_catalog.to_jsonb(operations) -> 'entry_deadline_at' = 'null'::JSONB
  )
ORDER BY operations.reserved_at, operations.operation_id;

DO $capability_action_digest_legacy_reservation_guard$
DECLARE
  unsafe_reserved_count BIGINT;
BEGIN
  SELECT count(*)
    INTO unsafe_reserved_count
    FROM public.ep_capability_operations AS operations
    WHERE operations.status = 'reserved'
      AND (
        NOT (pg_catalog.to_jsonb(operations) ? 'entry_deadline_at')
        OR pg_catalog.to_jsonb(operations) -> 'entry_deadline_at' = 'null'::JSONB
      );

  IF unsafe_reserved_count > 0 THEN
    RAISE EXCEPTION USING
      ERRCODE = '55000',
      MESSAGE = format(
        'EMILIA capability action-digest preflight found %s unsafe legacy reserved operation(s)',
        unsafe_reserved_count
      ),
      DETAIL = 'The preceding read-only result is the unsafe-reservation queue; no row was changed.',
      HINT = 'Reconcile each reservation through an evidence-preserving owner procedure before applying the migration.';
  END IF;
END
$capability_action_digest_legacy_reservation_guard$;

-- IF NOT EXISTS must not turn a same-named but physically different index into
-- deployment proof. If the name exists, validate its complete contract.
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
  index_key_collations OID[];
  expected_key_collations OID[];
  index_key_opclasses OID[];
  expected_key_opclasses OID[];
  index_key_options SMALLINT[];
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
      ARRAY(
        SELECT key_column.collation_oid
          FROM unnest(index_catalog.indcollation::OID[])
            WITH ORDINALITY AS key_column(collation_oid, ordinal)
          WHERE key_column.ordinal <= index_catalog.indnkeyatts
          ORDER BY key_column.ordinal
      ),
      ARRAY(
        SELECT attribute_catalog.attcollation
          FROM unnest(index_catalog.indkey::SMALLINT[])
            WITH ORDINALITY AS key_column(attnum, ordinal)
          JOIN pg_catalog.pg_attribute AS attribute_catalog
            ON attribute_catalog.attrelid = index_catalog.indrelid
           AND attribute_catalog.attnum = key_column.attnum
          WHERE key_column.ordinal <= index_catalog.indnkeyatts
          ORDER BY key_column.ordinal
      ),
      ARRAY(
        SELECT key_column.opclass_oid
          FROM unnest(index_catalog.indclass::OID[])
            WITH ORDINALITY AS key_column(opclass_oid, ordinal)
          WHERE key_column.ordinal <= index_catalog.indnkeyatts
          ORDER BY key_column.ordinal
      ),
      ARRAY(
        SELECT default_opclass.oid
          FROM unnest(index_catalog.indkey::SMALLINT[])
            WITH ORDINALITY AS key_column(attnum, ordinal)
          JOIN pg_catalog.pg_attribute AS attribute_catalog
            ON attribute_catalog.attrelid = index_catalog.indrelid
           AND attribute_catalog.attnum = key_column.attnum
          JOIN LATERAL (
            SELECT operator_class.oid
              FROM pg_catalog.pg_opclass AS operator_class
              WHERE operator_class.opcmethod = index_relation.relam
                AND operator_class.opcdefault
                AND operator_class.opcintype = attribute_catalog.atttypid
              ORDER BY operator_class.oid
              LIMIT 1
          ) AS default_opclass ON TRUE
          WHERE key_column.ordinal <= index_catalog.indnkeyatts
          ORDER BY key_column.ordinal
      ),
      ARRAY(
        SELECT key_column.option_bits
          FROM unnest(index_catalog.indoption::SMALLINT[])
            WITH ORDINALITY AS key_column(option_bits, ordinal)
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
      index_key_collations,
      expected_key_collations,
      index_key_opclasses,
      expected_key_opclasses,
      index_key_options,
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
     OR index_key_collations IS DISTINCT FROM expected_key_collations
     OR index_key_opclasses IS DISTINCT FROM expected_key_opclasses
     OR index_key_options IS DISTINCT FROM ARRAY[0, 0]::SMALLINT[]
     OR normalized_predicate IS DISTINCT FROM
       '(status=ANY(ARRAY[''reserved'',''provider_entered'',''committed'']))' THEN
    RAISE EXCEPTION USING
      ERRCODE = '55000',
      MESSAGE = 'EMILIA capability action-digest fence index does not match its required contract',
      DETAIL = format(
        'unique=%s valid=%s ready=%s immediate=%s exclusion=%s nulls_not_distinct=%s method=%s table_oid=%s key_count=%s attribute_count=%s columns=%s collations=%s expected_collations=%s opclasses=%s expected_opclasses=%s options=%s predicate=%s',
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
        coalesce(array_to_string(index_key_collations, ','), '<missing>'),
        coalesce(array_to_string(expected_key_collations, ','), '<missing>'),
        coalesce(array_to_string(index_key_opclasses, ','), '<missing>'),
        coalesce(array_to_string(expected_key_opclasses, ','), '<missing>'),
        coalesce(array_to_string(index_key_options, ','), '<missing>'),
        coalesce(index_predicate, '<missing>')
      ),
      HINT = 'Remove or repair the conflicting relation only through a reviewed migration after preserving all operation history.';
  END IF;
END
$capability_action_digest_existing_index_contract$;

-- Show duplicate live groups without secrets. A historical action_digest is
-- displayed only as compatibility identity; the migration does not claim it is
-- an authoritative semantic fence.
SELECT
  coalesce(
    pg_catalog.to_jsonb(operations) ->> 'operation_namespace',
    operations.capability_id
  ) AS operation_namespace,
  coalesce(
    pg_catalog.to_jsonb(operations) ->> 'action_fence_digest',
    operations.action_digest
  ) AS compatibility_fence_digest,
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
ORDER BY operation_namespace, compatibility_fence_digest;

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
      DETAIL = 'The preceding result is the reconciliation queue. This read-only preflight changed no rows.',
      HINT = 'Do not apply the unique-index migration until every group is resolved through an approved, evidence-preserving operator procedure.';
  END IF;
END
$capability_action_digest_duplicate_guard$;

-- Preview legacy capability IDs that the migration will permanently quarantine.
-- Do not set semantic_fence_ready back to TRUE for these IDs. Review may support
-- issuing a fresh capability with a new ID, but historical exact digests are
-- never a semantic-equivalence backfill.
SELECT
  operations.capability_id,
  count(*) AS historical_operation_count,
  FALSE AS semantic_fence_ready_after_migration
FROM public.ep_capability_operations AS operations
JOIN public.ep_capability_state AS capability_state
  ON capability_state.capability_id = operations.capability_id
WHERE NOT (pg_catalog.to_jsonb(capability_state) ? 'semantic_fence_ready')
   OR pg_catalog.to_jsonb(capability_state) -> 'semantic_fence_ready' = 'null'::JSONB
   OR NOT (pg_catalog.to_jsonb(operations) ? 'operation_namespace')
   OR pg_catalog.to_jsonb(operations) -> 'operation_namespace' = 'null'::JSONB
   OR NOT (pg_catalog.to_jsonb(operations) ? 'action_fence_digest')
   OR pg_catalog.to_jsonb(operations) -> 'action_fence_digest' = 'null'::JSONB
GROUP BY operations.capability_id
ORDER BY operations.capability_id;

COMMIT;
