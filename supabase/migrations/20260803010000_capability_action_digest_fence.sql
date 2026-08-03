-- Fence capability operations on the material action, not only on an
-- operation identifier. The explicit transaction is part of the deployment
-- contract: direct psql application with ON_ERROR_STOP must never leave a
-- partially upgraded historical schema.

BEGIN;

-- The journaled historical table predates the namespace, semantic fence, and
-- provider-entry lifecycle. Adding all fields here keeps the tracked migration
-- chain compatible with the packaged Gate runtime.
ALTER TABLE public.ep_capability_operations
  ADD COLUMN IF NOT EXISTS operation_namespace TEXT,
  ADD COLUMN IF NOT EXISTS action_fence_digest TEXT,
  ADD COLUMN IF NOT EXISTS entry_deadline_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS provider_entry_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS released_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS release_reason TEXT,
  ADD COLUMN IF NOT EXISTS release_evidence_profile TEXT,
  ADD COLUMN IF NOT EXISTS release_evidence_digest TEXT;

ALTER TABLE public.ep_capability_state
  ADD COLUMN IF NOT EXISTS semantic_fence_ready BOOLEAN;

-- Do not invent a namespace or accept malformed digest history. Constraint
-- restoration below is deliberate: ADD COLUMN IF NOT EXISTS alone does not
-- repair a same-named column that arrived without its governed CHECK.
DO $capability_operation_history_preflight$
DECLARE
  unbound_operation_count BIGINT;
BEGIN
  SELECT count(*)
    INTO unbound_operation_count
    FROM public.ep_capability_operations
    WHERE capability_id IS NULL
       OR btrim(capability_id) = ''
       OR action_digest !~ '^sha256:[0-9a-f]{64}$'
       OR (
         operation_namespace IS NOT NULL
         AND btrim(operation_namespace) = ''
       )
       OR (
         action_fence_digest IS NOT NULL
         AND action_fence_digest !~ '^sha256:[0-9a-f]{64}$'
       )
       OR (
         release_evidence_digest IS NOT NULL
         AND release_evidence_digest !~ '^sha256:[0-9a-f]{64}$'
       );

  IF unbound_operation_count > 0 THEN
    RAISE EXCEPTION USING
      ERRCODE = '23502',
      MESSAGE = format(
        'EMILIA capability namespace migration found %s unbound operation row(s)',
        unbound_operation_count
      ),
      DETAIL = 'The migration transaction was aborted. No namespace, semantic fence, or digest evidence was invented.',
      HINT = 'Quiesce capability writers and reconcile each row from authoritative operation history before retrying.';
  END IF;
END
$capability_operation_history_preflight$;

-- A legacy reserved row has no provider-entry deadline and its only owner token
-- may already be lost. Migrating it would make an unsafe reservation look
-- recoverable. Committed history may be retained, but reserved history must be
-- reconciled before this migration runs.
DO $capability_legacy_reservation_preflight$
DECLARE
  unsafe_reserved_count BIGINT;
BEGIN
  SELECT count(*)
    INTO unsafe_reserved_count
    FROM public.ep_capability_operations
    WHERE status = 'reserved'
      AND entry_deadline_at IS NULL;

  IF unsafe_reserved_count > 0 THEN
    RAISE EXCEPTION USING
      ERRCODE = '55000',
      MESSAGE = format(
        'EMILIA capability action-fence migration found %s unsafe legacy reserved operation(s)',
        unsafe_reserved_count
      ),
      DETAIL = 'The migration transaction was aborted; no schema or row change committed.',
      HINT = 'Keep writers quiesced and reconcile each reservation through an evidence-preserving owner procedure before retrying.';
  END IF;
END
$capability_legacy_reservation_preflight$;

-- Capture the legacy population before filling compatibility fields. This
-- forces quarantine even if an incomplete bootstrap previously added
-- semantic_fence_ready with its default TRUE. On a converged rerun, no row
-- qualifies, so the migration remains idempotent.
CREATE TEMP TABLE ep_capability_action_fence_legacy_ids
ON COMMIT DROP
AS
SELECT DISTINCT capability_id
FROM public.ep_capability_operations
WHERE operation_namespace IS NULL
   OR action_fence_digest IS NULL;

UPDATE public.ep_capability_operations
  SET operation_namespace = capability_id
  WHERE operation_namespace IS NULL;

-- Historical rows did not record a semantic action fence. Reusing the exact
-- action digest preserves compatibility identity only; it is not evidence that
-- wrappers are materially equivalent. The capability quarantine below prevents
-- new operations permanently for that legacy capability ID. Review may support
-- issuing a fresh capability with a new ID; it never converts historical exact
-- digests into semantic-equivalence evidence.
UPDATE public.ep_capability_operations
  SET action_fence_digest = action_digest
  WHERE action_fence_digest IS NULL;

UPDATE public.ep_capability_state AS capability_state
  SET semantic_fence_ready = FALSE
  FROM pg_temp.ep_capability_action_fence_legacy_ids AS legacy_capability
  WHERE legacy_capability.capability_id = capability_state.capability_id;

UPDATE public.ep_capability_state AS capability_state
  SET semantic_fence_ready = NOT EXISTS (
    SELECT 1
      FROM public.ep_capability_operations AS operation
      WHERE operation.capability_id = capability_state.capability_id
  )
  WHERE capability_state.semantic_fence_ready IS NULL;

ALTER TABLE public.ep_capability_state
  ALTER COLUMN semantic_fence_ready SET DEFAULT TRUE,
  ALTER COLUMN semantic_fence_ready SET NOT NULL;

ALTER TABLE public.ep_capability_operations
  ALTER COLUMN operation_namespace SET NOT NULL,
  ALTER COLUMN action_fence_digest SET NOT NULL;

-- Restore the exact current checks even when a prior bootstrap created the
-- columns without governed constraints.
ALTER TABLE public.ep_capability_operations
  DROP CONSTRAINT IF EXISTS ep_capability_operations_status_check,
  DROP CONSTRAINT IF EXISTS ep_capability_operations_action_digest_check,
  DROP CONSTRAINT IF EXISTS ep_capability_operations_action_fence_digest_check,
  DROP CONSTRAINT IF EXISTS ep_capability_operations_release_evidence_digest_check;

ALTER TABLE public.ep_capability_operations
  ADD CONSTRAINT ep_capability_operations_status_check
    CHECK (status IN ('reserved', 'provider_entered', 'committed', 'released')),
  ADD CONSTRAINT ep_capability_operations_action_digest_check
    CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$'),
  ADD CONSTRAINT ep_capability_operations_action_fence_digest_check
    CHECK (action_fence_digest ~ '^sha256:[0-9a-f]{64}$'),
  ADD CONSTRAINT ep_capability_operations_release_evidence_digest_check
    CHECK (
      release_evidence_digest IS NULL
      OR release_evidence_digest ~ '^sha256:[0-9a-f]{64}$'
    );

-- Replace only the exact historical primary key. Unknown primary-key drift is
-- never normalized automatically.
DO $capability_operation_primary_key$
DECLARE
  current_primary_key_name TEXT;
  current_primary_key_columns TEXT[];
BEGIN
  SELECT
      constraint_catalog.conname,
      ARRAY(
        SELECT attribute_catalog.attname
          FROM unnest(constraint_catalog.conkey)
            WITH ORDINALITY AS key_column(attnum, ordinal)
          JOIN pg_catalog.pg_attribute AS attribute_catalog
            ON attribute_catalog.attrelid = constraint_catalog.conrelid
           AND attribute_catalog.attnum = key_column.attnum
          ORDER BY key_column.ordinal
      )
    INTO current_primary_key_name, current_primary_key_columns
    FROM pg_catalog.pg_constraint AS constraint_catalog
    WHERE constraint_catalog.conrelid =
      'public.ep_capability_operations'::pg_catalog.regclass
      AND constraint_catalog.contype = 'p';

  IF current_primary_key_columns IS NOT DISTINCT FROM
    ARRAY['operation_namespace', 'operation_id']::TEXT[] THEN
    RETURN;
  END IF;

  IF current_primary_key_columns IS DISTINCT FROM ARRAY['operation_id']::TEXT[]
     OR current_primary_key_name IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = '55000',
      MESSAGE = 'EMILIA capability namespace migration found an unexpected primary key',
      DETAIL = format(
        'primary_key=%s columns=%s',
        coalesce(current_primary_key_name, '<missing>'),
        coalesce(array_to_string(current_primary_key_columns, ','), '<missing>')
      ),
      HINT = 'Reconcile the schema against the journaled capability migration before retrying.';
  END IF;

  EXECUTE format(
    'ALTER TABLE public.ep_capability_operations DROP CONSTRAINT %I, ADD CONSTRAINT ep_capability_operations_pkey PRIMARY KEY (operation_namespace, operation_id)',
    current_primary_key_name
  );
END
$capability_operation_primary_key$;

-- A quarantined capability cannot acquire new operation history through a
-- direct table writer. Existing rows remain mutable so authenticated
-- reconciliation and evidence-preserving closure are still possible.
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
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '55000',
      MESSAGE = 'capability semantic action fence is not ready',
      DETAIL = format('capability_id=%s', NEW.capability_id),
      HINT = 'Do not unquarantine this legacy capability ID or infer semantic equivalence from historical exact digests. After review, issue a fresh capability with a new capability ID.';
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

-- Refuse duplicate live history instead of deleting, relabeling, or assigning
-- semantic meaning to it.
DO $capability_action_digest_preflight$
DECLARE
  duplicate_group_count BIGINT;
BEGIN
  SELECT count(*)
    INTO duplicate_group_count
    FROM (
      SELECT operation_namespace, action_fence_digest
        FROM public.ep_capability_operations
        WHERE status IN ('reserved', 'provider_entered', 'committed')
        GROUP BY operation_namespace, action_fence_digest
        HAVING count(*) > 1
    ) AS duplicate_groups;

  IF duplicate_group_count > 0 THEN
    RAISE EXCEPTION USING
      ERRCODE = '23505',
      MESSAGE = format(
        'EMILIA capability action-digest fence preflight found %s duplicate live group(s)',
        duplicate_group_count
      ),
      DETAIL = 'The migration transaction was aborted; no schema or row change committed.',
      HINT = 'Reconcile every row through owner-fenced lifecycle operations. Never auto-delete or relabel provider_entered or committed history.';
  END IF;
END
$capability_action_digest_preflight$;

CREATE UNIQUE INDEX IF NOT EXISTS ep_capability_operations_live_action_uniq
  ON public.ep_capability_operations (operation_namespace, action_fence_digest)
  WHERE status IN ('reserved', 'provider_entered', 'committed');

-- IF NOT EXISTS is acceptable only after proving that a same-named object has
-- the exact physical contract: method, table, key order, column collations,
-- default btree operator classes, sort/null options, and predicate.
DO $capability_action_digest_index_contract$
DECLARE
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
      pg_catalog.pg_get_expr(index_catalog.indpred, index_catalog.indrelid)
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
    JOIN pg_catalog.pg_namespace AS index_namespace
      ON index_namespace.oid = index_relation.relnamespace
    JOIN pg_catalog.pg_am AS access_method
      ON access_method.oid = index_relation.relam
    WHERE index_namespace.nspname = 'public'
      AND index_relation.relname =
        'ep_capability_operations_live_action_uniq';

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
      HINT = 'Remove or repair the conflicting index only through a reviewed migration that preserves operation history.';
  END IF;
END
$capability_action_digest_index_contract$;

COMMENT ON COLUMN public.ep_capability_state.semantic_fence_ready IS
  'FALSE permanently quarantines a legacy capability ID whose historical operations lack an authoritative semantic action-fence mapping. Never infer equivalence from historical exact digests; after review, issue a fresh capability ID.';
COMMENT ON INDEX public.ep_capability_operations_live_action_uniq IS
  'At most one live operation per explicit material-action fence and authorization namespace. Historical exact-digest backfill is compatibility identity only; the legacy capability ID remains quarantined and reviewed use requires a freshly issued capability ID.';

COMMIT;
