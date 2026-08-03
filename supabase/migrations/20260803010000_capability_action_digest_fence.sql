-- Fence capability operations on the ACTION, not only on the operation id.
--
-- The current package table is keyed on (operation_namespace, operation_id),
-- while the journaled historical migration used operation_id alone and had no
-- namespace column. This migration first closes that schema gap, then installs
-- the separate store-level action fence so request wrappers with different
-- operation ids cannot both remain live when the caller supplies one stable
-- semantic fence digest.
--
-- reserveSpend reads and locks an existing holder inside its transaction, and
-- same-capability reservations serialize on the capability-state row. A custom
-- namespace can span different capability rows, however, and PostgreSQL cannot
-- lock an absent operation row. This index is therefore the authoritative race
-- backstop as well as protection for every other table writer. The adapter
-- translates its SQLSTATE 23505 collision into the same closed action_in_flight
-- result as the preflight read.
--
-- Scoped to operation_namespace on purpose. The namespace is the authorization
-- domain, defaulting to the capability id. Two DIFFERENT capabilities may each
-- hold the same action digest, which is what multi-party quorum requires: N
-- principals independently authorizing one action. A globally unique index
-- would silently make quorum unsatisfiable.
--
-- 'released' is excluded. A released operation carries outcome 'not_entered',
-- meaning the provider provably never received it, so re-authorizing that same
-- action is a genuine retry and must remain possible.

-- The journaled capability migration created operation_id as a global primary
-- key and predates operation_namespace. Historical rows do carry the exact
-- capability_id that supplied their authorization domain, so that is the only
-- defensible backfill. Blank capability bindings are not evidence and must be
-- reconciled explicitly rather than assigned a migration-invented namespace.
ALTER TABLE public.ep_capability_operations
  ADD COLUMN IF NOT EXISTS operation_namespace TEXT;

-- The current store separates the exact per-request action_digest from the
-- stable action_fence_digest used for semantic replay fencing. Historical rows
-- contain only action_digest. Copying those recorded bytes is the conservative
-- compatibility identity: it preserves the old exact-action distinction and
-- does not invent equivalence evidence that the historical row never carried.
ALTER TABLE public.ep_capability_operations
  ADD COLUMN IF NOT EXISTS action_fence_digest TEXT;

DO $capability_operation_namespace_preflight$
DECLARE
  unbound_operation_count BIGINT;
BEGIN
  SELECT count(*)
    INTO unbound_operation_count
    FROM public.ep_capability_operations
    WHERE capability_id IS NULL
       OR btrim(capability_id) = ''
       OR (
         operation_namespace IS NOT NULL
         AND btrim(operation_namespace) = ''
       )
       OR (
         action_fence_digest IS NOT NULL
         AND action_fence_digest !~ '^sha256:[0-9a-f]{64}$'
       );

  IF unbound_operation_count > 0 THEN
    RAISE EXCEPTION USING
      ERRCODE = '23502',
      MESSAGE = format(
        'EMILIA capability namespace migration found %s unbound operation row(s)',
        unbound_operation_count
      ),
      DETAIL = 'No namespace or semantic fence was invented. Blank bindings or malformed recorded fence digests require evidence-preserving operator reconciliation.',
      HINT = 'Quiesce capability writers and bind each row from authoritative operation history before retrying this migration.';
  END IF;
END
$capability_operation_namespace_preflight$;

UPDATE public.ep_capability_operations
  SET operation_namespace = capability_id
  WHERE operation_namespace IS NULL;

UPDATE public.ep_capability_operations
  SET action_fence_digest = action_digest
  WHERE action_fence_digest IS NULL;

ALTER TABLE public.ep_capability_operations
  ALTER COLUMN operation_namespace SET NOT NULL,
  ALTER COLUMN action_fence_digest SET NOT NULL;

ALTER TABLE public.ep_capability_operations
  DROP CONSTRAINT IF EXISTS ep_capability_operations_action_fence_digest_check;

ALTER TABLE public.ep_capability_operations
  ADD CONSTRAINT ep_capability_operations_action_fence_digest_check
  CHECK (action_fence_digest ~ '^sha256:[0-9a-f]{64}$');

-- Replace only the exact historical primary key. The DROP and ADD share one
-- ALTER TABLE statement and transaction, so PostgreSQL never commits a state
-- without a primary key. An absent or surprising key is schema drift and is
-- refused instead of being silently normalized.
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
      HINT = 'Do not drop or replace an unknown key automatically. Reconcile the schema against the journaled capability migration first.';
  END IF;

  EXECUTE format(
    'ALTER TABLE public.ep_capability_operations DROP CONSTRAINT %I, ADD CONSTRAINT ep_capability_operations_pkey PRIMARY KEY (operation_namespace, operation_id)',
    current_primary_key_name
  );
END
$capability_operation_primary_key$;

-- Do not let CREATE UNIQUE INDEX become an implicit or operator-invented data
-- repair. Existing duplicate live rows require explicit, status-aware
-- reconciliation before this migration can proceed. In particular,
-- provider_entered and committed rows must never be deleted or relabeled by a
-- generic migration: they may represent a real or indeterminate external
-- effect whose history must be preserved.
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
      DETAIL = 'No rows were changed. Inspect every conflicting status with the packaged capability-action-fence-preflight.sql before applying this migration.',
      HINT = 'Quiesce capability writers and reconcile through owner-fenced lifecycle operations. Never auto-delete or relabel provider_entered or committed rows.';
  END IF;
END
$capability_action_digest_preflight$;

CREATE UNIQUE INDEX IF NOT EXISTS ep_capability_operations_live_action_uniq
  ON public.ep_capability_operations (operation_namespace, action_fence_digest)
  WHERE status IN ('reserved', 'provider_entered', 'committed');

-- IF NOT EXISTS is safe only if an existing same-named index has the exact
-- contract. Refuse a stale, non-unique, differently keyed, or differently
-- predicated index rather than silently treating it as the fence.
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
  index_predicate TEXT;
  normalized_predicate TEXT;
BEGIN
  SELECT
      i.indisunique,
      i.indisvalid,
      i.indisready,
      i.indimmediate,
      i.indisexclusion,
      i.indnullsnotdistinct,
      access_method.amname,
      i.indrelid,
      i.indnkeyatts,
      i.indnatts,
      ARRAY(
        SELECT a.attname
          FROM unnest(i.indkey::SMALLINT[]) WITH ORDINALITY AS key(attnum, ordinal)
          JOIN pg_catalog.pg_attribute AS a
            ON a.attrelid = i.indrelid
           AND a.attnum = key.attnum
          WHERE key.ordinal <= i.indnkeyatts
          ORDER BY key.ordinal
      ),
      pg_catalog.pg_get_expr(i.indpred, i.indrelid)
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
    FROM pg_catalog.pg_index AS i
    JOIN pg_catalog.pg_class AS index_relation
      ON index_relation.oid = i.indexrelid
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
     OR index_key_columns IS DISTINCT FROM ARRAY['operation_namespace', 'action_fence_digest']::TEXT[]
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
      HINT = 'Do not continue. Remove or repair the conflicting index only through a reviewed migration after preserving all operation history.';
  END IF;
END
$capability_action_digest_index_contract$;

COMMENT ON INDEX public.ep_capability_operations_live_action_uniq IS
  'Store-level defense in depth: at most one live (reserved/provider_entered/committed) operation per explicitly supplied action fence digest per authorization namespace. Historical rows conservatively reuse their recorded exact-action digest; no broader equivalence is inferred. Released operations are excluded so a proven non-entry can be retried. Scoped per namespace so quorum across distinct capabilities stays possible.';
