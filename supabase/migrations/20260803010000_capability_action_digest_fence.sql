-- Fence capability operations on the ACTION, not only on the operation id.
--
-- Before this, ep_capability_operations was unique on (operation_namespace,
-- operation_id) only. If a caller deliberately supplies one stable semantic
-- action digest across request wrappers with different operation ids, this
-- store-level fence prevents both wrappers from remaining live. Gate does not
-- infer that two actions are equivalent after a wrapper operation id changes;
-- if that field changes the supplied action digest, this fence does not join
-- them. It is defense in depth for callers that define and preserve a stable
-- semantic digest at their trust boundary.
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
        'EMILIA capability action-digest fence preflight found %s duplicate live group(s)',
        duplicate_group_count
      ),
      DETAIL = 'No rows were changed. Inspect every conflicting status with the packaged capability-action-fence-preflight.sql before applying this migration.',
      HINT = 'Quiesce capability writers and reconcile through owner-fenced lifecycle operations. Never auto-delete or relabel provider_entered or committed rows.';
  END IF;
END
$capability_action_digest_preflight$;

CREATE UNIQUE INDEX IF NOT EXISTS ep_capability_operations_live_action_uniq
  ON ep_capability_operations (operation_namespace, action_digest)
  WHERE status IN ('reserved', 'provider_entered', 'committed');

-- IF NOT EXISTS is safe only if an existing same-named index has the exact
-- contract. Refuse a stale, non-unique, differently keyed, or differently
-- predicated index rather than silently treating it as the fence.
DO $capability_action_digest_index_contract$
DECLARE
  index_is_unique BOOLEAN;
  index_key_columns TEXT[];
  index_predicate TEXT;
  normalized_predicate TEXT;
BEGIN
  SELECT
      i.indisunique,
      ARRAY(
        SELECT a.attname
          FROM unnest(i.indkey::SMALLINT[]) WITH ORDINALITY AS key(attnum, ordinal)
          JOIN pg_attribute AS a
            ON a.attrelid = i.indrelid
           AND a.attnum = key.attnum
          WHERE key.ordinal <= i.indnkeyatts
          ORDER BY key.ordinal
      ),
      pg_get_expr(i.indpred, i.indrelid)
    INTO index_is_unique, index_key_columns, index_predicate
    FROM pg_index AS i
    WHERE i.indexrelid = to_regclass('ep_capability_operations_live_action_uniq')
      AND i.indrelid = 'ep_capability_operations'::regclass;

  normalized_predicate := replace(
    regexp_replace(coalesce(index_predicate, ''), '\s+', '', 'g'),
    '::text',
    ''
  );

  IF index_is_unique IS DISTINCT FROM TRUE
     OR index_key_columns IS DISTINCT FROM ARRAY['operation_namespace', 'action_digest']::TEXT[]
     OR normalized_predicate IS DISTINCT FROM
       '(status=ANY(ARRAY[''reserved'',''provider_entered'',''committed'']))' THEN
    RAISE EXCEPTION USING
      ERRCODE = '55000',
      MESSAGE = 'EMILIA capability action-digest fence index does not match its required contract',
      DETAIL = format(
        'unique=%s columns=%s predicate=%s',
        coalesce(index_is_unique::TEXT, '<missing>'),
        coalesce(array_to_string(index_key_columns, ','), '<missing>'),
        coalesce(index_predicate, '<missing>')
      ),
      HINT = 'Do not continue. Remove or repair the conflicting index only through a reviewed migration after preserving all operation history.';
  END IF;
END
$capability_action_digest_index_contract$;

COMMENT ON INDEX ep_capability_operations_live_action_uniq IS
  'Store-level defense in depth: at most one live (reserved/provider_entered/committed) operation per deliberately stable semantic action digest per authorization namespace. Gate does not infer equivalence after action-digest inputs change. Released operations are excluded so a proven non-entry can be retried. Scoped per namespace so quorum across distinct capabilities stays possible.';
