-- SPDX-License-Identifier: Apache-2.0
-- Terminal released-not-entered state for AEB operation consumption.
--
-- draft-schrock-action-evidence-boundary-04 s5.11: reconciling an authoritative
-- NOT_COMMITTED result must not resurrect the original authorization or
-- silently release its one-time replay unit. release_operation() DELETED the
-- row, which made the byte-identical operation key reservable again and let one
-- action instance drive repeated provider invocations. The row is now kept and
-- marked RELEASED_NOT_ENTERED, so the key is permanently unreservable, no late
-- commit can reopen it, and the replay fences that reference it survive because
-- the ON DELETE CASCADE never fires.
--
-- Mirrors AEB_CONSUMPTION_DDL in packages/gate/src/aeb-consumption-store.ts.

-- Production already owns the table and private schema through this NOLOGIN
-- role. PostgreSQL 17 can retain an older membership with SET/INHERIT disabled,
-- so a plain GRANT does not make the owner assumable by the migration runner.
GRANT ep_aeb_store_owner TO CURRENT_USER
  WITH INHERIT FALSE, SET TRUE;
SET ROLE ep_aeb_store_owner;

ALTER TABLE ep_aeb_consumption_operations
  ADD COLUMN IF NOT EXISTS released_at TIMESTAMPTZ NULL;

ALTER TABLE ep_aeb_consumption_operations
  DROP CONSTRAINT IF EXISTS ep_aeb_consumption_operations_state_check;
ALTER TABLE ep_aeb_consumption_operations
  ADD CONSTRAINT ep_aeb_consumption_operations_state_check
  CHECK (state IN ('RESERVED', 'CONSUMED', 'RELEASED_NOT_ENTERED'));

ALTER TABLE ep_aeb_consumption_operations
  DROP CONSTRAINT IF EXISTS ep_aeb_consumption_operations_check;
ALTER TABLE ep_aeb_consumption_operations
  DROP CONSTRAINT IF EXISTS ep_aeb_consumption_operations_lifecycle_check;
ALTER TABLE ep_aeb_consumption_operations
  ADD CONSTRAINT ep_aeb_consumption_operations_lifecycle_check CHECK (
    (state = 'RESERVED' AND owner_token IS NOT NULL AND consumed_at IS NULL AND released_at IS NULL)
    OR (state = 'CONSUMED' AND owner_token IS NULL AND consumed_at IS NOT NULL AND released_at IS NULL)
    OR (state = 'RELEASED_NOT_ENTERED' AND owner_token IS NULL AND consumed_at IS NULL
        AND released_at IS NOT NULL)
  );

CREATE OR REPLACE FUNCTION ep_aeb_private.release_terminal_operation(
  p_tenant_id TEXT, p_relying_party_id TEXT, p_operation_key TEXT, p_owner_token TEXT
)
RETURNS TABLE(operation_key TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);
  RETURN QUERY
    WITH transitioned AS (
      UPDATE public.ep_aeb_consumption_operations
        SET state = 'RELEASED_NOT_ENTERED',
            owner_token = NULL,
            released_at = pg_catalog.transaction_timestamp()
        WHERE tenant_id = p_tenant_id
          AND relying_party_id = p_relying_party_id
          AND ep_aeb_consumption_operations.operation_key = p_operation_key
          AND state = 'RESERVED'
          AND owner_token = p_owner_token
        RETURNING ep_aeb_consumption_operations.operation_key
    )
    SELECT transitioned.operation_key FROM transitioned
    UNION ALL
    SELECT existing.operation_key
      FROM public.ep_aeb_consumption_operations AS existing
      WHERE NOT EXISTS (SELECT 1 FROM transitioned)
        AND existing.tenant_id = p_tenant_id
        AND existing.relying_party_id = p_relying_party_id
        AND existing.operation_key = p_operation_key
        AND existing.state = 'RELEASED_NOT_ENTERED';
END
$fn$;

ALTER FUNCTION ep_aeb_private.release_terminal_operation(TEXT, TEXT, TEXT, TEXT)
  OWNER TO ep_aeb_store_owner;

REVOKE ALL ON FUNCTION ep_aeb_private.release_terminal_operation(TEXT, TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION ep_aeb_private.release_terminal_operation(TEXT, TEXT, TEXT, TEXT)
  TO ep_aeb_executor;

COMMENT ON COLUMN ep_aeb_consumption_operations.released_at IS
  'Set when an authoritative non-entry made the reservation terminally RELEASED_NOT_ENTERED. The row is never deleted, so the operation key stays unreservable.';

RESET ROLE;
REVOKE ep_aeb_store_owner FROM CURRENT_USER;
