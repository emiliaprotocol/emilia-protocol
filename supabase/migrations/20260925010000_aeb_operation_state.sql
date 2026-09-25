-- SPDX-License-Identifier: Apache-2.0
-- Authenticated durable read of one exact AEB consumption operation row.
--
-- The direct native consequence boundary (createNativeConsequenceBoundary in
-- @emilia-protocol/gate) must tell a lost write acknowledgement apart from a
-- write that never happened before it releases or closes a reservation. This
-- function returns the row state, or AVAILABLE when no row exists, without
-- granting table reads. It is granted to the executor principal only.
--
-- Mirrors AEB_CONSUMPTION_DDL in packages/gate/src/aeb-consumption-store.ts.

GRANT ep_aeb_store_owner TO CURRENT_USER
  WITH INHERIT FALSE, SET TRUE;
SET ROLE ep_aeb_store_owner;

CREATE OR REPLACE FUNCTION ep_aeb_private.operation_state(
  p_tenant_id TEXT,
  p_relying_party_id TEXT,
  p_operation_key TEXT
) RETURNS TABLE(state TEXT)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);
  RETURN QUERY SELECT COALESCE((
    SELECT operations.state
    FROM public.ep_aeb_consumption_operations AS operations
    WHERE operations.tenant_id = p_tenant_id
      AND operations.relying_party_id = p_relying_party_id
      AND operations.operation_key = p_operation_key
  ), 'AVAILABLE');
END
$fn$;

ALTER FUNCTION ep_aeb_private.operation_state(TEXT, TEXT, TEXT)
  OWNER TO ep_aeb_store_owner;

REVOKE ALL ON FUNCTION ep_aeb_private.operation_state(TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role, ep_aeb_recovery;
GRANT EXECUTE ON FUNCTION ep_aeb_private.operation_state(TEXT, TEXT, TEXT)
  TO ep_aeb_executor;

COMMENT ON FUNCTION ep_aeb_private.operation_state(TEXT, TEXT, TEXT) IS
  'Tenant-bound exact AEB operation state read. AVAILABLE means no row exists. Executor only.';

RESET ROLE;
REVOKE ep_aeb_store_owner FROM CURRENT_USER;
