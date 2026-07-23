-- Authenticated pre-reservation observation for exact AEB native replay units.
-- This closes the status-verifier boundary without granting table reads. The
-- later atomic reserve remains the race-closing operation.

GRANT ep_aeb_store_owner TO CURRENT_USER
  WITH INHERIT FALSE, SET TRUE;
SET ROLE ep_aeb_store_owner;

CREATE OR REPLACE FUNCTION ep_aeb_private.has_replay_fence(
  p_tenant_id TEXT,
  p_relying_party_id TEXT,
  p_replay_key TEXT
) RETURNS TABLE(fenced BOOLEAN)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);
  RETURN QUERY SELECT EXISTS (
    SELECT 1
    FROM public.ep_aeb_consumption_replay_fences AS fences
    WHERE fences.tenant_id = p_tenant_id
      AND fences.relying_party_id = p_relying_party_id
      AND fences.replay_key = p_replay_key
  );
END
$fn$;

ALTER FUNCTION ep_aeb_private.has_replay_fence(TEXT, TEXT, TEXT)
  OWNER TO ep_aeb_store_owner;

REVOKE ALL ON FUNCTION ep_aeb_private.has_replay_fence(TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role, ep_aeb_recovery;
GRANT EXECUTE ON FUNCTION ep_aeb_private.has_replay_fence(TEXT, TEXT, TEXT)
  TO ep_aeb_executor;

COMMENT ON FUNCTION ep_aeb_private.has_replay_fence(TEXT, TEXT, TEXT) IS
  'Tenant-bound exact native replay-fence lookup. True includes RESERVED and CONSUMED; atomic reserve closes races.';

RESET ROLE;
REVOKE ep_aeb_store_owner FROM CURRENT_USER;
