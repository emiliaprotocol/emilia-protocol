-- SPDX-License-Identifier: Apache-2.0
-- Forward-only exact lookup for lost-response recovery. This RPC reveals only
-- the immutable public attempt binding and never executes or rotates custody.

CREATE OR REPLACE FUNCTION proposal_to_effect_private.lookup_attempt(
  p_tenant_id TEXT,
  p_provider_id TEXT,
  p_provider_account_id TEXT,
  p_environment TEXT,
  p_request_digest TEXT
)
RETURNS TABLE(
  tenant_id TEXT,
  provider_id TEXT,
  provider_account_id TEXT,
  environment TEXT,
  attempt_id TEXT,
  request_digest TEXT
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_count BIGINT;
BEGIN
  PERFORM proposal_to_effect_private.assert_tenant_principal(p_tenant_id, NULL);

  SELECT pg_catalog.count(*)
  INTO v_count
  FROM proposal_to_effect_private.consequence_attempts AS attempts
  WHERE attempts.tenant_id = p_tenant_id
    AND attempts.provider_id = p_provider_id
    AND attempts.provider_account_id = p_provider_account_id
    AND attempts.environment = p_environment
    AND attempts.request_digest = p_request_digest;

  IF v_count > 1 THEN
    RAISE EXCEPTION 'PTE_ATTEMPT_LOOKUP_AMBIGUOUS'
      USING ERRCODE = '21000';
  END IF;

  IF v_count = 0 THEN
    RETURN;
  END IF;

  RETURN QUERY SELECT
    attempts.tenant_id,
    attempts.provider_id,
    attempts.provider_account_id,
    attempts.environment,
    attempts.attempt_id,
    attempts.request_digest
  FROM proposal_to_effect_private.consequence_attempts AS attempts
  WHERE attempts.tenant_id = p_tenant_id
    AND attempts.provider_id = p_provider_id
    AND attempts.provider_account_id = p_provider_account_id
    AND attempts.environment = p_environment
    AND attempts.request_digest = p_request_digest;
END
$fn$;

REVOKE ALL ON FUNCTION proposal_to_effect_private.lookup_attempt(
  TEXT, TEXT, TEXT, TEXT, TEXT
) FROM anon, authenticated, PUBLIC, service_role;

GRANT EXECUTE ON FUNCTION proposal_to_effect_private.lookup_attempt(
  TEXT, TEXT, TEXT, TEXT, TEXT
) TO proposal_to_effect_executor, proposal_to_effect_recovery;

COMMENT ON FUNCTION proposal_to_effect_private.lookup_attempt(
  TEXT, TEXT, TEXT, TEXT, TEXT
) IS
  'Authenticated exact lookup of an immutable public consequence-attempt binding for lost-response recovery.';
