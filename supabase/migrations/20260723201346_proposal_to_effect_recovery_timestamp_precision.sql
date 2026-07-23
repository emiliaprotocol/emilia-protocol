-- SPDX-License-Identifier: Apache-2.0
-- Preserve PostgreSQL's full microsecond timestamp precision in recovery
-- snapshots. recover_attempt uses the serialized lease as an exact
-- compare-and-swap fence; millisecond truncation makes every ordinary lease
-- conflict with its own database value.

CREATE OR REPLACE FUNCTION proposal_to_effect_private.read_attempt(
  p_tenant_id TEXT,
  p_provider_id TEXT,
  p_provider_account_id TEXT,
  p_environment TEXT,
  p_attempt_id TEXT,
  p_request_digest TEXT
)
RETURNS TABLE(
  tenant_id TEXT,
  provider_id TEXT,
  provider_account_id TEXT,
  environment TEXT,
  attempt_id TEXT,
  operation_digest TEXT,
  request_digest TEXT,
  action_digest TEXT,
  config_digest TEXT,
  attempt_digest TEXT,
  state TEXT,
  evidence_digest TEXT,
  owner_generation BIGINT,
  last_heartbeat_at TEXT,
  lease_expires_at TEXT,
  lease_stale BOOLEAN
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $fn$
BEGIN
  PERFORM proposal_to_effect_private.assert_tenant_principal(p_tenant_id, NULL);
  RETURN QUERY SELECT
    attempts.tenant_id,
    attempts.provider_id,
    attempts.provider_account_id,
    attempts.environment,
    attempts.attempt_id,
    attempts.operation_digest,
    attempts.request_digest,
    attempts.action_digest,
    attempts.config_digest,
    attempts.attempt_digest,
    attempts.state,
    attempts.evidence_digest,
    attempts.owner_generation,
    pg_catalog.to_char(
      attempts.last_heartbeat_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    ),
    pg_catalog.to_char(
      attempts.lease_expires_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    ),
    attempts.lease_expires_at <= pg_catalog.clock_timestamp()
  FROM proposal_to_effect_private.consequence_attempts AS attempts
  WHERE attempts.tenant_id = p_tenant_id
    AND attempts.provider_id = p_provider_id
    AND attempts.provider_account_id = p_provider_account_id
    AND attempts.environment = p_environment
    AND attempts.attempt_id = p_attempt_id
    AND attempts.request_digest = p_request_digest;
END
$fn$;

REVOKE ALL ON FUNCTION proposal_to_effect_private.read_attempt(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) FROM anon, authenticated, PUBLIC, service_role;

GRANT EXECUTE ON FUNCTION proposal_to_effect_private.read_attempt(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) TO proposal_to_effect_executor, proposal_to_effect_recovery;

COMMENT ON FUNCTION proposal_to_effect_private.read_attempt(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) IS
  'Authenticated consequence-attempt snapshot with lossless microsecond lease fencing for recovery.';
