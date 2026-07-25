-- SPDX-License-Identifier: Apache-2.0
-- Forward-only repair for PL/pgSQL output-column ambiguity in consume_envelope.
--
-- PostgreSQL exposes the TABLE return column as a PL/pgSQL variable. Qualify
-- every envelope-table predicate so the function cannot confuse that output
-- variable with the stored envelope_digest column.

SET ROLE consequence_actuator_store_owner;

CREATE OR REPLACE FUNCTION consequence_actuator_private.consume_envelope(
  p_tenant_id TEXT,
  p_attempt_id TEXT,
  p_action_digest TEXT,
  p_caid TEXT,
  p_provider_account_id TEXT,
  p_target_digest TEXT,
  p_operation TEXT,
  p_idempotency_key TEXT,
  p_nonce TEXT,
  p_envelope_digest TEXT,
  p_outcome TEXT
)
RETURNS TABLE(envelope_digest TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM consequence_actuator_private.assert_tenant_principal(p_tenant_id);
  IF p_attempt_id IS NULL
    OR pg_catalog.octet_length(p_attempt_id) NOT BETWEEN 1 AND 256
    OR p_action_digest IS NULL
    OR p_action_digest !~ '^sha256:[a-f0-9]{64}$'
    OR p_caid IS NULL
    OR pg_catalog.octet_length(p_caid) NOT BETWEEN 1 AND 512
    OR p_provider_account_id IS NULL
    OR pg_catalog.octet_length(p_provider_account_id) NOT BETWEEN 1 AND 256
    OR p_target_digest IS NULL
    OR p_target_digest !~ '^sha256:[a-f0-9]{64}$'
    OR p_operation IS NULL
    OR pg_catalog.octet_length(p_operation) NOT BETWEEN 1 AND 256
    OR p_idempotency_key IS NULL
    OR pg_catalog.octet_length(p_idempotency_key) NOT BETWEEN 1 AND 256
    OR p_nonce IS NULL
    OR pg_catalog.octet_length(p_nonce) NOT BETWEEN 22 AND 128
    OR p_nonce !~ '^[A-Za-z0-9_-]+$'
    OR p_envelope_digest IS NULL
    OR p_envelope_digest !~ '^sha256:[a-f0-9]{64}$'
  THEN
    RAISE EXCEPTION 'execution envelope binding is malformed or unbounded'
      USING ERRCODE = '22023';
  END IF;
  IF p_outcome NOT IN ('COMMITTED', 'INDETERMINATE') THEN
    RAISE EXCEPTION 'invalid consequence outcome' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  UPDATE public.consequence_actuator_envelopes AS envelopes
  SET state = 'CONSUMED',
      outcome = p_outcome,
      consumed_at = pg_catalog.clock_timestamp()
  WHERE envelopes.tenant_id = p_tenant_id
    AND envelopes.attempt_id = p_attempt_id
    AND envelopes.action_digest = p_action_digest
    AND envelopes.caid = p_caid
    AND envelopes.provider_account_id = p_provider_account_id
    AND envelopes.target_digest = p_target_digest
    AND envelopes.operation = p_operation
    AND envelopes.idempotency_key = p_idempotency_key
    AND envelopes.nonce = p_nonce
    AND envelopes.envelope_digest = p_envelope_digest
    AND envelopes.state = 'RESERVED'
  RETURNING envelopes.envelope_digest;
END
$fn$;

REVOKE ALL ON FUNCTION consequence_actuator_private.consume_envelope(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) FROM PUBLIC, anon, authenticated, service_role, consequence_actuator_executor;
GRANT EXECUTE ON FUNCTION consequence_actuator_private.consume_envelope(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) TO consequence_actuator_executor;

-- The Supabase CLI connects through a temporary login and begins migrations as
-- postgres. RESET ROLE would return to that restricted login before the CLI
-- writes its journal row, so restore the migration role explicitly.
SET ROLE postgres;
