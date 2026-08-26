-- SPDX-License-Identifier: Apache-2.0
-- STRIX-31 / STRIX-35: close every competing signoff lifecycle transition.
--
-- Lock order is deterministic:
--   issue: handshakes -> handshake_bindings -> handshake_policies
--          -> handshake_parties -> authorities
--   approve: handshakes -> handshake_bindings -> handshake_policies
--            -> signoff_challenges -> authorities -> ceremony evidence
--   consume: handshakes -> handshake_bindings -> handshake_policies
--            -> signoff_challenges -> authorities -> signoff_attestations
--            -> ceremony evidence
--   handshake revoke: handshakes -> handshake_bindings -> handshake_parties
--   other challenge decisions: signoff_challenges
--   attestation revoke: signoff_challenges -> signoff_attestations
--
-- Every authorization/state/expiry predicate is evaluated again while the
-- authoritative row is locked. JavaScript checks are a fast preflight only.
--
-- IMPORTANT: handshake_bindings.consumed_at is the verification-finalization
-- marker written by verify_handshake_writes. It is not the downstream one-time
-- authority-consumption record. That second, authoritative layer is the unique
-- handshake_consumptions(handshake_id) row. Signoff requires the first marker
-- and refuses the second, then creates the second atomically at execution.

ALTER TABLE public.signoff_challenges
  ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS revocation_reason TEXT,
  ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS required_authority_class TEXT,
  ADD COLUMN IF NOT EXISTS authority_organization_id TEXT,
  ADD COLUMN IF NOT EXISTS authority_id UUID
    REFERENCES public.authorities(authority_id);

ALTER TABLE public.signoff_attestations
  ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS revocation_reason TEXT,
  ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ;

ALTER TABLE public.handshakes
  ADD COLUMN IF NOT EXISTS revoked_by TEXT;

-- Reproduce the handshake policy hashing profile inside PostgreSQL. The
-- application hashes JSON.stringify(deepSortKeys(rules)); this renderer uses
-- the same recursive key order, NFC string normalization, compact separators,
-- and safe-integer number profile. Values outside that cross-runtime profile
-- fail closed instead of being hashed differently by JavaScript and SQL.
CREATE OR REPLACE FUNCTION public.signoff_canonical_policy_jsonb(
  p_value JSONB
)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = ''
AS $signoff_canonical_policy_jsonb$
DECLARE
  v_type TEXT := pg_catalog.jsonb_typeof(p_value);
  v_text TEXT;
BEGIN
  CASE v_type
    WHEN 'null' THEN
      RETURN 'null';
    WHEN 'boolean' THEN
      RETURN p_value::TEXT;
    WHEN 'string' THEN
      RETURN pg_catalog.to_jsonb(pg_catalog.normalize(p_value #>> '{}'))::TEXT;
    WHEN 'number' THEN
      v_text := p_value #>> '{}';
      IF v_text !~ '^-?(0|[1-9][0-9]*)$'
         OR v_text::NUMERIC < -9007199254740991
         OR v_text::NUMERIC > 9007199254740991 THEN
        RAISE EXCEPTION USING
          ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_POLICY_NUMBER_NOT_SAFE_INTEGER';
      END IF;
      RETURN v_text;
    WHEN 'array' THEN
      SELECT '[' || COALESCE(pg_catalog.string_agg(
        public.signoff_canonical_policy_jsonb(element.value),
        ',' ORDER BY element.ordinality
      ), '') || ']'
      INTO v_text
      FROM pg_catalog.jsonb_array_elements(p_value)
        WITH ORDINALITY AS element(value, ordinality);
      RETURN v_text;
    WHEN 'object' THEN
      IF EXISTS (
        SELECT 1
        FROM (
          SELECT pg_catalog.normalize(member.key) AS normalized_key,
                 pg_catalog.count(*) AS count
          FROM pg_catalog.jsonb_each(p_value) AS member(key, value)
          GROUP BY pg_catalog.normalize(member.key)
        ) AS normalized
        WHERE normalized.count <> 1
      ) THEN
        RAISE EXCEPTION USING
          ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_POLICY_KEY_NORMALIZATION_COLLISION';
      END IF;
      SELECT '{' || COALESCE(pg_catalog.string_agg(
        pg_catalog.to_jsonb(member.normalized_key)::TEXT || ':'
          || public.signoff_canonical_policy_jsonb(member.value),
        ',' ORDER BY member.normalized_key COLLATE "C"
      ), '') || '}'
      INTO v_text
      FROM (
        SELECT pg_catalog.normalize(source.key) AS normalized_key, source.value
        FROM pg_catalog.jsonb_each(p_value) AS source(key, value)
      ) AS member;
      RETURN v_text;
    ELSE
      RAISE EXCEPTION USING
        ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_POLICY_CANONICALIZATION_UNSUPPORTED';
  END CASE;
END;
$signoff_canonical_policy_jsonb$;

CREATE OR REPLACE FUNCTION public.signoff_policy_rules_hash(
  p_rules JSONB
)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = ''
AS $signoff_policy_rules_hash$
  SELECT pg_catalog.encode(
    extensions.digest(
      pg_catalog.convert_to(
        public.signoff_canonical_policy_jsonb(p_rules),
        'UTF8'
      ),
      'sha256'
    ),
    'hex'
  )
$signoff_policy_rules_hash$;

REVOKE ALL ON FUNCTION public.signoff_canonical_policy_jsonb(JSONB)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.signoff_policy_rules_hash(JSONB)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.signoff_canonical_policy_jsonb(JSONB)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.signoff_policy_rules_hash(JSONB)
  TO service_role;

-- A policy version is immutable trust material after any handshake pins it.
-- Status may still be changed to inactive/deprecated to stop new issuance, but
-- semantic changes require a new policy row/version and therefore a new hash.
CREATE OR REPLACE FUNCTION public.prevent_pinned_handshake_policy_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ''
AS $prevent_pinned_handshake_policy_mutation$
BEGIN
  IF (NEW.policy_key, NEW.version, NEW.mode, NEW.rules)
       IS DISTINCT FROM
     (OLD.policy_key, OLD.version, OLD.mode, OLD.rules)
     AND EXISTS (
       SELECT 1
       FROM public.handshakes
       WHERE policy_id = OLD.policy_id
     ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_PINNED_POLICY_IMMUTABLE';
  END IF;
  RETURN NEW;
END;
$prevent_pinned_handshake_policy_mutation$;

DROP TRIGGER IF EXISTS enforce_pinned_handshake_policy_immutable
  ON public.handshake_policies;
CREATE TRIGGER enforce_pinned_handshake_policy_immutable
  BEFORE UPDATE ON public.handshake_policies
  FOR EACH ROW EXECUTE FUNCTION public.prevent_pinned_handshake_policy_mutation();

-- Only a verified ceremony producer may insert these rows. The legacy JSON
-- attest route has no such producer and therefore fails closed. Approval locks
-- and consumes one exact evidence row in the same transaction as attestation.
CREATE TABLE IF NOT EXISTS public.signoff_ceremony_evidence (
  evidence_id UUID PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  challenge_id UUID NOT NULL REFERENCES public.signoff_challenges(challenge_id),
  human_entity_ref TEXT NOT NULL,
  authority_id UUID NOT NULL REFERENCES public.authorities(authority_id),
  auth_method TEXT NOT NULL CHECK (auth_method IN (
    'passkey', 'secure_app', 'platform_authenticator',
    'out_of_band', 'dual_signoff'
  )),
  assurance_level TEXT NOT NULL CHECK (assurance_level IN (
    'low', 'substantial', 'high'
  )),
  channel TEXT NOT NULL,
  evidence_hash TEXT NOT NULL,
  verified_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE OR REPLACE FUNCTION public.prevent_signoff_ceremony_evidence_rewrite()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ''
AS $prevent_signoff_ceremony_evidence_rewrite$
BEGIN
  IF OLD.consumed_at IS NOT NULL
     OR (NEW.evidence_id, NEW.challenge_id, NEW.human_entity_ref,
         NEW.authority_id, NEW.auth_method, NEW.assurance_level,
         NEW.channel, NEW.evidence_hash, NEW.verified_at, NEW.expires_at,
         NEW.metadata)
          IS DISTINCT FROM
        (OLD.evidence_id, OLD.challenge_id, OLD.human_entity_ref,
         OLD.authority_id, OLD.auth_method, OLD.assurance_level,
         OLD.channel, OLD.evidence_hash, OLD.verified_at, OLD.expires_at,
         OLD.metadata)
     OR NEW.consumed_at IS NULL
     OR NEW.consumed_at IS DISTINCT FROM pg_catalog.transaction_timestamp() THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CEREMONY_EVIDENCE_IMMUTABLE';
  END IF;
  RETURN NEW;
END;
$prevent_signoff_ceremony_evidence_rewrite$;

DROP TRIGGER IF EXISTS enforce_signoff_ceremony_evidence_immutable
  ON public.signoff_ceremony_evidence;
CREATE TRIGGER enforce_signoff_ceremony_evidence_immutable
  BEFORE UPDATE ON public.signoff_ceremony_evidence
  FOR EACH ROW EXECUTE FUNCTION public.prevent_signoff_ceremony_evidence_rewrite();

REVOKE ALL ON FUNCTION public.prevent_pinned_handshake_policy_mutation()
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.prevent_signoff_ceremony_evidence_rewrite()
  FROM PUBLIC, anon, authenticated;

ALTER TABLE public.signoff_attestations
  ADD COLUMN IF NOT EXISTS ceremony_evidence_id UUID
    REFERENCES public.signoff_ceremony_evidence(evidence_id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_signoff_attestation_ceremony_evidence
  ON public.signoff_attestations(ceremony_evidence_id)
  WHERE ceremony_evidence_id IS NOT NULL;

-- The original rank-only guards treated mutually exclusive terminal states as
-- interchangeable and allowed pending rows to jump directly to consumed.
-- Replace them with exact state-machine edges and immutable trust material.
CREATE OR REPLACE FUNCTION public.prevent_signoff_challenge_backward_status()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ''
AS $prevent_signoff_challenge_backward_status$
DECLARE
  v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
  IF (NEW.challenge_id, NEW.handshake_id, NEW.binding_hash,
      NEW.accountable_actor_ref, NEW.signoff_policy_id,
      NEW.signoff_policy_hash, NEW.required_assurance, NEW.allowed_methods,
      NEW.expires_at, NEW.issued_at, NEW.required_authority_class,
      NEW.authority_organization_id, NEW.authority_id)
       IS DISTINCT FROM
     (OLD.challenge_id, OLD.handshake_id, OLD.binding_hash,
      OLD.accountable_actor_ref, OLD.signoff_policy_id,
      OLD.signoff_policy_hash, OLD.required_assurance, OLD.allowed_methods,
      OLD.expires_at, OLD.issued_at, OLD.required_authority_class,
      OLD.authority_organization_id, OLD.authority_id) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_TRUST_FIELDS_IMMUTABLE';
  END IF;

  IF NEW.status = OLD.status THEN
    IF (NEW.metadata, NEW.revoked_at, NEW.revocation_reason, NEW.consumed_at)
         IS DISTINCT FROM
       (OLD.metadata, OLD.revoked_at, OLD.revocation_reason, OLD.consumed_at) THEN
      RAISE EXCEPTION USING
        ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_LIFECYCLE_FIELDS_INVALID';
    END IF;
    RETURN NEW;
  END IF;

  IF NOT (
    (OLD.status = 'challenge_issued' AND NEW.status IN (
      'challenge_viewed', 'approved', 'denied', 'expired', 'revoked'
    ))
    OR (OLD.status = 'challenge_viewed' AND NEW.status IN (
      'approved', 'denied', 'expired', 'revoked'
    ))
    OR (OLD.status = 'approved' AND NEW.status = 'consumed')
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_TRANSITION_INVALID',
      DETAIL = pg_catalog.format('old_status=%s new_status=%s', OLD.status, NEW.status);
  END IF;

  IF NEW.status = 'approved' THEN
    BEGIN
      IF (NEW.metadata ->> 'approved_at')::TIMESTAMPTZ IS DISTINCT FROM v_now THEN
        RAISE EXCEPTION USING
          ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_LIFECYCLE_FIELDS_INVALID';
      END IF;
    EXCEPTION WHEN invalid_datetime_format THEN
      RAISE EXCEPTION USING
        ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_LIFECYCLE_FIELDS_INVALID';
    END;
  ELSIF NEW.status = 'denied' THEN
    BEGIN
      IF (NEW.metadata ->> 'denied_at')::TIMESTAMPTZ IS DISTINCT FROM v_now
         OR NEW.metadata ->> 'denial_reason' IS NULL
         OR pg_catalog.btrim(NEW.metadata ->> 'denial_reason') = '' THEN
        RAISE EXCEPTION USING
          ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_LIFECYCLE_FIELDS_INVALID';
      END IF;
    EXCEPTION WHEN invalid_datetime_format THEN
      RAISE EXCEPTION USING
        ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_LIFECYCLE_FIELDS_INVALID';
    END;
  ELSIF NEW.status = 'revoked' THEN
    IF NEW.revoked_at IS DISTINCT FROM v_now
       OR NEW.revocation_reason IS NULL
       OR pg_catalog.btrim(NEW.revocation_reason) = '' THEN
      RAISE EXCEPTION USING
        ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_LIFECYCLE_FIELDS_INVALID';
    END IF;
  ELSIF NEW.status = 'consumed' THEN
    IF NEW.consumed_at IS DISTINCT FROM v_now THEN
      RAISE EXCEPTION USING
        ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_LIFECYCLE_FIELDS_INVALID';
    END IF;
  END IF;

  IF NEW.status <> 'revoked'
     AND (NEW.revoked_at, NEW.revocation_reason)
           IS DISTINCT FROM (OLD.revoked_at, OLD.revocation_reason) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_LIFECYCLE_FIELDS_INVALID';
  END IF;
  IF NEW.status <> 'consumed'
     AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_LIFECYCLE_FIELDS_INVALID';
  END IF;
  IF NEW.status NOT IN ('approved', 'denied')
     AND NEW.metadata IS DISTINCT FROM OLD.metadata THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_LIFECYCLE_FIELDS_INVALID';
  END IF;
  RETURN NEW;
END;
$prevent_signoff_challenge_backward_status$;

DROP TRIGGER IF EXISTS enforce_signoff_challenge_status_forward
  ON public.signoff_challenges;
DROP TRIGGER IF EXISTS enforce_signoff_challenge_forward_only
  ON public.signoff_challenges;
DROP TRIGGER IF EXISTS enforce_signoff_challenge_exact_transitions
  ON public.signoff_challenges;
CREATE TRIGGER enforce_signoff_challenge_exact_transitions
  BEFORE UPDATE ON public.signoff_challenges
  FOR EACH ROW EXECUTE FUNCTION public.prevent_signoff_challenge_backward_status();

CREATE OR REPLACE FUNCTION public.prevent_signoff_attestation_backward_status()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ''
AS $prevent_signoff_attestation_backward_status$
DECLARE
  v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
  IF (NEW.signoff_id, NEW.challenge_id, NEW.handshake_id, NEW.binding_hash,
      NEW.human_entity_ref, NEW.auth_method, NEW.assurance_level, NEW.channel,
      NEW.expires_at, NEW.attestation_hash, NEW.ceremony_evidence_id,
      NEW.approved_at, NEW.metadata)
       IS DISTINCT FROM
     (OLD.signoff_id, OLD.challenge_id, OLD.handshake_id, OLD.binding_hash,
      OLD.human_entity_ref, OLD.auth_method, OLD.assurance_level, OLD.channel,
      OLD.expires_at, OLD.attestation_hash, OLD.ceremony_evidence_id,
      OLD.approved_at, OLD.metadata) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_TRUST_FIELDS_IMMUTABLE';
  END IF;

  IF NEW.status = OLD.status THEN
    IF (NEW.revoked_at, NEW.revocation_reason, NEW.consumed_at)
         IS DISTINCT FROM
       (OLD.revoked_at, OLD.revocation_reason, OLD.consumed_at) THEN
      RAISE EXCEPTION USING
        ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_LIFECYCLE_FIELDS_INVALID';
    END IF;
    RETURN NEW;
  END IF;

  IF NOT (
    OLD.status = 'approved'
    AND NEW.status IN ('expired', 'revoked', 'consumed')
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_TRANSITION_INVALID',
      DETAIL = pg_catalog.format('old_status=%s new_status=%s', OLD.status, NEW.status);
  END IF;

  IF NEW.status = 'revoked' THEN
    IF NEW.revoked_at IS DISTINCT FROM v_now
       OR NEW.revocation_reason IS NULL
       OR pg_catalog.btrim(NEW.revocation_reason) = '' THEN
      RAISE EXCEPTION USING
        ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_LIFECYCLE_FIELDS_INVALID';
    END IF;
  ELSIF NEW.status = 'consumed' THEN
    IF NEW.consumed_at IS DISTINCT FROM v_now THEN
      RAISE EXCEPTION USING
        ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_LIFECYCLE_FIELDS_INVALID';
    END IF;
  END IF;

  IF NEW.status <> 'revoked'
     AND (NEW.revoked_at, NEW.revocation_reason)
           IS DISTINCT FROM (OLD.revoked_at, OLD.revocation_reason) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_LIFECYCLE_FIELDS_INVALID';
  END IF;
  IF NEW.status <> 'consumed'
     AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_LIFECYCLE_FIELDS_INVALID';
  END IF;
  RETURN NEW;
END;
$prevent_signoff_attestation_backward_status$;

DROP TRIGGER IF EXISTS enforce_signoff_attestation_status_forward
  ON public.signoff_attestations;
DROP TRIGGER IF EXISTS enforce_signoff_attestation_exact_transitions
  ON public.signoff_attestations;
CREATE TRIGGER enforce_signoff_attestation_exact_transitions
  BEFORE UPDATE ON public.signoff_attestations
  FOR EACH ROW EXECUTE FUNCTION public.prevent_signoff_attestation_backward_status();

CREATE OR REPLACE FUNCTION public.prevent_signoff_challenge_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ''
AS $prevent_signoff_challenge_delete$
BEGIN
  RAISE EXCEPTION USING
    ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_DELETE_FORBIDDEN';
END;
$prevent_signoff_challenge_delete$;

CREATE OR REPLACE FUNCTION public.prevent_signoff_attestation_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ''
AS $prevent_signoff_attestation_delete$
BEGIN
  RAISE EXCEPTION USING
    ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_DELETE_FORBIDDEN';
END;
$prevent_signoff_attestation_delete$;

DROP TRIGGER IF EXISTS enforce_signoff_challenges_no_delete
  ON public.signoff_challenges;
CREATE TRIGGER enforce_signoff_challenges_no_delete
  BEFORE DELETE ON public.signoff_challenges
  FOR EACH ROW EXECUTE FUNCTION public.prevent_signoff_challenge_delete();

DROP TRIGGER IF EXISTS enforce_signoff_attestations_no_delete
  ON public.signoff_attestations;
CREATE TRIGGER enforce_signoff_attestations_no_delete
  BEFORE DELETE ON public.signoff_attestations
  FOR EACH ROW EXECUTE FUNCTION public.prevent_signoff_attestation_delete();

REVOKE ALL ON FUNCTION public.prevent_signoff_challenge_backward_status()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.prevent_signoff_attestation_backward_status()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.prevent_signoff_challenge_delete()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.prevent_signoff_attestation_delete()
  FROM PUBLIC, anon, authenticated, service_role;

-- Service callers can read lifecycle state and execute the reviewed
-- SECURITY DEFINER RPCs, but cannot bypass them with direct row writes.
REVOKE INSERT, UPDATE, DELETE ON TABLE public.signoff_challenges
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE INSERT, UPDATE, DELETE ON TABLE public.signoff_attestations
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE INSERT, UPDATE, DELETE ON TABLE public.signoff_consumptions
  FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON TABLE public.signoff_challenges, public.signoff_attestations
  TO service_role;
GRANT SELECT ON TABLE public.signoff_consumptions TO service_role;

ALTER TABLE public.signoff_ceremony_evidence ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS service_role_bypass ON public.signoff_ceremony_evidence;
CREATE POLICY service_role_bypass ON public.signoff_ceremony_evidence
  FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public.signoff_ceremony_evidence
  FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON TABLE public.signoff_ceremony_evidence
  TO service_role;

COMMENT ON COLUMN public.handshake_bindings.consumed_at IS
  'Verification-finalization marker and re-verification guard. Downstream one-time authority consumption is represented by handshake_consumptions.';
COMMENT ON COLUMN public.handshake_bindings.consumed_for IS
  'Purpose of binding finalization; accepted verification records handshake_verified:<handshake_id>. This is not the downstream execution consumer.';
COMMENT ON TABLE public.handshake_consumptions IS
  'Unique downstream one-time authority-consumption records. Presence of a handshake_id row, not handshake_bindings.consumed_at, means execution authority is spent.';

COMMENT ON FUNCTION public.consume_handshake_atomic(
  UUID, TEXT, TEXT, TEXT, TEXT, TEXT
) IS 'Locks verified authority and inserts its unique downstream consumption row. A pre-existing handshake_verified binding marker remains the separate verification-finalization guard.';

-- Remove every legacy overload. Public callers used to choose the accountable
-- actor, policy, assurance, and methods. The replacement accepts only binding
-- identity plus a requested upper-bound expiry; all trust semantics are
-- derived from the pinned handshake policy and current authority registry.
DROP FUNCTION IF EXISTS public.issue_challenge_atomic(
  UUID, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT[], TIMESTAMPTZ, JSONB
);
DROP FUNCTION IF EXISTS public.issue_challenge_atomic(
  UUID, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT[], TIMESTAMPTZ, JSONB
);

CREATE OR REPLACE FUNCTION public.issue_challenge_atomic(
  p_challenge_id UUID,
  p_handshake_id UUID,
  p_binding_hash TEXT,
  p_actor_entity_ref TEXT,
  p_requested_expires_at TIMESTAMPTZ,
  p_metadata_json JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $issue_challenge_atomic$
DECLARE
  v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
  v_handshake public.handshakes%ROWTYPE;
  v_binding public.handshake_bindings%ROWTYPE;
  v_policy public.handshake_policies%ROWTYPE;
  v_authority public.authorities%ROWTYPE;
  v_signoff_rules JSONB;
  v_party public.handshake_parties%ROWTYPE;
  v_caller_is_party BOOLEAN := FALSE;
  v_accountable_actor_ref TEXT;
  v_accountable_role TEXT;
  v_required_authority_class TEXT;
  v_authority_organization_id TEXT;
  v_required_assurance TEXT;
  v_allowed_methods TEXT[];
  v_max_ttl_seconds INTEGER;
  v_action_types TEXT[];
  v_current_policy_hash TEXT;
  v_expires_at TIMESTAMPTZ;
  v_challenge JSONB;
BEGIN
  IF p_challenge_id IS NULL
     OR p_actor_entity_ref IS NULL OR pg_catalog.btrim(p_actor_entity_ref) = ''
     OR p_requested_expires_at IS NULL
     OR p_requested_expires_at <= v_now THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_REQUEST_INVALID';
  END IF;

  SELECT * INTO v_handshake
  FROM public.handshakes
  WHERE handshake_id = p_handshake_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_HANDSHAKE_NOT_FOUND';
  END IF;
  IF v_handshake.status <> 'verified' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_HANDSHAKE_NOT_VERIFIED',
      DETAIL = pg_catalog.format('current_status=%s', v_handshake.status);
  END IF;
  IF v_handshake.verified_at IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_HANDSHAKE_NOT_VERIFICATION_FINALIZED';
  END IF;
  IF v_handshake.expires_at IS NOT NULL AND v_handshake.expires_at <= v_now THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_HANDSHAKE_EXPIRED';
  END IF;

  SELECT * INTO v_binding
  FROM public.handshake_bindings
  WHERE handshake_id = p_handshake_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_BINDING_NOT_FOUND';
  END IF;
  IF v_binding.binding_hash IS NULL
     OR v_binding.binding_hash IS DISTINCT FROM p_binding_hash THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_BINDING_HASH_MISMATCH';
  END IF;
  IF v_binding.expires_at IS NULL OR v_binding.expires_at <= v_now THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_BINDING_EXPIRED';
  END IF;
  IF v_handshake.policy_id IS NULL
     OR v_handshake.policy_hash IS NULL
     OR pg_catalog.btrim(v_handshake.policy_hash) = ''
     OR v_binding.policy_hash IS NULL
     OR v_binding.policy_hash IS DISTINCT FROM v_handshake.policy_hash THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_POLICY_NOT_PINNED';
  END IF;
  IF v_binding.consumed_at IS NULL
     OR v_binding.consumed_for IS DISTINCT FROM
       'handshake_verified:' || v_handshake.handshake_id::TEXT THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_BINDING_NOT_VERIFICATION_FINALIZED';
  END IF;
  -- handshake lock serializes this check with consume_handshake_atomic and
  -- consume_signoff_atomic. The unique row, not binding.consumed_at, is the
  -- downstream one-time authority gate.
  IF EXISTS (
    SELECT 1
    FROM public.handshake_consumptions
    WHERE handshake_id = v_handshake.handshake_id
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_AUTHORITY_ALREADY_CONSUMED';
  END IF;

  SELECT * INTO v_policy
  FROM public.handshake_policies
  WHERE policy_id = v_handshake.policy_id
  FOR UPDATE;
  IF NOT FOUND
     OR v_policy.status <> 'active'
     OR v_handshake.policy_version_number IS NULL
     OR v_policy.version IS DISTINCT FROM v_handshake.policy_version_number THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_PINNED_POLICY_UNAVAILABLE';
  END IF;

  BEGIN
    v_current_policy_hash := public.signoff_policy_rules_hash(v_policy.rules);
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_POLICY_HASH_UNVERIFIABLE';
  END;
  IF v_current_policy_hash IS DISTINCT FROM v_handshake.policy_hash THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_POLICY_HASH_MISMATCH';
  END IF;

  v_signoff_rules := v_policy.rules -> 'accountable_signoff';
  IF v_signoff_rules IS NULL
     OR pg_catalog.jsonb_typeof(v_signoff_rules) <> 'object'
     OR v_signoff_rules ->> 'required' IS DISTINCT FROM 'true'
     OR v_signoff_rules ->> 'accountable_role' IS NULL
     OR v_signoff_rules ->> 'accountable_role' NOT IN (
       'initiator', 'responder', 'verifier', 'delegate'
     )
     OR v_signoff_rules ->> 'authority_class' IS NULL
     OR pg_catalog.btrim(v_signoff_rules ->> 'authority_class') = ''
     OR v_signoff_rules ->> 'organization_id' IS NULL
     OR pg_catalog.btrim(v_signoff_rules ->> 'organization_id') = ''
     OR v_signoff_rules ->> 'required_assurance' IS NULL
     OR v_signoff_rules ->> 'required_assurance' NOT IN (
       'low', 'substantial', 'high'
     )
     OR pg_catalog.jsonb_typeof(v_signoff_rules -> 'allowed_methods') <> 'array'
     OR pg_catalog.jsonb_array_length(v_signoff_rules -> 'allowed_methods') = 0
     OR pg_catalog.jsonb_typeof(v_signoff_rules -> 'action_types') <> 'array'
     OR pg_catalog.jsonb_array_length(v_signoff_rules -> 'action_types') = 0
     OR pg_catalog.jsonb_typeof(v_signoff_rules -> 'max_ttl_seconds') <> 'number'
     OR (v_signoff_rules ->> 'max_ttl_seconds') !~ '^[0-9]+$'
     OR (v_signoff_rules ->> 'max_ttl_seconds')::INTEGER NOT BETWEEN 60 AND 3600 THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_POLICY_BLOCK_INVALID';
  END IF;

  v_accountable_role := v_signoff_rules ->> 'accountable_role';
  v_required_authority_class := v_signoff_rules ->> 'authority_class';
  v_authority_organization_id := v_signoff_rules ->> 'organization_id';
  v_required_assurance := v_signoff_rules ->> 'required_assurance';
  v_max_ttl_seconds := (v_signoff_rules ->> 'max_ttl_seconds')::INTEGER;
  SELECT pg_catalog.array_agg(method.value ORDER BY method.ordinality)
    INTO v_allowed_methods
  FROM pg_catalog.jsonb_array_elements_text(
    v_signoff_rules -> 'allowed_methods'
  ) WITH ORDINALITY AS method(value, ordinality);
  SELECT pg_catalog.array_agg(action_type.value ORDER BY action_type.ordinality)
    INTO v_action_types
  FROM pg_catalog.jsonb_array_elements_text(
    v_signoff_rules -> 'action_types'
  ) WITH ORDINALITY AS action_type(value, ordinality);

  IF EXISTS (
       SELECT 1 FROM pg_catalog.unnest(v_allowed_methods) AS method(value)
       WHERE method.value NOT IN (
         'passkey', 'secure_app', 'platform_authenticator',
         'out_of_band', 'dual_signoff'
       )
     )
     OR v_handshake.action_type IS NULL
     OR NOT (v_handshake.action_type = ANY(v_action_types)) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_POLICY_SCOPE_MISMATCH';
  END IF;

  -- Keep party membership stable through commit. The accountable actor is the
  -- unique verified party in the server-pinned accountable role; it is never a
  -- public request field.
  FOR v_party IN
    SELECT *
    FROM public.handshake_parties
    WHERE handshake_id = p_handshake_id
    ORDER BY entity_ref, id
    FOR UPDATE
  LOOP
    IF v_party.entity_ref = p_actor_entity_ref THEN
      v_caller_is_party := TRUE;
    END IF;
    IF v_party.party_role = v_accountable_role
       AND v_party.verified_status = 'verified' THEN
      IF v_accountable_actor_ref IS NOT NULL THEN
        RAISE EXCEPTION USING
          ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ACCOUNTABLE_PARTY_AMBIGUOUS';
      END IF;
      v_accountable_actor_ref := v_party.entity_ref;
    END IF;
  END LOOP;

  IF NOT v_caller_is_party THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CALLER_NOT_HANDSHAKE_PARTY';
  END IF;
  IF v_accountable_actor_ref IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ACCOUNTABLE_PARTY_NOT_VERIFIED';
  END IF;
  IF v_accountable_actor_ref = p_actor_entity_ref THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_SELF_APPROVAL_FORBIDDEN';
  END IF;

  SELECT * INTO v_authority
  FROM public.authorities
  WHERE subject_type = 'human_approver'
    AND subject_ref = v_accountable_actor_ref
    AND organization_id = v_authority_organization_id
    AND role = v_required_authority_class
    AND status = 'active'
    AND revoked_at IS NULL
    AND valid_from <= v_now
    AND (valid_to IS NULL OR valid_to > v_now)
    AND (policy_hash IS NULL OR policy_hash = v_handshake.policy_hash)
    AND (action_scopes IS NULL OR v_handshake.action_type = ANY(action_scopes))
  ORDER BY authority_id
  LIMIT 1
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ACCOUNTABLE_AUTHORITY_UNAVAILABLE';
  END IF;

  v_expires_at := LEAST(
    p_requested_expires_at,
    v_now + pg_catalog.make_interval(secs => v_max_ttl_seconds),
    v_binding.expires_at,
    COALESCE(v_handshake.expires_at, v_binding.expires_at)
  );
  IF v_expires_at <= v_now THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_EXPIRY_INVALID';
  END IF;

  -- These legacy handshake_id columns reference handshake_bindings.id, so use
  -- the server-resolved binding id rather than the caller's handshake id.
  INSERT INTO public.signoff_challenges (
    challenge_id, handshake_id, binding_hash,
    accountable_actor_ref, signoff_policy_id, signoff_policy_hash,
    required_assurance, allowed_methods, required_authority_class,
    authority_organization_id, authority_id,
    status, expires_at, metadata, issued_at
  ) VALUES (
    p_challenge_id, v_binding.id, v_binding.binding_hash,
    v_accountable_actor_ref, v_policy.policy_id::TEXT, v_handshake.policy_hash,
    v_required_assurance, v_allowed_methods, v_required_authority_class,
    v_authority_organization_id, v_authority.authority_id,
    'challenge_issued', v_expires_at,
    COALESCE(p_metadata_json, '{}'::JSONB) || pg_catalog.jsonb_build_object(
      'accountable_role', v_accountable_role,
      'policy_version', v_policy.version,
      'max_ttl_seconds', v_max_ttl_seconds,
      'action_type', v_handshake.action_type
    ),
    v_now
  );

  -- challenge_id is an immediate FK, so the state row must precede the event.
  -- Both writes still commit or roll back in this single transaction.
  INSERT INTO public.signoff_events (
    event_id, handshake_id, challenge_id, signoff_id,
    event_type, actor_entity_ref, binding_hash, detail, created_at
  ) VALUES (
    pg_catalog.gen_random_uuid(), v_binding.id, p_challenge_id, NULL,
    'challenge_issued', p_actor_entity_ref, v_binding.binding_hash,
    pg_catalog.jsonb_build_object(
      'accountable_actor_ref', v_accountable_actor_ref,
      'accountable_role', v_accountable_role,
      'signoff_policy_id', v_policy.policy_id::TEXT,
      'signoff_policy_hash', v_handshake.policy_hash,
      'required_assurance', v_required_assurance,
      'allowed_methods', pg_catalog.to_jsonb(v_allowed_methods),
      'required_authority_class', v_required_authority_class,
      'authority_id', v_authority.authority_id,
      'expires_at', v_expires_at
    ),
    v_now
  );

  SELECT pg_catalog.to_jsonb(challenge.*) INTO v_challenge
  FROM public.signoff_challenges AS challenge
  WHERE challenge.challenge_id = p_challenge_id;
  RETURN v_challenge;
END;
$issue_challenge_atomic$;

REVOKE ALL ON FUNCTION public.issue_challenge_atomic(
  UUID, UUID, TEXT, TEXT, TIMESTAMPTZ, JSONB
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.issue_challenge_atomic(
  UUID, UUID, TEXT, TEXT, TIMESTAMPTZ, JSONB
) TO service_role;

COMMENT ON FUNCTION public.issue_challenge_atomic(
  UUID, UUID, TEXT, TEXT, TIMESTAMPTZ, JSONB
) IS 'Derives accountable actor, assurance, methods, authority class, scope, policy identity, and maximum TTL from the pinned accountable_signoff policy block and current authority registry under deterministic locks.';

CREATE OR REPLACE FUNCTION public.approve_attestation_atomic(
  p_signoff_id UUID,
  p_challenge_id UUID,
  p_handshake_id UUID,
  p_binding_hash TEXT,
  p_human_entity_ref TEXT,
  p_auth_method TEXT,
  p_assurance_level TEXT,
  p_channel TEXT,
  p_expires_at TIMESTAMPTZ,
  p_attestation_hash TEXT,
  p_metadata_json JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $approve_attestation_atomic$
DECLARE
  v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
  v_authority_handshake_id UUID;
  v_handshake public.handshakes%ROWTYPE;
  v_challenge public.signoff_challenges%ROWTYPE;
  v_binding public.handshake_bindings%ROWTYPE;
  v_policy public.handshake_policies%ROWTYPE;
  v_authority public.authorities%ROWTYPE;
  v_ceremony public.signoff_ceremony_evidence%ROWTYPE;
  v_ceremony_evidence_id UUID;
  v_attestation JSONB;
  v_achieved_rank INTEGER;
  v_required_rank INTEGER;
BEGIN
  -- Discover the parent authority without taking a competing child-first lock.
  -- The relationship is rechecked after all authoritative rows are locked.
  SELECT binding.handshake_id INTO v_authority_handshake_id
  FROM public.signoff_challenges AS challenge
  JOIN public.handshake_bindings AS binding
    ON binding.id = challenge.handshake_id
  WHERE challenge.challenge_id = p_challenge_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_CHALLENGE_NOT_FOUND';
  END IF;

  SELECT * INTO v_handshake
  FROM public.handshakes
  WHERE handshake_id = v_authority_handshake_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_HANDSHAKE_NOT_FOUND';
  END IF;
  IF v_handshake.status <> 'verified' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_HANDSHAKE_NOT_VERIFIED',
      DETAIL = pg_catalog.format('current_status=%s', v_handshake.status);
  END IF;
  IF v_handshake.verified_at IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_HANDSHAKE_NOT_VERIFICATION_FINALIZED';
  END IF;
  IF v_handshake.expires_at IS NOT NULL AND v_handshake.expires_at <= v_now THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_HANDSHAKE_EXPIRED';
  END IF;

  SELECT * INTO v_binding
  FROM public.handshake_bindings
  WHERE handshake_id = v_handshake.handshake_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_BINDING_NOT_FOUND';
  END IF;
  IF v_binding.id IS DISTINCT FROM p_handshake_id
     OR v_binding.binding_hash IS DISTINCT FROM p_binding_hash THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_BINDING_MISMATCH';
  END IF;
  IF v_binding.expires_at IS NULL OR v_binding.expires_at <= v_now THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_BINDING_EXPIRED';
  END IF;
  IF v_binding.consumed_at IS NULL
     OR v_binding.consumed_for IS DISTINCT FROM
       'handshake_verified:' || v_handshake.handshake_id::TEXT THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_BINDING_NOT_VERIFICATION_FINALIZED';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM public.handshake_consumptions
    WHERE handshake_id = v_handshake.handshake_id
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_AUTHORITY_ALREADY_CONSUMED';
  END IF;

  SELECT * INTO v_policy
  FROM public.handshake_policies
  WHERE policy_id = v_handshake.policy_id
  FOR UPDATE;
  IF NOT FOUND
     OR v_policy.status <> 'active'
     OR v_policy.version IS DISTINCT FROM v_handshake.policy_version_number THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_PINNED_POLICY_UNAVAILABLE';
  END IF;
  BEGIN
    IF public.signoff_policy_rules_hash(v_policy.rules)
         IS DISTINCT FROM v_handshake.policy_hash THEN
      RAISE EXCEPTION USING
        ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_POLICY_HASH_MISMATCH';
    END IF;
  EXCEPTION WHEN SQLSTATE 'P0001' THEN
    IF SQLERRM = 'SIGNOFF_POLICY_HASH_MISMATCH' THEN
      RAISE;
    END IF;
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_POLICY_HASH_UNVERIFIABLE';
  END;

  SELECT * INTO v_challenge
  FROM public.signoff_challenges
  WHERE challenge_id = p_challenge_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_CHALLENGE_NOT_FOUND';
  END IF;
  IF v_challenge.status NOT IN ('challenge_issued', 'challenge_viewed') THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_NOT_ATTESTABLE',
      DETAIL = pg_catalog.format('current_status=%s', v_challenge.status);
  END IF;
  IF v_challenge.expires_at IS NULL OR v_challenge.expires_at <= v_now THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_EXPIRED';
  END IF;
  IF v_challenge.handshake_id IS DISTINCT FROM v_binding.id
     OR v_challenge.binding_hash IS DISTINCT FROM p_binding_hash
     OR v_binding.binding_hash IS DISTINCT FROM v_challenge.binding_hash THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_BINDING_MISMATCH';
  END IF;
  IF v_challenge.expires_at > v_binding.expires_at THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_OUTLIVES_BINDING';
  END IF;
  IF v_handshake.policy_id IS NULL
     OR v_handshake.policy_hash IS NULL
     OR v_binding.policy_hash IS DISTINCT FROM v_handshake.policy_hash
     OR v_challenge.signoff_policy_id IS DISTINCT FROM v_handshake.policy_id::TEXT
     OR v_challenge.signoff_policy_hash IS DISTINCT FROM v_handshake.policy_hash
     OR v_challenge.required_authority_class IS NULL
     OR v_challenge.authority_organization_id IS NULL
     OR v_challenge.authority_id IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_POLICY_MISMATCH';
  END IF;
  IF v_challenge.accountable_actor_ref IS DISTINCT FROM p_human_entity_ref THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_ACTOR_MISMATCH';
  END IF;

  -- Revalidate the exact current authority grant pinned at challenge issuance.
  -- FOR UPDATE serializes approval with revocation/status changes.
  SELECT * INTO v_authority
  FROM public.authorities
  WHERE authority_id = v_challenge.authority_id
  FOR UPDATE;
  IF NOT FOUND
     OR v_authority.subject_type <> 'human_approver'
     OR v_authority.subject_ref IS DISTINCT FROM p_human_entity_ref
     OR v_authority.organization_id IS DISTINCT FROM v_challenge.authority_organization_id
     OR v_authority.role IS DISTINCT FROM v_challenge.required_authority_class
     OR v_authority.status <> 'active'
     OR v_authority.revoked_at IS NOT NULL
     OR v_authority.valid_from > v_now
     OR (v_authority.valid_to IS NOT NULL AND v_authority.valid_to <= v_now)
     OR (v_authority.policy_hash IS NOT NULL
         AND v_authority.policy_hash IS DISTINCT FROM v_handshake.policy_hash)
     OR (v_authority.action_scopes IS NOT NULL
         AND (v_handshake.action_type IS NULL
              OR NOT (v_handshake.action_type = ANY(v_authority.action_scopes)))) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_AUTHORITY_INVALID_OR_REVOKED';
  END IF;

  IF p_metadata_json IS NULL
     OR pg_catalog.jsonb_typeof(p_metadata_json) <> 'object'
     OR p_metadata_json ->> 'ceremony_evidence_id' IS NULL
     OR (p_metadata_json ->> 'ceremony_evidence_id') !~*
       '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CEREMONY_EVIDENCE_REQUIRED';
  END IF;
  v_ceremony_evidence_id := (p_metadata_json ->> 'ceremony_evidence_id')::UUID;

  SELECT * INTO v_ceremony
  FROM public.signoff_ceremony_evidence
  WHERE evidence_id = v_ceremony_evidence_id
  FOR UPDATE;
  IF NOT FOUND
     OR v_ceremony.challenge_id IS DISTINCT FROM v_challenge.challenge_id
     OR v_ceremony.human_entity_ref IS DISTINCT FROM p_human_entity_ref
     OR v_ceremony.authority_id IS DISTINCT FROM v_authority.authority_id
     OR v_ceremony.verified_at < v_challenge.issued_at
     OR v_ceremony.verified_at > v_now
     OR v_ceremony.expires_at <= v_now
     OR v_ceremony.consumed_at IS NOT NULL
     OR v_ceremony.evidence_hash IS NULL
     OR pg_catalog.btrim(v_ceremony.evidence_hash) = '' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CEREMONY_EVIDENCE_INVALID';
  END IF;

  -- Request fields are consistency assertions only. Method, assurance, and
  -- channel are persisted from the locked server-side ceremony evidence.
  IF p_auth_method IS DISTINCT FROM v_ceremony.auth_method
     OR NOT (v_ceremony.auth_method = ANY(v_challenge.allowed_methods)) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_METHOD_NOT_ALLOWED';
  END IF;

  v_achieved_rank := CASE v_ceremony.assurance_level
    WHEN 'low' THEN 0 WHEN 'substantial' THEN 1 WHEN 'high' THEN 2 ELSE NULL END;
  v_required_rank := CASE v_challenge.required_assurance
    WHEN 'low' THEN 0 WHEN 'substantial' THEN 1 WHEN 'high' THEN 2 ELSE NULL END;
  IF v_achieved_rank IS NULL OR v_required_rank IS NULL
     OR v_achieved_rank < v_required_rank
     OR p_assurance_level IS DISTINCT FROM v_ceremony.assurance_level THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_ASSURANCE_INSUFFICIENT';
  END IF;
  IF p_channel IS DISTINCT FROM v_ceremony.channel
     OR p_attestation_hash IS NULL OR pg_catalog.btrim(p_attestation_hash) = '' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_MATERIAL_INVALID';
  END IF;
  IF p_expires_at IS NULL OR p_expires_at <= v_now
     OR p_expires_at > v_challenge.expires_at
     OR p_expires_at > v_binding.expires_at
     OR p_expires_at > v_ceremony.expires_at THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_EXPIRY_INVALID';
  END IF;

  INSERT INTO public.signoff_attestations (
    signoff_id, challenge_id, handshake_id, binding_hash,
    human_entity_ref, auth_method, assurance_level,
    channel, status, expires_at,
    attestation_hash, metadata, ceremony_evidence_id, approved_at
  ) VALUES (
    p_signoff_id, p_challenge_id, v_challenge.handshake_id, v_challenge.binding_hash,
    p_human_entity_ref, v_ceremony.auth_method, v_ceremony.assurance_level,
    v_ceremony.channel, 'approved', p_expires_at,
    p_attestation_hash,
    COALESCE(p_metadata_json, '{}'::JSONB) || pg_catalog.jsonb_build_object(
      'ceremony_evidence_hash', v_ceremony.evidence_hash,
      'ceremony_verified_at', v_ceremony.verified_at,
      'authority_id', v_authority.authority_id
    ),
    v_ceremony.evidence_id, v_now
  );

  UPDATE public.signoff_ceremony_evidence
  SET consumed_at = v_now
  WHERE evidence_id = v_ceremony.evidence_id
    AND consumed_at IS NULL;

  INSERT INTO public.signoff_events (
    event_id, handshake_id, challenge_id, signoff_id,
    event_type, actor_entity_ref, binding_hash, detail, created_at
  ) VALUES (
    pg_catalog.gen_random_uuid(), v_challenge.handshake_id, p_challenge_id, p_signoff_id,
    'signoff_approved', p_human_entity_ref, v_challenge.binding_hash,
    pg_catalog.jsonb_build_object(
      'human_entity_ref', p_human_entity_ref,
      'auth_method', v_ceremony.auth_method,
      'assurance_level', v_ceremony.assurance_level,
      'channel', v_ceremony.channel,
      'ceremony_evidence_id', v_ceremony.evidence_id,
      'authority_id', v_authority.authority_id
    ),
    v_now
  );

  UPDATE public.signoff_challenges
  SET status = 'approved',
      metadata = COALESCE(metadata, '{}'::JSONB)
        || pg_catalog.jsonb_build_object('approved_at', v_now)
  WHERE challenge_id = p_challenge_id;

  SELECT pg_catalog.to_jsonb(attestation.*) INTO v_attestation
  FROM public.signoff_attestations AS attestation
  WHERE attestation.signoff_id = p_signoff_id;
  RETURN v_attestation;
END;
$approve_attestation_atomic$;

REVOKE ALL ON FUNCTION public.approve_attestation_atomic(
  UUID, UUID, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TEXT, JSONB
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.approve_attestation_atomic(
  UUID, UUID, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TEXT, JSONB
) TO service_role;

COMMENT ON FUNCTION public.approve_attestation_atomic(
  UUID, UUID, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TEXT, JSONB
) IS 'Locks an attestable, unexpired challenge and atomically commits its exact actor-bound approval.';

CREATE OR REPLACE FUNCTION public.deny_challenge_atomic(
  p_challenge_id UUID,
  p_actor_entity_ref TEXT,
  p_reason TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $deny_challenge_atomic$
DECLARE
  v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
  v_challenge public.signoff_challenges%ROWTYPE;
  v_result JSONB;
BEGIN
  SELECT * INTO v_challenge
  FROM public.signoff_challenges
  WHERE challenge_id = p_challenge_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_CHALLENGE_NOT_FOUND';
  END IF;
  IF v_challenge.accountable_actor_ref IS DISTINCT FROM p_actor_entity_ref THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_ACTOR_MISMATCH';
  END IF;
  IF v_challenge.status NOT IN ('challenge_issued', 'challenge_viewed') THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_NOT_DENIABLE',
      DETAIL = pg_catalog.format('current_status=%s', v_challenge.status);
  END IF;
  IF v_challenge.expires_at IS NULL OR v_challenge.expires_at <= v_now THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_EXPIRED';
  END IF;

  INSERT INTO public.signoff_events (
    event_id, handshake_id, challenge_id, signoff_id,
    event_type, actor_entity_ref, binding_hash, detail, created_at
  ) VALUES (
    pg_catalog.gen_random_uuid(), v_challenge.handshake_id, p_challenge_id, NULL,
    'signoff_denied', p_actor_entity_ref, v_challenge.binding_hash,
    pg_catalog.jsonb_build_object(
      'reason', COALESCE(NULLIF(pg_catalog.btrim(p_reason), ''), 'Human denied the action')
    ),
    v_now
  );

  UPDATE public.signoff_challenges
  SET status = 'denied',
      metadata = COALESCE(metadata, '{}'::JSONB)
        || pg_catalog.jsonb_build_object(
          'denied_at', v_now,
          'denial_reason', COALESCE(NULLIF(pg_catalog.btrim(p_reason), ''), 'Human denied the action')
        )
  WHERE challenge_id = p_challenge_id;

  SELECT pg_catalog.to_jsonb(challenge.*) INTO v_result
  FROM public.signoff_challenges AS challenge
  WHERE challenge.challenge_id = p_challenge_id;
  RETURN v_result;
END;
$deny_challenge_atomic$;

REVOKE ALL ON FUNCTION public.deny_challenge_atomic(UUID, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.deny_challenge_atomic(UUID, TEXT, TEXT)
  TO service_role;

COMMENT ON FUNCTION public.deny_challenge_atomic(UUID, TEXT, TEXT)
  IS 'Locks a pending, unexpired challenge and atomically records its accountable actor denial.';

CREATE OR REPLACE FUNCTION public.revoke_challenge_atomic(
  p_challenge_id UUID,
  p_actor_entity_ref TEXT,
  p_reason TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $revoke_challenge_atomic$
DECLARE
  v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
  v_challenge public.signoff_challenges%ROWTYPE;
  v_result JSONB;
BEGIN
  SELECT * INTO v_challenge
  FROM public.signoff_challenges
  WHERE challenge_id = p_challenge_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_CHALLENGE_NOT_FOUND';
  END IF;
  IF v_challenge.accountable_actor_ref IS DISTINCT FROM p_actor_entity_ref THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_ACTOR_MISMATCH';
  END IF;
  IF v_challenge.status NOT IN ('challenge_issued', 'challenge_viewed') THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_NOT_REVOCABLE',
      DETAIL = pg_catalog.format('current_status=%s', v_challenge.status);
  END IF;
  IF v_challenge.expires_at IS NULL OR v_challenge.expires_at <= v_now THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_EXPIRED';
  END IF;
  IF p_reason IS NULL OR pg_catalog.btrim(p_reason) = '' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_REVOCATION_REASON_REQUIRED';
  END IF;

  INSERT INTO public.signoff_events (
    event_id, handshake_id, challenge_id, signoff_id,
    event_type, actor_entity_ref, binding_hash, detail, created_at
  ) VALUES (
    pg_catalog.gen_random_uuid(), v_challenge.handshake_id, p_challenge_id, NULL,
    'challenge_revoked', p_actor_entity_ref, v_challenge.binding_hash,
    pg_catalog.jsonb_build_object('reason', p_reason), v_now
  );

  UPDATE public.signoff_challenges
  SET status = 'revoked', revoked_at = v_now, revocation_reason = p_reason
  WHERE challenge_id = p_challenge_id;

  SELECT pg_catalog.to_jsonb(challenge.*) INTO v_result
  FROM public.signoff_challenges AS challenge
  WHERE challenge.challenge_id = p_challenge_id;
  RETURN v_result;
END;
$revoke_challenge_atomic$;

REVOKE ALL ON FUNCTION public.revoke_challenge_atomic(UUID, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.revoke_challenge_atomic(UUID, TEXT, TEXT)
  TO service_role;

COMMENT ON FUNCTION public.revoke_challenge_atomic(UUID, TEXT, TEXT)
  IS 'Locks a pending, unexpired challenge and atomically records its accountable actor revocation.';

CREATE OR REPLACE FUNCTION public.revoke_attestation_atomic(
  p_signoff_id UUID,
  p_challenge_id UUID,
  p_actor_entity_ref TEXT,
  p_reason TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $revoke_attestation_atomic$
DECLARE
  v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
  v_challenge public.signoff_challenges%ROWTYPE;
  v_attestation public.signoff_attestations%ROWTYPE;
  v_result JSONB;
BEGIN
  SELECT * INTO v_challenge
  FROM public.signoff_challenges
  WHERE challenge_id = p_challenge_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_CHALLENGE_NOT_FOUND';
  END IF;

  SELECT * INTO v_attestation
  FROM public.signoff_attestations
  WHERE signoff_id = p_signoff_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_ATTESTATION_NOT_FOUND';
  END IF;
  IF v_attestation.challenge_id IS DISTINCT FROM v_challenge.challenge_id
     OR v_attestation.handshake_id IS DISTINCT FROM v_challenge.handshake_id
     OR v_attestation.binding_hash IS DISTINCT FROM v_challenge.binding_hash THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_BINDING_MISMATCH';
  END IF;
  IF v_attestation.human_entity_ref IS DISTINCT FROM p_actor_entity_ref THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_ACTOR_MISMATCH';
  END IF;
  IF v_attestation.status <> 'approved' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_NOT_REVOCABLE',
      DETAIL = pg_catalog.format('current_status=%s', v_attestation.status);
  END IF;
  IF v_attestation.expires_at IS NULL OR v_attestation.expires_at <= v_now THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_EXPIRED';
  END IF;
  IF p_reason IS NULL OR pg_catalog.btrim(p_reason) = '' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_REVOCATION_REASON_REQUIRED';
  END IF;

  INSERT INTO public.signoff_events (
    event_id, handshake_id, challenge_id, signoff_id,
    event_type, actor_entity_ref, binding_hash, detail, created_at
  ) VALUES (
    pg_catalog.gen_random_uuid(), v_attestation.handshake_id,
    v_attestation.challenge_id, v_attestation.signoff_id,
    'signoff_revoked', p_actor_entity_ref, v_attestation.binding_hash,
    pg_catalog.jsonb_build_object('reason', p_reason), v_now
  );

  UPDATE public.signoff_attestations
  SET status = 'revoked', revoked_at = v_now, revocation_reason = p_reason
  WHERE signoff_id = p_signoff_id;

  SELECT pg_catalog.to_jsonb(attestation.*) INTO v_result
  FROM public.signoff_attestations AS attestation
  WHERE attestation.signoff_id = p_signoff_id;
  RETURN v_result;
END;
$revoke_attestation_atomic$;

REVOKE ALL ON FUNCTION public.revoke_attestation_atomic(UUID, UUID, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.revoke_attestation_atomic(UUID, UUID, TEXT, TEXT)
  TO service_role;

COMMENT ON FUNCTION public.revoke_attestation_atomic(UUID, UUID, TEXT, TEXT)
  IS 'Locks challenge then attestation and atomically revokes an approved, unexpired actor-owned attestation.';

CREATE OR REPLACE FUNCTION public.expire_challenge_atomic(
  p_challenge_id UUID,
  p_actor_entity_ref TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $expire_challenge_atomic$
DECLARE
  v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
  v_challenge public.signoff_challenges%ROWTYPE;
  v_result JSONB;
BEGIN
  IF p_actor_entity_ref IS NULL OR pg_catalog.btrim(p_actor_entity_ref) = '' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ACTOR_REQUIRED';
  END IF;

  SELECT * INTO v_challenge
  FROM public.signoff_challenges
  WHERE challenge_id = p_challenge_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_CHALLENGE_NOT_FOUND';
  END IF;
  IF v_challenge.status NOT IN ('challenge_issued', 'challenge_viewed') THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_NOT_EXPIRABLE',
      DETAIL = pg_catalog.format('current_status=%s', v_challenge.status);
  END IF;
  IF v_challenge.expires_at IS NULL OR v_challenge.expires_at > v_now THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_NOT_EXPIRED';
  END IF;

  INSERT INTO public.signoff_events (
    event_id, handshake_id, challenge_id, signoff_id,
    event_type, actor_entity_ref, binding_hash, detail, created_at
  ) VALUES (
    pg_catalog.gen_random_uuid(), v_challenge.handshake_id,
    v_challenge.challenge_id, NULL,
    'challenge_expired', p_actor_entity_ref, v_challenge.binding_hash,
    pg_catalog.jsonb_build_object(
      'deadline', v_challenge.expires_at,
      'expired_at', v_now
    ),
    v_now
  );

  UPDATE public.signoff_challenges
  SET status = 'expired'
  WHERE challenge_id = v_challenge.challenge_id;

  SELECT pg_catalog.to_jsonb(challenge.*) INTO v_result
  FROM public.signoff_challenges AS challenge
  WHERE challenge.challenge_id = v_challenge.challenge_id;
  RETURN v_result;
END;
$expire_challenge_atomic$;

REVOKE ALL ON FUNCTION public.expire_challenge_atomic(UUID, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.expire_challenge_atomic(UUID, TEXT)
  TO service_role;

COMMENT ON FUNCTION public.expire_challenge_atomic(UUID, TEXT)
  IS 'Locks an issued or viewed challenge and atomically records expiry only after its deadline.';

CREATE OR REPLACE FUNCTION public.expire_attestation_atomic(
  p_signoff_id UUID,
  p_actor_entity_ref TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $expire_attestation_atomic$
DECLARE
  v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
  v_challenge_id UUID;
  v_challenge public.signoff_challenges%ROWTYPE;
  v_attestation public.signoff_attestations%ROWTYPE;
  v_result JSONB;
BEGIN
  IF p_actor_entity_ref IS NULL OR pg_catalog.btrim(p_actor_entity_ref) = '' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ACTOR_REQUIRED';
  END IF;

  -- Resolve the immutable parent identifier without taking locks, then follow
  -- the lifecycle-wide challenge -> attestation lock order used by revoke and
  -- consume. The relationship is rechecked after both rows are locked.
  SELECT attestation.challenge_id INTO v_challenge_id
  FROM public.signoff_attestations AS attestation
  WHERE attestation.signoff_id = p_signoff_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_ATTESTATION_NOT_FOUND';
  END IF;

  SELECT * INTO v_challenge
  FROM public.signoff_challenges
  WHERE challenge_id = v_challenge_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_CHALLENGE_NOT_FOUND';
  END IF;

  SELECT * INTO v_attestation
  FROM public.signoff_attestations
  WHERE signoff_id = p_signoff_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_ATTESTATION_NOT_FOUND';
  END IF;
  IF v_attestation.challenge_id IS DISTINCT FROM v_challenge.challenge_id
     OR v_attestation.handshake_id IS DISTINCT FROM v_challenge.handshake_id
     OR v_attestation.binding_hash IS DISTINCT FROM v_challenge.binding_hash THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_BINDING_MISMATCH';
  END IF;
  IF v_challenge.status <> 'approved'
     OR v_attestation.status <> 'approved' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_NOT_EXPIRABLE',
      DETAIL = pg_catalog.format(
        'challenge_status=%s attestation_status=%s',
        v_challenge.status, v_attestation.status
      );
  END IF;
  IF v_attestation.expires_at IS NULL OR v_attestation.expires_at > v_now THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_NOT_EXPIRED';
  END IF;

  INSERT INTO public.signoff_events (
    event_id, handshake_id, challenge_id, signoff_id,
    event_type, actor_entity_ref, binding_hash, detail, created_at
  ) VALUES (
    pg_catalog.gen_random_uuid(), v_attestation.handshake_id,
    v_attestation.challenge_id, v_attestation.signoff_id,
    'signoff_expired', p_actor_entity_ref, v_attestation.binding_hash,
    pg_catalog.jsonb_build_object(
      'deadline', v_attestation.expires_at,
      'expired_at', v_now
    ),
    v_now
  );

  UPDATE public.signoff_attestations
  SET status = 'expired'
  WHERE signoff_id = v_attestation.signoff_id;

  SELECT pg_catalog.to_jsonb(attestation.*) INTO v_result
  FROM public.signoff_attestations AS attestation
  WHERE attestation.signoff_id = v_attestation.signoff_id;
  RETURN v_result;
END;
$expire_attestation_atomic$;

REVOKE ALL ON FUNCTION public.expire_attestation_atomic(UUID, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.expire_attestation_atomic(UUID, TEXT)
  TO service_role;

COMMENT ON FUNCTION public.expire_attestation_atomic(UUID, TEXT)
  IS 'Locks challenge then approved attestation and atomically records expiry only after the attestation deadline.';

CREATE OR REPLACE FUNCTION public.consume_signoff_atomic(
  p_signoff_id TEXT,
  p_binding_hash TEXT,
  p_execution_ref TEXT,
  p_handshake_id TEXT,
  p_challenge_id TEXT,
  p_human_entity_ref TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $consume_signoff_atomic$
DECLARE
  v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
  v_authority_handshake_id UUID;
  v_handshake public.handshakes%ROWTYPE;
  v_challenge public.signoff_challenges%ROWTYPE;
  v_binding public.handshake_bindings%ROWTYPE;
  v_policy public.handshake_policies%ROWTYPE;
  v_authority public.authorities%ROWTYPE;
  v_attestation public.signoff_attestations%ROWTYPE;
  v_ceremony public.signoff_ceremony_evidence%ROWTYPE;
  v_consumption_id UUID;
  v_handshake_consumption_id BIGINT;
BEGIN
  IF p_signoff_id IS NULL OR pg_catalog.btrim(p_signoff_id) = ''
     OR p_challenge_id IS NULL OR pg_catalog.btrim(p_challenge_id) = '' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_ATTESTATION_NOT_FOUND';
  END IF;

  SELECT binding.handshake_id INTO v_authority_handshake_id
  FROM public.signoff_challenges AS challenge
  JOIN public.handshake_bindings AS binding
    ON binding.id = challenge.handshake_id
  WHERE challenge.challenge_id = p_challenge_id::UUID;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_CHALLENGE_NOT_FOUND';
  END IF;

  SELECT * INTO v_handshake
  FROM public.handshakes
  WHERE handshake_id = v_authority_handshake_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_HANDSHAKE_NOT_FOUND';
  END IF;
  IF v_handshake.status <> 'verified' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_HANDSHAKE_NOT_VERIFIED',
      DETAIL = pg_catalog.format('current_status=%s', v_handshake.status);
  END IF;
  IF v_handshake.verified_at IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_HANDSHAKE_NOT_VERIFICATION_FINALIZED';
  END IF;
  IF v_handshake.expires_at IS NOT NULL AND v_handshake.expires_at <= v_now THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_HANDSHAKE_EXPIRED';
  END IF;

  SELECT * INTO v_binding
  FROM public.handshake_bindings
  WHERE handshake_id = v_handshake.handshake_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_BINDING_NOT_FOUND';
  END IF;
  IF v_binding.id IS DISTINCT FROM p_handshake_id::UUID
     OR v_binding.binding_hash IS DISTINCT FROM p_binding_hash THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_BINDING_MISMATCH';
  END IF;
  IF v_binding.expires_at IS NULL OR v_binding.expires_at <= v_now THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_BINDING_EXPIRED';
  END IF;
  IF v_binding.consumed_at IS NULL
     OR v_binding.consumed_for IS DISTINCT FROM
       'handshake_verified:' || v_handshake.handshake_id::TEXT THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_BINDING_NOT_VERIFICATION_FINALIZED';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM public.handshake_consumptions
    WHERE handshake_id = v_handshake.handshake_id
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_AUTHORITY_ALREADY_CONSUMED';
  END IF;

  SELECT * INTO v_policy
  FROM public.handshake_policies
  WHERE policy_id = v_handshake.policy_id
  FOR UPDATE;
  IF NOT FOUND
     OR v_policy.status <> 'active'
     OR v_policy.version IS DISTINCT FROM v_handshake.policy_version_number THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_PINNED_POLICY_UNAVAILABLE';
  END IF;
  BEGIN
    IF public.signoff_policy_rules_hash(v_policy.rules)
         IS DISTINCT FROM v_handshake.policy_hash THEN
      RAISE EXCEPTION USING
        ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_POLICY_HASH_MISMATCH';
    END IF;
  EXCEPTION WHEN SQLSTATE 'P0001' THEN
    IF SQLERRM = 'SIGNOFF_POLICY_HASH_MISMATCH' THEN
      RAISE;
    END IF;
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_POLICY_HASH_UNVERIFIABLE';
  END;

  SELECT * INTO v_challenge
  FROM public.signoff_challenges
  WHERE challenge_id = p_challenge_id::UUID
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_CHALLENGE_NOT_FOUND';
  END IF;
  IF v_challenge.status <> 'approved' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_NOT_CONSUMABLE',
      DETAIL = pg_catalog.format('current_status=%s', v_challenge.status);
  END IF;
  IF v_challenge.expires_at IS NULL OR v_challenge.expires_at <= v_now THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_EXPIRED';
  END IF;
  IF v_challenge.handshake_id IS DISTINCT FROM v_binding.id
     OR v_challenge.binding_hash IS DISTINCT FROM v_binding.binding_hash THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_BINDING_MISMATCH';
  END IF;
  IF v_challenge.expires_at > v_binding.expires_at THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_OUTLIVES_BINDING';
  END IF;
  IF v_handshake.policy_id IS NULL
     OR v_handshake.policy_hash IS NULL
     OR v_binding.policy_hash IS DISTINCT FROM v_handshake.policy_hash
     OR v_challenge.signoff_policy_id IS DISTINCT FROM v_handshake.policy_id::TEXT
     OR v_challenge.signoff_policy_hash IS DISTINCT FROM v_handshake.policy_hash
     OR v_challenge.required_authority_class IS NULL
     OR v_challenge.authority_organization_id IS NULL
     OR v_challenge.authority_id IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_POLICY_MISMATCH';
  END IF;

  SELECT * INTO v_authority
  FROM public.authorities
  WHERE authority_id = v_challenge.authority_id
  FOR UPDATE;
  IF NOT FOUND
     OR v_authority.subject_type <> 'human_approver'
     OR v_authority.subject_ref IS DISTINCT FROM v_challenge.accountable_actor_ref
     OR v_authority.organization_id IS DISTINCT FROM v_challenge.authority_organization_id
     OR v_authority.role IS DISTINCT FROM v_challenge.required_authority_class
     OR v_authority.status <> 'active'
     OR v_authority.revoked_at IS NOT NULL
     OR v_authority.valid_from > v_now
     OR (v_authority.valid_to IS NOT NULL AND v_authority.valid_to <= v_now)
     OR (v_authority.policy_hash IS NOT NULL
         AND v_authority.policy_hash IS DISTINCT FROM v_handshake.policy_hash)
     OR (v_authority.action_scopes IS NOT NULL
         AND (v_handshake.action_type IS NULL
              OR NOT (v_handshake.action_type = ANY(v_authority.action_scopes)))) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_AUTHORITY_INVALID_OR_REVOKED';
  END IF;

  SELECT * INTO v_attestation
  FROM public.signoff_attestations
  WHERE signoff_id = p_signoff_id::UUID
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_ATTESTATION_NOT_FOUND';
  END IF;
  IF v_attestation.status <> 'approved' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_NOT_CONSUMABLE',
      DETAIL = pg_catalog.format('current_status=%s', v_attestation.status);
  END IF;
  IF v_attestation.expires_at IS NULL OR v_attestation.expires_at <= v_now THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_EXPIRED';
  END IF;
  IF v_attestation.expires_at > v_binding.expires_at THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_OUTLIVES_BINDING';
  END IF;
  IF v_attestation.challenge_id IS DISTINCT FROM v_challenge.challenge_id
     OR v_attestation.binding_hash IS DISTINCT FROM p_binding_hash
     OR v_attestation.binding_hash IS DISTINCT FROM v_challenge.binding_hash
     OR v_attestation.handshake_id IS DISTINCT FROM p_handshake_id::UUID
     OR v_attestation.handshake_id IS DISTINCT FROM v_challenge.handshake_id THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_BINDING_MISMATCH';
  END IF;
  IF v_attestation.human_entity_ref IS DISTINCT FROM p_human_entity_ref THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_ACTOR_MISMATCH';
  END IF;
  IF p_execution_ref IS NULL OR pg_catalog.btrim(p_execution_ref) = '' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_EXECUTION_REF_REQUIRED';
  END IF;

  IF v_attestation.ceremony_evidence_id IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CEREMONY_EVIDENCE_INVALID';
  END IF;
  SELECT * INTO v_ceremony
  FROM public.signoff_ceremony_evidence
  WHERE evidence_id = v_attestation.ceremony_evidence_id
  FOR UPDATE;
  IF NOT FOUND
     OR v_ceremony.challenge_id IS DISTINCT FROM v_challenge.challenge_id
     OR v_ceremony.human_entity_ref IS DISTINCT FROM v_attestation.human_entity_ref
     OR v_ceremony.authority_id IS DISTINCT FROM v_authority.authority_id
     OR v_ceremony.auth_method IS DISTINCT FROM v_attestation.auth_method
     OR v_ceremony.assurance_level IS DISTINCT FROM v_attestation.assurance_level
     OR v_ceremony.channel IS DISTINCT FROM v_attestation.channel
     OR v_attestation.approved_at IS NULL
     OR v_ceremony.verified_at < v_challenge.issued_at
     OR v_ceremony.verified_at > v_attestation.approved_at
     OR v_ceremony.consumed_at IS DISTINCT FROM v_attestation.approved_at
     OR v_ceremony.expires_at < v_attestation.expires_at THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CEREMONY_EVIDENCE_INVALID';
  END IF;

  -- Consume downstream authority in this same transaction. The binding's
  -- consumed_at/consumed_for fields remain the immutable verification marker;
  -- the unique handshake_consumptions row is the execution single-use gate.
  -- Any later signoff write failure rolls this insert back as well.
  INSERT INTO public.handshake_consumptions (
    handshake_id, binding_hash, consumed_by_type, consumed_by_id,
    consumed_at, actor_entity_ref, consumed_by_action
  ) VALUES (
    v_handshake.handshake_id, v_binding.binding_hash,
    'signoff_execution', v_attestation.signoff_id::TEXT,
    v_now, v_attestation.human_entity_ref, p_execution_ref
  )
  RETURNING id INTO v_handshake_consumption_id;

  INSERT INTO public.signoff_events (
    event_id, handshake_id, challenge_id, signoff_id,
    event_type, detail, actor_entity_ref, binding_hash, created_at
  ) VALUES (
    pg_catalog.gen_random_uuid(), v_attestation.handshake_id,
    v_attestation.challenge_id, v_attestation.signoff_id,
    'signoff_consumed',
    pg_catalog.jsonb_build_object(
      'execution_ref', p_execution_ref,
      'human_entity_ref', p_human_entity_ref
    ),
    v_attestation.human_entity_ref, v_attestation.binding_hash, v_now
  );

  INSERT INTO public.signoff_consumptions (
    signoff_id, binding_hash, execution_ref, consumed_at
  ) VALUES (
    v_attestation.signoff_id, v_attestation.binding_hash, p_execution_ref, v_now
  )
  RETURNING signoff_consumption_id INTO v_consumption_id;

  UPDATE public.signoff_attestations
  SET status = 'consumed', consumed_at = v_now
  WHERE signoff_id = v_attestation.signoff_id;

  UPDATE public.signoff_challenges
  SET status = 'consumed', consumed_at = v_now
  WHERE challenge_id = v_challenge.challenge_id;

  RETURN pg_catalog.jsonb_build_object(
    'consumption_id', v_consumption_id,
    'handshake_consumption_id', v_handshake_consumption_id,
    'consumed_at', v_now
  );
END;
$consume_signoff_atomic$;

REVOKE ALL ON FUNCTION public.consume_signoff_atomic(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_signoff_atomic(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) TO service_role;

COMMENT ON FUNCTION public.consume_signoff_atomic(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) IS 'Locks handshake, verification-finalized binding, challenge, then attestation and atomically records downstream authority and exact signoff consumption without overwriting the verification marker.';

CREATE OR REPLACE FUNCTION public.revoke_handshake_atomic(
  p_handshake_id UUID,
  p_reason TEXT,
  p_actor_entity_ref TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $revoke_handshake_atomic$
DECLARE
  v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
  v_handshake public.handshakes%ROWTYPE;
  v_binding public.handshake_bindings%ROWTYPE;
  v_actor_is_party BOOLEAN := FALSE;
  v_result JSONB;
BEGIN
  IF p_reason IS NULL OR pg_catalog.btrim(p_reason) = '' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'HANDSHAKE_REVOCATION_REASON_REQUIRED';
  END IF;
  IF p_actor_entity_ref IS NULL OR pg_catalog.btrim(p_actor_entity_ref) = '' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'HANDSHAKE_REVOCATION_ACTOR_REQUIRED';
  END IF;

  SELECT * INTO v_handshake
  FROM public.handshakes
  WHERE handshake_id = p_handshake_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'HANDSHAKE_NOT_FOUND';
  END IF;

  -- Match signoff approval/consumption lock order even when a pre-binding
  -- handshake is being revoked. A missing binding is valid before verification.
  SELECT * INTO v_binding
  FROM public.handshake_bindings
  WHERE handshake_id = p_handshake_id
  FOR UPDATE;

  -- A verified binding normally has consumed_at set by verification. Revocation
  -- remains valid until the separate downstream authority-consumption row
  -- exists. The handshake lock serializes this check with both consume RPCs.
  IF EXISTS (
    SELECT 1
    FROM public.handshake_consumptions
    WHERE handshake_id = p_handshake_id
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'HANDSHAKE_ALREADY_CONSUMED';
  END IF;
  IF v_handshake.status IN ('rejected', 'revoked', 'expired', 'consumed') THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'HANDSHAKE_NOT_REVOCABLE',
      DETAIL = pg_catalog.format('current_status=%s', v_handshake.status);
  END IF;

  IF p_actor_entity_ref <> 'system' THEN
    SELECT TRUE INTO v_actor_is_party
    FROM public.handshake_parties
    WHERE handshake_id = p_handshake_id
      AND entity_ref = p_actor_entity_ref
    ORDER BY id
    LIMIT 1
    FOR KEY SHARE;
    IF NOT COALESCE(v_actor_is_party, FALSE) THEN
      RAISE EXCEPTION USING
        ERRCODE = 'P0001', MESSAGE = 'HANDSHAKE_REVOCATION_ACTOR_UNAUTHORIZED';
    END IF;
  END IF;

  INSERT INTO public.handshake_events (
    event_id, handshake_id, event_type,
    actor_entity_ref, detail, created_at
  ) VALUES (
    pg_catalog.gen_random_uuid(), p_handshake_id, 'revoked',
    p_actor_entity_ref,
    pg_catalog.jsonb_build_object(
      'reason', p_reason,
      'previous_status', v_handshake.status
    ),
    v_now
  );

  UPDATE public.handshakes
  SET status = 'revoked',
      decision_ref = p_reason,
      revoked_by = p_actor_entity_ref
  WHERE handshake_id = p_handshake_id;

  SELECT pg_catalog.to_jsonb(handshake.*) INTO v_result
  FROM public.handshakes AS handshake
  WHERE handshake.handshake_id = p_handshake_id;
  RETURN v_result;
END;
$revoke_handshake_atomic$;

REVOKE ALL ON FUNCTION public.revoke_handshake_atomic(UUID, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.revoke_handshake_atomic(UUID, TEXT, TEXT)
  TO service_role;

COMMENT ON FUNCTION public.revoke_handshake_atomic(UUID, TEXT, TEXT)
  IS 'Locks handshake then binding and atomically records a party-authorized revocation unless the one-time authority was already consumed.';
