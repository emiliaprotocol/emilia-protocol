-- Reconcile security and authority invariants that existed only in historical
-- local migration aliases and therefore were never part of the production
-- journal or a reproducible fresh migration chain.
--
-- This forward migration is intentionally idempotent. It does not replay the
-- obsolete credential-to-authority backfill: credentials prove key control,
-- not current permission, so authority enrollment remains explicit.

-- Prevent concurrent appenders from producing two children for one security
-- event predecessor. The index intentionally refuses deployment if a fork
-- already exists so an operator must investigate rather than bless one branch.
CREATE UNIQUE INDEX IF NOT EXISTS idx_security_events_single_child_per_parent
  ON public.security_events (
    COALESCE(tenant_id, ''),
    COALESCE(previous_hash, 'root')
  );

-- EP-AUTHORITY-REGISTRY-v1 scope, limits, delegation, and policy binding.
ALTER TABLE public.authorities
  ADD COLUMN IF NOT EXISTS action_scopes TEXT[],
  ADD COLUMN IF NOT EXISTS max_amount_usd NUMERIC,
  ADD COLUMN IF NOT EXISTS currency TEXT DEFAULT 'USD',
  ADD COLUMN IF NOT EXISTS delegation_parent TEXT,
  ADD COLUMN IF NOT EXISTS policy_hash TEXT;

COMMENT ON COLUMN public.authorities.action_scopes IS
  'EP-AUTHORITY-REGISTRY-v1 action types this authority may approve; NULL is unscoped and must be handled by relying-party policy.';
COMMENT ON COLUMN public.authorities.max_amount_usd IS
  'EP-AUTHORITY-REGISTRY-v1 amount ceiling denominated in currency; NULL is unbounded and must be handled by relying-party policy.';
COMMENT ON COLUMN public.authorities.delegation_parent IS
  'EP-AUTHORITY-REGISTRY-v1 parent authority identifier; a child may narrow but never widen its parent.';
COMMENT ON COLUMN public.authorities.policy_hash IS
  'EP-AUTHORITY-REGISTRY-v1 optional exact policy binding.';

CREATE INDEX IF NOT EXISTS idx_authorities_delegation_parent
  ON public.authorities (delegation_parent);

CREATE TABLE IF NOT EXISTS public.authority_registry_epoch (
  organization_id TEXT PRIMARY KEY,
  epoch BIGINT NOT NULL DEFAULT 1,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now()
);

ALTER TABLE public.authority_registry_epoch ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS service_role_all ON public.authority_registry_epoch;
CREATE POLICY service_role_all ON public.authority_registry_epoch
  FOR ALL TO service_role USING (true) WITH CHECK (true);

REVOKE ALL ON TABLE public.authority_registry_epoch
  FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.authority_registry_epoch
  TO service_role;

COMMENT ON TABLE public.authority_registry_epoch IS
  'EP-AUTHORITY-REGISTRY-v1 monotonic per-organization authority-set version bound into receipts for freshness checks.';

CREATE OR REPLACE FUNCTION public.bump_authority_registry_epoch()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_org TEXT := COALESCE(NEW.organization_id, OLD.organization_id);
BEGIN
  IF v_org IS NULL THEN
    RETURN COALESCE(NEW, OLD);
  END IF;

  INSERT INTO public.authority_registry_epoch (organization_id, epoch, updated_at)
  VALUES (v_org, 1, pg_catalog.now())
  ON CONFLICT (organization_id)
  DO UPDATE
    SET epoch = public.authority_registry_epoch.epoch + 1,
        updated_at = pg_catalog.now();

  RETURN COALESCE(NEW, OLD);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.bump_authority_registry_epoch()
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.bump_authority_registry_epoch()
  TO service_role;

DROP TRIGGER IF EXISTS trg_bump_authority_registry_epoch ON public.authorities;
CREATE TRIGGER trg_bump_authority_registry_epoch
  AFTER INSERT OR UPDATE OR DELETE ON public.authorities
  FOR EACH ROW
  EXECUTE FUNCTION public.bump_authority_registry_epoch();

INSERT INTO public.authority_registry_epoch (organization_id, epoch)
SELECT DISTINCT organization_id, 1
FROM public.authorities
WHERE organization_id IS NOT NULL
ON CONFLICT (organization_id) DO NOTHING;

-- The authority registry and commit ledger are server-side permission roots.
-- RLS and table ACLs are independent gates, so close both.
REVOKE ALL ON TABLE public.authorities, public.commits, public.consumed_gate_refs
  FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.authorities
  TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.commits
  TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.consumed_gate_refs
  TO service_role;

-- Commit verification resolves custody by kid. The column was required by code
-- and the live contract but had no journaled creating migration.
ALTER TABLE public.commits
  ADD COLUMN IF NOT EXISTS kid TEXT NOT NULL DEFAULT 'ep-signing-key-1';

CREATE INDEX IF NOT EXISTS idx_commits_kid ON public.commits (kid);

-- A receipt hash chain is not linear unless one predecessor has at most one
-- child for an entity. This deliberately fails on historical forks.
CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_single_child_per_parent
  ON public.receipts (entity_id, COALESCE(previous_hash, 'root'));

COMMENT ON INDEX public.idx_receipts_single_child_per_parent IS
  'Prevents concurrent receipt writers from forking an entity hash chain at the same predecessor.';

-- Atomically validate and consume one exact Gate allow decision. A common
-- advisory lock linearizes consumption against emergency kid revocation.
CREATE OR REPLACE FUNCTION public.consume_gate_ref_atomic(
  p_gate_ref TEXT,
  p_entity_id TEXT,
  p_action_type TEXT,
  p_binding_version TEXT,
  p_binding_hash TEXT
)
RETURNS SETOF public.consumed_gate_refs
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_commit public.commits%ROWTYPE;
  v_consumption public.consumed_gate_refs%ROWTYPE;
BEGIN
  IF p_gate_ref IS NULL OR p_entity_id IS NULL OR p_action_type IS NULL OR
     p_binding_version IS NULL OR p_binding_hash IS NULL THEN
    RAISE EXCEPTION 'GATE_ARGUMENT_MISSING' USING ERRCODE = 'P0001';
  END IF;

  SELECT * INTO v_commit
  FROM public.commits
  WHERE commit_id = p_gate_ref
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'GATE_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;

  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('ep-commit-kid:' || v_commit.kid, 0)
  );

  IF v_commit.entity_id IS DISTINCT FROM p_entity_id OR
     v_commit.action_type IS DISTINCT FROM p_action_type THEN
    RAISE EXCEPTION 'GATE_ACTION_MISMATCH' USING ERRCODE = 'P0003';
  END IF;
  IF v_commit.decision IS DISTINCT FROM 'allow' THEN
    RAISE EXCEPTION 'GATE_NOT_ALLOW' USING ERRCODE = 'P0004';
  END IF;
  IF v_commit.status IS DISTINCT FROM 'active' OR
     v_commit.expires_at IS NULL OR
     v_commit.expires_at <= pg_catalog.clock_timestamp() THEN
    RAISE EXCEPTION 'GATE_NOT_ACTIVE' USING ERRCODE = 'P0005';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.revoked_commit_keys
    WHERE kid = v_commit.kid
  ) THEN
    RAISE EXCEPTION 'GATE_SIGNING_KEY_REVOKED' USING ERRCODE = 'P0006';
  END IF;
  IF v_commit.scope->>'gate_binding_version' IS DISTINCT FROM p_binding_version OR
     v_commit.scope->>'gate_binding_hash' IS DISTINCT FROM p_binding_hash THEN
    RAISE EXCEPTION 'GATE_BINDING_MISMATCH' USING ERRCODE = 'P0007';
  END IF;

  INSERT INTO public.consumed_gate_refs (
    gate_ref,
    consumed_by_entity,
    consumed_for_action
  ) VALUES (
    p_gate_ref,
    p_entity_id,
    p_action_type
  )
  RETURNING * INTO v_consumption;

  RETURN NEXT v_consumption;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.consume_gate_ref_atomic(TEXT, TEXT, TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_gate_ref_atomic(TEXT, TEXT, TEXT, TEXT, TEXT)
  TO service_role;

COMMENT ON FUNCTION public.consume_gate_ref_atomic(TEXT, TEXT, TEXT, TEXT, TEXT) IS
  'Atomically locks, validates, and consumes one exact-action Gate allow decision; refuses expiry, revocation, substitution, and replay.';

CREATE OR REPLACE FUNCTION public.revoke_commit_key_atomic(
  p_kid TEXT,
  p_reason TEXT,
  p_revoked_by TEXT
)
RETURNS SETOF public.revoked_commit_keys
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_revocation public.revoked_commit_keys%ROWTYPE;
BEGIN
  IF p_kid IS NULL OR pg_catalog.length(p_kid) = 0 OR
     p_revoked_by IS NULL OR pg_catalog.length(p_revoked_by) = 0 THEN
    RAISE EXCEPTION 'COMMIT_KEY_REVOCATION_ARGUMENT_MISSING' USING ERRCODE = 'P0001';
  END IF;

  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('ep-commit-kid:' || p_kid, 0)
  );

  INSERT INTO public.revoked_commit_keys (kid, reason, revoked_by, revoked_at)
  VALUES (p_kid, p_reason, p_revoked_by, pg_catalog.now())
  ON CONFLICT (kid) DO UPDATE
    SET reason = EXCLUDED.reason,
        revoked_by = EXCLUDED.revoked_by,
        revoked_at = LEAST(
          public.revoked_commit_keys.revoked_at,
          EXCLUDED.revoked_at
        )
  RETURNING * INTO v_revocation;

  RETURN NEXT v_revocation;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.revoke_commit_key_atomic(TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.revoke_commit_key_atomic(TEXT, TEXT, TEXT)
  TO service_role;

COMMENT ON FUNCTION public.revoke_commit_key_atomic(TEXT, TEXT, TEXT) IS
  'Records emergency commit-key revocation under the same advisory lock used by Gate consumption.';
