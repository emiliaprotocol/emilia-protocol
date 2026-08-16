-- SPDX-License-Identifier: Apache-2.0
-- Consent-first Authority Records for the flag-gated EMILIA Marketplace.
-- Private scans remain non-enumerable until repository control is proved and
-- the owner approves the exact current projection digest.

CREATE TABLE public.works_authority_records (
  record_id TEXT COLLATE "C" PRIMARY KEY
    CHECK (record_id ~ '^authority-record-[a-z0-9][a-z0-9-]{2,63}$'),
  repository_url TEXT COLLATE "C" NOT NULL
    CHECK (repository_url ~ '^https://github\.com/[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$'),
  contact_route TEXT COLLATE "C" NOT NULL
    CHECK (
      pg_catalog.octet_length(contact_route) BETWEEN 8 AND 600
      AND (contact_route ~ '^mailto:' OR contact_route ~ '^https://')
    ),
  created_by_entity_id UUID NOT NULL
    REFERENCES public.entities(id) ON DELETE RESTRICT,
  owner_token_digest TEXT COLLATE "C" UNIQUE
    CHECK (owner_token_digest IS NULL OR owner_token_digest ~ '^sha256:[0-9a-f]{64}$'),
  current_version INTEGER NOT NULL DEFAULT 1 CHECK (current_version >= 1),
  current_digest TEXT COLLATE "C" NOT NULL
    CHECK (current_digest ~ '^sha256:[0-9a-f]{64}$'),
  status TEXT COLLATE "C" NOT NULL DEFAULT 'PRIVATE_DRAFT'
    CHECK (status IN ('PRIVATE_DRAFT', 'CLAIMED_PRIVATE', 'PUBLISHED', 'WITHDRAWN')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  claimed_at TIMESTAMPTZ,
  approved_at TIMESTAMPTZ,
  withdrawn_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  CHECK (updated_at >= created_at),
  CHECK ((status = 'PRIVATE_DRAFT') = (owner_token_digest IS NULL)),
  CHECK ((status = 'PUBLISHED') = (approved_at IS NOT NULL)),
  CHECK ((status = 'WITHDRAWN') = (withdrawn_at IS NOT NULL))
);

CREATE TABLE public.works_authority_record_versions (
  record_id TEXT COLLATE "C" NOT NULL
    REFERENCES public.works_authority_records(record_id) ON DELETE RESTRICT,
  version INTEGER NOT NULL CHECK (version >= 1),
  record_digest TEXT COLLATE "C" NOT NULL UNIQUE
    CHECK (record_digest ~ '^sha256:[0-9a-f]{64}$'),
  projection JSONB NOT NULL CHECK (
    pg_catalog.jsonb_typeof(projection) = 'object'
    AND pg_catalog.pg_column_size(projection) <= 131072
    AND projection ->> '@version' = 'EMILIA-AUTHORITY-RECORD-v1'
    AND projection ->> 'record_id' = record_id
    AND projection ->> 'claim_boundary' =
      'versioned_public_authority_mapping_not_certification_not_safety_rating_not_complete_mediation'
    AND projection -> 'provenance' ->> 'resolved_revision' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
    AND projection -> 'provenance' ->> 'artifact_digest' ~ '^sha256:[0-9a-f]{64}$'
    AND projection -> 'provenance' -> 'scanner' ->> 'profile_digest' ~ '^sha256:[0-9a-f]{64}$'
  ),
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (record_id, version)
);

CREATE TABLE public.works_authority_invitations (
  invitation_token_digest TEXT COLLATE "C" PRIMARY KEY
    CHECK (invitation_token_digest ~ '^sha256:[0-9a-f]{64}$'),
  record_id TEXT COLLATE "C" NOT NULL UNIQUE
    REFERENCES public.works_authority_records(record_id) ON DELETE RESTRICT,
  claim_challenge TEXT COLLATE "C" NOT NULL UNIQUE
    CHECK (claim_challenge ~ '^claim_[A-Za-z0-9_-]{32,96}$'),
  invitation_expires_at TIMESTAMPTZ NOT NULL,
  claimed_at TIMESTAMPTZ,
  proof_url TEXT COLLATE "C",
  proof_revision TEXT COLLATE "C"
    CHECK (proof_revision IS NULL OR proof_revision ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
  proof_digest TEXT COLLATE "C" UNIQUE
    CHECK (proof_digest IS NULL OR proof_digest ~ '^sha256:[0-9a-f]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  CHECK (invitation_expires_at > created_at),
  CHECK (
    (claimed_at IS NULL AND proof_url IS NULL AND proof_revision IS NULL AND proof_digest IS NULL)
    OR
    (claimed_at IS NOT NULL AND proof_url IS NOT NULL AND proof_revision IS NOT NULL AND proof_digest IS NOT NULL)
  )
);

CREATE TABLE public.works_authority_events (
  event_sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  record_id TEXT COLLATE "C" NOT NULL
    REFERENCES public.works_authority_records(record_id) ON DELETE RESTRICT,
  event_type TEXT COLLATE "C" NOT NULL
    CHECK (event_type IN ('DRAFTED', 'CLAIMED', 'REVISED', 'PUBLISHED', 'WITHDRAWN')),
  version INTEGER NOT NULL CHECK (version >= 1),
  record_digest TEXT COLLATE "C" NOT NULL
    CHECK (record_digest ~ '^sha256:[0-9a-f]{64}$'),
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp()
);

CREATE INDEX works_authority_records_public_idx
  ON public.works_authority_records (approved_at DESC, record_id)
  WHERE status = 'PUBLISHED';
CREATE INDEX works_authority_events_record_idx
  ON public.works_authority_events (record_id, event_sequence);

-- Demand events do not use names or email addresses as the counting key. The
-- application stores a keyed digest and exact verified organization domain.
CREATE TABLE public.works_authority_demand_requests (
  request_id UUID PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
  record_id TEXT COLLATE "C" NOT NULL
    REFERENCES public.works_authority_records(record_id) ON DELETE RESTRICT,
  requester_digest TEXT COLLATE "C" NOT NULL
    CHECK (requester_digest ~ '^hmac-sha256:[0-9a-f]{64}$'),
  organization_domain TEXT COLLATE "C" NOT NULL
    CHECK (organization_domain ~ '^[a-z0-9.-]{3,253}$'),
  verification_token_digest TEXT COLLATE "C" NOT NULL UNIQUE
    CHECK (verification_token_digest ~ '^sha256:[0-9a-f]{64}$'),
  status TEXT COLLATE "C" NOT NULL DEFAULT 'PENDING'
    CHECK (status IN ('PENDING', 'VERIFIED', 'WITHDRAWN')),
  test_event BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  expires_at TIMESTAMPTZ NOT NULL,
  verified_at TIMESTAMPTZ,
  UNIQUE (record_id, requester_digest),
  CHECK (expires_at > created_at),
  CHECK ((status = 'VERIFIED') = (verified_at IS NOT NULL))
);

CREATE TABLE public.works_authority_entitlements (
  record_id TEXT COLLATE "C" PRIMARY KEY
    REFERENCES public.works_authority_records(record_id) ON DELETE RESTRICT,
  tier TEXT COLLATE "C" NOT NULL CHECK (tier IN ('FREE', 'MONITORED')),
  status TEXT COLLATE "C" NOT NULL
    CHECK (status IN ('ACTIVE', 'TRIALING', 'PAST_DUE', 'INACTIVE')),
  stripe_customer_id TEXT COLLATE "C",
  stripe_subscription_id TEXT COLLATE "C" UNIQUE,
  current_period_end TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp()
);

CREATE TABLE public.works_authority_stripe_events (
  stripe_event_id TEXT COLLATE "C" PRIMARY KEY
    CHECK (stripe_event_id ~ '^evt_[A-Za-z0-9_]{8,255}$'),
  event_type TEXT COLLATE "C" NOT NULL
    CHECK (pg_catalog.octet_length(event_type) BETWEEN 3 AND 120),
  record_id TEXT COLLATE "C" NOT NULL
    REFERENCES public.works_authority_records(record_id) ON DELETE RESTRICT,
  event_created_at TIMESTAMPTZ NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp()
);

ALTER TABLE public.works_authority_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.works_authority_records FORCE ROW LEVEL SECURITY;
ALTER TABLE public.works_authority_record_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.works_authority_record_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.works_authority_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.works_authority_invitations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.works_authority_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.works_authority_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.works_authority_demand_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.works_authority_demand_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE public.works_authority_entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.works_authority_entitlements FORCE ROW LEVEL SECURITY;
ALTER TABLE public.works_authority_stripe_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.works_authority_stripe_events FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.works_authority_records,
  public.works_authority_record_versions,
  public.works_authority_invitations,
  public.works_authority_events,
  public.works_authority_demand_requests,
  public.works_authority_entitlements,
  public.works_authority_stripe_events
  FROM PUBLIC, anon, authenticated, service_role;

CREATE FUNCTION public.works_authority_immutable_row()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $works_authority_immutable_row$
BEGIN
  RAISE EXCEPTION 'works authority history is immutable'
    USING ERRCODE = '55000';
END
$works_authority_immutable_row$;

CREATE TRIGGER works_authority_record_versions_immutable
  BEFORE UPDATE OR DELETE ON public.works_authority_record_versions
  FOR EACH ROW EXECUTE FUNCTION public.works_authority_immutable_row();
CREATE TRIGGER works_authority_events_immutable
  BEFORE UPDATE OR DELETE ON public.works_authority_events
  FOR EACH ROW EXECUTE FUNCTION public.works_authority_immutable_row();
CREATE TRIGGER works_authority_stripe_events_immutable
  BEFORE UPDATE OR DELETE ON public.works_authority_stripe_events
  FOR EACH ROW EXECUTE FUNCTION public.works_authority_immutable_row();

CREATE FUNCTION public.create_works_authority_record_draft(
  p_record_id TEXT,
  p_record_digest TEXT,
  p_projection JSONB,
  p_repository_url TEXT,
  p_contact_route TEXT,
  p_created_by_entity_id UUID,
  p_invitation_token_digest TEXT,
  p_claim_challenge TEXT,
  p_invitation_expires_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $create_works_authority_record_draft$
BEGIN
  IF p_record_id IS NULL
    OR p_record_id !~ '^authority-record-[a-z0-9][a-z0-9-]{2,63}$'
    OR p_record_digest IS NULL
    OR p_record_digest !~ '^sha256:[0-9a-f]{64}$'
    OR p_projection IS NULL
    OR p_projection ->> '@version' IS DISTINCT FROM 'EMILIA-AUTHORITY-RECORD-v1'
    OR p_projection ->> 'record_id' IS DISTINCT FROM p_record_id
    OR p_projection -> 'subject' ->> 'repository_url' IS DISTINCT FROM p_repository_url
    OR p_projection -> 'provenance' ->> 'source_locator' IS DISTINCT FROM p_repository_url
    OR p_invitation_token_digest IS NULL
    OR p_invitation_token_digest !~ '^sha256:[0-9a-f]{64}$'
    OR p_claim_challenge IS NULL
    OR p_claim_challenge !~ '^claim_[A-Za-z0-9_-]{32,96}$'
    OR p_invitation_expires_at <= pg_catalog.transaction_timestamp()
    OR p_invitation_expires_at > pg_catalog.transaction_timestamp() + INTERVAL '8 days'
  THEN
    RAISE EXCEPTION 'works authority draft input is invalid' USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.works_authority_records (
    record_id, repository_url, contact_route, created_by_entity_id, current_digest
  ) VALUES (
    p_record_id, p_repository_url, p_contact_route, p_created_by_entity_id, p_record_digest
  );
  INSERT INTO public.works_authority_record_versions (
    record_id, version, record_digest, projection, created_at
  ) VALUES (
    p_record_id, 1, p_record_digest, p_projection, pg_catalog.transaction_timestamp()
  );
  INSERT INTO public.works_authority_invitations (
    invitation_token_digest, record_id, claim_challenge, invitation_expires_at
  ) VALUES (
    p_invitation_token_digest, p_record_id, p_claim_challenge, p_invitation_expires_at
  );
  INSERT INTO public.works_authority_events (record_id, event_type, version, record_digest)
    VALUES (p_record_id, 'DRAFTED', 1, p_record_digest);
  RETURN pg_catalog.jsonb_build_object('record_id', p_record_id);
END
$create_works_authority_record_draft$;

CREATE FUNCTION public.inspect_works_authority_record_invitation(
  p_invitation_token_digest TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $inspect_works_authority_record_invitation$
DECLARE
  v_row RECORD;
BEGIN
  SELECT record.record_id, record.current_digest, version.projection,
    record.repository_url, record.contact_route, invitation.claim_challenge,
    invitation.invitation_expires_at, invitation.claimed_at
  INTO v_row
  FROM public.works_authority_invitations AS invitation
  JOIN public.works_authority_records AS record USING (record_id)
  JOIN public.works_authority_record_versions AS version
    ON version.record_id = record.record_id AND version.version = record.current_version
  WHERE invitation.invitation_token_digest = p_invitation_token_digest;
  IF NOT FOUND THEN RETURN NULL; END IF;
  RETURN pg_catalog.jsonb_build_object(
    'record_id', v_row.record_id,
    'record_digest', v_row.current_digest,
    'projection', v_row.projection,
    'repository_url', v_row.repository_url,
    'contact_route', v_row.contact_route,
    'claim_challenge', v_row.claim_challenge,
    'invitation_expires_at', v_row.invitation_expires_at,
    'claimed_at', v_row.claimed_at
  );
END
$inspect_works_authority_record_invitation$;

CREATE FUNCTION public.claim_works_authority_record(
  p_invitation_token_digest TEXT,
  p_owner_token_digest TEXT,
  p_proof_url TEXT,
  p_proof_revision TEXT,
  p_proof_digest TEXT,
  p_claimed_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $claim_works_authority_record$
DECLARE
  v_invitation public.works_authority_invitations%ROWTYPE;
  v_record public.works_authority_records%ROWTYPE;
  v_projection JSONB;
BEGIN
  IF p_owner_token_digest !~ '^sha256:[0-9a-f]{64}$'
    OR p_proof_revision !~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
    OR p_proof_digest !~ '^sha256:[0-9a-f]{64}$'
    OR p_claimed_at > pg_catalog.transaction_timestamp() + INTERVAL '5 minutes'
  THEN RAISE EXCEPTION 'works authority claim input is invalid' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO v_invitation
  FROM public.works_authority_invitations
  WHERE invitation_token_digest = p_invitation_token_digest
  FOR UPDATE;
  IF NOT FOUND OR v_invitation.claimed_at IS NOT NULL
    OR v_invitation.invitation_expires_at <= p_claimed_at
  THEN RAISE EXCEPTION 'works authority invitation unavailable' USING ERRCODE = 'AR001';
  END IF;
  SELECT * INTO v_record
  FROM public.works_authority_records
  WHERE record_id = v_invitation.record_id
  FOR UPDATE;
  IF NOT FOUND OR v_record.status IS DISTINCT FROM 'PRIVATE_DRAFT'
    OR v_record.owner_token_digest IS NOT NULL
  THEN RAISE EXCEPTION 'works authority invitation unavailable' USING ERRCODE = 'AR001';
  END IF;
  SELECT projection INTO v_projection
  FROM public.works_authority_record_versions
  WHERE record_id = v_record.record_id AND version = v_record.current_version;

  UPDATE public.works_authority_invitations SET
    claimed_at = p_claimed_at,
    proof_url = p_proof_url,
    proof_revision = p_proof_revision,
    proof_digest = p_proof_digest
  WHERE invitation_token_digest = p_invitation_token_digest;
  UPDATE public.works_authority_records SET
    owner_token_digest = p_owner_token_digest,
    status = 'CLAIMED_PRIVATE',
    claimed_at = p_claimed_at,
    updated_at = p_claimed_at
  WHERE record_id = v_record.record_id;
  INSERT INTO public.works_authority_events (record_id, event_type, version, record_digest, occurred_at)
    VALUES (v_record.record_id, 'CLAIMED', v_record.current_version, v_record.current_digest, p_claimed_at);
  RETURN pg_catalog.jsonb_build_object(
    'record_id', v_record.record_id,
    'current_version', v_record.current_version,
    'current_digest', v_record.current_digest,
    'current_projection', v_projection,
    'repository_url', v_record.repository_url,
    'status', 'CLAIMED_PRIVATE',
    'approved_at', NULL,
    'withdrawn_at', NULL
  );
END
$claim_works_authority_record$;

CREATE FUNCTION public.read_works_authority_record_owner(
  p_record_id TEXT,
  p_owner_token_digest TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $read_works_authority_record_owner$
DECLARE v_row RECORD;
BEGIN
  SELECT record.record_id, record.current_version, record.current_digest,
    version.projection, record.repository_url, record.status,
    record.approved_at, record.withdrawn_at
  INTO v_row
  FROM public.works_authority_records AS record
  JOIN public.works_authority_record_versions AS version
    ON version.record_id = record.record_id AND version.version = record.current_version
  WHERE record.record_id = p_record_id
    AND record.owner_token_digest = p_owner_token_digest;
  IF NOT FOUND THEN RETURN NULL; END IF;
  RETURN pg_catalog.jsonb_build_object(
    'record_id', v_row.record_id, 'current_version', v_row.current_version,
    'current_digest', v_row.current_digest, 'current_projection', v_row.projection,
    'repository_url', v_row.repository_url, 'status', v_row.status,
    'approved_at', v_row.approved_at, 'withdrawn_at', v_row.withdrawn_at
  );
END
$read_works_authority_record_owner$;

CREATE FUNCTION public.append_works_authority_record_version(
  p_record_id TEXT,
  p_owner_token_digest TEXT,
  p_record_digest TEXT,
  p_projection JSONB,
  p_created_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $append_works_authority_record_version$
DECLARE
  v_record public.works_authority_records%ROWTYPE;
  v_version INTEGER;
BEGIN
  SELECT * INTO v_record FROM public.works_authority_records
  WHERE record_id = p_record_id FOR UPDATE;
  IF NOT FOUND OR v_record.owner_token_digest IS DISTINCT FROM p_owner_token_digest
  THEN RAISE EXCEPTION 'works authority owner invalid' USING ERRCODE = 'AR002';
  END IF;
  IF p_record_digest !~ '^sha256:[0-9a-f]{64}$'
    OR p_record_digest = v_record.current_digest
    OR p_projection ->> 'record_id' IS DISTINCT FROM p_record_id
    OR p_projection -> 'subject' ->> 'repository_url' IS DISTINCT FROM v_record.repository_url
    OR p_projection -> 'provenance' ->> 'source_locator' IS DISTINCT FROM v_record.repository_url
  THEN RAISE EXCEPTION 'works authority revision invalid' USING ERRCODE = '22023';
  END IF;
  v_version := v_record.current_version + 1;
  INSERT INTO public.works_authority_record_versions (
    record_id, version, record_digest, projection, created_at
  ) VALUES (p_record_id, v_version, p_record_digest, p_projection, p_created_at);
  UPDATE public.works_authority_records SET
    current_version = v_version,
    current_digest = p_record_digest,
    status = 'CLAIMED_PRIVATE',
    approved_at = NULL,
    withdrawn_at = NULL,
    updated_at = p_created_at
  WHERE record_id = p_record_id;
  INSERT INTO public.works_authority_events (record_id, event_type, version, record_digest, occurred_at)
    VALUES (p_record_id, 'REVISED', v_version, p_record_digest, p_created_at);
  RETURN pg_catalog.jsonb_build_object(
    'record_id', p_record_id, 'current_version', v_version,
    'current_digest', p_record_digest, 'current_projection', p_projection,
    'repository_url', v_record.repository_url, 'status', 'CLAIMED_PRIVATE',
    'approved_at', NULL, 'withdrawn_at', NULL
  );
END
$append_works_authority_record_version$;

CREATE FUNCTION public.approve_works_authority_record_version(
  p_record_id TEXT,
  p_owner_token_digest TEXT,
  p_record_digest TEXT,
  p_approved_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $approve_works_authority_record_version$
DECLARE
  v_record public.works_authority_records%ROWTYPE;
  v_projection JSONB;
BEGIN
  SELECT * INTO v_record FROM public.works_authority_records
  WHERE record_id = p_record_id FOR UPDATE;
  IF NOT FOUND OR v_record.owner_token_digest IS DISTINCT FROM p_owner_token_digest
  THEN RAISE EXCEPTION 'works authority owner invalid' USING ERRCODE = 'AR002';
  END IF;
  IF v_record.current_digest IS DISTINCT FROM p_record_digest
  THEN RAISE EXCEPTION 'works authority digest mismatch' USING ERRCODE = 'AR003';
  END IF;
  SELECT projection INTO v_projection FROM public.works_authority_record_versions
    WHERE record_id = p_record_id AND version = v_record.current_version;
  IF v_record.status = 'PUBLISHED' THEN
    RETURN pg_catalog.jsonb_build_object(
      'record_id', p_record_id, 'current_version', v_record.current_version,
      'current_digest', v_record.current_digest, 'current_projection', v_projection,
      'repository_url', v_record.repository_url, 'status', v_record.status,
      'approved_at', v_record.approved_at, 'withdrawn_at', NULL
    );
  END IF;
  UPDATE public.works_authority_records SET
    status = 'PUBLISHED', approved_at = p_approved_at,
    withdrawn_at = NULL, updated_at = p_approved_at
  WHERE record_id = p_record_id;
  INSERT INTO public.works_authority_events (record_id, event_type, version, record_digest, occurred_at)
    VALUES (p_record_id, 'PUBLISHED', v_record.current_version, v_record.current_digest, p_approved_at);
  RETURN pg_catalog.jsonb_build_object(
    'record_id', p_record_id, 'current_version', v_record.current_version,
    'current_digest', v_record.current_digest, 'current_projection', v_projection,
    'repository_url', v_record.repository_url, 'status', 'PUBLISHED',
    'approved_at', p_approved_at, 'withdrawn_at', NULL
  );
END
$approve_works_authority_record_version$;

CREATE FUNCTION public.withdraw_works_authority_record(
  p_record_id TEXT,
  p_owner_token_digest TEXT,
  p_withdrawn_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $withdraw_works_authority_record$
DECLARE
  v_record public.works_authority_records%ROWTYPE;
  v_projection JSONB;
BEGIN
  SELECT * INTO v_record FROM public.works_authority_records
  WHERE record_id = p_record_id FOR UPDATE;
  IF NOT FOUND OR v_record.owner_token_digest IS DISTINCT FROM p_owner_token_digest
  THEN RAISE EXCEPTION 'works authority owner invalid' USING ERRCODE = 'AR002';
  END IF;
  SELECT projection INTO v_projection FROM public.works_authority_record_versions
    WHERE record_id = p_record_id AND version = v_record.current_version;
  IF v_record.status <> 'WITHDRAWN' THEN
    UPDATE public.works_authority_records SET
      status = 'WITHDRAWN', approved_at = NULL,
      withdrawn_at = p_withdrawn_at, updated_at = p_withdrawn_at
    WHERE record_id = p_record_id;
    INSERT INTO public.works_authority_events (record_id, event_type, version, record_digest, occurred_at)
      VALUES (p_record_id, 'WITHDRAWN', v_record.current_version, v_record.current_digest, p_withdrawn_at);
  END IF;
  RETURN pg_catalog.jsonb_build_object(
    'record_id', p_record_id, 'current_version', v_record.current_version,
    'current_digest', v_record.current_digest, 'current_projection', v_projection,
    'repository_url', v_record.repository_url, 'status', 'WITHDRAWN',
    'approved_at', NULL, 'withdrawn_at', COALESCE(v_record.withdrawn_at, p_withdrawn_at)
  );
END
$withdraw_works_authority_record$;

CREATE FUNCTION public.read_works_authority_record_public(p_record_id TEXT)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $read_works_authority_record_public$
DECLARE v_row RECORD;
BEGIN
  SELECT record.record_id, record.current_version, record.current_digest,
    record.approved_at, version.projection
  INTO v_row
  FROM public.works_authority_records AS record
  JOIN public.works_authority_record_versions AS version
    ON version.record_id = record.record_id AND version.version = record.current_version
  WHERE record.record_id = p_record_id
    AND record.status = 'PUBLISHED'
    AND (version.projection -> 'provenance' ->> 'expires_at')::TIMESTAMPTZ
      > pg_catalog.transaction_timestamp();
  IF NOT FOUND THEN RETURN NULL; END IF;
  RETURN pg_catalog.jsonb_build_object(
    'record_id', v_row.record_id, 'version', v_row.current_version,
    'record_digest', v_row.current_digest, 'approved_at', v_row.approved_at,
    'projection', v_row.projection
  );
END
$read_works_authority_record_public$;

CREATE FUNCTION public.list_works_authority_records_public()
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $list_works_authority_records_public$
  SELECT COALESCE(pg_catalog.jsonb_agg(
    pg_catalog.jsonb_build_object(
      'record_id', record.record_id, 'version', record.current_version,
      'record_digest', record.current_digest, 'approved_at', record.approved_at,
      'projection', version.projection
    ) ORDER BY record.approved_at DESC, record.record_id
  ), '[]'::JSONB)
  FROM public.works_authority_records AS record
  JOIN public.works_authority_record_versions AS version
    ON version.record_id = record.record_id AND version.version = record.current_version
  WHERE record.status = 'PUBLISHED'
    AND (version.projection -> 'provenance' ->> 'expires_at')::TIMESTAMPTZ
      > pg_catalog.transaction_timestamp()
$list_works_authority_records_public$;

CREATE FUNCTION public.create_works_authority_demand_request(
  p_record_id TEXT,
  p_requester_digest TEXT,
  p_organization_domain TEXT,
  p_verification_token_digest TEXT,
  p_verification_expires_at TIMESTAMPTZ,
  p_created_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $create_works_authority_demand_request$
DECLARE
  v_record_exists BOOLEAN;
  v_existing public.works_authority_demand_requests%ROWTYPE;
BEGIN
  IF p_requester_digest !~ '^hmac-sha256:[0-9a-f]{64}$'
    OR pg_catalog.octet_length(p_organization_domain) NOT BETWEEN 3 AND 253
    OR p_organization_domain !~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
    OR p_organization_domain = 'emiliaprotocol.ai'
    OR p_organization_domain LIKE '%.emiliaprotocol.ai'
    OR p_verification_token_digest !~ '^sha256:[0-9a-f]{64}$'
    OR p_verification_expires_at <= p_created_at
    OR p_verification_expires_at > p_created_at + INTERVAL '25 hours'
    OR p_created_at > pg_catalog.transaction_timestamp() + INTERVAL '5 minutes'
  THEN RAISE EXCEPTION 'works authority demand input is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT EXISTS (
    SELECT 1
    FROM public.works_authority_records AS record
    JOIN public.works_authority_record_versions AS version
      ON version.record_id = record.record_id AND version.version = record.current_version
    WHERE record.record_id = p_record_id
      AND record.status = 'PUBLISHED'
      AND (version.projection -> 'provenance' ->> 'expires_at')::TIMESTAMPTZ
        > pg_catalog.transaction_timestamp()
  ) INTO v_record_exists;
  IF NOT v_record_exists THEN
    RAISE EXCEPTION 'works authority record unavailable' USING ERRCODE = 'AR005';
  END IF;

  SELECT * INTO v_existing
  FROM public.works_authority_demand_requests
  WHERE record_id = p_record_id AND requester_digest = p_requester_digest
  FOR UPDATE;

  IF FOUND AND v_existing.status = 'VERIFIED' THEN
    RETURN pg_catalog.jsonb_build_object('status', 'ALREADY_VERIFIED');
  ELSIF FOUND THEN
    UPDATE public.works_authority_demand_requests SET
      organization_domain = p_organization_domain,
      verification_token_digest = p_verification_token_digest,
      status = 'PENDING', test_event = FALSE,
      created_at = p_created_at, expires_at = p_verification_expires_at,
      verified_at = NULL
    WHERE request_id = v_existing.request_id;
  ELSE
    INSERT INTO public.works_authority_demand_requests (
      record_id, requester_digest, organization_domain,
      verification_token_digest, created_at, expires_at
    ) VALUES (
      p_record_id, p_requester_digest, p_organization_domain,
      p_verification_token_digest, p_created_at, p_verification_expires_at
    );
  END IF;
  RETURN pg_catalog.jsonb_build_object('status', 'PENDING');
END
$create_works_authority_demand_request$;

CREATE FUNCTION public.verify_works_authority_demand_request(
  p_verification_token_digest TEXT,
  p_verified_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $verify_works_authority_demand_request$
DECLARE
  v_request public.works_authority_demand_requests%ROWTYPE;
  v_requesters INTEGER;
  v_organizations INTEGER;
BEGIN
  SELECT * INTO v_request
  FROM public.works_authority_demand_requests
  WHERE verification_token_digest = p_verification_token_digest
  FOR UPDATE;
  IF NOT FOUND OR v_request.status <> 'PENDING' OR v_request.expires_at <= p_verified_at THEN
    RAISE EXCEPTION 'works authority verification unavailable' USING ERRCODE = 'AR004';
  END IF;
  UPDATE public.works_authority_demand_requests SET
    status = 'VERIFIED', verified_at = p_verified_at
  WHERE request_id = v_request.request_id;

  SELECT pg_catalog.count(DISTINCT requester_digest),
    pg_catalog.count(DISTINCT organization_domain)
  INTO v_requesters, v_organizations
  FROM public.works_authority_demand_requests
  WHERE record_id = v_request.record_id
    AND status = 'VERIFIED' AND test_event = FALSE
    AND organization_domain <> 'emiliaprotocol.ai'
    AND organization_domain NOT LIKE '%.emiliaprotocol.ai';
  RETURN pg_catalog.jsonb_build_object(
    'record_id', v_request.record_id,
    'verified_requesters', v_requesters,
    'verified_organizations', v_organizations
  );
END
$verify_works_authority_demand_request$;

CREATE FUNCTION public.read_works_authority_demand_counts(p_record_id TEXT)
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $read_works_authority_demand_counts$
  SELECT CASE WHEN EXISTS (
    SELECT 1
    FROM public.works_authority_records AS record
    JOIN public.works_authority_record_versions AS version
      ON version.record_id = record.record_id AND version.version = record.current_version
    WHERE record.record_id = p_record_id AND record.status = 'PUBLISHED'
      AND (version.projection -> 'provenance' ->> 'expires_at')::TIMESTAMPTZ
        > pg_catalog.transaction_timestamp()
  ) THEN pg_catalog.jsonb_build_object(
    'verified_requesters', pg_catalog.count(DISTINCT requester_digest),
    'verified_organizations', pg_catalog.count(DISTINCT organization_domain)
  ) ELSE NULL END
  FROM public.works_authority_demand_requests
  WHERE record_id = p_record_id
    AND status = 'VERIFIED' AND test_event = FALSE
    AND organization_domain <> 'emiliaprotocol.ai'
    AND organization_domain NOT LIKE '%.emiliaprotocol.ai'
$read_works_authority_demand_counts$;

CREATE FUNCTION public.apply_works_authority_stripe_event(
  p_stripe_event_id TEXT,
  p_event_type TEXT,
  p_record_id TEXT,
  p_subscription_status TEXT,
  p_stripe_customer_id TEXT,
  p_stripe_subscription_id TEXT,
  p_current_period_end TIMESTAMPTZ,
  p_event_created_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $apply_works_authority_stripe_event$
DECLARE v_tier TEXT; v_status TEXT; v_entitlement public.works_authority_entitlements%ROWTYPE;
BEGIN
  IF p_stripe_event_id !~ '^evt_[A-Za-z0-9_]{8,255}$'
    OR p_event_type NOT IN (
      'checkout.session.completed', 'customer.subscription.created',
      'customer.subscription.updated', 'customer.subscription.deleted'
    )
    OR p_subscription_status NOT IN (
      'active', 'trialing', 'past_due', 'unpaid', 'canceled', 'incomplete', 'incomplete_expired'
    )
  THEN RAISE EXCEPTION 'works authority Stripe event invalid' USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.works_authority_stripe_events (
    stripe_event_id, event_type, record_id, event_created_at
  ) VALUES (p_stripe_event_id, p_event_type, p_record_id, p_event_created_at)
  ON CONFLICT (stripe_event_id) DO NOTHING;
  IF NOT FOUND THEN
    SELECT * INTO v_entitlement FROM public.works_authority_entitlements
      WHERE record_id = p_record_id;
    RETURN pg_catalog.to_jsonb(v_entitlement);
  END IF;
  SELECT * INTO v_entitlement
  FROM public.works_authority_entitlements
  WHERE record_id = p_record_id
  FOR UPDATE;
  IF FOUND
    AND p_event_type IN ('customer.subscription.updated', 'customer.subscription.deleted')
    AND v_entitlement.stripe_subscription_id IS DISTINCT FROM p_stripe_subscription_id
  THEN
    -- A delayed event for a superseded subscription cannot downgrade the
    -- record's current subscription. The signed event remains deduplicated.
    RETURN pg_catalog.to_jsonb(v_entitlement);
  END IF;
  v_tier := CASE WHEN p_subscription_status IN ('active', 'trialing', 'past_due')
    THEN 'MONITORED' ELSE 'FREE' END;
  v_status := CASE p_subscription_status
    WHEN 'active' THEN 'ACTIVE'
    WHEN 'trialing' THEN 'TRIALING'
    WHEN 'past_due' THEN 'PAST_DUE'
    ELSE 'INACTIVE' END;
  INSERT INTO public.works_authority_entitlements (
    record_id, tier, status, stripe_customer_id, stripe_subscription_id,
    current_period_end, updated_at
  ) VALUES (
    p_record_id, v_tier, v_status, p_stripe_customer_id,
    p_stripe_subscription_id, p_current_period_end, pg_catalog.transaction_timestamp()
  ) ON CONFLICT (record_id) DO UPDATE SET
    tier = EXCLUDED.tier, status = EXCLUDED.status,
    stripe_customer_id = EXCLUDED.stripe_customer_id,
    stripe_subscription_id = EXCLUDED.stripe_subscription_id,
    current_period_end = EXCLUDED.current_period_end,
    updated_at = EXCLUDED.updated_at;
  SELECT * INTO v_entitlement FROM public.works_authority_entitlements
    WHERE record_id = p_record_id;
  RETURN pg_catalog.to_jsonb(v_entitlement);
END
$apply_works_authority_stripe_event$;

CREATE FUNCTION public.read_works_authority_entitlement(p_record_id TEXT)
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $read_works_authority_entitlement$
  SELECT pg_catalog.to_jsonb(entitlement)
  FROM public.works_authority_entitlements AS entitlement
  WHERE entitlement.record_id = p_record_id
$read_works_authority_entitlement$;

CREATE FUNCTION public.reconcile_works_authority_entitlement(
  p_record_id TEXT,
  p_subscription_status TEXT,
  p_stripe_customer_id TEXT,
  p_stripe_subscription_id TEXT,
  p_current_period_end TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $reconcile_works_authority_entitlement$
DECLARE
  v_existing public.works_authority_entitlements%ROWTYPE;
  v_tier TEXT;
  v_status TEXT;
BEGIN
  IF p_subscription_status NOT IN (
    'active', 'trialing', 'past_due', 'unpaid', 'canceled', 'incomplete', 'incomplete_expired'
  ) OR p_stripe_customer_id !~ '^cus_[A-Za-z0-9_]{8,255}$'
    OR p_stripe_subscription_id !~ '^sub_[A-Za-z0-9_]{8,255}$'
  THEN RAISE EXCEPTION 'works authority entitlement reconciliation invalid' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO v_existing
  FROM public.works_authority_entitlements
  WHERE record_id = p_record_id
  FOR UPDATE;
  IF NOT FOUND OR v_existing.stripe_subscription_id IS DISTINCT FROM p_stripe_subscription_id THEN
    RAISE EXCEPTION 'works authority entitlement unavailable' USING ERRCODE = 'AR006';
  END IF;
  v_tier := CASE WHEN p_subscription_status IN ('active', 'trialing', 'past_due')
    THEN 'MONITORED' ELSE 'FREE' END;
  v_status := CASE p_subscription_status
    WHEN 'active' THEN 'ACTIVE'
    WHEN 'trialing' THEN 'TRIALING'
    WHEN 'past_due' THEN 'PAST_DUE'
    ELSE 'INACTIVE' END;
  UPDATE public.works_authority_entitlements SET
    tier = v_tier,
    status = v_status,
    stripe_customer_id = p_stripe_customer_id,
    current_period_end = p_current_period_end,
    updated_at = pg_catalog.transaction_timestamp()
  WHERE record_id = p_record_id;
  SELECT * INTO v_existing FROM public.works_authority_entitlements
    WHERE record_id = p_record_id;
  RETURN pg_catalog.to_jsonb(v_existing);
END
$reconcile_works_authority_entitlement$;

REVOKE ALL ON FUNCTION public.works_authority_immutable_row() FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.works_authority_immutable_row() TO service_role;

REVOKE ALL ON FUNCTION public.create_works_authority_record_draft(TEXT, TEXT, JSONB, TEXT, TEXT, UUID, TEXT, TEXT, TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.inspect_works_authority_record_invitation(TEXT)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.claim_works_authority_record(TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.read_works_authority_record_owner(TEXT, TEXT)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.append_works_authority_record_version(TEXT, TEXT, TEXT, JSONB, TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.approve_works_authority_record_version(TEXT, TEXT, TEXT, TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.withdraw_works_authority_record(TEXT, TEXT, TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.read_works_authority_record_public(TEXT)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.list_works_authority_records_public()
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.apply_works_authority_stripe_event(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.create_works_authority_demand_request(TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.verify_works_authority_demand_request(TEXT, TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.read_works_authority_demand_counts(TEXT)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.read_works_authority_entitlement(TEXT)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.reconcile_works_authority_entitlement(TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.create_works_authority_record_draft(TEXT, TEXT, JSONB, TEXT, TEXT, UUID, TEXT, TEXT, TIMESTAMPTZ) TO service_role;
GRANT EXECUTE ON FUNCTION public.inspect_works_authority_record_invitation(TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.claim_works_authority_record(TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ) TO service_role;
GRANT EXECUTE ON FUNCTION public.read_works_authority_record_owner(TEXT, TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.append_works_authority_record_version(TEXT, TEXT, TEXT, JSONB, TIMESTAMPTZ) TO service_role;
GRANT EXECUTE ON FUNCTION public.approve_works_authority_record_version(TEXT, TEXT, TEXT, TIMESTAMPTZ) TO service_role;
GRANT EXECUTE ON FUNCTION public.withdraw_works_authority_record(TEXT, TEXT, TIMESTAMPTZ) TO service_role;
GRANT EXECUTE ON FUNCTION public.read_works_authority_record_public(TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.list_works_authority_records_public() TO service_role;
GRANT EXECUTE ON FUNCTION public.apply_works_authority_stripe_event(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ) TO service_role;
GRANT EXECUTE ON FUNCTION public.create_works_authority_demand_request(TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ) TO service_role;
GRANT EXECUTE ON FUNCTION public.verify_works_authority_demand_request(TEXT, TIMESTAMPTZ) TO service_role;
GRANT EXECUTE ON FUNCTION public.read_works_authority_demand_counts(TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.read_works_authority_entitlement(TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.reconcile_works_authority_entitlement(TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ) TO service_role;

COMMENT ON TABLE public.works_authority_records IS
  'Consent-first Authority Record lifecycle; no private draft is public before exact-byte owner approval.';
