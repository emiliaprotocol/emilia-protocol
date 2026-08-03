-- SPDX-License-Identifier: Apache-2.0
-- Agent Adoption v1: public, server-mediated, no-egress demonstration custody.
--
-- This schema does not hold money, provider credentials, civil identity, an
-- approver or Class A credential, certification, marketplace state, or
-- production-execution authority. WebAuthn verification remains outside the
-- database transaction; these RPCs atomically store its bounded outputs.

DO $roles$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles
    WHERE rolname = 'agent_adoption_store_owner'
  ) THEN
    CREATE ROLE agent_adoption_store_owner NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$roles$;

DO $least_privilege_role$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = 'agent_adoption_store_owner'
      AND NOT role.rolcanlogin
      AND NOT role.rolsuper
      AND NOT role.rolcreatedb
      AND NOT role.rolcreaterole
      AND NOT role.rolreplication
      AND NOT role.rolbypassrls
  ) THEN
    RAISE EXCEPTION 'agent adoption owner must have least-privilege posture'
      USING ERRCODE = '42501';
  END IF;
END
$least_privilege_role$;

GRANT agent_adoption_store_owner TO CURRENT_USER
  WITH INHERIT FALSE, SET TRUE;
GRANT USAGE, CREATE ON SCHEMA public TO agent_adoption_store_owner;

CREATE SCHEMA agent_adoption_private
  AUTHORIZATION agent_adoption_store_owner;
REVOKE ALL ON SCHEMA agent_adoption_private
  FROM PUBLIC, anon, authenticated, service_role;

GRANT USAGE ON SCHEMA extensions TO agent_adoption_store_owner;
GRANT EXECUTE ON FUNCTION extensions.digest(BYTEA, TEXT)
  TO agent_adoption_store_owner;
GRANT EXECUTE ON FUNCTION extensions.gen_random_bytes(INTEGER)
  TO agent_adoption_store_owner;

SET ROLE agent_adoption_store_owner;

ALTER DEFAULT PRIVILEGES IN SCHEMA agent_adoption_private
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA agent_adoption_private
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE TABLE agent_adoption_private.adoption_sessions (
  tenant_id UUID NOT NULL,
  adoption_id UUID NOT NULL,
  session_token_hash TEXT COLLATE "C" NOT NULL UNIQUE
    CHECK (session_token_hash ~ '^[0-9a-f]{64}$'),
  agent_label TEXT COLLATE "C" NOT NULL
    CHECK (
      pg_catalog.octet_length(agent_label) BETWEEN 1 AND 80
      AND agent_label !~ '[[:cntrl:]]'
    ),
  candidate_digest TEXT COLLATE "C" NOT NULL
    CHECK (candidate_digest ~ '^sha256:[0-9a-f]{64}$'),
  bond_digest TEXT COLLATE "C" NOT NULL
    CHECK (bond_digest ~ '^sha256:[0-9a-f]{64}$'),
  operating_bond JSONB NOT NULL CHECK (
    pg_catalog.jsonb_typeof(operating_bond) = 'object'
    AND pg_catalog.pg_column_size(operating_bond) <= 32768
    AND operating_bond ->> '@version' = 'EP-OPERATING-BOND-v1'
    AND operating_bond ->> 'candidate_digest' = candidate_digest
    AND operating_bond -> 'candidate' ->> 'label' = agent_label
  ),
  public_projection JSONB NOT NULL CHECK (
    pg_catalog.jsonb_typeof(public_projection) = 'object'
    AND pg_catalog.pg_column_size(public_projection) <= 32768
    AND public_projection ->> '@version' = 'EP-OPERATING-BOND-PUBLIC-v1'
    AND public_projection ->> 'candidate_digest' = candidate_digest
    AND public_projection ->> 'bond_digest' = bond_digest
    AND public_projection -> 'candidate' ->> 'label' = agent_label
  ),
  scope TEXT COLLATE "C" NOT NULL DEFAULT 'synthetic_no_egress_demonstration'
    CHECK (scope = 'synthetic_no_egress_demonstration'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, adoption_id),
  UNIQUE (tenant_id, adoption_id, candidate_digest, bond_digest),
  CHECK (
    expires_at > created_at
    AND expires_at <= created_at + INTERVAL '30 days'
  )
);

CREATE TABLE agent_adoption_private.adoption_credentials (
  tenant_id UUID NOT NULL,
  adoption_id UUID NOT NULL,
  credential_id TEXT COLLATE "C" NOT NULL
    CHECK (
      pg_catalog.octet_length(credential_id) BETWEEN 1 AND 1024
      AND credential_id ~ '^[A-Za-z0-9_-]+$'
    ),
  public_key_cose TEXT COLLATE "C" NOT NULL
    CHECK (
      pg_catalog.octet_length(public_key_cose) BETWEEN 1 AND 1368
      AND public_key_cose ~ '^[A-Za-z0-9_-]+$'
    ),
  public_key_spki TEXT COLLATE "C" NOT NULL
    CHECK (
      pg_catalog.octet_length(public_key_spki) BETWEEN 1 AND 512
      AND public_key_spki ~ '^[A-Za-z0-9_-]+$'
    ),
  algorithm TEXT COLLATE "C" NOT NULL CHECK (algorithm = 'ES256'),
  curve TEXT COLLATE "C" NOT NULL CHECK (curve = 'P-256'),
  transports TEXT[],
  device_type TEXT COLLATE "C" NOT NULL
    CHECK (device_type IN ('singleDevice', 'multiDevice')),
  backed_up BOOLEAN NOT NULL,
  sign_count BIGINT NOT NULL CHECK (sign_count BETWEEN 0 AND 4294967295),
  counter_supported BOOLEAN NOT NULL,
  rp_id TEXT COLLATE "C" NOT NULL
    CHECK (pg_catalog.octet_length(rp_id) BETWEEN 1 AND 253),
  origin TEXT COLLATE "C" NOT NULL
    CHECK (pg_catalog.octet_length(origin) BETWEEN 1 AND 512),
  claim_boundary TEXT COLLATE "C" NOT NULL CHECK (
    claim_boundary = 'public_no_egress_agent_adoption_evidence_only_not_real_money_not_provider_credentials_not_civil_identity_not_certification_not_marketplace_not_production_execution'
  ),
  registration_digest TEXT COLLATE "C" NOT NULL
    CHECK (registration_digest ~ '^sha256:[0-9a-f]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  last_asserted_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, adoption_id, credential_id),
  UNIQUE (tenant_id, adoption_id),
  UNIQUE (tenant_id, adoption_id, registration_digest),
  FOREIGN KEY (tenant_id, adoption_id)
    REFERENCES agent_adoption_private.adoption_sessions (tenant_id, adoption_id)
    ON DELETE RESTRICT,
  CHECK (transports IS NULL OR pg_catalog.cardinality(transports) BETWEEN 0 AND 7),
  CHECK (counter_supported = (sign_count > 0)),
  CHECK (last_asserted_at IS NULL OR last_asserted_at >= created_at)
);

CREATE TABLE agent_adoption_private.adoption_challenges (
  tenant_id UUID NOT NULL,
  adoption_id UUID NOT NULL,
  challenge_id UUID NOT NULL,
  candidate_digest TEXT COLLATE "C" NOT NULL
    CHECK (candidate_digest ~ '^sha256:[0-9a-f]{64}$'),
  bond_digest TEXT COLLATE "C" NOT NULL
    CHECK (bond_digest ~ '^sha256:[0-9a-f]{64}$'),
  purpose TEXT COLLATE "C" NOT NULL CHECK (purpose IN ('registration', 'assertion')),
  credential_id TEXT COLLATE "C",
  nonce_hash TEXT COLLATE "C" NOT NULL UNIQUE
    CHECK (nonce_hash ~ '^[0-9a-f]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  completion_digest TEXT COLLATE "C"
    CHECK (
      completion_digest IS NULL
      OR completion_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
  PRIMARY KEY (tenant_id, adoption_id, challenge_id),
  FOREIGN KEY (tenant_id, adoption_id)
    REFERENCES agent_adoption_private.adoption_sessions (tenant_id, adoption_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, adoption_id, candidate_digest, bond_digest)
    REFERENCES agent_adoption_private.adoption_sessions (
      tenant_id, adoption_id, candidate_digest, bond_digest
    ) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, adoption_id, credential_id)
    REFERENCES agent_adoption_private.adoption_credentials (tenant_id, adoption_id, credential_id)
    ON DELETE RESTRICT,
  CHECK (
    (purpose = 'registration' AND credential_id IS NULL)
    OR (purpose = 'assertion' AND credential_id IS NOT NULL)
  ),
  CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '10 minutes'),
  CHECK ((consumed_at IS NULL) = (completion_digest IS NULL)),
  CHECK (consumed_at IS NULL OR consumed_at <= expires_at)
);

CREATE TABLE agent_adoption_private.operating_bonds (
  tenant_id UUID NOT NULL,
  adoption_id UUID NOT NULL,
  bond_id UUID NOT NULL,
  candidate_digest TEXT COLLATE "C" NOT NULL
    CHECK (candidate_digest ~ '^sha256:[0-9a-f]{64}$'),
  bond_digest TEXT COLLATE "C" NOT NULL
    CHECK (bond_digest ~ '^sha256:[0-9a-f]{64}$'),
  operating_bond JSONB NOT NULL CHECK (
    pg_catalog.jsonb_typeof(operating_bond) = 'object'
    AND pg_catalog.pg_column_size(operating_bond) <= 32768
    AND operating_bond ->> '@version' = 'EP-OPERATING-BOND-v1'
    AND operating_bond ->> 'candidate_digest' = candidate_digest
  ),
  public_projection JSONB NOT NULL CHECK (
    pg_catalog.jsonb_typeof(public_projection) = 'object'
    AND pg_catalog.pg_column_size(public_projection) <= 32768
    AND public_projection ->> '@version' = 'EP-OPERATING-BOND-PUBLIC-v1'
    AND public_projection ->> 'candidate_digest' = candidate_digest
    AND public_projection ->> 'bond_digest' = bond_digest
  ),
  credential_id TEXT COLLATE "C" NOT NULL,
  challenge_id UUID NOT NULL,
  assertion_digest TEXT COLLATE "C" NOT NULL
    CHECK (assertion_digest ~ '^sha256:[0-9a-f]{64}$'),
  counter_before BIGINT NOT NULL CHECK (counter_before >= 0),
  counter_after BIGINT NOT NULL CHECK (counter_after >= 0),
  assertion_event_hash TEXT COLLATE "C" NOT NULL
    CHECK (assertion_event_hash ~ '^sha256:[0-9a-f]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  PRIMARY KEY (tenant_id, adoption_id, bond_id),
  UNIQUE (tenant_id, adoption_id),
  UNIQUE (tenant_id, adoption_id, challenge_id),
  UNIQUE (tenant_id, adoption_id, bond_digest),
  UNIQUE (tenant_id, adoption_id, bond_id, bond_digest),
  FOREIGN KEY (tenant_id, adoption_id)
    REFERENCES agent_adoption_private.adoption_sessions (tenant_id, adoption_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, adoption_id, candidate_digest, bond_digest)
    REFERENCES agent_adoption_private.adoption_sessions (
      tenant_id, adoption_id, candidate_digest, bond_digest
    ) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, adoption_id, credential_id)
    REFERENCES agent_adoption_private.adoption_credentials (tenant_id, adoption_id, credential_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, adoption_id, challenge_id)
    REFERENCES agent_adoption_private.adoption_challenges (tenant_id, adoption_id, challenge_id)
    ON DELETE RESTRICT,
  CHECK (
    (counter_before = 0 AND counter_after = 0)
    OR counter_after > counter_before
  )
);

CREATE TABLE agent_adoption_private.adoption_events (
  tenant_id UUID NOT NULL,
  adoption_id UUID NOT NULL,
  event_sequence BIGINT NOT NULL CHECK (event_sequence >= 0),
  event_type TEXT COLLATE "C" NOT NULL CHECK (event_type IN (
    'session_created',
    'credential_registered',
    'agent_assertion_completed',
    'adoption_revoked',
    'share_published',
    'share_revoked'
  )),
  event_data JSONB NOT NULL CHECK (
    pg_catalog.jsonb_typeof(event_data) = 'object'
    AND pg_catalog.pg_column_size(event_data) <= 16384
  ),
  previous_event_hash TEXT COLLATE "C"
    CHECK (
      previous_event_hash IS NULL
      OR previous_event_hash ~ '^sha256:[0-9a-f]{64}$'
    ),
  event_hash TEXT COLLATE "C" NOT NULL
    CHECK (event_hash ~ '^sha256:[0-9a-f]{64}$'),
  recorded_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, adoption_id, event_sequence),
  UNIQUE (tenant_id, adoption_id, event_hash),
  FOREIGN KEY (tenant_id, adoption_id)
    REFERENCES agent_adoption_private.adoption_sessions (tenant_id, adoption_id)
    ON DELETE RESTRICT,
  CHECK ((event_sequence = 0 AND previous_event_hash IS NULL)
    OR (event_sequence > 0 AND previous_event_hash IS NOT NULL))
);

CREATE TABLE agent_adoption_private.adoption_revocations (
  tenant_id UUID NOT NULL,
  adoption_id UUID NOT NULL,
  revocation_id UUID NOT NULL,
  revocation_nonce_hash TEXT COLLATE "C" NOT NULL UNIQUE
    CHECK (revocation_nonce_hash ~ '^[0-9a-f]{64}$'),
  reason TEXT COLLATE "C" NOT NULL CHECK (
    pg_catalog.octet_length(reason) BETWEEN 1 AND 280
    AND reason !~ '[[:cntrl:]]'
  ),
  revoked_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  PRIMARY KEY (tenant_id, adoption_id),
  UNIQUE (tenant_id, adoption_id, revocation_id),
  FOREIGN KEY (tenant_id, adoption_id)
    REFERENCES agent_adoption_private.adoption_sessions (tenant_id, adoption_id)
    ON DELETE RESTRICT
);

CREATE TABLE agent_adoption_private.public_shares (
  tenant_id UUID NOT NULL,
  adoption_id UUID NOT NULL,
  share_id TEXT COLLATE "C" NOT NULL
    CHECK (share_id ~ '^agent_share_[0-9a-f]{40}$'),
  bond_id UUID NOT NULL,
  bond_digest TEXT COLLATE "C" NOT NULL
    CHECK (bond_digest ~ '^sha256:[0-9a-f]{64}$'),
  public_projection JSONB NOT NULL CHECK (
    pg_catalog.jsonb_typeof(public_projection) = 'object'
    AND pg_catalog.pg_column_size(public_projection) <= 65536
    AND public_projection ->> '@version' = 'EP-OPERATING-BOND-PUBLIC-v1'
    AND public_projection ->> 'bond_digest' = bond_digest
  ),
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  PRIMARY KEY (tenant_id, adoption_id, share_id),
  UNIQUE (tenant_id, adoption_id, bond_id),
  FOREIGN KEY (tenant_id, adoption_id)
    REFERENCES agent_adoption_private.adoption_sessions (tenant_id, adoption_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, adoption_id, bond_id, bond_digest)
    REFERENCES agent_adoption_private.operating_bonds (
      tenant_id, adoption_id, bond_id, bond_digest
    )
    ON DELETE RESTRICT
);

CREATE TABLE agent_adoption_private.share_revocations (
  tenant_id UUID NOT NULL,
  adoption_id UUID NOT NULL,
  share_id TEXT COLLATE "C" NOT NULL,
  revocation_id UUID NOT NULL,
  revocation_nonce_hash TEXT COLLATE "C" NOT NULL UNIQUE
    CHECK (revocation_nonce_hash ~ '^[0-9a-f]{64}$'),
  reason TEXT COLLATE "C" NOT NULL CHECK (
    pg_catalog.octet_length(reason) BETWEEN 1 AND 280
    AND reason !~ '[[:cntrl:]]'
  ),
  revoked_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  PRIMARY KEY (tenant_id, adoption_id, share_id),
  UNIQUE (tenant_id, adoption_id, revocation_id),
  FOREIGN KEY (tenant_id, adoption_id, share_id)
    REFERENCES agent_adoption_private.public_shares (tenant_id, adoption_id, share_id)
    ON DELETE RESTRICT
);

CREATE INDEX agent_adoption_sessions_tenant_created_idx
  ON agent_adoption_private.adoption_sessions
  (tenant_id, created_at, adoption_id);
CREATE INDEX agent_adoption_credentials_tenant_created_idx
  ON agent_adoption_private.adoption_credentials
  (tenant_id, adoption_id, created_at, credential_id);
CREATE INDEX agent_adoption_challenges_pending_idx
  ON agent_adoption_private.adoption_challenges
  (tenant_id, adoption_id, purpose, consumed_at, expires_at, challenge_id);
CREATE INDEX agent_adoption_bonds_tenant_created_idx
  ON agent_adoption_private.operating_bonds
  (tenant_id, adoption_id, created_at, bond_id);
CREATE INDEX agent_adoption_events_tenant_sequence_idx
  ON agent_adoption_private.adoption_events
  (tenant_id, adoption_id, event_sequence);
CREATE INDEX agent_adoption_revocations_tenant_time_idx
  ON agent_adoption_private.adoption_revocations
  (tenant_id, revoked_at, adoption_id);
CREATE INDEX agent_adoption_shares_tenant_created_idx
  ON agent_adoption_private.public_shares
  (tenant_id, adoption_id, created_at, share_id);
CREATE INDEX agent_adoption_share_revocations_tenant_time_idx
  ON agent_adoption_private.share_revocations
  (tenant_id, adoption_id, revoked_at, share_id);
CREATE UNIQUE INDEX agent_adoption_public_share_lookup_idx
  ON agent_adoption_private.public_shares (share_id);

ALTER TABLE agent_adoption_private.adoption_sessions
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_adoption_private.adoption_sessions
  FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_adoption_private.adoption_credentials
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_adoption_private.adoption_credentials
  FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_adoption_private.adoption_challenges
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_adoption_private.adoption_challenges
  FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_adoption_private.operating_bonds
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_adoption_private.operating_bonds
  FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_adoption_private.adoption_events
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_adoption_private.adoption_events
  FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_adoption_private.adoption_revocations
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_adoption_private.adoption_revocations
  FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_adoption_private.public_shares
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_adoption_private.public_shares
  FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_adoption_private.share_revocations
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_adoption_private.share_revocations
  FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_adoption_sessions_owner_only
  ON agent_adoption_private.adoption_sessions
  TO agent_adoption_store_owner USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY agent_adoption_credentials_owner_only
  ON agent_adoption_private.adoption_credentials
  TO agent_adoption_store_owner USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY agent_adoption_challenges_owner_only
  ON agent_adoption_private.adoption_challenges
  TO agent_adoption_store_owner USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY agent_adoption_bonds_owner_only
  ON agent_adoption_private.operating_bonds
  TO agent_adoption_store_owner USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY agent_adoption_events_owner_only
  ON agent_adoption_private.adoption_events
  TO agent_adoption_store_owner USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY agent_adoption_revocations_owner_only
  ON agent_adoption_private.adoption_revocations
  TO agent_adoption_store_owner USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY agent_adoption_shares_owner_only
  ON agent_adoption_private.public_shares
  TO agent_adoption_store_owner USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY agent_adoption_share_revocations_owner_only
  ON agent_adoption_private.share_revocations
  TO agent_adoption_store_owner USING (TRUE) WITH CHECK (TRUE);

REVOKE ALL ON TABLE agent_adoption_private.adoption_sessions
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE agent_adoption_private.adoption_credentials
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE agent_adoption_private.adoption_challenges
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE agent_adoption_private.operating_bonds
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE agent_adoption_private.adoption_events
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE agent_adoption_private.adoption_revocations
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE agent_adoption_private.public_shares
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE agent_adoption_private.share_revocations
  FROM PUBLIC, anon, authenticated, service_role;

CREATE FUNCTION agent_adoption_private.token_hash(p_token TEXT)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
SECURITY DEFINER
SET search_path = ''
AS $token_hash$
  SELECT pg_catalog.encode(
    extensions.digest(pg_catalog.convert_to(p_token, 'UTF8'), 'sha256'),
    'hex'
  );
$token_hash$;

CREATE FUNCTION agent_adoption_private.sha256_json(
  p_domain TEXT,
  p_value JSONB
)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
SECURITY DEFINER
SET search_path = ''
AS $sha256_json$
  SELECT 'sha256:' || pg_catalog.encode(
    extensions.digest(
      pg_catalog.convert_to(p_domain, 'UTF8')
        || pg_catalog.decode('00', 'hex')
        || pg_catalog.convert_to(p_value::TEXT, 'UTF8'),
      'sha256'
    ),
    'hex'
  );
$sha256_json$;

CREATE FUNCTION agent_adoption_private.iso_ms(p_value TIMESTAMPTZ)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
SECURITY DEFINER
SET search_path = ''
AS $iso_ms$
  SELECT pg_catalog.to_char(
    p_value AT TIME ZONE 'UTC',
    'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
  );
$iso_ms$;

CREATE FUNCTION agent_adoption_private.reject_immutable_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $immutable_guard$
BEGIN
  IF TG_OP = 'DELETE'
    AND CURRENT_USER = 'agent_adoption_store_owner'
    AND pg_catalog.current_setting('app.agent_adoption_retention_purge', TRUE) = 'v1'
  THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION '% rows are immutable and append-only', TG_TABLE_NAME
    USING ERRCODE = '55000';
END
$immutable_guard$;

CREATE FUNCTION agent_adoption_private.adoption_credential_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $credential_guard$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF CURRENT_USER = 'agent_adoption_store_owner'
      AND pg_catalog.current_setting('app.agent_adoption_retention_purge', TRUE) = 'v1'
    THEN
      RETURN OLD;
    END IF;
    RAISE EXCEPTION 'adoption credential rows cannot be deleted'
      USING ERRCODE = '55000';
  END IF;
  IF (
    pg_catalog.to_jsonb(OLD)
      - 'device_type' - 'backed_up' - 'sign_count'
      - 'counter_supported' - 'last_asserted_at'
  ) IS DISTINCT FROM (
    pg_catalog.to_jsonb(NEW)
      - 'device_type' - 'backed_up' - 'sign_count'
      - 'counter_supported' - 'last_asserted_at'
  ) THEN
    RAISE EXCEPTION 'adoption credential registration fields are immutable'
      USING ERRCODE = '55000';
  END IF;
  IF NOT (
    (OLD.sign_count = 0 AND NEW.sign_count = 0)
    OR NEW.sign_count > OLD.sign_count
  ) THEN
    RAISE EXCEPTION 'credential counter must remain 0/0 or strictly advance'
      USING ERRCODE = '22023';
  END IF;
  IF NEW.counter_supported IS DISTINCT FROM (NEW.sign_count > 0) THEN
    RAISE EXCEPTION 'credential counter support metadata is inconsistent'
      USING ERRCODE = '22023';
  END IF;
  IF NEW.last_asserted_at IS NULL
    OR NEW.last_asserted_at < OLD.created_at
    OR (
      OLD.last_asserted_at IS NOT NULL
      AND NEW.last_asserted_at < OLD.last_asserted_at
    )
  THEN
    RAISE EXCEPTION 'credential assertion time must advance monotonically'
      USING ERRCODE = '22023';
  END IF;
  RETURN NEW;
END
$credential_guard$;

CREATE FUNCTION agent_adoption_private.adoption_challenge_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $challenge_guard$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF CURRENT_USER = 'agent_adoption_store_owner'
      AND pg_catalog.current_setting('app.agent_adoption_retention_purge', TRUE) = 'v1'
    THEN
      RETURN OLD;
    END IF;
    RAISE EXCEPTION 'adoption challenge rows cannot be deleted'
      USING ERRCODE = '55000';
  END IF;
  IF NOT (
    OLD.consumed_at IS NULL
    AND NEW.consumed_at IS NOT NULL
    AND OLD.completion_digest IS NULL
    AND NEW.completion_digest IS NOT NULL
    AND (
      pg_catalog.to_jsonb(OLD) - 'consumed_at' - 'completion_digest'
    ) IS NOT DISTINCT FROM (
      pg_catalog.to_jsonb(NEW) - 'consumed_at' - 'completion_digest'
    )
  ) THEN
    RAISE EXCEPTION 'challenge permits exactly one unconsumed-to-consumed transition'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END
$challenge_guard$;

CREATE TRIGGER agent_adoption_sessions_immutable
BEFORE UPDATE OR DELETE
ON agent_adoption_private.adoption_sessions
FOR EACH ROW
EXECUTE FUNCTION agent_adoption_private.reject_immutable_mutation();
CREATE TRIGGER agent_adoption_sessions_no_truncate
BEFORE TRUNCATE
ON agent_adoption_private.adoption_sessions
FOR EACH STATEMENT
EXECUTE FUNCTION agent_adoption_private.reject_immutable_mutation();

CREATE TRIGGER agent_adoption_credentials_guard
BEFORE UPDATE OR DELETE
ON agent_adoption_private.adoption_credentials
FOR EACH ROW
EXECUTE FUNCTION agent_adoption_private.adoption_credential_guard();
CREATE TRIGGER agent_adoption_credentials_no_truncate
BEFORE TRUNCATE
ON agent_adoption_private.adoption_credentials
FOR EACH STATEMENT
EXECUTE FUNCTION agent_adoption_private.reject_immutable_mutation();

CREATE TRIGGER agent_adoption_challenges_guard
BEFORE UPDATE OR DELETE
ON agent_adoption_private.adoption_challenges
FOR EACH ROW
EXECUTE FUNCTION agent_adoption_private.adoption_challenge_guard();
CREATE TRIGGER agent_adoption_challenges_no_truncate
BEFORE TRUNCATE
ON agent_adoption_private.adoption_challenges
FOR EACH STATEMENT
EXECUTE FUNCTION agent_adoption_private.reject_immutable_mutation();

CREATE TRIGGER agent_adoption_bonds_immutable
BEFORE UPDATE OR DELETE
ON agent_adoption_private.operating_bonds
FOR EACH ROW
EXECUTE FUNCTION agent_adoption_private.reject_immutable_mutation();
CREATE TRIGGER agent_adoption_bonds_no_truncate
BEFORE TRUNCATE
ON agent_adoption_private.operating_bonds
FOR EACH STATEMENT
EXECUTE FUNCTION agent_adoption_private.reject_immutable_mutation();

CREATE TRIGGER agent_adoption_events_append_only
BEFORE UPDATE OR DELETE
ON agent_adoption_private.adoption_events
FOR EACH ROW
EXECUTE FUNCTION agent_adoption_private.reject_immutable_mutation();
CREATE TRIGGER agent_adoption_events_no_truncate
BEFORE TRUNCATE
ON agent_adoption_private.adoption_events
FOR EACH STATEMENT
EXECUTE FUNCTION agent_adoption_private.reject_immutable_mutation();

CREATE TRIGGER agent_adoption_revocations_terminal
BEFORE UPDATE OR DELETE
ON agent_adoption_private.adoption_revocations
FOR EACH ROW
EXECUTE FUNCTION agent_adoption_private.reject_immutable_mutation();
CREATE TRIGGER agent_adoption_revocations_no_truncate
BEFORE TRUNCATE
ON agent_adoption_private.adoption_revocations
FOR EACH STATEMENT
EXECUTE FUNCTION agent_adoption_private.reject_immutable_mutation();

CREATE TRIGGER agent_adoption_public_shares_immutable
BEFORE UPDATE OR DELETE
ON agent_adoption_private.public_shares
FOR EACH ROW
EXECUTE FUNCTION agent_adoption_private.reject_immutable_mutation();
CREATE TRIGGER agent_adoption_public_shares_no_truncate
BEFORE TRUNCATE
ON agent_adoption_private.public_shares
FOR EACH STATEMENT
EXECUTE FUNCTION agent_adoption_private.reject_immutable_mutation();

CREATE TRIGGER agent_adoption_share_revocations_append_only
BEFORE UPDATE OR DELETE
ON agent_adoption_private.share_revocations
FOR EACH ROW
EXECUTE FUNCTION agent_adoption_private.reject_immutable_mutation();
CREATE TRIGGER agent_adoption_share_revocations_no_truncate
BEFORE TRUNCATE
ON agent_adoption_private.share_revocations
FOR EACH STATEMENT
EXECUTE FUNCTION agent_adoption_private.reject_immutable_mutation();

CREATE FUNCTION agent_adoption_private.append_event(
  p_tenant_id UUID,
  p_adoption_id UUID,
  p_event_type TEXT,
  p_event_data JSONB
)
RETURNS TEXT
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $append_event$
DECLARE
  v_locked_tenant UUID;
  v_sequence BIGINT;
  v_previous_hash TEXT;
  v_event_hash TEXT;
  v_recorded_at TIMESTAMPTZ;
  v_envelope JSONB;
BEGIN
  IF p_event_type NOT IN (
    'session_created',
    'credential_registered',
    'agent_assertion_completed',
    'adoption_revoked',
    'share_published',
    'share_revoked'
  ) OR p_event_data IS NULL
    OR pg_catalog.jsonb_typeof(p_event_data) IS DISTINCT FROM 'object'
    OR pg_catalog.pg_column_size(p_event_data) > 16384
  THEN
    RAISE EXCEPTION 'adoption event input is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT session.tenant_id
  INTO v_locked_tenant
  FROM agent_adoption_private.adoption_sessions AS session
  WHERE session.tenant_id = p_tenant_id
    AND session.adoption_id = p_adoption_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'agent adoption session not found'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT event.event_sequence, event.event_hash
  INTO v_sequence, v_previous_hash
  FROM agent_adoption_private.adoption_events AS event
  WHERE event.tenant_id = p_tenant_id
    AND event.adoption_id = p_adoption_id
  ORDER BY event.event_sequence DESC
  LIMIT 1;

  IF FOUND THEN
    v_sequence := v_sequence + 1;
  ELSE
    v_sequence := 0;
    v_previous_hash := NULL;
  END IF;
  v_recorded_at := pg_catalog.transaction_timestamp();
  v_envelope := pg_catalog.jsonb_build_object(
    'tenant_id', p_tenant_id::TEXT,
    'adoption_id', p_adoption_id::TEXT,
    'event_sequence', v_sequence,
    'event_type', p_event_type,
    'event_data', p_event_data,
    'previous_event_hash', v_previous_hash,
    'recorded_at', pg_catalog.to_char(
      v_recorded_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
    )
  );
  v_event_hash := agent_adoption_private.sha256_json(
    'EMILIA-AGENT-ADOPTION-EVENT-V1',
    v_envelope
  );

  INSERT INTO agent_adoption_private.adoption_events (
    tenant_id,
    adoption_id,
    event_sequence,
    event_type,
    event_data,
    previous_event_hash,
    event_hash,
    recorded_at
  ) VALUES (
    p_tenant_id, p_adoption_id, v_sequence, p_event_type, p_event_data,
    v_previous_hash, v_event_hash, v_recorded_at
  );
  RETURN v_event_hash;
END
$append_event$;

CREATE FUNCTION public.create_agent_adoption_session(
  p_agent_label TEXT,
  p_candidate_digest TEXT,
  p_bond_digest TEXT,
  p_operating_bond JSONB,
  p_public_projection JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $create_session$
DECLARE
  v_tenant_id UUID;
  v_adoption_id UUID;
  v_session_token TEXT;
  v_claim_boundaries JSONB;
  v_expected_job JSONB;
  v_expected_allowance JSONB;
  v_expected_constraints JSONB;
  v_expected_limits JSONB;
  v_job_display_name TEXT;
  v_job_action_type TEXT;
  v_job_target TEXT;
  v_allowance_total INTEGER;
  v_allowance_max_per_action INTEGER;
  v_created_at TIMESTAMPTZ;
  v_expires_at TIMESTAMPTZ;
BEGIN
  IF p_agent_label IS NULL
    OR p_agent_label IS DISTINCT FROM pg_catalog.btrim(p_agent_label)
    OR pg_catalog.octet_length(p_agent_label) NOT BETWEEN 1 AND 80
    OR p_agent_label ~ '[[:cntrl:]]'
    OR p_candidate_digest IS NULL
    OR p_candidate_digest !~ '^sha256:[0-9a-f]{64}$'
    OR p_bond_digest IS NULL
    OR p_bond_digest !~ '^sha256:[0-9a-f]{64}$'
    OR p_operating_bond IS NULL
    OR pg_catalog.jsonb_typeof(p_operating_bond) IS DISTINCT FROM 'object'
    OR pg_catalog.pg_column_size(p_operating_bond) > 32768
    OR p_public_projection IS NULL
    OR pg_catalog.jsonb_typeof(p_public_projection) IS DISTINCT FROM 'object'
    OR pg_catalog.pg_column_size(p_public_projection) > 32768
  THEN
    RAISE EXCEPTION 'agent adoption session input is invalid or unbounded'
      USING ERRCODE = '22023';
  END IF;

  v_claim_boundaries := pg_catalog.jsonb_build_object(
    'scope', 'synthetic_no_egress_demonstration',
    'real_money', 'not_used_or_represented',
    'provider_credentials', 'not_collected_or_used',
    'civil_identity', 'not_verified_or_claimed',
    'certification', 'not_issued_or_claimed',
    'marketplace', 'not_offered_or_claimed',
    'production_execution', 'not_authorized_or_claimed',
    'source_metadata', 'url_is_metadata_only_never_fetched'
  );
  CASE p_operating_bond -> 'candidate' ->> 'job_template_id'
    WHEN 'job_vendor_intake_v1' THEN
      v_job_display_name := 'Vendor intake';
      v_job_action_type := 'agent-adoption.synthetic.vendor-intake.1';
      v_job_target := 'vendor.demo';
    WHEN 'job_compute_batch_v1' THEN
      v_job_display_name := 'Batch compute request';
      v_job_action_type := 'agent-adoption.synthetic.compute-allocate.1';
      v_job_target := 'compute.batch';
    WHEN 'job_document_route_v1' THEN
      v_job_display_name := 'Document routing';
      v_job_action_type := 'agent-adoption.synthetic.document-route.1';
      v_job_target := 'documents.demo';
    ELSE
      NULL;
  END CASE;
  CASE p_operating_bond -> 'candidate' ->> 'allowance_template_id'
    WHEN 'allowance_cautious_v1' THEN
      v_allowance_total := 200;
      v_allowance_max_per_action := 40;
    WHEN 'allowance_balanced_v1' THEN
      v_allowance_total := 500;
      v_allowance_max_per_action := 100;
    WHEN 'allowance_stretch_v1' THEN
      v_allowance_total := 1000;
      v_allowance_max_per_action := 250;
    ELSE
      NULL;
  END CASE;
  v_expected_job := pg_catalog.jsonb_build_object(
    '@version', 'EP-AGENT-ADOPTION-JOB-TEMPLATE-v1',
    'template_id', p_operating_bond -> 'candidate' ->> 'job_template_id',
    'display_name', v_job_display_name,
    'environment', 'synthetic',
    'network_egress', 'forbidden',
    'external_side_effects', 'forbidden',
    'allowed_action_types', pg_catalog.jsonb_build_array(v_job_action_type),
    'allowed_targets', pg_catalog.jsonb_build_array(v_job_target),
    'max_actions', 5,
    'max_concurrency', 1
  );
  v_expected_allowance := pg_catalog.jsonb_build_object(
    '@version', 'EP-AGENT-ADOPTION-ALLOWANCE-TEMPLATE-v1',
    'template_id', p_operating_bond -> 'candidate' ->> 'allowance_template_id',
    'unit', 'synthetic_credit',
    'total', v_allowance_total,
    'max_per_action', v_allowance_max_per_action,
    'max_actions', 5,
    'validity_seconds', 900,
    'transferable', FALSE,
    'redeemable', FALSE,
    'real_world_value', FALSE
  );
  v_expected_constraints := pg_catalog.jsonb_build_object(
    'environment', 'synthetic',
    'network_egress', 'forbidden',
    'external_side_effects', 'forbidden',
    'allowed_action_types', pg_catalog.jsonb_build_array(v_job_action_type),
    'allowed_targets', pg_catalog.jsonb_build_array(v_job_target),
    'max_actions', 5,
    'max_concurrency', 1,
    'validity_seconds', 900
  );
  v_expected_limits := pg_catalog.jsonb_build_object(
    'job_template_id', p_operating_bond -> 'candidate' ->> 'job_template_id',
    'allowance_template_id',
      p_operating_bond -> 'candidate' ->> 'allowance_template_id',
    'environment', 'synthetic',
    'network_egress', 'forbidden',
    'allowed_action_types', pg_catalog.jsonb_build_array(v_job_action_type),
    'max_actions', 5,
    'max_concurrency', 1,
    'validity_seconds', 900,
    'allowance_unit', 'synthetic_credit',
    'allowance_total', v_allowance_total,
    'allowance_max_per_action', v_allowance_max_per_action
  );
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(p_operating_bond)) <> 7
    OR NOT (
      p_operating_bond ? '@version'
      AND p_operating_bond ? 'candidate'
      AND p_operating_bond ? 'candidate_digest'
      AND p_operating_bond ? 'job'
      AND p_operating_bond ? 'allowance'
      AND p_operating_bond ? 'constraints'
      AND p_operating_bond ? 'claim_boundaries'
    )
    OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(p_public_projection)) <> 6
    OR NOT (
      p_public_projection ? '@version'
      AND p_public_projection ? 'bond_digest'
      AND p_public_projection ? 'candidate_digest'
      AND p_public_projection ? 'candidate'
      AND p_public_projection ? 'operating_limits'
      AND p_public_projection ? 'claim_boundaries'
    )
    OR p_public_projection ? 'share_id'
    OR p_public_projection ? 'adoption_id'
    OR p_public_projection ? 'assertion_observation'
    OR p_operating_bond ->> '@version' IS DISTINCT FROM 'EP-OPERATING-BOND-v1'
    OR p_public_projection ->> '@version' IS DISTINCT FROM 'EP-OPERATING-BOND-PUBLIC-v1'
    OR pg_catalog.jsonb_typeof(p_operating_bond -> 'candidate') IS DISTINCT FROM 'object'
    OR pg_catalog.jsonb_typeof(p_operating_bond -> 'job') IS DISTINCT FROM 'object'
    OR pg_catalog.jsonb_typeof(p_operating_bond -> 'allowance') IS DISTINCT FROM 'object'
    OR pg_catalog.jsonb_typeof(p_operating_bond -> 'constraints') IS DISTINCT FROM 'object'
    OR pg_catalog.jsonb_typeof(p_public_projection -> 'candidate') IS DISTINCT FROM 'object'
    OR pg_catalog.jsonb_typeof(p_public_projection -> 'operating_limits') IS DISTINCT FROM 'object'
    OR (SELECT pg_catalog.count(*)
        FROM pg_catalog.jsonb_object_keys(p_operating_bond -> 'candidate'))
      NOT BETWEEN 5 AND 7
    OR NOT (
      p_operating_bond -> 'candidate' ? '@version'
      AND p_operating_bond -> 'candidate' ? 'label'
      AND p_operating_bond -> 'candidate' ? 'source_kind'
      AND p_operating_bond -> 'candidate' ? 'job_template_id'
      AND p_operating_bond -> 'candidate' ? 'allowance_template_id'
    )
    OR EXISTS (
      SELECT 1
      FROM pg_catalog.jsonb_object_keys(
        p_operating_bond -> 'candidate'
      ) AS candidate_key(key_name)
      WHERE candidate_key.key_name NOT IN (
        '@version', 'label', 'source_kind', 'source_url',
        'agent_key_thumbprint', 'job_template_id', 'allowance_template_id'
      )
    )
    OR p_operating_bond -> 'candidate' ->> '@version'
      IS DISTINCT FROM 'EP-AGENT-ADOPTION-CANDIDATE-v1'
    OR p_operating_bond -> 'job' ->> '@version'
      IS DISTINCT FROM 'EP-AGENT-ADOPTION-JOB-TEMPLATE-v1'
    OR p_operating_bond -> 'allowance' ->> '@version'
      IS DISTINCT FROM 'EP-AGENT-ADOPTION-ALLOWANCE-TEMPLATE-v1'
    OR p_operating_bond -> 'candidate' ->> 'label' IS DISTINCT FROM p_agent_label
    OR p_operating_bond ->> 'candidate_digest' IS DISTINCT FROM p_candidate_digest
    OR p_public_projection ->> 'candidate_digest' IS DISTINCT FROM p_candidate_digest
    OR p_public_projection ->> 'bond_digest' IS DISTINCT FROM p_bond_digest
    OR p_public_projection -> 'candidate' ->> 'label' IS DISTINCT FROM p_agent_label
    OR p_public_projection -> 'candidate' ->> 'source_kind' IS DISTINCT FROM
      p_operating_bond -> 'candidate' ->> 'source_kind'
    OR p_public_projection -> 'candidate' IS DISTINCT FROM
      pg_catalog.jsonb_build_object(
        'label', p_agent_label,
        'source_kind', p_operating_bond -> 'candidate' ->> 'source_kind'
      )
    OR p_operating_bond -> 'candidate' ->> 'source_kind' NOT IN ('github', 'mcp', 'a2a', 'local')
    OR p_operating_bond -> 'candidate' ->> 'job_template_id' NOT IN (
      'job_vendor_intake_v1', 'job_compute_batch_v1', 'job_document_route_v1'
    )
    OR p_operating_bond -> 'candidate' ->> 'allowance_template_id' NOT IN (
      'allowance_cautious_v1', 'allowance_balanced_v1', 'allowance_stretch_v1'
    )
    OR p_operating_bond -> 'job' ->> 'template_id' IS DISTINCT FROM
      p_operating_bond -> 'candidate' ->> 'job_template_id'
    OR p_operating_bond -> 'allowance' ->> 'template_id' IS DISTINCT FROM
      p_operating_bond -> 'candidate' ->> 'allowance_template_id'
    OR p_operating_bond -> 'job' ->> 'environment' IS DISTINCT FROM 'synthetic'
    OR p_operating_bond -> 'job' ->> 'network_egress' IS DISTINCT FROM 'forbidden'
    OR p_operating_bond -> 'job' ->> 'external_side_effects' IS DISTINCT FROM 'forbidden'
    OR p_operating_bond -> 'allowance' ->> 'unit' IS DISTINCT FROM 'synthetic_credit'
    OR p_operating_bond -> 'allowance' -> 'transferable' IS DISTINCT FROM 'false'::JSONB
    OR p_operating_bond -> 'allowance' -> 'redeemable' IS DISTINCT FROM 'false'::JSONB
    OR p_operating_bond -> 'allowance' -> 'real_world_value' IS DISTINCT FROM 'false'::JSONB
    OR p_operating_bond -> 'job' IS DISTINCT FROM v_expected_job
    OR p_operating_bond -> 'allowance' IS DISTINCT FROM v_expected_allowance
    OR p_operating_bond -> 'constraints' IS DISTINCT FROM v_expected_constraints
    OR p_public_projection -> 'operating_limits' IS DISTINCT FROM v_expected_limits
    OR p_operating_bond -> 'constraints' ->> 'environment' IS DISTINCT FROM 'synthetic'
    OR p_operating_bond -> 'constraints' ->> 'network_egress' IS DISTINCT FROM 'forbidden'
    OR p_operating_bond -> 'constraints' ->> 'external_side_effects' IS DISTINCT FROM 'forbidden'
    OR p_operating_bond -> 'claim_boundaries' IS DISTINCT FROM v_claim_boundaries
    OR p_public_projection -> 'claim_boundaries' IS DISTINCT FROM v_claim_boundaries
    OR p_public_projection -> 'operating_limits' ->> 'job_template_id' IS DISTINCT FROM
      p_operating_bond -> 'job' ->> 'template_id'
    OR p_public_projection -> 'operating_limits' ->> 'allowance_template_id' IS DISTINCT FROM
      p_operating_bond -> 'allowance' ->> 'template_id'
    OR p_public_projection -> 'operating_limits' ->> 'environment' IS DISTINCT FROM
      p_operating_bond -> 'constraints' ->> 'environment'
    OR p_public_projection -> 'operating_limits' ->> 'network_egress' IS DISTINCT FROM
      p_operating_bond -> 'constraints' ->> 'network_egress'
    OR p_public_projection -> 'operating_limits' -> 'allowed_action_types' IS DISTINCT FROM
      p_operating_bond -> 'constraints' -> 'allowed_action_types'
    OR p_public_projection -> 'operating_limits' -> 'max_actions' IS DISTINCT FROM
      p_operating_bond -> 'constraints' -> 'max_actions'
    OR p_public_projection -> 'operating_limits' -> 'max_concurrency' IS DISTINCT FROM
      p_operating_bond -> 'constraints' -> 'max_concurrency'
    OR p_public_projection -> 'operating_limits' -> 'validity_seconds' IS DISTINCT FROM
      p_operating_bond -> 'constraints' -> 'validity_seconds'
    OR p_public_projection -> 'operating_limits' ->> 'allowance_unit' IS DISTINCT FROM
      p_operating_bond -> 'allowance' ->> 'unit'
    OR p_public_projection -> 'operating_limits' -> 'allowance_total' IS DISTINCT FROM
      p_operating_bond -> 'allowance' -> 'total'
    OR p_public_projection -> 'operating_limits' -> 'allowance_max_per_action' IS DISTINCT FROM
      p_operating_bond -> 'allowance' -> 'max_per_action'
  THEN
    RAISE EXCEPTION 'operating bond and public projection are inconsistent'
      USING ERRCODE = '22023';
  END IF;
  IF p_operating_bond -> 'candidate' ? 'source_url'
    AND (
      p_operating_bond -> 'candidate' ->> 'source_url'
        !~ '^https://[^/?#:@]+(?:/[^?#]*)?$'
      OR pg_catalog.octet_length(
        p_operating_bond -> 'candidate' ->> 'source_url'
      ) > 2048
    )
  THEN
    RAISE EXCEPTION 'candidate source URL is not bounded metadata'
      USING ERRCODE = '22023';
  END IF;
  IF p_operating_bond -> 'candidate' ? 'agent_key_thumbprint'
    AND p_operating_bond -> 'candidate' ->> 'agent_key_thumbprint'
      !~ '^sha256:[0-9a-f]{64}$'
  THEN
    RAISE EXCEPTION 'candidate key thumbprint is invalid'
      USING ERRCODE = '22023';
  END IF;

  v_tenant_id := pg_catalog.gen_random_uuid();
  v_adoption_id := pg_catalog.gen_random_uuid();
  v_session_token := 'eaa1_' ||
    pg_catalog.encode(extensions.gen_random_bytes(32), 'hex');
  v_created_at := pg_catalog.date_trunc(
    'milliseconds', pg_catalog.clock_timestamp()
  );
  v_expires_at := v_created_at + INTERVAL '30 days';

  INSERT INTO agent_adoption_private.adoption_sessions (
    tenant_id,
    adoption_id,
    session_token_hash,
    agent_label,
    candidate_digest,
    bond_digest,
    operating_bond,
    public_projection,
    created_at,
    expires_at
  ) VALUES (
    v_tenant_id,
    v_adoption_id,
    agent_adoption_private.token_hash(v_session_token),
    p_agent_label,
    p_candidate_digest,
    p_bond_digest,
    p_operating_bond,
    p_public_projection,
    v_created_at,
    v_expires_at
  );

  PERFORM agent_adoption_private.append_event(
    v_tenant_id,
    v_adoption_id,
    'session_created',
    pg_catalog.jsonb_build_object(
      'scope', 'synthetic_no_egress_demonstration',
      'agent_label', p_agent_label,
      'candidate_digest', p_candidate_digest,
      'bond_digest', p_bond_digest
    )
  );

  RETURN pg_catalog.jsonb_build_object(
    'tenant_id', v_tenant_id,
    'adoption_id', v_adoption_id,
    'session_id', v_adoption_id,
    'session_token', v_session_token,
    'agent_label', p_agent_label,
    'candidate_digest', p_candidate_digest,
    'bond_digest', p_bond_digest,
    'operating_bond', p_operating_bond,
    'public_projection', p_public_projection,
    'scope', 'synthetic_no_egress_demonstration',
    'created_at', agent_adoption_private.iso_ms(v_created_at),
    'expires_at', agent_adoption_private.iso_ms(v_expires_at)
  );
END
$create_session$;

CREATE FUNCTION public.read_agent_adoption_session(
  p_adoption_id UUID,
  p_session_token TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $read_session$
DECLARE
  v_session agent_adoption_private.adoption_sessions%ROWTYPE;
  v_revocation agent_adoption_private.adoption_revocations%ROWTYPE;
  v_credential_count BIGINT;
  v_bond_count BIGINT;
  v_latest_bond_id UUID;
  v_latest_bond_digest TEXT;
BEGIN
  IF p_adoption_id IS NULL
    OR p_session_token IS NULL
    OR p_session_token !~ '^eaa1_[0-9a-f]{64}$'
  THEN
    RAISE EXCEPTION 'agent adoption session credential is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT session.*
  INTO v_session
  FROM agent_adoption_private.adoption_sessions AS session
  WHERE session.adoption_id = p_adoption_id
    AND session.session_token_hash =
      agent_adoption_private.token_hash(p_session_token)
    AND session.expires_at > pg_catalog.clock_timestamp();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'agent adoption session not found'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT revocation.*
  INTO v_revocation
  FROM agent_adoption_private.adoption_revocations AS revocation
  WHERE revocation.tenant_id = v_session.tenant_id
    AND revocation.adoption_id = v_session.adoption_id;

  SELECT pg_catalog.count(*)
  INTO v_credential_count
  FROM agent_adoption_private.adoption_credentials AS credential
  WHERE credential.tenant_id = v_session.tenant_id
    AND credential.adoption_id = v_session.adoption_id;
  SELECT pg_catalog.count(*)
  INTO v_bond_count
  FROM agent_adoption_private.operating_bonds AS bond
  WHERE bond.tenant_id = v_session.tenant_id
    AND bond.adoption_id = v_session.adoption_id;
  SELECT bond.bond_id, bond.bond_digest
  INTO v_latest_bond_id, v_latest_bond_digest
  FROM agent_adoption_private.operating_bonds AS bond
  WHERE bond.tenant_id = v_session.tenant_id
    AND bond.adoption_id = v_session.adoption_id
  ORDER BY bond.created_at DESC, bond.bond_id DESC
  LIMIT 1;

  RETURN pg_catalog.jsonb_build_object(
    'tenant_id', v_session.tenant_id,
    'adoption_id', v_session.adoption_id,
    'agent_label', v_session.agent_label,
    'candidate_digest', v_session.candidate_digest,
    'bond_digest', v_session.bond_digest,
    'operating_bond', v_session.operating_bond,
    'public_projection', v_session.public_projection,
    'scope', v_session.scope,
    'status', CASE WHEN v_revocation.revocation_id IS NULL
      THEN 'active' ELSE 'revoked' END,
    'created_at', v_session.created_at,
    'expires_at', v_session.expires_at,
    'credential_count', v_credential_count,
    'bond_count', v_bond_count,
    'latest_bond_id', v_latest_bond_id,
    'latest_bond_digest', v_latest_bond_digest,
    'revoked_at', v_revocation.revoked_at
  );
END
$read_session$;

CREATE FUNCTION public.create_agent_adoption_registration_challenge(
  p_adoption_id UUID,
  p_session_token TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $registration_challenge$
DECLARE
  v_session agent_adoption_private.adoption_sessions%ROWTYPE;
  v_challenge_id UUID;
  v_challenge_token TEXT;
  v_created_at TIMESTAMPTZ;
  v_expires_at TIMESTAMPTZ;
BEGIN
  IF p_adoption_id IS NULL
    OR p_session_token IS NULL
    OR p_session_token !~ '^eaa1_[0-9a-f]{64}$'
  THEN
    RAISE EXCEPTION 'agent adoption session credential is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT session.*
  INTO v_session
  FROM agent_adoption_private.adoption_sessions AS session
  WHERE session.adoption_id = p_adoption_id
    AND session.session_token_hash =
      agent_adoption_private.token_hash(p_session_token)
    AND session.expires_at > pg_catalog.clock_timestamp()
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'agent adoption session not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM agent_adoption_private.adoption_revocations AS revocation
    WHERE revocation.tenant_id = v_session.tenant_id
      AND revocation.adoption_id = v_session.adoption_id
  ) THEN
    RAISE EXCEPTION 'adoption is revoked'
      USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM agent_adoption_private.adoption_credentials AS credential
    WHERE credential.tenant_id = v_session.tenant_id
      AND credential.adoption_id = v_session.adoption_id
  ) THEN
    RAISE EXCEPTION 'adoption credential is already registered'
      USING ERRCODE = '55000';
  END IF;
  IF (
    SELECT pg_catalog.count(*)
    FROM agent_adoption_private.adoption_challenges AS challenge
    WHERE challenge.tenant_id = v_session.tenant_id
      AND challenge.adoption_id = v_session.adoption_id
  ) >= 32 THEN
    RAISE EXCEPTION 'adoption challenge lifetime limit reached'
      USING ERRCODE = '55000';
  END IF;
  IF (
    SELECT pg_catalog.count(*)
    FROM agent_adoption_private.adoption_challenges AS challenge
    WHERE challenge.tenant_id = v_session.tenant_id
      AND challenge.adoption_id = v_session.adoption_id
      AND challenge.purpose = 'registration'
      AND challenge.consumed_at IS NULL
      AND challenge.expires_at > pg_catalog.clock_timestamp()
  ) >= 4 THEN
    RAISE EXCEPTION 'too many pending registration challenges'
      USING ERRCODE = '55000';
  END IF;

  v_challenge_id := pg_catalog.gen_random_uuid();
  v_challenge_token := 'ear1_' ||
    pg_catalog.encode(extensions.gen_random_bytes(32), 'hex');
  v_created_at := pg_catalog.date_trunc(
    'milliseconds', pg_catalog.transaction_timestamp()
  );
  v_expires_at := v_created_at + INTERVAL '5 minutes';
  INSERT INTO agent_adoption_private.adoption_challenges (
    tenant_id,
    adoption_id,
    challenge_id,
    candidate_digest,
    bond_digest,
    purpose,
    nonce_hash,
    created_at,
    expires_at
  ) VALUES (
    v_session.tenant_id,
    v_session.adoption_id,
    v_challenge_id,
    v_session.candidate_digest,
    v_session.bond_digest,
    'registration',
    agent_adoption_private.token_hash(v_challenge_token),
    v_created_at,
    v_expires_at
  );

  RETURN pg_catalog.jsonb_build_object(
    'challenge_id', v_challenge_id,
    'challenge_token', v_challenge_token,
    'purpose', 'registration',
    'tenant_id', v_session.tenant_id,
    'adoption_id', v_session.adoption_id,
    'candidate_digest', v_session.candidate_digest,
    'bond_digest', v_session.bond_digest,
    'bond_purpose', 'synthetic_agent_adoption_operating_bond_v1',
    'created_at', agent_adoption_private.iso_ms(v_created_at),
    'issued_at', agent_adoption_private.iso_ms(v_created_at),
    'expires_at', agent_adoption_private.iso_ms(v_expires_at)
  );
END
$registration_challenge$;

CREATE FUNCTION public.complete_agent_adoption_registration(
  p_adoption_id UUID,
  p_session_token TEXT,
  p_challenge_token TEXT,
  p_credential_id TEXT,
  p_public_key_cose TEXT,
  p_public_key_spki TEXT,
  p_algorithm TEXT,
  p_curve TEXT,
  p_transports TEXT[],
  p_device_type TEXT,
  p_backed_up BOOLEAN,
  p_sign_count BIGINT,
  p_counter_supported BOOLEAN,
  p_rp_id TEXT,
  p_origin TEXT,
  p_registration_digest TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $complete_registration$
DECLARE
  v_session agent_adoption_private.adoption_sessions%ROWTYPE;
  v_challenge agent_adoption_private.adoption_challenges%ROWTYPE;
  v_origin_host TEXT;
  v_completed_at TIMESTAMPTZ;
BEGIN
  IF p_adoption_id IS NULL
    OR p_session_token IS NULL
    OR p_session_token !~ '^eaa1_[0-9a-f]{64}$'
    OR p_challenge_token IS NULL
    OR p_challenge_token !~ '^ear1_[0-9a-f]{64}$'
    OR p_credential_id IS NULL
    OR pg_catalog.octet_length(p_credential_id) NOT BETWEEN 1 AND 1024
    OR p_credential_id !~ '^[A-Za-z0-9_-]+$'
    OR p_public_key_cose IS NULL
    OR pg_catalog.octet_length(p_public_key_cose) NOT BETWEEN 1 AND 1368
    OR p_public_key_cose !~ '^[A-Za-z0-9_-]+$'
    OR p_public_key_spki IS NULL
    OR pg_catalog.octet_length(p_public_key_spki) NOT BETWEEN 1 AND 512
    OR p_public_key_spki !~ '^[A-Za-z0-9_-]+$'
    OR p_algorithm IS DISTINCT FROM 'ES256'
    OR p_curve IS DISTINCT FROM 'P-256'
    OR p_device_type NOT IN ('singleDevice', 'multiDevice')
    OR p_backed_up IS NULL
    OR p_sign_count IS NULL
    OR p_sign_count NOT BETWEEN 0 AND 4294967295
    OR p_counter_supported IS DISTINCT FROM (p_sign_count > 0)
    OR p_rp_id IS NULL
    OR pg_catalog.octet_length(p_rp_id) NOT BETWEEN 1 AND 253
    OR (
      p_rp_id <> 'localhost'
      AND (
        p_rp_id !~ '^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$'
        OR p_rp_id !~ '[.]'
        OR p_rp_id ~ '[.][.]'
      )
    )
    OR p_origin IS NULL
    OR pg_catalog.octet_length(p_origin) NOT BETWEEN 1 AND 512
    OR NOT (
      p_origin ~ '^https://[a-z0-9.-]+(:[0-9]{1,5})?$'
      OR (p_rp_id = 'localhost' AND p_origin ~ '^http://localhost(:[0-9]{1,5})?$')
    )
    OR p_registration_digest IS NULL
    OR p_registration_digest !~ '^sha256:[0-9a-f]{64}$'
  THEN
    RAISE EXCEPTION 'registration completion input is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF p_transports IS NOT NULL AND (
    pg_catalog.cardinality(p_transports) > 7
    OR pg_catalog.cardinality(p_transports) IS DISTINCT FROM (
      SELECT pg_catalog.count(DISTINCT transport)::INTEGER
      FROM pg_catalog.unnest(p_transports) AS transport
    )
    OR EXISTS (
      SELECT 1
      FROM pg_catalog.unnest(p_transports) AS transport
      WHERE transport NOT IN (
        'ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'
      )
    )
  ) THEN
    RAISE EXCEPTION 'credential transports are invalid'
      USING ERRCODE = '22023';
  END IF;
  v_origin_host := pg_catalog.split_part(
    pg_catalog.split_part(p_origin, '://', 2), ':', 1
  );
  IF NOT (
    v_origin_host = p_rp_id
    OR v_origin_host LIKE '%.' || p_rp_id
  ) THEN
    RAISE EXCEPTION 'credential origin is outside the relying-party scope'
      USING ERRCODE = '22023';
  END IF;

  SELECT session.*
  INTO v_session
  FROM agent_adoption_private.adoption_sessions AS session
  WHERE session.adoption_id = p_adoption_id
    AND session.session_token_hash =
      agent_adoption_private.token_hash(p_session_token)
    AND session.expires_at > pg_catalog.clock_timestamp()
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'agent adoption session not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM agent_adoption_private.adoption_revocations AS revocation
    WHERE revocation.tenant_id = v_session.tenant_id
      AND revocation.adoption_id = v_session.adoption_id
  ) THEN
    RAISE EXCEPTION 'adoption is revoked'
      USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM agent_adoption_private.adoption_credentials AS credential
    WHERE credential.tenant_id = v_session.tenant_id
      AND credential.adoption_id = v_session.adoption_id
  ) THEN
    RAISE EXCEPTION 'adoption credential is already registered'
      USING ERRCODE = '55000';
  END IF;

  SELECT challenge.*
  INTO v_challenge
  FROM agent_adoption_private.adoption_challenges AS challenge
  WHERE challenge.tenant_id = v_session.tenant_id
    AND challenge.adoption_id = v_session.adoption_id
    AND challenge.candidate_digest = v_session.candidate_digest
    AND challenge.bond_digest = v_session.bond_digest
    AND challenge.purpose = 'registration'
    AND challenge.nonce_hash =
      agent_adoption_private.token_hash(p_challenge_token)
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'registration challenge not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF v_challenge.consumed_at IS NOT NULL THEN
    RAISE EXCEPTION 'registration challenge was already consumed'
      USING ERRCODE = '55000';
  END IF;
  v_completed_at := pg_catalog.clock_timestamp();
  IF v_challenge.expires_at <= v_completed_at THEN
    RAISE EXCEPTION 'registration challenge expired'
      USING ERRCODE = '55000';
  END IF;

  INSERT INTO agent_adoption_private.adoption_credentials (
    tenant_id,
    adoption_id,
    credential_id,
    public_key_cose,
    public_key_spki,
    algorithm,
    curve,
    transports,
    device_type,
    backed_up,
    sign_count,
    counter_supported,
    rp_id,
    origin,
    claim_boundary,
    registration_digest
  ) VALUES (
    v_session.tenant_id,
    v_session.adoption_id,
    p_credential_id,
    p_public_key_cose,
    p_public_key_spki,
    p_algorithm,
    p_curve,
    p_transports,
    p_device_type,
    p_backed_up,
    p_sign_count,
    p_counter_supported,
    p_rp_id,
    p_origin,
    'public_no_egress_agent_adoption_evidence_only_not_real_money_not_provider_credentials_not_civil_identity_not_certification_not_marketplace_not_production_execution',
    p_registration_digest
  );
  UPDATE agent_adoption_private.adoption_challenges
  SET consumed_at = v_completed_at,
      completion_digest = p_registration_digest
  WHERE tenant_id = v_challenge.tenant_id
    AND adoption_id = v_challenge.adoption_id
    AND challenge_id = v_challenge.challenge_id;

  PERFORM agent_adoption_private.append_event(
    v_session.tenant_id,
    v_session.adoption_id,
    'credential_registered',
    pg_catalog.jsonb_build_object(
      'registration_digest', p_registration_digest,
      'credential_id_digest', agent_adoption_private.token_hash(p_credential_id),
      'initial_counter', p_sign_count,
      'counter_supported', p_counter_supported,
      'rp_id', p_rp_id
    )
  );
  RETURN pg_catalog.jsonb_build_object(
    'adoption_id', v_session.adoption_id,
    'credential_id', p_credential_id,
    'registration_digest', p_registration_digest,
    'sign_count', p_sign_count,
    'counter_supported', p_counter_supported,
    'registered', TRUE
  );
END
$complete_registration$;

CREATE FUNCTION public.create_agent_adoption_assertion_challenge(
  p_adoption_id UUID,
  p_session_token TEXT,
  p_credential_id TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $assertion_challenge$
DECLARE
  v_session agent_adoption_private.adoption_sessions%ROWTYPE;
  v_credential agent_adoption_private.adoption_credentials%ROWTYPE;
  v_challenge_id UUID;
  v_challenge_token TEXT;
  v_created_at TIMESTAMPTZ;
  v_expires_at TIMESTAMPTZ;
BEGIN
  IF p_adoption_id IS NULL
    OR p_session_token IS NULL
    OR p_session_token !~ '^eaa1_[0-9a-f]{64}$'
    OR p_credential_id IS NULL
    OR pg_catalog.octet_length(p_credential_id) NOT BETWEEN 1 AND 1024
    OR p_credential_id !~ '^[A-Za-z0-9_-]+$'
  THEN
    RAISE EXCEPTION 'assertion challenge input is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT session.*
  INTO v_session
  FROM agent_adoption_private.adoption_sessions AS session
  WHERE session.adoption_id = p_adoption_id
    AND session.session_token_hash =
      agent_adoption_private.token_hash(p_session_token)
    AND session.expires_at > pg_catalog.clock_timestamp()
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'agent adoption session not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM agent_adoption_private.adoption_revocations AS revocation
    WHERE revocation.tenant_id = v_session.tenant_id
      AND revocation.adoption_id = v_session.adoption_id
  ) THEN
    RAISE EXCEPTION 'adoption is revoked'
      USING ERRCODE = '55000';
  END IF;
  SELECT credential.*
  INTO v_credential
    FROM agent_adoption_private.adoption_credentials AS credential
    WHERE credential.tenant_id = v_session.tenant_id
      AND credential.adoption_id = v_session.adoption_id
      AND credential.credential_id = p_credential_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'adoption credential not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM agent_adoption_private.operating_bonds AS bond
    WHERE bond.tenant_id = v_session.tenant_id
      AND bond.adoption_id = v_session.adoption_id
  ) THEN
    RAISE EXCEPTION 'operating bond was already asserted'
      USING ERRCODE = '55000';
  END IF;
  IF (
    SELECT pg_catalog.count(*)
    FROM agent_adoption_private.adoption_challenges AS challenge
    WHERE challenge.tenant_id = v_session.tenant_id
      AND challenge.adoption_id = v_session.adoption_id
  ) >= 32 THEN
    RAISE EXCEPTION 'adoption challenge lifetime limit reached'
      USING ERRCODE = '55000';
  END IF;
  IF (
    SELECT pg_catalog.count(*)
    FROM agent_adoption_private.adoption_challenges AS challenge
    WHERE challenge.tenant_id = v_session.tenant_id
      AND challenge.adoption_id = v_session.adoption_id
      AND challenge.purpose = 'assertion'
      AND challenge.consumed_at IS NULL
      AND challenge.expires_at > pg_catalog.clock_timestamp()
  ) >= 4 THEN
    RAISE EXCEPTION 'too many pending assertion challenges'
      USING ERRCODE = '55000';
  END IF;

  v_challenge_id := pg_catalog.gen_random_uuid();
  v_challenge_token := 'eaa1c_' ||
    pg_catalog.encode(extensions.gen_random_bytes(32), 'hex');
  v_created_at := pg_catalog.date_trunc(
    'milliseconds', pg_catalog.transaction_timestamp()
  );
  v_expires_at := v_created_at + INTERVAL '5 minutes';
  INSERT INTO agent_adoption_private.adoption_challenges (
    tenant_id,
    adoption_id,
    challenge_id,
    candidate_digest,
    bond_digest,
    purpose,
    credential_id,
    nonce_hash,
    created_at,
    expires_at
  ) VALUES (
    v_session.tenant_id,
    v_session.adoption_id,
    v_challenge_id,
    v_session.candidate_digest,
    v_session.bond_digest,
    'assertion',
    p_credential_id,
    agent_adoption_private.token_hash(v_challenge_token),
    v_created_at,
    v_expires_at
  );

  RETURN pg_catalog.jsonb_build_object(
    'challenge_id', v_challenge_id,
    'challenge_token', v_challenge_token,
    'purpose', 'assertion',
    'tenant_id', v_session.tenant_id,
    'adoption_id', v_session.adoption_id,
    'candidate_digest', v_session.candidate_digest,
    'bond_digest', v_session.bond_digest,
    'bond_purpose', 'synthetic_agent_adoption_operating_bond_v1',
    'created_at', agent_adoption_private.iso_ms(v_created_at),
    'issued_at', agent_adoption_private.iso_ms(v_created_at),
    'expires_at', agent_adoption_private.iso_ms(v_expires_at),
    'credential', pg_catalog.jsonb_build_object(
      'claim_boundary', v_credential.claim_boundary,
      'credential_id', v_credential.credential_id,
      'public_key_cose', v_credential.public_key_cose,
      'public_key_spki', v_credential.public_key_spki,
      'algorithm', v_credential.algorithm,
      'curve', v_credential.curve,
      'transports', v_credential.transports,
      'device_type', v_credential.device_type,
      'backed_up', v_credential.backed_up,
      'sign_count', v_credential.sign_count,
      'counter_supported', v_credential.counter_supported,
      'rp_id', v_credential.rp_id,
      'origin', v_credential.origin
    )
  );
END
$assertion_challenge$;

CREATE FUNCTION public.complete_agent_adoption_assertion(
  p_adoption_id UUID,
  p_session_token TEXT,
  p_challenge_token TEXT,
  p_credential_id TEXT,
  p_new_counter BIGINT,
  p_counter_supported BOOLEAN,
  p_device_type TEXT,
  p_backed_up BOOLEAN,
  p_assertion_digest TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $complete_assertion$
DECLARE
  v_session agent_adoption_private.adoption_sessions%ROWTYPE;
  v_credential agent_adoption_private.adoption_credentials%ROWTYPE;
  v_challenge agent_adoption_private.adoption_challenges%ROWTYPE;
  v_bond_id UUID;
  v_created_at TIMESTAMPTZ;
  v_completed_at TIMESTAMPTZ;
  v_event_hash TEXT;
BEGIN
  IF p_adoption_id IS NULL
    OR p_session_token IS NULL
    OR p_session_token !~ '^eaa1_[0-9a-f]{64}$'
    OR p_challenge_token IS NULL
    OR p_challenge_token !~ '^eaa1c_[0-9a-f]{64}$'
    OR p_credential_id IS NULL
    OR pg_catalog.octet_length(p_credential_id) NOT BETWEEN 1 AND 1024
    OR p_credential_id !~ '^[A-Za-z0-9_-]+$'
    OR p_new_counter IS NULL
    OR p_new_counter NOT BETWEEN 0 AND 4294967295
    OR p_counter_supported IS DISTINCT FROM (p_new_counter > 0)
    OR p_device_type NOT IN ('singleDevice', 'multiDevice')
    OR p_backed_up IS NULL
    OR p_assertion_digest IS NULL
    OR p_assertion_digest !~ '^sha256:[0-9a-f]{64}$'
  THEN
    RAISE EXCEPTION 'assertion completion input is invalid'
      USING ERRCODE = '22023';
  END IF;

  -- All mutating RPCs take the adoption lock first. Assertion completion then
  -- locks the credential before its challenge, giving one consistent order.
  SELECT session.*
  INTO v_session
  FROM agent_adoption_private.adoption_sessions AS session
  WHERE session.adoption_id = p_adoption_id
    AND session.session_token_hash =
      agent_adoption_private.token_hash(p_session_token)
    AND session.expires_at > pg_catalog.clock_timestamp()
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'agent adoption session not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM agent_adoption_private.adoption_revocations AS revocation
    WHERE revocation.tenant_id = v_session.tenant_id
      AND revocation.adoption_id = v_session.adoption_id
  ) THEN
    RAISE EXCEPTION 'adoption is revoked'
      USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM agent_adoption_private.operating_bonds AS bond
    WHERE bond.tenant_id = v_session.tenant_id
      AND bond.adoption_id = v_session.adoption_id
  ) THEN
    RAISE EXCEPTION 'operating bond was already asserted'
      USING ERRCODE = '55000';
  END IF;

  SELECT credential.*
  INTO v_credential
  FROM agent_adoption_private.adoption_credentials AS credential
  WHERE credential.tenant_id = v_session.tenant_id
    AND credential.adoption_id = v_session.adoption_id
    AND credential.credential_id = p_credential_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'adoption credential not found'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT challenge.*
  INTO v_challenge
  FROM agent_adoption_private.adoption_challenges AS challenge
  WHERE challenge.tenant_id = v_session.tenant_id
    AND challenge.adoption_id = v_session.adoption_id
    AND challenge.candidate_digest = v_session.candidate_digest
    AND challenge.bond_digest = v_session.bond_digest
    AND challenge.purpose = 'assertion'
    AND challenge.credential_id = p_credential_id
    AND challenge.nonce_hash =
      agent_adoption_private.token_hash(p_challenge_token)
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'assertion challenge not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF v_challenge.consumed_at IS NOT NULL THEN
    RAISE EXCEPTION 'assertion challenge was already consumed'
      USING ERRCODE = '55000';
  END IF;
  v_completed_at := pg_catalog.clock_timestamp();
  IF v_challenge.expires_at <= v_completed_at THEN
    RAISE EXCEPTION 'assertion challenge expired'
      USING ERRCODE = '55000';
  END IF;
  IF NOT (
    (v_credential.sign_count = 0 AND p_new_counter = 0)
    OR p_new_counter > v_credential.sign_count
  ) THEN
    RAISE EXCEPTION 'assertion counter must remain 0/0 or strictly advance'
      USING ERRCODE = '55000';
  END IF;

  v_bond_id := pg_catalog.gen_random_uuid();
  v_created_at := pg_catalog.date_trunc(
    'milliseconds', pg_catalog.transaction_timestamp()
  );

  UPDATE agent_adoption_private.adoption_challenges
  SET consumed_at = v_completed_at,
      completion_digest = p_assertion_digest
  WHERE tenant_id = v_challenge.tenant_id
    AND adoption_id = v_challenge.adoption_id
    AND challenge_id = v_challenge.challenge_id;
  UPDATE agent_adoption_private.adoption_credentials
  SET device_type = p_device_type,
      backed_up = p_backed_up,
      sign_count = p_new_counter,
      counter_supported = p_counter_supported,
      last_asserted_at = v_created_at
  WHERE tenant_id = v_credential.tenant_id
    AND adoption_id = v_credential.adoption_id
    AND credential_id = v_credential.credential_id;
  v_event_hash := agent_adoption_private.append_event(
    v_session.tenant_id,
    v_session.adoption_id,
    'agent_assertion_completed',
    pg_catalog.jsonb_build_object(
      'bond_id', v_bond_id,
      'bond_digest', v_session.bond_digest,
      'assertion_digest', p_assertion_digest,
      'counter_before', v_credential.sign_count,
      'counter_after', p_new_counter,
      'counter_supported', p_counter_supported,
      'device_type', p_device_type,
      'backed_up', p_backed_up
    )
  );
  INSERT INTO agent_adoption_private.operating_bonds (
    tenant_id,
    adoption_id,
    bond_id,
    candidate_digest,
    bond_digest,
    operating_bond,
    public_projection,
    credential_id,
    challenge_id,
    assertion_digest,
    counter_before,
    counter_after,
    assertion_event_hash,
    created_at
  ) VALUES (
    v_session.tenant_id,
    v_session.adoption_id,
    v_bond_id,
    v_session.candidate_digest,
    v_session.bond_digest,
    v_session.operating_bond,
    v_session.public_projection,
    v_credential.credential_id,
    v_challenge.challenge_id,
    p_assertion_digest,
    v_credential.sign_count,
    p_new_counter,
    v_event_hash,
    v_created_at
  );
  RETURN pg_catalog.jsonb_build_object(
    'bond_id', v_bond_id,
    'adoption_id', v_session.adoption_id,
    'candidate_digest', v_session.candidate_digest,
    'bond_digest', v_session.bond_digest,
    'operating_bond', v_session.operating_bond,
    'public_projection', v_session.public_projection,
    'assertion_observation', pg_catalog.jsonb_build_object(
      'assertion_digest', p_assertion_digest,
      'counter_before', v_credential.sign_count,
      'counter_after', p_new_counter,
      'counter_supported', p_counter_supported,
      'device_type', p_device_type,
      'backed_up', p_backed_up,
      'observed_at', agent_adoption_private.iso_ms(v_created_at),
      'event_hash', v_event_hash
    )
  );
END
$complete_assertion$;

CREATE FUNCTION public.read_agent_operating_bond(
  p_adoption_id UUID,
  p_session_token TEXT,
  p_bond_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $read_bond$
DECLARE
  v_session agent_adoption_private.adoption_sessions%ROWTYPE;
  v_bond agent_adoption_private.operating_bonds%ROWTYPE;
BEGIN
  IF p_adoption_id IS NULL
    OR p_session_token IS NULL
    OR p_session_token !~ '^eaa1_[0-9a-f]{64}$'
    OR p_bond_id IS NULL
  THEN
    RAISE EXCEPTION 'bond read credential is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT session.*
  INTO v_session
  FROM agent_adoption_private.adoption_sessions AS session
  WHERE session.adoption_id = p_adoption_id
    AND session.session_token_hash =
      agent_adoption_private.token_hash(p_session_token)
    AND session.expires_at > pg_catalog.clock_timestamp();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'agent adoption session not found'
      USING ERRCODE = 'P0002';
  END IF;
  SELECT bond.*
  INTO v_bond
  FROM agent_adoption_private.operating_bonds AS bond
  WHERE bond.tenant_id = v_session.tenant_id
    AND bond.adoption_id = v_session.adoption_id
    AND bond.bond_id = p_bond_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'operating bond not found'
      USING ERRCODE = 'P0002';
  END IF;

  RETURN pg_catalog.jsonb_build_object(
    'bond_id', v_bond.bond_id,
    'adoption_id', v_bond.adoption_id,
    'candidate_digest', v_bond.candidate_digest,
    'bond_digest', v_bond.bond_digest,
    'operating_bond', v_bond.operating_bond,
    'public_projection', v_bond.public_projection,
    'assertion_digest', v_bond.assertion_digest,
    'counter_before', v_bond.counter_before,
    'counter_after', v_bond.counter_after,
    'assertion_event_hash', v_bond.assertion_event_hash,
    'created_at', agent_adoption_private.iso_ms(v_bond.created_at)
  );
END
$read_bond$;

CREATE FUNCTION public.revoke_agent_adoption(
  p_adoption_id UUID,
  p_session_token TEXT,
  p_reason TEXT,
  p_revocation_nonce TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $revoke_adoption$
DECLARE
  v_session agent_adoption_private.adoption_sessions%ROWTYPE;
  v_existing agent_adoption_private.adoption_revocations%ROWTYPE;
  v_revocation_id UUID;
  v_revoked_at TIMESTAMPTZ;
BEGIN
  IF p_adoption_id IS NULL
    OR p_session_token IS NULL
    OR p_session_token !~ '^eaa1_[0-9a-f]{64}$'
    OR p_reason IS NULL
    OR pg_catalog.octet_length(pg_catalog.btrim(p_reason)) NOT BETWEEN 1 AND 280
    OR pg_catalog.btrim(p_reason) ~ '[[:cntrl:]]'
    OR p_revocation_nonce IS NULL
    OR p_revocation_nonce !~ '^earv1_[0-9a-f]{48,128}$'
  THEN
    RAISE EXCEPTION 'adoption revocation input is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT session.*
  INTO v_session
  FROM agent_adoption_private.adoption_sessions AS session
  WHERE session.adoption_id = p_adoption_id
    AND session.session_token_hash =
      agent_adoption_private.token_hash(p_session_token)
    AND session.expires_at > pg_catalog.clock_timestamp()
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'agent adoption session not found'
      USING ERRCODE = 'P0002';
  END IF;
  SELECT revocation.*
  INTO v_existing
  FROM agent_adoption_private.adoption_revocations AS revocation
  WHERE revocation.tenant_id = v_session.tenant_id
    AND revocation.adoption_id = v_session.adoption_id;
  IF v_existing.revocation_id IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object(
      'adoption_id', v_session.adoption_id,
      'revocation_id', v_existing.revocation_id,
      'revoked_at', v_existing.revoked_at,
      'status', 'revoked'
    );
  END IF;

  v_revocation_id := pg_catalog.gen_random_uuid();
  v_revoked_at := pg_catalog.transaction_timestamp();
  INSERT INTO agent_adoption_private.adoption_revocations (
    tenant_id,
    adoption_id,
    revocation_id,
    revocation_nonce_hash,
    reason,
    revoked_at
  ) VALUES (
    v_session.tenant_id,
    v_session.adoption_id,
    v_revocation_id,
    agent_adoption_private.token_hash(p_revocation_nonce),
    pg_catalog.btrim(p_reason),
    v_revoked_at
  );
  PERFORM agent_adoption_private.append_event(
    v_session.tenant_id,
    v_session.adoption_id,
    'adoption_revoked',
    pg_catalog.jsonb_build_object(
      'revocation_id', v_revocation_id,
      'reason', pg_catalog.btrim(p_reason)
    )
  );
  RETURN pg_catalog.jsonb_build_object(
    'adoption_id', v_session.adoption_id,
    'revocation_id', v_revocation_id,
    'revoked_at', v_revoked_at,
    'status', 'revoked'
  );
END
$revoke_adoption$;

CREATE FUNCTION public.publish_agent_adoption_share(
  p_adoption_id UUID,
  p_session_token TEXT,
  p_bond_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $publish_share$
DECLARE
  v_session agent_adoption_private.adoption_sessions%ROWTYPE;
  v_bond agent_adoption_private.operating_bonds%ROWTYPE;
  v_existing agent_adoption_private.public_shares%ROWTYPE;
  v_share_id TEXT;
  v_projection JSONB;
BEGIN
  IF p_adoption_id IS NULL
    OR p_session_token IS NULL
    OR p_session_token !~ '^eaa1_[0-9a-f]{64}$'
    OR p_bond_id IS NULL
  THEN
    RAISE EXCEPTION 'share publication input is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT session.*
  INTO v_session
  FROM agent_adoption_private.adoption_sessions AS session
  WHERE session.adoption_id = p_adoption_id
    AND session.session_token_hash =
      agent_adoption_private.token_hash(p_session_token)
    AND session.expires_at > pg_catalog.clock_timestamp()
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'agent adoption session not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM agent_adoption_private.adoption_revocations AS revocation
    WHERE revocation.tenant_id = v_session.tenant_id
      AND revocation.adoption_id = v_session.adoption_id
  ) THEN
    RAISE EXCEPTION 'adoption is revoked'
      USING ERRCODE = '55000';
  END IF;
  SELECT bond.*
  INTO v_bond
  FROM agent_adoption_private.operating_bonds AS bond
  WHERE bond.tenant_id = v_session.tenant_id
    AND bond.adoption_id = v_session.adoption_id
    AND bond.bond_id = p_bond_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'operating bond not found'
      USING ERRCODE = 'P0002';
  END IF;
  SELECT share.*
  INTO v_existing
  FROM agent_adoption_private.public_shares AS share
  WHERE share.tenant_id = v_session.tenant_id
    AND share.adoption_id = v_session.adoption_id
    AND share.bond_id = v_bond.bond_id;
  IF v_existing.share_id IS NOT NULL THEN
    IF EXISTS (
      SELECT 1
      FROM agent_adoption_private.share_revocations AS revocation
      WHERE revocation.tenant_id = v_existing.tenant_id
        AND revocation.adoption_id = v_existing.adoption_id
        AND revocation.share_id = v_existing.share_id
    ) THEN
      RAISE EXCEPTION 'public share was revoked and cannot be republished'
        USING ERRCODE = '55000';
    END IF;
    RETURN pg_catalog.jsonb_build_object(
      'share_id', v_existing.share_id,
      'projection', v_existing.public_projection,
      'published', TRUE
    );
  END IF;

  v_share_id := 'agent_share_' ||
    pg_catalog.encode(extensions.gen_random_bytes(20), 'hex');
  v_projection := v_bond.public_projection || pg_catalog.jsonb_build_object(
    'share_id', v_share_id,
    'assertion_observation', pg_catalog.jsonb_build_object(
      'assertion_digest', v_bond.assertion_digest,
      'counter_before', v_bond.counter_before,
      'counter_after', v_bond.counter_after,
      'observed_at', agent_adoption_private.iso_ms(v_bond.created_at),
      'event_hash', v_bond.assertion_event_hash
    )
  );
  INSERT INTO agent_adoption_private.public_shares (
    tenant_id,
    adoption_id,
    share_id,
    bond_id,
    bond_digest,
    public_projection
  ) VALUES (
    v_session.tenant_id,
    v_session.adoption_id,
    v_share_id,
    v_bond.bond_id,
    v_bond.bond_digest,
    v_projection
  );
  PERFORM agent_adoption_private.append_event(
    v_session.tenant_id,
    v_session.adoption_id,
    'share_published',
    pg_catalog.jsonb_build_object(
      'share_id', v_share_id,
      'bond_id', v_bond.bond_id,
      'bond_digest', v_bond.bond_digest
    )
  );
  RETURN pg_catalog.jsonb_build_object(
    'share_id', v_share_id,
    'projection', v_projection,
    'published', TRUE
  );
END
$publish_share$;

CREATE FUNCTION public.revoke_agent_adoption_share(
  p_adoption_id UUID,
  p_session_token TEXT,
  p_share_id TEXT,
  p_reason TEXT,
  p_revocation_nonce TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $revoke_share$
DECLARE
  v_session agent_adoption_private.adoption_sessions%ROWTYPE;
  v_share agent_adoption_private.public_shares%ROWTYPE;
  v_existing agent_adoption_private.share_revocations%ROWTYPE;
  v_revocation_id UUID;
  v_revoked_at TIMESTAMPTZ;
BEGIN
  IF p_adoption_id IS NULL
    OR p_session_token IS NULL
    OR p_session_token !~ '^eaa1_[0-9a-f]{64}$'
    OR p_share_id IS NULL
    OR p_share_id !~ '^agent_share_[0-9a-f]{40}$'
    OR p_reason IS NULL
    OR pg_catalog.octet_length(pg_catalog.btrim(p_reason)) NOT BETWEEN 1 AND 280
    OR pg_catalog.btrim(p_reason) ~ '[[:cntrl:]]'
    OR p_revocation_nonce IS NULL
    OR p_revocation_nonce !~ '^easrv1_[0-9a-f]{48,128}$'
  THEN
    RAISE EXCEPTION 'share revocation input is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT session.*
  INTO v_session
  FROM agent_adoption_private.adoption_sessions AS session
  WHERE session.adoption_id = p_adoption_id
    AND session.session_token_hash =
      agent_adoption_private.token_hash(p_session_token)
    AND session.expires_at > pg_catalog.clock_timestamp()
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'agent adoption session not found'
      USING ERRCODE = 'P0002';
  END IF;
  SELECT share.*
  INTO v_share
  FROM agent_adoption_private.public_shares AS share
  WHERE share.tenant_id = v_session.tenant_id
    AND share.adoption_id = v_session.adoption_id
    AND share.share_id = p_share_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'public share not found'
      USING ERRCODE = 'P0002';
  END IF;
  SELECT revocation.*
  INTO v_existing
  FROM agent_adoption_private.share_revocations AS revocation
  WHERE revocation.tenant_id = v_session.tenant_id
    AND revocation.adoption_id = v_session.adoption_id
    AND revocation.share_id = v_share.share_id;
  IF v_existing.revocation_id IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object(
      'share_id', v_share.share_id,
      'revocation_id', v_existing.revocation_id,
      'revoked_at', v_existing.revoked_at,
      'revoked', TRUE
    );
  END IF;

  v_revocation_id := pg_catalog.gen_random_uuid();
  v_revoked_at := pg_catalog.transaction_timestamp();
  INSERT INTO agent_adoption_private.share_revocations (
    tenant_id,
    adoption_id,
    share_id,
    revocation_id,
    revocation_nonce_hash,
    reason,
    revoked_at
  ) VALUES (
    v_session.tenant_id,
    v_session.adoption_id,
    v_share.share_id,
    v_revocation_id,
    agent_adoption_private.token_hash(p_revocation_nonce),
    pg_catalog.btrim(p_reason),
    v_revoked_at
  );
  PERFORM agent_adoption_private.append_event(
    v_session.tenant_id,
    v_session.adoption_id,
    'share_revoked',
    pg_catalog.jsonb_build_object(
      'share_id', v_share.share_id,
      'revocation_id', v_revocation_id,
      'reason', pg_catalog.btrim(p_reason)
    )
  );
  RETURN pg_catalog.jsonb_build_object(
    'share_id', v_share.share_id,
    'revocation_id', v_revocation_id,
    'revoked_at', v_revoked_at,
    'revoked', TRUE
  );
END
$revoke_share$;

CREATE FUNCTION public.read_agent_adoption_share(p_share_id TEXT)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $read_share$
DECLARE
  v_projection JSONB;
  v_created_at TIMESTAMPTZ;
  v_adoption_revoked BOOLEAN;
  v_direct_revoked BOOLEAN;
  v_share_revoked BOOLEAN;
  v_revoked_at TIMESTAMPTZ;
BEGIN
  IF p_share_id IS NULL
    OR p_share_id !~ '^agent_share_[0-9a-f]{40}$'
  THEN
    RAISE EXCEPTION 'public share id is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT
    share.public_projection,
    share.created_at,
    adoption_revocation.revocation_id IS NOT NULL,
    share_revocation.revocation_id IS NOT NULL,
    CASE
      WHEN adoption_revocation.revoked_at IS NULL
        THEN share_revocation.revoked_at
      WHEN share_revocation.revoked_at IS NULL
        THEN adoption_revocation.revoked_at
      ELSE LEAST(
        adoption_revocation.revoked_at,
        share_revocation.revoked_at
      )
    END
  INTO
    v_projection,
    v_created_at,
    v_adoption_revoked,
    v_direct_revoked,
    v_revoked_at
  FROM agent_adoption_private.public_shares AS share
  INNER JOIN agent_adoption_private.adoption_sessions AS session
    ON session.tenant_id = share.tenant_id
    AND session.adoption_id = share.adoption_id
    AND session.expires_at > pg_catalog.clock_timestamp()
  LEFT JOIN agent_adoption_private.adoption_revocations AS adoption_revocation
    ON adoption_revocation.tenant_id = share.tenant_id
    AND adoption_revocation.adoption_id = share.adoption_id
  LEFT JOIN agent_adoption_private.share_revocations AS share_revocation
    ON share_revocation.tenant_id = share.tenant_id
    AND share_revocation.adoption_id = share.adoption_id
    AND share_revocation.share_id = share.share_id
  WHERE share.share_id = p_share_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'public share not found'
      USING ERRCODE = 'P0002';
  END IF;
  v_share_revoked := v_adoption_revoked OR v_direct_revoked;
  RETURN pg_catalog.jsonb_build_object(
    'share_id', p_share_id,
    'revoked', v_share_revoked,
    'revoked_at', v_revoked_at,
    'created_at', v_created_at,
    'projection', CASE WHEN v_share_revoked THEN NULL ELSE v_projection END
  );
END
$read_share$;

CREATE FUNCTION public.purge_expired_agent_adoptions(p_limit INTEGER DEFAULT 100)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '10s'
AS $purge_expired$
DECLARE
  v_session RECORD;
  v_purged INTEGER := 0;
BEGIN
  IF p_limit IS NULL OR p_limit < 1 OR p_limit > 500 THEN
    RAISE EXCEPTION 'agent adoption purge limit must be between 1 and 500'
      USING ERRCODE = '22023';
  END IF;

  PERFORM pg_catalog.set_config('app.agent_adoption_retention_purge', 'v1', TRUE);
  FOR v_session IN
    SELECT session.tenant_id, session.adoption_id
    FROM agent_adoption_private.adoption_sessions AS session
    WHERE session.expires_at <= pg_catalog.clock_timestamp()
    ORDER BY session.expires_at, session.tenant_id, session.adoption_id
    LIMIT p_limit
    FOR UPDATE SKIP LOCKED
  LOOP
    DELETE FROM agent_adoption_private.share_revocations
      WHERE tenant_id = v_session.tenant_id AND adoption_id = v_session.adoption_id;
    DELETE FROM agent_adoption_private.public_shares
      WHERE tenant_id = v_session.tenant_id AND adoption_id = v_session.adoption_id;
    DELETE FROM agent_adoption_private.adoption_revocations
      WHERE tenant_id = v_session.tenant_id AND adoption_id = v_session.adoption_id;
    DELETE FROM agent_adoption_private.operating_bonds
      WHERE tenant_id = v_session.tenant_id AND adoption_id = v_session.adoption_id;
    DELETE FROM agent_adoption_private.adoption_events
      WHERE tenant_id = v_session.tenant_id AND adoption_id = v_session.adoption_id;
    DELETE FROM agent_adoption_private.adoption_challenges
      WHERE tenant_id = v_session.tenant_id AND adoption_id = v_session.adoption_id;
    DELETE FROM agent_adoption_private.adoption_credentials
      WHERE tenant_id = v_session.tenant_id AND adoption_id = v_session.adoption_id;
    DELETE FROM agent_adoption_private.adoption_sessions
      WHERE tenant_id = v_session.tenant_id AND adoption_id = v_session.adoption_id;
    v_purged := v_purged + 1;
  END LOOP;
  RETURN v_purged;
END
$purge_expired$;

REVOKE ALL ON FUNCTION agent_adoption_private.token_hash(TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION agent_adoption_private.sha256_json(TEXT, JSONB)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION agent_adoption_private.iso_ms(TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION agent_adoption_private.reject_immutable_mutation()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION agent_adoption_private.adoption_credential_guard()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION agent_adoption_private.adoption_challenge_guard()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION agent_adoption_private.append_event(UUID, UUID, TEXT, JSONB)
  FROM PUBLIC, anon, authenticated, service_role;

REVOKE ALL ON FUNCTION public.create_agent_adoption_session(TEXT, TEXT, TEXT, JSONB, JSONB)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.create_agent_adoption_session(TEXT, TEXT, TEXT, JSONB, JSONB)
  TO service_role;
REVOKE ALL ON FUNCTION public.read_agent_adoption_session(UUID, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.read_agent_adoption_session(UUID, TEXT)
  TO service_role;
REVOKE ALL ON FUNCTION public.create_agent_adoption_registration_challenge(UUID, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.create_agent_adoption_registration_challenge(UUID, TEXT)
  TO service_role;
REVOKE ALL ON FUNCTION public.complete_agent_adoption_registration(UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT[], TEXT, BOOLEAN, BIGINT, BOOLEAN, TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.complete_agent_adoption_registration(UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT[], TEXT, BOOLEAN, BIGINT, BOOLEAN, TEXT, TEXT, TEXT)
  TO service_role;
REVOKE ALL ON FUNCTION public.create_agent_adoption_assertion_challenge(UUID, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.create_agent_adoption_assertion_challenge(UUID, TEXT, TEXT)
  TO service_role;
REVOKE ALL ON FUNCTION public.complete_agent_adoption_assertion(UUID, TEXT, TEXT, TEXT, BIGINT, BOOLEAN, TEXT, BOOLEAN, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.complete_agent_adoption_assertion(UUID, TEXT, TEXT, TEXT, BIGINT, BOOLEAN, TEXT, BOOLEAN, TEXT)
  TO service_role;
REVOKE ALL ON FUNCTION public.read_agent_operating_bond(UUID, TEXT, UUID)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.read_agent_operating_bond(UUID, TEXT, UUID)
  TO service_role;
REVOKE ALL ON FUNCTION public.revoke_agent_adoption(UUID, TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.revoke_agent_adoption(UUID, TEXT, TEXT, TEXT)
  TO service_role;
REVOKE ALL ON FUNCTION public.publish_agent_adoption_share(UUID, TEXT, UUID)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.publish_agent_adoption_share(UUID, TEXT, UUID)
  TO service_role;
REVOKE ALL ON FUNCTION public.revoke_agent_adoption_share(UUID, TEXT, TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.revoke_agent_adoption_share(UUID, TEXT, TEXT, TEXT, TEXT)
  TO service_role;
REVOKE ALL ON FUNCTION public.read_agent_adoption_share(TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.read_agent_adoption_share(TEXT)
  TO service_role;
REVOKE ALL ON FUNCTION public.purge_expired_agent_adoptions(INTEGER)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.purge_expired_agent_adoptions(INTEGER)
  TO service_role;

COMMENT ON SCHEMA agent_adoption_private IS
  'RPC-only custody for the public no-egress Agent Adoption demonstration.';
COMMENT ON TABLE agent_adoption_private.adoption_credentials IS
  'Private adoption credentials, intentionally separate from approver and Class A authority.';
COMMENT ON TABLE agent_adoption_private.operating_bonds IS
  'Immutable no-egress demonstration evidence; not certification or production authority.';
COMMENT ON TABLE agent_adoption_private.adoption_events IS
  'Append-only, per-adoption SHA-256 event chain serialized by the adoption row lock.';
COMMENT ON TABLE agent_adoption_private.adoption_revocations IS
  'One immutable terminal revocation per adoption.';
COMMENT ON TABLE agent_adoption_private.share_revocations IS
  'Append-only public-share revocations; source shares remain immutable.';

RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM agent_adoption_store_owner;
REVOKE agent_adoption_store_owner FROM CURRENT_USER;
