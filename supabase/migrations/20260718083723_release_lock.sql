-- SPDX-License-Identifier: Apache-2.0
-- Migration version: 20260718083723
--
-- Release Lock has two independently consumed exact-action rounds:
--   1. CO_ACCEPTED records acceptance of a retained change order. It can never
--      reserve or invoke a payment/custodian effect.
--   2. DRAW_RELEASE is staged only after CO_ACCEPTED and binds the accepted CO,
--      exact draw/payees, completion evidence, lien waivers, draw documents,
--      and one custodian instruction. Only its completed quorum can reserve an
--      effect.
--
-- The service does not hold funds, inspect work, arbitrate, or establish legal
-- enforceability. Tables are service-only. Raw invitation/session capabilities
-- and raw contact identifiers are never stored.

CREATE TABLE public.release_locks (
  lock_id                 TEXT PRIMARY KEY
    CHECK (lock_id ~ '^rlk_[a-f0-9]{32}$'),
  organization_id         TEXT NOT NULL,
  contractor_entity_id    TEXT NOT NULL,
  current_version         INTEGER NOT NULL DEFAULT 1 CHECK (current_version >= 1),
  frozen_version          INTEGER,
  frozen_round            TEXT CHECK (frozen_round IN ('CO_ACCEPTED', 'DRAW_RELEASE')),
  status                  TEXT NOT NULL DEFAULT 'co_pending'
    CHECK (status IN (
      'co_pending',
      'co_frozen',
      'co_accepted',
      'draw_pending',
      'draw_frozen',
      'effect_reserved',
      'effect_claimed',
      'effect_applied',
      'effect_refused',
      'effect_indeterminate',
      'expired'
    )),
  max_expires_at          TIMESTAMPTZ NOT NULL,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CHECK (
    (frozen_version IS NULL AND frozen_round IS NULL)
    OR (frozen_version IS NOT NULL AND frozen_round IS NOT NULL)
  )
);

CREATE INDEX release_locks_org_idx
  ON public.release_locks (organization_id, created_at DESC);

CREATE TABLE public.release_lock_versions (
  lock_id                 TEXT NOT NULL REFERENCES public.release_locks(lock_id),
  version                 INTEGER NOT NULL CHECK (version >= 1),
  co_action               JSONB NOT NULL CHECK (jsonb_typeof(co_action) = 'object'),
  co_action_hash          TEXT NOT NULL CHECK (co_action_hash ~ '^sha256:[0-9a-f]{64}$'),
  co_material_hash        TEXT NOT NULL CHECK (co_material_hash ~ '^sha256:[0-9a-f]{64}$'),
  document_provider       TEXT NOT NULL,
  document_reference      TEXT NOT NULL,
  document_digest         TEXT NOT NULL CHECK (document_digest ~ '^sha256:[0-9a-f]{64}$'),
  document_evidence       JSONB NOT NULL CHECK (jsonb_typeof(document_evidence) = 'object'),
  expires_at              TIMESTAMPTZ NOT NULL,
  created_by              TEXT NOT NULL,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (lock_id, version),
  UNIQUE (lock_id, co_action_hash),
  CHECK (co_action->>'@version' = 'EP-RELEASE-LOCK-CO-ACTION-v1'),
  CHECK (co_action->>'round' = 'CO_ACCEPTED'),
  CHECK ((co_action->>'lock_id') IS NOT DISTINCT FROM lock_id),
  CHECK (((co_action->>'version')::INTEGER) IS NOT DISTINCT FROM version),
  CHECK (co_action->>'payment_authorization' = 'false'),
  CHECK ((co_action->'retained_change_order'->'document'->>'digest') IS NOT DISTINCT FROM document_digest),
  CHECK ((co_action->>'expires_at')::TIMESTAMPTZ IS NOT DISTINCT FROM expires_at)
);

CREATE TABLE public.release_lock_draw_actions (
  lock_id                 TEXT NOT NULL,
  version                 INTEGER NOT NULL,
  draw_action             JSONB NOT NULL CHECK (jsonb_typeof(draw_action) = 'object'),
  draw_action_hash        TEXT NOT NULL CHECK (draw_action_hash ~ '^sha256:[0-9a-f]{64}$'),
  draw_material_hash      TEXT NOT NULL CHECK (draw_material_hash ~ '^sha256:[0-9a-f]{64}$'),
  accepted_co_action_hash TEXT NOT NULL CHECK (accepted_co_action_hash ~ '^sha256:[0-9a-f]{64}$'),
  accepted_co_digest      TEXT NOT NULL CHECK (accepted_co_digest ~ '^sha256:[0-9a-f]{64}$'),
  completion_digest       TEXT NOT NULL CHECK (completion_digest ~ '^sha256:[0-9a-f]{64}$'),
  lien_waiver_digests     JSONB NOT NULL CHECK (jsonb_typeof(lien_waiver_digests) = 'array'),
  draw_document_digests   JSONB NOT NULL CHECK (jsonb_typeof(draw_document_digests) = 'array'),
  expires_at              TIMESTAMPTZ NOT NULL,
  created_by              TEXT NOT NULL,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (lock_id, version),
  UNIQUE (lock_id, draw_action_hash),
  FOREIGN KEY (lock_id, version)
    REFERENCES public.release_lock_versions(lock_id, version),
  CHECK (draw_action->>'@version' = 'EP-RELEASE-LOCK-DRAW-ACTION-v1'),
  CHECK (draw_action->>'round' = 'DRAW_RELEASE'),
  CHECK ((draw_action->>'lock_id') IS NOT DISTINCT FROM lock_id),
  CHECK (((draw_action->>'version')::INTEGER) IS NOT DISTINCT FROM version),
  CHECK ((draw_action->'accepted_change_order'->>'action_hash') IS NOT DISTINCT FROM accepted_co_action_hash),
  CHECK ((draw_action->'accepted_change_order'->>'acceptance_digest') IS NOT DISTINCT FROM accepted_co_digest),
  CHECK ((draw_action->'evidence_hashes'->>'completion_evidence_hash') IS NOT DISTINCT FROM completion_digest),
  CHECK (draw_action->>'custodian_eligibility' = 'after_complete_draw_release_round'),
  CHECK (draw_action->'custodian'->>'instruction' = 'release_milestone'),
  CHECK ((draw_action->>'expires_at')::TIMESTAMPTZ IS NOT DISTINCT FROM expires_at)
);

CREATE TABLE public.release_lock_round_acceptances (
  lock_id                 TEXT NOT NULL,
  version                 INTEGER NOT NULL,
  round                   TEXT NOT NULL CHECK (round IN ('CO_ACCEPTED', 'DRAW_RELEASE')),
  action_hash             TEXT NOT NULL CHECK (action_hash ~ '^sha256:[0-9a-f]{64}$'),
  acceptance_digest       TEXT NOT NULL CHECK (acceptance_digest ~ '^sha256:[0-9a-f]{64}$'),
  accepted_at             TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (lock_id, version, round),
  UNIQUE (acceptance_digest),
  FOREIGN KEY (lock_id, version)
    REFERENCES public.release_lock_versions(lock_id, version)
);

CREATE TABLE public.release_lock_contact_bindings (
  contact_binding_id      UUID PRIMARY KEY,
  lock_id                 TEXT NOT NULL REFERENCES public.release_locks(lock_id),
  role                    TEXT NOT NULL CHECK (role IN ('contractor', 'customer')),
  channel                 TEXT NOT NULL CHECK (channel IN ('email', 'sms')),
  identifier_digest       TEXT NOT NULL CHECK (identifier_digest ~ '^hmac-sha256:[0-9a-f]{64}$'),
  verification_provider   TEXT NOT NULL,
  verification_reference  TEXT NOT NULL,
  verification_proof_digest TEXT NOT NULL
    CHECK (verification_proof_digest ~ '^hmac-sha256:[0-9a-f]{64}$'),
  verified_at             TIMESTAMPTZ NOT NULL,
  verification_expires_at TIMESTAMPTZ NOT NULL,
  authority_provider      TEXT NOT NULL,
  authority_key_id        TEXT NOT NULL,
  authority_reference     TEXT NOT NULL,
  authority_assertion     JSONB NOT NULL CHECK (jsonb_typeof(authority_assertion) = 'object'),
  authority_signature     TEXT NOT NULL
    CHECK (authority_signature ~ '^[A-Za-z0-9_-]{86}$'),
  authority_assertion_digest TEXT NOT NULL
    CHECK (authority_assertion_digest ~ '^sha256:[0-9a-f]{64}$'),
  authority_subject_digest TEXT NOT NULL
    CHECK (authority_subject_digest ~ '^sha256:[0-9a-f]{64}$'),
  authority_contact_binding_digest TEXT NOT NULL
    CHECK (authority_contact_binding_digest ~ '^hmac-sha256:[0-9a-f]{64}$'),
  authority_verified_at   TIMESTAMPTZ NOT NULL,
  authority_expires_at    TIMESTAMPTZ NOT NULL,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (lock_id, role),
  UNIQUE (lock_id, identifier_digest),
  UNIQUE (lock_id, authority_subject_digest),
  UNIQUE (contact_binding_id, lock_id, role),
  CHECK (verified_at < verification_expires_at),
  CHECK (authority_verified_at < authority_expires_at)
);

CREATE TABLE public.release_lock_invitations (
  invitation_id           UUID PRIMARY KEY,
  lock_id                 TEXT NOT NULL REFERENCES public.release_locks(lock_id),
  role                    TEXT NOT NULL CHECK (role IN ('contractor', 'customer')),
  contact_binding_id      UUID NOT NULL,
  token_digest            TEXT NOT NULL UNIQUE
    CHECK (token_digest ~ '^hmac-sha256:[0-9a-f]{64}$'),
  expires_at              TIMESTAMPTZ NOT NULL,
  activated_at            TIMESTAMPTZ,
  delivery_reference      TEXT,
  delivery_receipt_digest TEXT
    CHECK (delivery_receipt_digest IS NULL OR delivery_receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
  revoked_at              TIMESTAMPTZ,
  revocation_reason       TEXT,
  exchanged_at            TIMESTAMPTZ,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (lock_id, role),
  FOREIGN KEY (contact_binding_id, lock_id, role)
    REFERENCES public.release_lock_contact_bindings(contact_binding_id, lock_id, role),
  CHECK (
    (activated_at IS NULL AND delivery_reference IS NULL AND delivery_receipt_digest IS NULL)
    OR (activated_at IS NOT NULL AND delivery_reference IS NOT NULL AND delivery_receipt_digest IS NOT NULL)
  ),
  CHECK (revoked_at IS NULL OR revocation_reason IS NOT NULL),
  CHECK (exchanged_at IS NULL OR (activated_at IS NOT NULL AND revoked_at IS NULL))
);

CREATE TABLE public.release_lock_sessions (
  session_id              UUID PRIMARY KEY,
  invitation_id           UUID NOT NULL REFERENCES public.release_lock_invitations(invitation_id),
  lock_id                 TEXT NOT NULL REFERENCES public.release_locks(lock_id),
  role                    TEXT NOT NULL CHECK (role IN ('contractor', 'customer')),
  contact_binding_id      UUID NOT NULL,
  scope_round             TEXT CHECK (scope_round IN ('CO_ACCEPTED', 'DRAW_RELEASE')),
  scope_version           INTEGER CHECK (scope_version >= 1),
  scope_action_hash       TEXT
    CHECK (scope_action_hash IS NULL OR scope_action_hash ~ '^sha256:[0-9a-f]{64}$'),
  token_digest            TEXT NOT NULL UNIQUE
    CHECK (token_digest ~ '^hmac-sha256:[0-9a-f]{64}$'),
  expires_at              TIMESTAMPTZ NOT NULL,
  revoked_at              TIMESTAMPTZ,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (contact_binding_id, lock_id, role)
    REFERENCES public.release_lock_contact_bindings(contact_binding_id, lock_id, role),
  FOREIGN KEY (lock_id, scope_version)
    REFERENCES public.release_lock_versions(lock_id, version),
  CHECK (
    (scope_round IS NULL AND scope_version IS NULL AND scope_action_hash IS NULL)
    OR (scope_round IS NOT NULL AND scope_version IS NOT NULL AND scope_action_hash IS NOT NULL)
  )
);

CREATE INDEX release_lock_sessions_scope_idx
  ON public.release_lock_sessions (
    lock_id, role, scope_round, scope_version, scope_action_hash, expires_at
  );

CREATE TABLE public.release_lock_pairings (
  pairing_id              UUID PRIMARY KEY,
  source_session_id       UUID NOT NULL REFERENCES public.release_lock_sessions(session_id),
  lock_id                 TEXT NOT NULL REFERENCES public.release_locks(lock_id),
  role                    TEXT NOT NULL CHECK (role IN ('contractor', 'customer')),
  contact_binding_id      UUID NOT NULL,
  round                   TEXT NOT NULL CHECK (round IN ('CO_ACCEPTED', 'DRAW_RELEASE')),
  version                 INTEGER NOT NULL CHECK (version >= 1),
  action_hash             TEXT NOT NULL CHECK (action_hash ~ '^sha256:[0-9a-f]{64}$'),
  lock_status             TEXT NOT NULL,
  token_digest            TEXT NOT NULL UNIQUE
    CHECK (token_digest ~ '^hmac-sha256:[0-9a-f]{64}$'),
  expires_at              TIMESTAMPTZ NOT NULL,
  exchanged_at            TIMESTAMPTZ,
  revoked_at              TIMESTAMPTZ,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (contact_binding_id, lock_id, role)
    REFERENCES public.release_lock_contact_bindings(contact_binding_id, lock_id, role),
  FOREIGN KEY (lock_id, version)
    REFERENCES public.release_lock_versions(lock_id, version),
  CHECK (created_at < expires_at),
  CHECK (
    (round = 'CO_ACCEPTED' AND lock_status IN ('co_pending', 'co_frozen'))
    OR (round = 'DRAW_RELEASE' AND lock_status IN ('draw_pending', 'draw_frozen'))
  )
);

CREATE INDEX release_lock_pairings_scope_idx
  ON public.release_lock_pairings (
    lock_id, role, round, version, action_hash, expires_at
  );

CREATE UNIQUE INDEX release_lock_pairings_one_live_idx
  ON public.release_lock_pairings (source_session_id, role, round, version)
  WHERE exchanged_at IS NULL AND revoked_at IS NULL;

CREATE TABLE public.release_lock_registration_challenges (
  challenge_id            UUID PRIMARY KEY,
  session_id              UUID NOT NULL REFERENCES public.release_lock_sessions(session_id),
  lock_id                 TEXT NOT NULL REFERENCES public.release_locks(lock_id),
  role                    TEXT NOT NULL CHECK (role IN ('contractor', 'customer')),
  contact_binding_id      UUID NOT NULL,
  challenge               TEXT NOT NULL UNIQUE,
  rp_id                   TEXT NOT NULL,
  origin                  TEXT NOT NULL,
  expires_at              TIMESTAMPTZ NOT NULL,
  consumed_at             TIMESTAMPTZ,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (contact_binding_id, lock_id, role)
    REFERENCES public.release_lock_contact_bindings(contact_binding_id, lock_id, role)
);

CREATE TABLE public.release_lock_credentials (
  credential_id           TEXT PRIMARY KEY,
  lock_id                 TEXT NOT NULL REFERENCES public.release_locks(lock_id),
  role                    TEXT NOT NULL CHECK (role IN ('contractor', 'customer')),
  contact_binding_id      UUID NOT NULL,
  public_key_cose         TEXT NOT NULL,
  public_key_spki         TEXT NOT NULL,
  sign_count              BIGINT NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
  transports              JSONB,
  device_type             TEXT,
  backed_up               BOOLEAN NOT NULL DEFAULT FALSE,
  attestation_format      TEXT,
  rp_id                   TEXT NOT NULL,
  origin                  TEXT NOT NULL,
  enrolled_at             TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  revoked_at              TIMESTAMPTZ,
  UNIQUE (lock_id, role),
  UNIQUE (lock_id, contact_binding_id),
  FOREIGN KEY (contact_binding_id, lock_id, role)
    REFERENCES public.release_lock_contact_bindings(contact_binding_id, lock_id, role)
);

CREATE TABLE public.release_lock_action_challenges (
  challenge_id            UUID PRIMARY KEY,
  session_id              UUID NOT NULL REFERENCES public.release_lock_sessions(session_id),
  lock_id                 TEXT NOT NULL,
  version                 INTEGER NOT NULL,
  round                   TEXT NOT NULL CHECK (round IN ('CO_ACCEPTED', 'DRAW_RELEASE')),
  role                    TEXT NOT NULL CHECK (role IN ('contractor', 'customer')),
  contact_binding_id      UUID NOT NULL,
  credential_id           TEXT NOT NULL REFERENCES public.release_lock_credentials(credential_id),
  action_hash             TEXT NOT NULL CHECK (action_hash ~ '^sha256:[0-9a-f]{64}$'),
  prompt_set              JSONB NOT NULL CHECK (jsonb_typeof(prompt_set) = 'object'),
  prompt_set_digest       TEXT NOT NULL CHECK (prompt_set_digest ~ '^sha256:[0-9a-f]{64}$'),
  answer_digest           TEXT NOT NULL CHECK (answer_digest ~ '^sha256:[0-9a-f]{64}$'),
  binding_moment          JSONB NOT NULL CHECK (jsonb_typeof(binding_moment) = 'object'),
  random_nonce            TEXT NOT NULL,
  nonce                   TEXT NOT NULL UNIQUE,
  resolution_context      JSONB NOT NULL CHECK (jsonb_typeof(resolution_context) = 'object'),
  challenge               TEXT NOT NULL UNIQUE,
  issued_at               TIMESTAMPTZ NOT NULL,
  expires_at              TIMESTAMPTZ NOT NULL,
  consumed_at             TIMESTAMPTZ,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (lock_id, version)
    REFERENCES public.release_lock_versions(lock_id, version),
  FOREIGN KEY (contact_binding_id, lock_id, role)
    REFERENCES public.release_lock_contact_bindings(contact_binding_id, lock_id, role),
  CHECK (issued_at < expires_at),
  CHECK ((prompt_set->>'round') IS NOT DISTINCT FROM round),
  CHECK ((resolution_context->>'action_hash') IS NOT DISTINCT FROM action_hash),
  CHECK ((resolution_context->>'nonce') IS NOT DISTINCT FROM nonce),
  CHECK ((resolution_context->>'principal_key_id') IS NOT DISTINCT FROM credential_id)
);

CREATE INDEX release_lock_action_challenges_live_idx
  ON public.release_lock_action_challenges (lock_id, version, round, role, expires_at)
  WHERE consumed_at IS NULL;

CREATE TABLE public.release_lock_decisions (
  decision_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  lock_id                 TEXT NOT NULL,
  version                 INTEGER NOT NULL,
  round                   TEXT NOT NULL CHECK (round IN ('CO_ACCEPTED', 'DRAW_RELEASE')),
  role                    TEXT NOT NULL CHECK (role IN ('contractor', 'customer')),
  challenge_id            UUID NOT NULL UNIQUE
    REFERENCES public.release_lock_action_challenges(challenge_id),
  contact_binding_id      UUID NOT NULL,
  credential_id           TEXT NOT NULL REFERENCES public.release_lock_credentials(credential_id),
  action_hash             TEXT NOT NULL CHECK (action_hash ~ '^sha256:[0-9a-f]{64}$'),
  prompt_set_digest       TEXT NOT NULL CHECK (prompt_set_digest ~ '^sha256:[0-9a-f]{64}$'),
  answer_digest           TEXT NOT NULL CHECK (answer_digest ~ '^sha256:[0-9a-f]{64}$'),
  submitted_answers       JSONB NOT NULL CHECK (jsonb_typeof(submitted_answers) = 'array'),
  resolution              JSONB NOT NULL CHECK (jsonb_typeof(resolution) = 'object'),
  resolution_digest       TEXT NOT NULL CHECK (resolution_digest ~ '^sha256:[0-9a-f]{64}$'),
  sign_count              BIGINT NOT NULL CHECK (sign_count >= 0),
  decided_at              TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (lock_id, version, round, role),
  UNIQUE (lock_id, version, round, credential_id),
  UNIQUE (lock_id, version, round, contact_binding_id),
  FOREIGN KEY (lock_id, version)
    REFERENCES public.release_lock_versions(lock_id, version),
  FOREIGN KEY (contact_binding_id, lock_id, role)
    REFERENCES public.release_lock_contact_bindings(contact_binding_id, lock_id, role)
);

CREATE TABLE public.release_lock_decision_invalidations (
  decision_id             UUID PRIMARY KEY REFERENCES public.release_lock_decisions(decision_id),
  lock_id                 TEXT NOT NULL,
  invalidated_version     INTEGER NOT NULL CHECK (invalidated_version >= 1),
  invalidated_round       TEXT NOT NULL CHECK (invalidated_round IN ('CO_ACCEPTED', 'DRAW_RELEASE')),
  superseded_by_version   INTEGER NOT NULL CHECK (superseded_by_version >= 2),
  reason                  TEXT NOT NULL CHECK (reason = 'amended'),
  invalidated_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CHECK (superseded_by_version > invalidated_version)
);

CREATE TABLE public.release_lock_effects (
  effect_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  lock_id                 TEXT NOT NULL,
  version                 INTEGER NOT NULL,
  draw_action_hash        TEXT NOT NULL CHECK (draw_action_hash ~ '^sha256:[0-9a-f]{64}$'),
  draw_acceptance_digest  TEXT NOT NULL CHECK (draw_acceptance_digest ~ '^sha256:[0-9a-f]{64}$'),
  effect_reference        TEXT NOT NULL UNIQUE,
  provider                TEXT NOT NULL,
  environment             TEXT NOT NULL CHECK (environment IN ('sandbox', 'production')),
  transaction_id          TEXT NOT NULL,
  milestone_id            TEXT NOT NULL,
  instruction             TEXT NOT NULL CHECK (instruction = 'release_milestone'),
  effect_contract         JSONB,
  effect_contract_digest  TEXT
    CHECK (effect_contract_digest IS NULL OR effect_contract_digest ~ '^sha256:[0-9a-f]{64}$'),
  status                  TEXT NOT NULL DEFAULT 'reserved'
    CHECK (status IN ('reserved', 'claimed', 'applied', 'refused', 'indeterminate', 'released')),
  provider_result         JSONB,
  reserved_at             TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  reservation_expires_at  TIMESTAMPTZ NOT NULL
    DEFAULT (clock_timestamp() + INTERVAL '2 minutes'),
  reservation_attempts    INTEGER NOT NULL DEFAULT 1
    CHECK (reservation_attempts BETWEEN 1 AND 3),
  claim_attempts          INTEGER NOT NULL DEFAULT 0
    CHECK (claim_attempts BETWEEN 0 AND 3),
  retryable               BOOLEAN NOT NULL DEFAULT FALSE,
  claimed_at              TIMESTAMPTZ,
  released_at             TIMESTAMPTZ,
  last_recovery_at        TIMESTAMPTZ,
  recovery_evidence       JSONB,
  completed_at            TIMESTAMPTZ,
  reconciled_at           TIMESTAMPTZ,
  UNIQUE (lock_id, version),
  FOREIGN KEY (lock_id, version)
    REFERENCES public.release_lock_draw_actions(lock_id, version),
  CHECK (reserved_at < reservation_expires_at),
  CHECK (
    (effect_contract IS NULL AND effect_contract_digest IS NULL)
    OR (jsonb_typeof(effect_contract) = 'object' AND effect_contract_digest IS NOT NULL)
  ),
  CHECK (released_at IS NULL OR status = 'released'),
  CHECK (recovery_evidence IS NULL OR jsonb_typeof(recovery_evidence) = 'array')
);

CREATE OR REPLACE FUNCTION public.release_lock_refuse_immutable_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
  RAISE EXCEPTION 'RL_IMMUTABLE_RECORD' USING ERRCODE = 'P0001';
END;
$$;

CREATE TRIGGER release_lock_versions_immutable
  BEFORE UPDATE OR DELETE ON public.release_lock_versions
  FOR EACH ROW EXECUTE FUNCTION public.release_lock_refuse_immutable_mutation();
CREATE TRIGGER release_lock_draw_actions_immutable
  BEFORE UPDATE OR DELETE ON public.release_lock_draw_actions
  FOR EACH ROW EXECUTE FUNCTION public.release_lock_refuse_immutable_mutation();
CREATE TRIGGER release_lock_acceptances_immutable
  BEFORE UPDATE OR DELETE ON public.release_lock_round_acceptances
  FOR EACH ROW EXECUTE FUNCTION public.release_lock_refuse_immutable_mutation();
CREATE TRIGGER release_lock_contacts_immutable
  BEFORE UPDATE OR DELETE ON public.release_lock_contact_bindings
  FOR EACH ROW EXECUTE FUNCTION public.release_lock_refuse_immutable_mutation();
CREATE TRIGGER release_lock_decisions_immutable
  BEFORE UPDATE OR DELETE ON public.release_lock_decisions
  FOR EACH ROW EXECUTE FUNCTION public.release_lock_refuse_immutable_mutation();
CREATE TRIGGER release_lock_invalidations_immutable
  BEFORE UPDATE OR DELETE ON public.release_lock_decision_invalidations
  FOR EACH ROW EXECUTE FUNCTION public.release_lock_refuse_immutable_mutation();

ALTER TABLE public.release_locks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.release_locks FORCE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_draw_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_draw_actions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_round_acceptances ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_round_acceptances FORCE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_contact_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_contact_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_invitations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_pairings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_pairings FORCE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_registration_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_registration_challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_credentials FORCE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_action_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_action_challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_decisions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_decision_invalidations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_decision_invalidations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_effects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.release_lock_effects FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.release_locks FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_versions FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_draw_actions FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_round_acceptances FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_contact_bindings FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_invitations FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_sessions FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_pairings FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_registration_challenges FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_credentials FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_action_challenges FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_decisions FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_decision_invalidations FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_effects FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.release_lock_refuse_immutable_mutation()
  FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.release_lock_acceptance_digest(
  p_lock_id TEXT,
  p_version INTEGER,
  p_round TEXT,
  p_action_hash TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_members TEXT;
BEGIN
  SELECT string_agg(d.role || ':' || d.resolution_digest, '|' ORDER BY d.role)
  INTO v_members
  FROM public.release_lock_decisions d
  LEFT JOIN public.release_lock_decision_invalidations i
    ON i.decision_id = d.decision_id
  WHERE d.lock_id = p_lock_id
    AND d.version = p_version
    AND d.round = p_round
    AND d.action_hash = p_action_hash
    AND i.decision_id IS NULL;
  IF v_members IS NULL OR (
    SELECT count(*)
    FROM public.release_lock_decisions d
    LEFT JOIN public.release_lock_decision_invalidations i
      ON i.decision_id = d.decision_id
    WHERE d.lock_id = p_lock_id
      AND d.version = p_version
      AND d.round = p_round
      AND d.action_hash = p_action_hash
      AND i.decision_id IS NULL
  ) <> 2 THEN
    RAISE EXCEPTION 'RL_APPROVAL_LIMIT' USING ERRCODE = 'P0001';
  END IF;
  RETURN 'sha256:' || encode(digest(
    convert_to(
      'EP-RELEASE-LOCK-ROUND-ACCEPTANCE-v1' || chr(31)
        || p_lock_id || chr(31)
        || p_version::TEXT || chr(31)
        || p_round || chr(31)
        || p_action_hash || chr(31)
        || v_members,
      'UTF8'
    ),
    'sha256'
  ), 'hex');
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_acceptance_digest(TEXT, INTEGER, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.release_lock_create_pending(
  p_lock_id TEXT,
  p_organization_id TEXT,
  p_contractor_entity_id TEXT,
  p_co_action JSONB,
  p_co_action_hash TEXT,
  p_co_material_hash TEXT,
  p_document_evidence JSONB,
  p_contacts JSONB,
  p_invitations JSONB,
  p_max_expires_at TIMESTAMPTZ,
  p_created_by TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_contact JSONB;
  v_invitation JSONB;
  v_co_expires_at TIMESTAMPTZ;
  v_roles TEXT[];
BEGIN
  IF p_lock_id IS NULL
     OR p_lock_id !~ '^rlk_[a-f0-9]{32}$'
     OR p_organization_id IS NULL
     OR length(p_organization_id) = 0
     OR p_contractor_entity_id IS NULL
     OR length(p_contractor_entity_id) = 0
     OR p_created_by IS DISTINCT FROM p_contractor_entity_id
     OR jsonb_typeof(p_co_action) IS DISTINCT FROM 'object'
     OR p_co_action->>'@version' IS DISTINCT FROM 'EP-RELEASE-LOCK-CO-ACTION-v1'
     OR p_co_action->>'round' IS DISTINCT FROM 'CO_ACCEPTED'
     OR p_co_action->>'payment_authorization' IS DISTINCT FROM 'false'
     OR p_co_action->>'lock_id' IS DISTINCT FROM p_lock_id
     OR p_co_action->>'version' IS DISTINCT FROM '1'
     OR p_co_action_hash !~ '^sha256:[0-9a-f]{64}$'
     OR p_co_material_hash !~ '^sha256:[0-9a-f]{64}$'
     OR jsonb_typeof(p_document_evidence) IS DISTINCT FROM 'object'
     OR jsonb_typeof(p_contacts) IS DISTINCT FROM 'array'
     OR jsonb_array_length(p_contacts) <> 2
     OR jsonb_typeof(p_invitations) IS DISTINCT FROM 'array'
     OR jsonb_array_length(p_invitations) <> 2
     OR p_max_expires_at IS NULL
     OR p_max_expires_at <= clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;
  BEGIN
    v_co_expires_at := (p_co_action->>'expires_at')::TIMESTAMPTZ;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END;
  IF v_co_expires_at <= clock_timestamp() OR v_co_expires_at > p_max_expires_at THEN
    RAISE EXCEPTION 'RL_LOCK_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  SELECT array_agg(value->>'role' ORDER BY value->>'role')
  INTO v_roles
  FROM jsonb_array_elements(p_contacts);
  IF v_roles IS DISTINCT FROM ARRAY['contractor', 'customer']::TEXT[] THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;
  IF (
    SELECT count(DISTINCT value->>'authority_subject_digest')
    FROM jsonb_array_elements(p_contacts)
  ) <> 2 THEN
    RAISE EXCEPTION 'RL_AUTHORITY_REUSED' USING ERRCODE = 'P0002';
  END IF;

  INSERT INTO public.release_locks (
    lock_id,
    organization_id,
    contractor_entity_id,
    max_expires_at
  ) VALUES (
    p_lock_id,
    p_organization_id,
    p_contractor_entity_id,
    p_max_expires_at
  );
  INSERT INTO public.release_lock_versions (
    lock_id,
    version,
    co_action,
    co_action_hash,
    co_material_hash,
    document_provider,
    document_reference,
    document_digest,
    document_evidence,
    expires_at,
    created_by
  ) VALUES (
    p_lock_id,
    1,
    p_co_action,
    p_co_action_hash,
    p_co_material_hash,
    p_co_action->'retained_change_order'->'document'->>'provider',
    p_co_action->'retained_change_order'->'document'->>'reference',
    p_co_action->'retained_change_order'->'document'->>'digest',
    p_document_evidence,
    v_co_expires_at,
    p_created_by
  );

  FOR v_contact IN SELECT value FROM jsonb_array_elements(p_contacts)
  LOOP
    IF v_contact->>'role' NOT IN ('contractor', 'customer')
       OR v_contact->>'contact_binding_id' IS NULL
       OR v_contact->>'channel' NOT IN ('email', 'sms')
       OR v_contact->>'identifier_digest' !~ '^hmac-sha256:[0-9a-f]{64}$'
       OR v_contact->>'verification_provider' IS NULL
       OR v_contact->>'verification_reference' IS NULL
       OR v_contact->>'verification_proof_digest' !~ '^hmac-sha256:[0-9a-f]{64}$'
       OR (v_contact->>'verified_at')::TIMESTAMPTZ > clock_timestamp()
       OR (v_contact->>'verification_expires_at')::TIMESTAMPTZ <= clock_timestamp()
       OR (v_contact->>'verification_expires_at')::TIMESTAMPTZ < p_max_expires_at
       OR v_contact->>'authority_provider' IS NULL
       OR v_contact->>'authority_key_id' IS NULL
       OR v_contact->>'authority_reference' IS NULL
       OR jsonb_typeof(v_contact->'authority_assertion') IS DISTINCT FROM 'object'
       OR v_contact->>'authority_signature' !~ '^[A-Za-z0-9_-]{86}$'
       OR v_contact->>'authority_assertion_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR v_contact->>'authority_subject_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR v_contact->>'authority_contact_binding_digest' !~ '^hmac-sha256:[0-9a-f]{64}$'
       OR v_contact->>'authority_contact_binding_digest'
         IS DISTINCT FROM v_contact->>'identifier_digest'
       OR v_contact->'authority_assertion'->>'@version'
         IS DISTINCT FROM 'EP-RELEASE-LOCK-AUTHORITY-ASSERTION-v1'
       OR v_contact->'authority_assertion'->>'algorithm' IS DISTINCT FROM 'Ed25519'
       OR v_contact->'authority_assertion'->>'provider'
         IS DISTINCT FROM v_contact->>'authority_provider'
       OR v_contact->'authority_assertion'->>'key_id'
         IS DISTINCT FROM v_contact->>'authority_key_id'
       OR v_contact->'authority_assertion'->>'reference'
         IS DISTINCT FROM v_contact->>'authority_reference'
       OR v_contact->'authority_assertion'->>'role'
         IS DISTINCT FROM v_contact->>'role'
       OR v_contact->'authority_assertion'->>'subject_digest'
         IS DISTINCT FROM v_contact->>'authority_subject_digest'
       OR v_contact->'authority_assertion'->>'contact_binding_digest'
         IS DISTINCT FROM v_contact->>'identifier_digest'
       OR NOT EXISTS (
         SELECT 1
         FROM jsonb_array_elements(p_co_action->'parties') AS p(value)
         WHERE p.value->>'role' = v_contact->>'role'
           AND p.value->>'party_id'
             = v_contact->'authority_assertion'->>'party_id'
           AND p.value->'authority'->'assertion'
             = v_contact->'authority_assertion'
           AND p.value->'authority'->>'signature'
             = v_contact->>'authority_signature'
       )
       OR (v_contact->>'authority_verified_at')::TIMESTAMPTZ > clock_timestamp()
       OR (v_contact->>'authority_expires_at')::TIMESTAMPTZ <= clock_timestamp()
       OR (v_contact->>'authority_expires_at')::TIMESTAMPTZ < p_max_expires_at
       OR v_contact->'authority_assertion'->>'verified_at'
         IS DISTINCT FROM v_contact->>'authority_verified_at'
       OR v_contact->'authority_assertion'->>'expires_at'
         IS DISTINCT FROM v_contact->>'authority_expires_at'
    THEN
      RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
    END IF;
    INSERT INTO public.release_lock_contact_bindings (
      contact_binding_id,
      lock_id,
      role,
      channel,
      identifier_digest,
      verification_provider,
      verification_reference,
      verification_proof_digest,
      verified_at,
      verification_expires_at,
      authority_provider,
      authority_key_id,
      authority_reference,
      authority_assertion,
      authority_signature,
      authority_assertion_digest,
      authority_subject_digest,
      authority_contact_binding_digest,
      authority_verified_at,
      authority_expires_at
    ) VALUES (
      (v_contact->>'contact_binding_id')::UUID,
      p_lock_id,
      v_contact->>'role',
      v_contact->>'channel',
      v_contact->>'identifier_digest',
      v_contact->>'verification_provider',
      v_contact->>'verification_reference',
      v_contact->>'verification_proof_digest',
      (v_contact->>'verified_at')::TIMESTAMPTZ,
      (v_contact->>'verification_expires_at')::TIMESTAMPTZ,
      v_contact->>'authority_provider',
      v_contact->>'authority_key_id',
      v_contact->>'authority_reference',
      v_contact->'authority_assertion',
      v_contact->>'authority_signature',
      v_contact->>'authority_assertion_digest',
      v_contact->>'authority_subject_digest',
      v_contact->>'authority_contact_binding_digest',
      (v_contact->>'authority_verified_at')::TIMESTAMPTZ,
      (v_contact->>'authority_expires_at')::TIMESTAMPTZ
    );
  END LOOP;

  SELECT array_agg(value->>'role' ORDER BY value->>'role')
  INTO v_roles
  FROM jsonb_array_elements(p_invitations);
  IF v_roles IS DISTINCT FROM ARRAY['contractor', 'customer']::TEXT[] THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;
  FOR v_invitation IN SELECT value FROM jsonb_array_elements(p_invitations)
  LOOP
    IF v_invitation->>'role' NOT IN ('contractor', 'customer')
       OR v_invitation->>'invitation_id' IS NULL
       OR v_invitation->>'contact_binding_id' IS NULL
       OR v_invitation->>'token_digest' !~ '^hmac-sha256:[0-9a-f]{64}$'
       OR (v_invitation->>'expires_at')::TIMESTAMPTZ <= clock_timestamp()
       OR (v_invitation->>'expires_at')::TIMESTAMPTZ > p_max_expires_at
    THEN
      RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
    END IF;
    INSERT INTO public.release_lock_invitations (
      invitation_id,
      lock_id,
      role,
      contact_binding_id,
      token_digest,
      expires_at
    ) VALUES (
      (v_invitation->>'invitation_id')::UUID,
      p_lock_id,
      v_invitation->>'role',
      (v_invitation->>'contact_binding_id')::UUID,
      v_invitation->>'token_digest',
      (v_invitation->>'expires_at')::TIMESTAMPTZ
    );
  END LOOP;

  RETURN jsonb_build_object(
    'lock_id', p_lock_id,
    'version', 1,
    'round', 'CO_ACCEPTED',
    'co_action_hash', p_co_action_hash,
    'status', 'co_pending',
    'invitation_state', 'pending_activation',
    'co_expires_at', v_co_expires_at,
    'lock_expires_at', p_max_expires_at
  );
EXCEPTION
  WHEN unique_violation OR foreign_key_violation OR check_violation OR invalid_text_representation THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_create_pending(
  TEXT, TEXT, TEXT, JSONB, TEXT, TEXT, JSONB, JSONB, JSONB, TIMESTAMPTZ, TEXT
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_create_pending(
  TEXT, TEXT, TEXT, JSONB, TEXT, TEXT, JSONB, JSONB, JSONB, TIMESTAMPTZ, TEXT
) TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_activate_invitations(
  p_lock_id TEXT,
  p_organization_id TEXT,
  p_invitation_ids JSONB,
  p_delivery_receipts JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_lock public.release_locks%ROWTYPE;
  v_delivery JSONB;
  v_invitation public.release_lock_invitations%ROWTYPE;
  v_contact public.release_lock_contact_bindings%ROWTYPE;
  v_invitation_id UUID;
  v_delivery_digest TEXT;
  v_index INTEGER;
BEGIN
  IF p_lock_id !~ '^rlk_[a-f0-9]{32}$'
     OR jsonb_typeof(p_invitation_ids) IS DISTINCT FROM 'array'
     OR jsonb_array_length(p_invitation_ids) <> 2
     OR jsonb_typeof(p_delivery_receipts) IS DISTINCT FROM 'array'
     OR jsonb_array_length(p_delivery_receipts) <> 2
  THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;
  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = p_lock_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_LOCK_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.organization_id IS DISTINCT FROM p_organization_id THEN
    RAISE EXCEPTION 'RL_ORGANIZATION_MISMATCH' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.max_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_LOCK_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  IF (
    SELECT count(DISTINCT value #>> '{}')
    FROM jsonb_array_elements(p_invitation_ids)
  ) <> 2 THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;

  FOR v_index IN 0..1
  LOOP
    BEGIN
      v_invitation_id := (p_invitation_ids->>v_index)::UUID;
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
    END;
    v_delivery := p_delivery_receipts->v_index;
    IF jsonb_typeof(v_delivery) IS DISTINCT FROM 'object'
       OR v_delivery->>'role' NOT IN ('contractor', 'customer')
       OR v_delivery->>'channel' NOT IN ('email', 'sms')
       OR length(COALESCE(v_delivery->>'provider', '')) = 0
       OR length(COALESCE(v_delivery->>'reference', '')) = 0
       OR v_delivery->>'delivered' IS DISTINCT FROM 'true'
    THEN
      RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
    END IF;
    SELECT *
    INTO v_invitation
    FROM public.release_lock_invitations
    WHERE invitation_id = v_invitation_id
      AND lock_id = p_lock_id
    FOR UPDATE;
    IF NOT FOUND
       OR v_invitation.activated_at IS NOT NULL
       OR v_invitation.revoked_at IS NOT NULL
       OR v_invitation.exchanged_at IS NOT NULL
       OR v_invitation.expires_at <= clock_timestamp()
    THEN
      RAISE EXCEPTION 'RL_INVITATION_INACTIVE' USING ERRCODE = 'P0002';
    END IF;
    SELECT *
    INTO STRICT v_contact
    FROM public.release_lock_contact_bindings
    WHERE contact_binding_id = v_invitation.contact_binding_id;
    IF v_delivery->>'role' IS DISTINCT FROM v_invitation.role
       OR v_delivery->>'channel' IS DISTINCT FROM v_contact.channel
    THEN
      RAISE EXCEPTION 'RL_INVITATION_SCOPE' USING ERRCODE = 'P0002';
    END IF;
    v_delivery_digest := 'sha256:' || encode(digest(
      convert_to(
        'EP-RELEASE-LOCK-INVITATION-DELIVERY-v1' || chr(31)
          || p_lock_id || chr(31)
          || v_invitation.invitation_id::TEXT || chr(31)
          || v_invitation.role || chr(31)
          || (v_delivery->>'channel') || chr(31)
          || (v_delivery->>'provider') || chr(31)
          || (v_delivery->>'reference'),
        'UTF8'
      ),
      'sha256'
    ), 'hex');
    UPDATE public.release_lock_invitations
    SET activated_at = clock_timestamp(),
        delivery_reference = (v_delivery->>'provider') || ':' || (v_delivery->>'reference'),
        delivery_receipt_digest = v_delivery_digest
    WHERE invitation_id = v_invitation.invitation_id
      AND activated_at IS NULL
      AND revoked_at IS NULL
      AND exchanged_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'RL_INVITATION_INACTIVE' USING ERRCODE = 'P0002';
    END IF;
  END LOOP;

  IF (
    SELECT count(*)
    FROM public.release_lock_invitations
    WHERE lock_id = p_lock_id
      AND activated_at IS NOT NULL
      AND revoked_at IS NULL
      AND exchanged_at IS NULL
  ) <> 2 THEN
    RAISE EXCEPTION 'RL_INVITATION_INACTIVE' USING ERRCODE = 'P0002';
  END IF;
  RETURN jsonb_build_object(
    'lock_id', p_lock_id,
    'version', v_lock.current_version,
    'round', 'CO_ACCEPTED',
    'status', v_lock.status,
    'invitation_state', 'active',
    'activated_count', 2
  );
EXCEPTION
  WHEN invalid_text_representation OR check_violation OR foreign_key_violation THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_activate_invitations(
  TEXT, TEXT, JSONB, JSONB
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_activate_invitations(
  TEXT, TEXT, JSONB, JSONB
) TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_cancel_pending(
  p_lock_id TEXT,
  p_organization_id TEXT,
  p_reason_code TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_lock public.release_locks%ROWTYPE;
  v_revoked INTEGER;
BEGIN
  IF p_lock_id !~ '^rlk_[a-f0-9]{32}$'
     OR p_reason_code NOT IN (
       'INVITATION_DELIVERY_FAILED',
       'INVITATION_ACTIVATION_FAILED'
     )
  THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;
  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = p_lock_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_LOCK_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.organization_id IS DISTINCT FROM p_organization_id THEN
    RAISE EXCEPTION 'RL_ORGANIZATION_MISMATCH' USING ERRCODE = 'P0002';
  END IF;
  UPDATE public.release_lock_invitations
  SET revoked_at = clock_timestamp(),
      revocation_reason = p_reason_code
  WHERE lock_id = p_lock_id
    AND exchanged_at IS NULL
    AND revoked_at IS NULL;
  GET DIAGNOSTICS v_revoked = ROW_COUNT;
  UPDATE public.release_locks
  SET status = 'expired',
      updated_at = clock_timestamp()
  WHERE lock_id = p_lock_id
    AND status = 'co_pending';
  RETURN jsonb_build_object(
    'lock_id', p_lock_id,
    'status', 'cancelled',
    'invitation_state', 'revoked',
    'revoked_count', v_revoked
  );
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_cancel_pending(
  TEXT, TEXT, TEXT
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_cancel_pending(
  TEXT, TEXT, TEXT
) TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_exchange_invitation(
  p_token_digest TEXT,
  p_session_id UUID,
  p_session_digest TEXT,
  p_expected_lock_id TEXT,
  p_expected_role TEXT,
  p_session_expires_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_invitation public.release_lock_invitations%ROWTYPE;
  v_lock public.release_locks%ROWTYPE;
  v_contact public.release_lock_contact_bindings%ROWTYPE;
  v_session_expires_at TIMESTAMPTZ;
BEGIN
  IF p_token_digest !~ '^hmac-sha256:[0-9a-f]{64}$'
     OR p_session_digest !~ '^hmac-sha256:[0-9a-f]{64}$'
     OR p_expected_lock_id !~ '^rlk_[a-f0-9]{32}$'
     OR p_expected_role NOT IN ('contractor', 'customer')
     OR p_session_expires_at IS NULL
  THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;

  SELECT *
  INTO v_invitation
  FROM public.release_lock_invitations
  WHERE token_digest = p_token_digest
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_INVITATION_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_invitation.lock_id IS DISTINCT FROM p_expected_lock_id
     OR v_invitation.role IS DISTINCT FROM p_expected_role
  THEN
    RAISE EXCEPTION 'RL_INVITATION_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  IF v_invitation.activated_at IS NULL
     OR v_invitation.delivery_reference IS NULL
     OR v_invitation.delivery_receipt_digest IS NULL
     OR v_invitation.revoked_at IS NOT NULL
  THEN
    RAISE EXCEPTION 'RL_INVITATION_INACTIVE' USING ERRCODE = 'P0002';
  END IF;
  IF v_invitation.exchanged_at IS NOT NULL THEN
    RAISE EXCEPTION 'RL_INVITATION_REPLAYED' USING ERRCODE = 'P0002';
  END IF;
  IF v_invitation.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_INVITATION_EXPIRED' USING ERRCODE = 'P0002';
  END IF;

  SELECT *
  INTO STRICT v_lock
  FROM public.release_locks
  WHERE lock_id = v_invitation.lock_id
  FOR UPDATE;
  SELECT *
  INTO STRICT v_contact
  FROM public.release_lock_contact_bindings
  WHERE contact_binding_id = v_invitation.contact_binding_id;

  IF v_lock.max_expires_at <= clock_timestamp()
     OR v_contact.verification_expires_at <= clock_timestamp()
     OR v_contact.authority_expires_at <= clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_INVITATION_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  IF p_session_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;
  v_session_expires_at := LEAST(
    p_session_expires_at,
    v_lock.max_expires_at,
    v_contact.verification_expires_at,
    v_contact.authority_expires_at
  );

  UPDATE public.release_lock_invitations
  SET exchanged_at = clock_timestamp()
  WHERE invitation_id = v_invitation.invitation_id
    AND exchanged_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_INVITATION_REPLAYED' USING ERRCODE = 'P0002';
  END IF;

  INSERT INTO public.release_lock_sessions (
    session_id,
    invitation_id,
    lock_id,
    role,
    contact_binding_id,
    token_digest,
    expires_at
  ) VALUES (
    p_session_id,
    v_invitation.invitation_id,
    v_invitation.lock_id,
    v_invitation.role,
    v_invitation.contact_binding_id,
    p_session_digest,
    v_session_expires_at
  );

  RETURN jsonb_build_object(
    'lock_id', v_invitation.lock_id,
    'role', v_invitation.role,
    'session_expires_at', v_session_expires_at,
    'status', v_lock.status,
    'current_version', v_lock.current_version
  );
EXCEPTION
  WHEN unique_violation OR foreign_key_violation OR check_violation
       OR invalid_text_representation THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_exchange_invitation(
  TEXT, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_exchange_invitation(
  TEXT, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ
) TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_create_pairing(
  p_session_digest TEXT,
  p_lock_id TEXT,
  p_round TEXT,
  p_pairing_id UUID,
  p_token_digest TEXT,
  p_expires_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_session public.release_lock_sessions%ROWTYPE;
  v_lock public.release_locks%ROWTYPE;
  v_contact public.release_lock_contact_bindings%ROWTYPE;
  v_action_hash TEXT;
BEGIN
  IF p_session_digest !~ '^hmac-sha256:[0-9a-f]{64}$'
     OR p_lock_id !~ '^rlk_[a-f0-9]{32}$'
     OR p_round NOT IN ('CO_ACCEPTED', 'DRAW_RELEASE')
     OR p_token_digest !~ '^hmac-sha256:[0-9a-f]{64}$'
     OR p_expires_at IS NULL
     OR p_expires_at <= clock_timestamp()
     OR p_expires_at > clock_timestamp() + INTERVAL '5 minutes'
  THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;

  SELECT *
  INTO v_session
  FROM public.release_lock_sessions
  WHERE token_digest = p_session_digest
  FOR UPDATE;
  IF NOT FOUND
     OR v_session.revoked_at IS NOT NULL
     OR v_session.expires_at <= clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;
  IF v_session.lock_id IS DISTINCT FROM p_lock_id
     OR (v_session.scope_round IS NOT NULL AND v_session.scope_round IS DISTINCT FROM p_round)
  THEN
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;

  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = p_lock_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_LOCK_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_contact
  FROM public.release_lock_contact_bindings
  WHERE contact_binding_id = v_session.contact_binding_id;
  IF NOT FOUND
     OR v_lock.max_expires_at <= clock_timestamp()
     OR v_contact.verification_expires_at <= clock_timestamp()
     OR v_contact.authority_expires_at <= clock_timestamp()
     OR p_expires_at > v_session.expires_at
     OR p_expires_at > v_lock.max_expires_at
     OR p_expires_at > v_contact.verification_expires_at
     OR p_expires_at > v_contact.authority_expires_at
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;

  IF p_round = 'CO_ACCEPTED' THEN
    IF v_lock.status NOT IN ('co_pending', 'co_frozen') THEN
      RAISE EXCEPTION 'RL_ROUND_COMPLETE' USING ERRCODE = 'P0002';
    END IF;
    SELECT co_action_hash
    INTO STRICT v_action_hash
    FROM public.release_lock_versions
    WHERE lock_id = p_lock_id
      AND version = v_lock.current_version;
  ELSE
    IF v_lock.status = 'co_accepted' THEN
      RAISE EXCEPTION 'RL_ROUND_UNAVAILABLE' USING ERRCODE = 'P0002';
    END IF;
    IF v_lock.status NOT IN ('draw_pending', 'draw_frozen') THEN
      RAISE EXCEPTION 'RL_ROUND_COMPLETE' USING ERRCODE = 'P0002';
    END IF;
    SELECT draw_action_hash
    INTO STRICT v_action_hash
    FROM public.release_lock_draw_actions
    WHERE lock_id = p_lock_id
      AND version = v_lock.current_version;
  END IF;
  IF v_session.scope_version IS NOT NULL
     AND (
       v_session.scope_version IS DISTINCT FROM v_lock.current_version
       OR v_session.scope_action_hash IS DISTINCT FROM v_action_hash
     )
  THEN
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;

  UPDATE public.release_lock_pairings
  SET revoked_at = clock_timestamp()
  WHERE source_session_id = v_session.session_id
    AND round = p_round
    AND exchanged_at IS NULL
    AND revoked_at IS NULL;

  INSERT INTO public.release_lock_pairings (
    pairing_id,
    source_session_id,
    lock_id,
    role,
    contact_binding_id,
    round,
    version,
    action_hash,
    lock_status,
    token_digest,
    expires_at
  ) VALUES (
    p_pairing_id,
    v_session.session_id,
    p_lock_id,
    v_session.role,
    v_session.contact_binding_id,
    p_round,
    v_lock.current_version,
    v_action_hash,
    v_lock.status,
    p_token_digest,
    p_expires_at
  );

  RETURN jsonb_build_object(
    'pairing_id', p_pairing_id,
    'lock_id', p_lock_id,
    'role', v_session.role,
    'round', p_round,
    'version', v_lock.current_version,
    'action_hash', v_action_hash,
    'lock_status', v_lock.status,
    'expires_at', p_expires_at
  );
EXCEPTION
  WHEN unique_violation OR foreign_key_violation OR check_violation
       OR invalid_text_representation THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_create_pairing(
  TEXT, TEXT, TEXT, UUID, TEXT, TIMESTAMPTZ
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_create_pairing(
  TEXT, TEXT, TEXT, UUID, TEXT, TIMESTAMPTZ
) TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_exchange_pairing(
  p_token_digest TEXT,
  p_expected_lock_id TEXT,
  p_expected_role TEXT,
  p_expected_round TEXT,
  p_session_id UUID,
  p_session_digest TEXT,
  p_session_expires_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_pairing public.release_lock_pairings%ROWTYPE;
  v_source public.release_lock_sessions%ROWTYPE;
  v_lock public.release_locks%ROWTYPE;
  v_contact public.release_lock_contact_bindings%ROWTYPE;
  v_session_expires_at TIMESTAMPTZ;
  v_current_action_hash TEXT;
BEGIN
  IF p_token_digest !~ '^hmac-sha256:[0-9a-f]{64}$'
     OR p_session_digest !~ '^hmac-sha256:[0-9a-f]{64}$'
     OR p_expected_lock_id !~ '^rlk_[a-f0-9]{32}$'
     OR p_expected_role NOT IN ('contractor', 'customer')
     OR p_expected_round NOT IN ('CO_ACCEPTED', 'DRAW_RELEASE')
     OR p_session_expires_at IS NULL
     OR p_session_expires_at <= clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;

  SELECT *
  INTO v_pairing
  FROM public.release_lock_pairings
  WHERE token_digest = p_token_digest
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_PAIRING_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_pairing.lock_id IS DISTINCT FROM p_expected_lock_id
     OR v_pairing.role IS DISTINCT FROM p_expected_role
     OR v_pairing.round IS DISTINCT FROM p_expected_round
  THEN
    RAISE EXCEPTION 'RL_PAIRING_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  IF v_pairing.exchanged_at IS NOT NULL OR v_pairing.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'RL_PAIRING_REPLAYED' USING ERRCODE = 'P0002';
  END IF;
  IF v_pairing.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_PAIRING_EXPIRED' USING ERRCODE = 'P0002';
  END IF;

  SELECT *
  INTO v_source
  FROM public.release_lock_sessions
  WHERE session_id = v_pairing.source_session_id
  FOR UPDATE;
  IF NOT FOUND
     OR v_source.revoked_at IS NOT NULL
     OR v_source.expires_at <= clock_timestamp()
     OR v_source.lock_id IS DISTINCT FROM v_pairing.lock_id
     OR v_source.role IS DISTINCT FROM v_pairing.role
     OR v_source.contact_binding_id IS DISTINCT FROM v_pairing.contact_binding_id
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO STRICT v_lock
  FROM public.release_locks
  WHERE lock_id = v_pairing.lock_id
  FOR UPDATE;
  SELECT *
  INTO STRICT v_contact
  FROM public.release_lock_contact_bindings
  WHERE contact_binding_id = v_pairing.contact_binding_id;
  IF v_lock.max_expires_at <= clock_timestamp()
     OR v_contact.verification_expires_at <= clock_timestamp()
     OR v_contact.authority_expires_at <= clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_PAIRING_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.current_version IS DISTINCT FROM v_pairing.version
     OR v_lock.status IS DISTINCT FROM v_pairing.lock_status
  THEN
    RAISE EXCEPTION 'RL_PAIRING_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  IF v_pairing.round = 'CO_ACCEPTED' THEN
    IF v_lock.status NOT IN ('co_pending', 'co_frozen') THEN
      RAISE EXCEPTION 'RL_PAIRING_SCOPE' USING ERRCODE = 'P0002';
    END IF;
    SELECT co_action_hash
    INTO STRICT v_current_action_hash
    FROM public.release_lock_versions
    WHERE lock_id = v_pairing.lock_id
      AND version = v_pairing.version;
  ELSE
    IF v_lock.status NOT IN ('draw_pending', 'draw_frozen') THEN
      RAISE EXCEPTION 'RL_PAIRING_SCOPE' USING ERRCODE = 'P0002';
    END IF;
    SELECT draw_action_hash
    INTO STRICT v_current_action_hash
    FROM public.release_lock_draw_actions
    WHERE lock_id = v_pairing.lock_id
      AND version = v_pairing.version;
  END IF;
  IF v_current_action_hash IS DISTINCT FROM v_pairing.action_hash
     OR (
       v_source.scope_version IS NOT NULL
       AND (
         v_source.scope_version IS DISTINCT FROM v_pairing.version
         OR v_source.scope_action_hash IS DISTINCT FROM v_pairing.action_hash
       )
     )
  THEN
    RAISE EXCEPTION 'RL_PAIRING_SCOPE' USING ERRCODE = 'P0002';
  END IF;

  v_session_expires_at := LEAST(
    p_session_expires_at,
    v_source.expires_at,
    v_lock.max_expires_at,
    v_contact.verification_expires_at,
    v_contact.authority_expires_at
  );

  UPDATE public.release_lock_pairings
  SET exchanged_at = clock_timestamp()
  WHERE pairing_id = v_pairing.pairing_id
    AND exchanged_at IS NULL
    AND revoked_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_PAIRING_REPLAYED' USING ERRCODE = 'P0002';
  END IF;

  INSERT INTO public.release_lock_sessions (
    session_id,
    invitation_id,
    lock_id,
    role,
    contact_binding_id,
    scope_round,
    scope_version,
    scope_action_hash,
    token_digest,
    expires_at
  ) VALUES (
    p_session_id,
    v_source.invitation_id,
    v_pairing.lock_id,
    v_pairing.role,
    v_pairing.contact_binding_id,
    v_pairing.round,
    v_pairing.version,
    v_pairing.action_hash,
    p_session_digest,
    v_session_expires_at
  );

  RETURN jsonb_build_object(
    'lock_id', v_pairing.lock_id,
    'role', v_pairing.role,
    'round', v_pairing.round,
    'version', v_pairing.version,
    'action_hash', v_pairing.action_hash,
    'session_expires_at', v_session_expires_at,
    'status', v_lock.status,
    'current_version', v_lock.current_version
  );
EXCEPTION
  WHEN unique_violation OR foreign_key_violation OR check_violation
       OR invalid_text_representation THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_exchange_pairing(
  TEXT, TEXT, TEXT, TEXT, UUID, TEXT, TIMESTAMPTZ
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_exchange_pairing(
  TEXT, TEXT, TEXT, TEXT, UUID, TEXT, TIMESTAMPTZ
) TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_resolve_session(
  p_session_digest TEXT,
  p_lock_id TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_session public.release_lock_sessions%ROWTYPE;
  v_lock public.release_locks%ROWTYPE;
  v_scope_action_hash TEXT;
BEGIN
  IF p_session_digest !~ '^hmac-sha256:[0-9a-f]{64}$'
     OR p_lock_id !~ '^rlk_[a-f0-9]{32}$'
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_session
  FROM public.release_lock_sessions
  WHERE token_digest = p_session_digest;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;
  IF v_session.lock_id IS DISTINCT FROM p_lock_id THEN
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  IF v_session.revoked_at IS NOT NULL
     OR v_session.expires_at <= clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = p_lock_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_LOCK_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.max_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_LOCK_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  IF v_session.scope_version IS NOT NULL THEN
    IF v_session.scope_version IS DISTINCT FROM v_lock.current_version THEN
      RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
    END IF;
    IF v_session.scope_round = 'CO_ACCEPTED' THEN
      SELECT co_action_hash
      INTO STRICT v_scope_action_hash
      FROM public.release_lock_versions
      WHERE lock_id = p_lock_id
        AND version = v_session.scope_version;
    ELSE
      SELECT draw_action_hash
      INTO STRICT v_scope_action_hash
      FROM public.release_lock_draw_actions
      WHERE lock_id = p_lock_id
        AND version = v_session.scope_version;
    END IF;
    IF v_scope_action_hash IS DISTINCT FROM v_session.scope_action_hash THEN
      RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
    END IF;
  END IF;
  RETURN jsonb_build_object(
    'session_id', v_session.session_id,
    'lock_id', v_session.lock_id,
    'role', v_session.role,
    'contact_binding_id', v_session.contact_binding_id,
    'scope_round', v_session.scope_round,
    'scope_version', v_session.scope_version,
    'scope_action_hash', v_session.scope_action_hash,
    'session_expires_at', v_session.expires_at,
    'current_version', v_lock.current_version,
    'status', v_lock.status,
    'lock_expires_at', v_lock.max_expires_at
  );
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_resolve_session(TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_resolve_session(TEXT, TEXT)
  TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_begin_registration(
  p_session_digest TEXT,
  p_lock_id TEXT,
  p_challenge_id UUID,
  p_challenge TEXT,
  p_rp_id TEXT,
  p_origin TEXT,
  p_expires_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_session public.release_lock_sessions%ROWTYPE;
  v_lock public.release_locks%ROWTYPE;
  v_contact public.release_lock_contact_bindings%ROWTYPE;
  v_existing JSONB;
BEGIN
  IF p_lock_id !~ '^rlk_[a-f0-9]{32}$'
     OR p_challenge IS NULL
     OR length(p_challenge) < 16
     OR length(p_challenge) > 1024
     OR p_rp_id IS NULL
     OR length(p_rp_id) > 253
     OR p_origin IS NULL
     OR length(p_origin) > 512
     OR p_expires_at IS NULL
  THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;
  SELECT *
  INTO v_session
  FROM public.release_lock_sessions
  WHERE token_digest = p_session_digest;
  IF NOT FOUND
     OR v_session.revoked_at IS NOT NULL
     OR v_session.expires_at <= clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;
  IF v_session.lock_id IS DISTINCT FROM p_lock_id THEN
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO STRICT v_lock
  FROM public.release_locks
  WHERE lock_id = p_lock_id;
  SELECT *
  INTO STRICT v_contact
  FROM public.release_lock_contact_bindings
  WHERE contact_binding_id = v_session.contact_binding_id;
  IF v_lock.max_expires_at <= clock_timestamp()
     OR v_contact.verification_expires_at <= clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;
  IF p_expires_at <= clock_timestamp()
     OR p_expires_at > v_session.expires_at
     OR p_expires_at > v_lock.max_expires_at
     OR p_expires_at > v_contact.verification_expires_at
  THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM public.release_lock_credentials c
    WHERE c.lock_id = p_lock_id
      AND c.role = v_session.role
      AND c.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'RL_CREDENTIAL_EXISTS' USING ERRCODE = 'P0002';
  END IF;

  UPDATE public.release_lock_registration_challenges
  SET consumed_at = clock_timestamp()
  WHERE session_id = v_session.session_id
    AND consumed_at IS NULL;

  INSERT INTO public.release_lock_registration_challenges (
    challenge_id,
    session_id,
    lock_id,
    role,
    contact_binding_id,
    challenge,
    rp_id,
    origin,
    expires_at
  ) VALUES (
    p_challenge_id,
    v_session.session_id,
    p_lock_id,
    v_session.role,
    v_session.contact_binding_id,
    p_challenge,
    p_rp_id,
    p_origin,
    p_expires_at
  );

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'credential_id', c.credential_id,
    'transports', c.transports
  ) ORDER BY c.credential_id), '[]'::JSONB)
  INTO v_existing
  FROM public.release_lock_credentials c
  WHERE c.lock_id = p_lock_id
    AND c.revoked_at IS NULL;

  RETURN jsonb_build_object(
    'challenge_id', p_challenge_id,
    'lock_id', p_lock_id,
    'role', v_session.role,
    'contact_binding_id', v_session.contact_binding_id,
    'expires_at', p_expires_at,
    'existing_credentials', v_existing
  );
EXCEPTION
  WHEN unique_violation OR foreign_key_violation OR check_violation
       OR invalid_text_representation THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_begin_registration(
  TEXT, TEXT, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_begin_registration(
  TEXT, TEXT, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ
) TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_load_registration(
  p_session_digest TEXT,
  p_lock_id TEXT,
  p_challenge_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_session public.release_lock_sessions%ROWTYPE;
  v_challenge public.release_lock_registration_challenges%ROWTYPE;
BEGIN
  SELECT *
  INTO v_session
  FROM public.release_lock_sessions
  WHERE token_digest = p_session_digest;
  IF NOT FOUND
     OR v_session.revoked_at IS NOT NULL
     OR v_session.expires_at <= clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;
  IF v_session.lock_id IS DISTINCT FROM p_lock_id THEN
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_challenge
  FROM public.release_lock_registration_challenges
  WHERE challenge_id = p_challenge_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_CHALLENGE_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_challenge.session_id IS DISTINCT FROM v_session.session_id
     OR v_challenge.lock_id IS DISTINCT FROM p_lock_id
     OR v_challenge.role IS DISTINCT FROM v_session.role
     OR v_challenge.contact_binding_id IS DISTINCT FROM v_session.contact_binding_id
  THEN
    RAISE EXCEPTION 'RL_CHALLENGE_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  IF v_challenge.consumed_at IS NOT NULL THEN
    RAISE EXCEPTION 'RL_CHALLENGE_REPLAYED' USING ERRCODE = 'P0002';
  END IF;
  IF v_challenge.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_CHALLENGE_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  RETURN jsonb_build_object(
    'challenge_id', v_challenge.challenge_id,
    'challenge', v_challenge.challenge,
    'lock_id', v_challenge.lock_id,
    'role', v_challenge.role,
    'contact_binding_id', v_challenge.contact_binding_id,
    'rp_id', v_challenge.rp_id,
    'origin', v_challenge.origin,
    'expires_at', v_challenge.expires_at
  );
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_load_registration(TEXT, TEXT, UUID)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_load_registration(TEXT, TEXT, UUID)
  TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_complete_registration(
  p_session_digest TEXT,
  p_lock_id TEXT,
  p_challenge_id UUID,
  p_credential_id TEXT,
  p_public_key_cose TEXT,
  p_public_key_spki TEXT,
  p_sign_count BIGINT,
  p_transports JSONB,
  p_device_type TEXT,
  p_backed_up BOOLEAN,
  p_attestation_format TEXT,
  p_rp_id TEXT,
  p_origin TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_session public.release_lock_sessions%ROWTYPE;
  v_challenge public.release_lock_registration_challenges%ROWTYPE;
BEGIN
  IF p_credential_id IS NULL
     OR length(p_credential_id) > 1024
     OR p_public_key_cose IS NULL
     OR length(p_public_key_cose) > 8192
     OR p_public_key_spki IS NULL
     OR length(p_public_key_spki) > 8192
     OR p_sign_count IS NULL
     OR p_sign_count < 0
     OR p_rp_id IS NULL
     OR p_origin IS NULL
  THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;
  SELECT *
  INTO v_session
  FROM public.release_lock_sessions
  WHERE token_digest = p_session_digest
  FOR UPDATE;
  IF NOT FOUND
     OR v_session.revoked_at IS NOT NULL
     OR v_session.expires_at <= clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;
  IF v_session.lock_id IS DISTINCT FROM p_lock_id THEN
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_challenge
  FROM public.release_lock_registration_challenges
  WHERE challenge_id = p_challenge_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_CHALLENGE_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_challenge.session_id IS DISTINCT FROM v_session.session_id
     OR v_challenge.lock_id IS DISTINCT FROM p_lock_id
     OR v_challenge.role IS DISTINCT FROM v_session.role
     OR v_challenge.contact_binding_id IS DISTINCT FROM v_session.contact_binding_id
     OR v_challenge.rp_id IS DISTINCT FROM p_rp_id
     OR v_challenge.origin IS DISTINCT FROM p_origin
  THEN
    RAISE EXCEPTION 'RL_CHALLENGE_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  IF v_challenge.consumed_at IS NOT NULL THEN
    RAISE EXCEPTION 'RL_CHALLENGE_REPLAYED' USING ERRCODE = 'P0002';
  END IF;
  IF v_challenge.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_CHALLENGE_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM public.release_lock_credentials c
    WHERE c.credential_id = p_credential_id
       OR (
         c.lock_id = p_lock_id
         AND (c.role = v_session.role OR c.contact_binding_id = v_session.contact_binding_id)
         AND c.revoked_at IS NULL
       )
  ) THEN
    RAISE EXCEPTION 'RL_CREDENTIAL_EXISTS' USING ERRCODE = 'P0002';
  END IF;

  UPDATE public.release_lock_registration_challenges
  SET consumed_at = clock_timestamp()
  WHERE challenge_id = p_challenge_id
    AND consumed_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_CHALLENGE_REPLAYED' USING ERRCODE = 'P0002';
  END IF;

  INSERT INTO public.release_lock_credentials (
    credential_id,
    lock_id,
    role,
    contact_binding_id,
    public_key_cose,
    public_key_spki,
    sign_count,
    transports,
    device_type,
    backed_up,
    attestation_format,
    rp_id,
    origin
  ) VALUES (
    p_credential_id,
    p_lock_id,
    v_session.role,
    v_session.contact_binding_id,
    p_public_key_cose,
    p_public_key_spki,
    p_sign_count,
    p_transports,
    p_device_type,
    p_backed_up,
    p_attestation_format,
    p_rp_id,
    p_origin
  );

  RETURN jsonb_build_object(
    'credential_id', p_credential_id,
    'lock_id', p_lock_id,
    'role', v_session.role,
    'contact_binding_id', v_session.contact_binding_id,
    'sign_count', p_sign_count,
    'device_type', p_device_type,
    'backed_up', p_backed_up,
    'rp_id', p_rp_id,
    'origin', p_origin,
    'identity_verified', false,
    'biometric_verified', false,
    'device_bound_claimed', false
  );
EXCEPTION
  WHEN unique_violation THEN
    RAISE EXCEPTION 'RL_CREDENTIAL_EXISTS' USING ERRCODE = 'P0002';
  WHEN foreign_key_violation OR check_violation OR invalid_text_representation THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_complete_registration(
  TEXT, TEXT, UUID, TEXT, TEXT, TEXT, BIGINT, JSONB, TEXT, BOOLEAN, TEXT, TEXT, TEXT
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_complete_registration(
  TEXT, TEXT, UUID, TEXT, TEXT, TEXT, BIGINT, JSONB, TEXT, BOOLEAN, TEXT, TEXT, TEXT
) TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_action_check_context(
  p_session_digest TEXT,
  p_lock_id TEXT,
  p_round TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_session public.release_lock_sessions%ROWTYPE;
  v_lock public.release_locks%ROWTYPE;
  v_credential public.release_lock_credentials%ROWTYPE;
  v_action JSONB;
  v_action_hash TEXT;
  v_action_expires_at TIMESTAMPTZ;
BEGIN
  IF p_round NOT IN ('CO_ACCEPTED', 'DRAW_RELEASE') THEN
    RAISE EXCEPTION 'RL_ROUND_INVALID' USING ERRCODE = 'P0001';
  END IF;
  SELECT *
  INTO v_session
  FROM public.release_lock_sessions
  WHERE token_digest = p_session_digest;
  IF NOT FOUND
     OR v_session.revoked_at IS NOT NULL
     OR v_session.expires_at <= clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;
  IF v_session.lock_id IS DISTINCT FROM p_lock_id
     OR (v_session.scope_round IS NOT NULL AND v_session.scope_round IS DISTINCT FROM p_round)
  THEN
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = p_lock_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_LOCK_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.max_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_LOCK_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_credential
  FROM public.release_lock_credentials
  WHERE lock_id = p_lock_id
    AND role = v_session.role
    AND contact_binding_id = v_session.contact_binding_id
    AND revoked_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_CREDENTIAL_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;

  IF p_round = 'CO_ACCEPTED' THEN
    IF v_lock.status NOT IN ('co_pending', 'co_frozen') THEN
      RAISE EXCEPTION 'RL_ROUND_COMPLETE' USING ERRCODE = 'P0002';
    END IF;
    SELECT co_action, co_action_hash, expires_at
    INTO STRICT v_action, v_action_hash, v_action_expires_at
    FROM public.release_lock_versions
    WHERE lock_id = p_lock_id
      AND version = v_lock.current_version;
  ELSE
    IF v_lock.status = 'co_accepted' THEN
      RAISE EXCEPTION 'RL_ROUND_UNAVAILABLE' USING ERRCODE = 'P0002';
    END IF;
    IF v_lock.status NOT IN ('draw_pending', 'draw_frozen') THEN
      RAISE EXCEPTION 'RL_ROUND_COMPLETE' USING ERRCODE = 'P0002';
    END IF;
    SELECT draw_action, draw_action_hash, expires_at
    INTO STRICT v_action, v_action_hash, v_action_expires_at
    FROM public.release_lock_draw_actions
    WHERE lock_id = p_lock_id
      AND version = v_lock.current_version;
  END IF;
  IF v_session.scope_version IS NOT NULL
     AND (
       v_session.scope_version IS DISTINCT FROM v_lock.current_version
       OR v_session.scope_action_hash IS DISTINCT FROM v_action_hash
     )
  THEN
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  IF v_action_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_LOCK_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.frozen_version IS NOT NULL
     AND (
       v_lock.frozen_version IS DISTINCT FROM v_lock.current_version
       OR v_lock.frozen_round IS DISTINCT FROM p_round
     )
  THEN
    RAISE EXCEPTION 'RL_VERSION_FROZEN' USING ERRCODE = 'P0002';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM public.release_lock_decisions d
    LEFT JOIN public.release_lock_decision_invalidations i
      ON i.decision_id = d.decision_id
    WHERE d.lock_id = p_lock_id
      AND d.version = v_lock.current_version
      AND d.round = p_round
      AND d.role = v_session.role
      AND i.decision_id IS NULL
  ) THEN
    RAISE EXCEPTION 'RL_APPROVAL_REPLAYED' USING ERRCODE = 'P0002';
  END IF;

  RETURN jsonb_build_object(
    'session_id', v_session.session_id,
    'lock_id', p_lock_id,
    'version', v_lock.current_version,
    'round', p_round,
    'role', v_session.role,
    'contact_binding_id', v_session.contact_binding_id,
    'contractor_entity_id', v_lock.contractor_entity_id,
    'action', v_action,
    'action_hash', v_action_hash,
    'action_expires_at', v_action_expires_at,
    'lock_expires_at', v_lock.max_expires_at,
    'session_expires_at', v_session.expires_at,
    'credential', jsonb_build_object(
      'credential_id', v_credential.credential_id,
      'public_key_cose', v_credential.public_key_cose,
      'public_key_spki', v_credential.public_key_spki,
      'sign_count', v_credential.sign_count,
      'transports', v_credential.transports,
      'rp_id', v_credential.rp_id,
      'origin', v_credential.origin
    )
  );
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_action_check_context(TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_action_check_context(TEXT, TEXT, TEXT)
  TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_store_action_challenge(
  p_session_digest TEXT,
  p_lock_id TEXT,
  p_challenge_id UUID,
  p_version INTEGER,
  p_round TEXT,
  p_credential_id TEXT,
  p_action_hash TEXT,
  p_prompt_set JSONB,
  p_prompt_set_digest TEXT,
  p_answer_digest TEXT,
  p_binding_moment JSONB,
  p_random_nonce TEXT,
  p_nonce TEXT,
  p_resolution_context JSONB,
  p_challenge TEXT,
  p_issued_at TIMESTAMPTZ,
  p_expires_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_session public.release_lock_sessions%ROWTYPE;
  v_lock public.release_locks%ROWTYPE;
  v_action_hash TEXT;
  v_action_expires_at TIMESTAMPTZ;
BEGIN
  IF p_round NOT IN ('CO_ACCEPTED', 'DRAW_RELEASE')
     OR p_version IS NULL
     OR p_version < 1
     OR p_action_hash !~ '^sha256:[0-9a-f]{64}$'
     OR p_prompt_set_digest !~ '^sha256:[0-9a-f]{64}$'
     OR p_answer_digest !~ '^sha256:[0-9a-f]{64}$'
     OR jsonb_typeof(p_prompt_set) IS DISTINCT FROM 'object'
     OR jsonb_typeof(p_binding_moment) IS DISTINCT FROM 'object'
     OR jsonb_typeof(p_resolution_context) IS DISTINCT FROM 'object'
     OR p_prompt_set->>'round' IS DISTINCT FROM p_round
     OR p_prompt_set->>'lock_id' IS DISTINCT FROM p_lock_id
     OR p_prompt_set->>'version' IS DISTINCT FROM p_version::TEXT
     OR p_resolution_context->>'action_hash' IS DISTINCT FROM p_action_hash
     OR p_resolution_context->>'principal_key_id' IS DISTINCT FROM p_credential_id
     OR p_resolution_context->>'nonce' IS DISTINCT FROM p_nonce
     OR p_resolution_context#>>'{resolution,outcome}' IS DISTINCT FROM 'approved'
     OR p_resolution_context#>>'{resolution,selected_option}' IS DISTINCT FROM '0'
     OR p_challenge IS NULL
     OR length(p_challenge) < 16
     OR length(p_challenge) > 1024
     OR p_random_nonce IS NULL
     OR p_nonce IS NULL
     OR p_issued_at IS NULL
     OR p_expires_at IS NULL
     OR p_issued_at >= p_expires_at
  THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;
  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = p_lock_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_LOCK_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.current_version IS DISTINCT FROM p_version THEN
    RAISE EXCEPTION 'RL_VERSION_STALE' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.max_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_LOCK_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_session
  FROM public.release_lock_sessions
  WHERE token_digest = p_session_digest;
  IF NOT FOUND
     OR v_session.revoked_at IS NOT NULL
     OR v_session.expires_at <= clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;
  IF v_session.lock_id IS DISTINCT FROM p_lock_id
     OR (v_session.scope_round IS NOT NULL AND v_session.scope_round IS DISTINCT FROM p_round)
  THEN
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.release_lock_credentials c
    WHERE c.credential_id = p_credential_id
      AND c.lock_id = p_lock_id
      AND c.role = v_session.role
      AND c.contact_binding_id = v_session.contact_binding_id
      AND c.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'RL_CREDENTIAL_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;

  IF p_round = 'CO_ACCEPTED' THEN
    IF v_lock.status NOT IN ('co_pending', 'co_frozen') THEN
      RAISE EXCEPTION 'RL_ROUND_COMPLETE' USING ERRCODE = 'P0002';
    END IF;
    SELECT co_action_hash, expires_at
    INTO STRICT v_action_hash, v_action_expires_at
    FROM public.release_lock_versions
    WHERE lock_id = p_lock_id AND version = p_version;
  ELSE
    IF v_lock.status = 'co_accepted' THEN
      RAISE EXCEPTION 'RL_ROUND_UNAVAILABLE' USING ERRCODE = 'P0002';
    END IF;
    IF v_lock.status NOT IN ('draw_pending', 'draw_frozen') THEN
      RAISE EXCEPTION 'RL_ROUND_COMPLETE' USING ERRCODE = 'P0002';
    END IF;
    SELECT draw_action_hash, expires_at
    INTO STRICT v_action_hash, v_action_expires_at
    FROM public.release_lock_draw_actions
    WHERE lock_id = p_lock_id AND version = p_version;
  END IF;
  IF v_session.scope_version IS NOT NULL
     AND (
       v_session.scope_version IS DISTINCT FROM p_version
       OR v_session.scope_action_hash IS DISTINCT FROM v_action_hash
     )
  THEN
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  IF v_action_hash IS DISTINCT FROM p_action_hash THEN
    RAISE EXCEPTION 'RL_APPROVAL_BINDING' USING ERRCODE = 'P0002';
  END IF;
  IF p_expires_at > v_action_expires_at
     OR p_expires_at > v_session.expires_at
     OR p_expires_at > v_lock.max_expires_at
     OR p_expires_at <= clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_CHALLENGE_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM public.release_lock_decisions d
    LEFT JOIN public.release_lock_decision_invalidations i
      ON i.decision_id = d.decision_id
    WHERE d.lock_id = p_lock_id
      AND d.version = p_version
      AND d.round = p_round
      AND d.role = v_session.role
      AND i.decision_id IS NULL
  ) THEN
    RAISE EXCEPTION 'RL_APPROVAL_REPLAYED' USING ERRCODE = 'P0002';
  END IF;

  UPDATE public.release_lock_action_challenges
  SET consumed_at = clock_timestamp()
  WHERE session_id = v_session.session_id
    AND round = p_round
    AND consumed_at IS NULL;

  INSERT INTO public.release_lock_action_challenges (
    challenge_id,
    session_id,
    lock_id,
    version,
    round,
    role,
    contact_binding_id,
    credential_id,
    action_hash,
    prompt_set,
    prompt_set_digest,
    answer_digest,
    binding_moment,
    random_nonce,
    nonce,
    resolution_context,
    challenge,
    issued_at,
    expires_at
  ) VALUES (
    p_challenge_id,
    v_session.session_id,
    p_lock_id,
    p_version,
    p_round,
    v_session.role,
    v_session.contact_binding_id,
    p_credential_id,
    p_action_hash,
    p_prompt_set,
    p_prompt_set_digest,
    p_answer_digest,
    p_binding_moment,
    p_random_nonce,
    p_nonce,
    p_resolution_context,
    p_challenge,
    p_issued_at,
    p_expires_at
  );
  RETURN jsonb_build_object(
    'challenge_id', p_challenge_id,
    'lock_id', p_lock_id,
    'version', p_version,
    'round', p_round,
    'role', v_session.role,
    'action_hash', p_action_hash,
    'expires_at', p_expires_at
  );
EXCEPTION
  WHEN unique_violation OR foreign_key_violation OR check_violation
       OR invalid_text_representation THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_store_action_challenge(
  TEXT, TEXT, UUID, INTEGER, TEXT, TEXT, TEXT, JSONB, TEXT, TEXT, JSONB,
  TEXT, TEXT, JSONB, TEXT, TIMESTAMPTZ, TIMESTAMPTZ
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_store_action_challenge(
  TEXT, TEXT, UUID, INTEGER, TEXT, TEXT, TEXT, JSONB, TEXT, TEXT, JSONB,
  TEXT, TEXT, JSONB, TEXT, TIMESTAMPTZ, TIMESTAMPTZ
) TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_load_action_challenge(
  p_session_digest TEXT,
  p_lock_id TEXT,
  p_round TEXT,
  p_challenge_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_session public.release_lock_sessions%ROWTYPE;
  v_lock public.release_locks%ROWTYPE;
  v_challenge public.release_lock_action_challenges%ROWTYPE;
  v_credential public.release_lock_credentials%ROWTYPE;
  v_current_action_hash TEXT;
  v_current_expires_at TIMESTAMPTZ;
BEGIN
  IF p_round NOT IN ('CO_ACCEPTED', 'DRAW_RELEASE') THEN
    RAISE EXCEPTION 'RL_ROUND_INVALID' USING ERRCODE = 'P0001';
  END IF;
  SELECT *
  INTO v_session
  FROM public.release_lock_sessions
  WHERE token_digest = p_session_digest;
  IF NOT FOUND
     OR v_session.revoked_at IS NOT NULL
     OR v_session.expires_at <= clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;
  IF v_session.lock_id IS DISTINCT FROM p_lock_id
     OR (v_session.scope_round IS NOT NULL AND v_session.scope_round IS DISTINCT FROM p_round)
  THEN
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = p_lock_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_LOCK_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.current_version IS NULL OR v_lock.max_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_LOCK_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_challenge
  FROM public.release_lock_action_challenges
  WHERE challenge_id = p_challenge_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_CHALLENGE_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_challenge.session_id IS DISTINCT FROM v_session.session_id
     OR v_challenge.lock_id IS DISTINCT FROM p_lock_id
     OR v_challenge.version IS DISTINCT FROM v_lock.current_version
     OR v_challenge.round IS DISTINCT FROM p_round
     OR v_challenge.role IS DISTINCT FROM v_session.role
     OR v_challenge.contact_binding_id IS DISTINCT FROM v_session.contact_binding_id
  THEN
    RAISE EXCEPTION 'RL_CHALLENGE_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  IF v_challenge.consumed_at IS NOT NULL THEN
    RAISE EXCEPTION 'RL_CHALLENGE_REPLAYED' USING ERRCODE = 'P0002';
  END IF;
  IF v_challenge.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_CHALLENGE_EXPIRED' USING ERRCODE = 'P0002';
  END IF;

  IF p_round = 'CO_ACCEPTED' THEN
    IF v_lock.status NOT IN ('co_pending', 'co_frozen') THEN
      RAISE EXCEPTION 'RL_ROUND_COMPLETE' USING ERRCODE = 'P0002';
    END IF;
    SELECT co_action_hash, expires_at
    INTO STRICT v_current_action_hash, v_current_expires_at
    FROM public.release_lock_versions
    WHERE lock_id = p_lock_id AND version = v_lock.current_version;
  ELSE
    IF v_lock.status NOT IN ('draw_pending', 'draw_frozen') THEN
      RAISE EXCEPTION 'RL_ROUND_COMPLETE' USING ERRCODE = 'P0002';
    END IF;
    SELECT draw_action_hash, expires_at
    INTO STRICT v_current_action_hash, v_current_expires_at
    FROM public.release_lock_draw_actions
    WHERE lock_id = p_lock_id AND version = v_lock.current_version;
  END IF;
  IF v_session.scope_version IS NOT NULL
     AND (
       v_session.scope_version IS DISTINCT FROM v_lock.current_version
       OR v_session.scope_action_hash IS DISTINCT FROM v_current_action_hash
     )
  THEN
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  IF v_current_action_hash IS DISTINCT FROM v_challenge.action_hash THEN
    RAISE EXCEPTION 'RL_APPROVAL_BINDING' USING ERRCODE = 'P0002';
  END IF;
  IF v_current_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_LOCK_EXPIRED' USING ERRCODE = 'P0002';
  END IF;

  SELECT *
  INTO v_credential
  FROM public.release_lock_credentials
  WHERE credential_id = v_challenge.credential_id
    AND lock_id = p_lock_id
    AND role = v_session.role
    AND contact_binding_id = v_session.contact_binding_id
    AND revoked_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_CREDENTIAL_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  RETURN jsonb_build_object(
    'challenge_id', v_challenge.challenge_id,
    'session_id', v_challenge.session_id,
    'lock_id', v_challenge.lock_id,
    'version', v_challenge.version,
    'round', v_challenge.round,
    'role', v_challenge.role,
    'contact_binding_id', v_challenge.contact_binding_id,
    'credential_id', v_challenge.credential_id,
    'action_hash', v_challenge.action_hash,
    'prompt_set', v_challenge.prompt_set,
    'prompt_set_digest', v_challenge.prompt_set_digest,
    'answer_digest', v_challenge.answer_digest,
    'binding_moment', v_challenge.binding_moment,
    'random_nonce', v_challenge.random_nonce,
    'nonce', v_challenge.nonce,
    'resolution_context', v_challenge.resolution_context,
    'challenge', v_challenge.challenge,
    'issued_at', v_challenge.issued_at,
    'expires_at', v_challenge.expires_at,
    'contractor_entity_id', v_lock.contractor_entity_id,
    'credential', jsonb_build_object(
      'credential_id', v_credential.credential_id,
      'public_key_cose', v_credential.public_key_cose,
      'public_key_spki', v_credential.public_key_spki,
      'sign_count', v_credential.sign_count,
      'transports', v_credential.transports,
      'rp_id', v_credential.rp_id,
      'origin', v_credential.origin
    )
  );
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_load_action_challenge(TEXT, TEXT, TEXT, UUID)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_load_action_challenge(TEXT, TEXT, TEXT, UUID)
  TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_record_approval(
  p_session_digest TEXT,
  p_lock_id TEXT,
  p_round TEXT,
  p_challenge_id UUID,
  p_credential_id TEXT,
  p_new_sign_count BIGINT,
  p_submitted_answers JSONB,
  p_submitted_answer_digest TEXT,
  p_resolution JSONB,
  p_resolution_digest TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_lock public.release_locks%ROWTYPE;
  v_session public.release_lock_sessions%ROWTYPE;
  v_challenge public.release_lock_action_challenges%ROWTYPE;
  v_credential public.release_lock_credentials%ROWTYPE;
  v_draw public.release_lock_draw_actions%ROWTYPE;
  v_action_hash TEXT;
  v_action_expires_at TIMESTAMPTZ;
  v_approval_count INTEGER;
  v_acceptance_digest TEXT;
  v_reservation_expires_at TIMESTAMPTZ;
BEGIN
  IF p_round NOT IN ('CO_ACCEPTED', 'DRAW_RELEASE')
     OR p_new_sign_count IS NULL
     OR p_new_sign_count < 0
     OR jsonb_typeof(p_submitted_answers) IS DISTINCT FROM 'array'
     OR p_submitted_answer_digest !~ '^sha256:[0-9a-f]{64}$'
     OR jsonb_typeof(p_resolution) IS DISTINCT FROM 'object'
     OR p_resolution_digest !~ '^sha256:[0-9a-f]{64}$'
     OR p_resolution->>'profile' IS DISTINCT FROM 'EP-RESOLUTION-v1'
     OR p_resolution#>>'{signoff,context,resolution,outcome}' IS DISTINCT FROM 'approved'
     OR p_resolution#>>'{signoff,context,resolution,selected_option}' IS DISTINCT FROM '0'
  THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;

  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = p_lock_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_LOCK_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.max_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_LOCK_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_session
  FROM public.release_lock_sessions
  WHERE token_digest = p_session_digest;
  IF NOT FOUND
     OR v_session.revoked_at IS NOT NULL
     OR v_session.expires_at <= clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;
  IF v_session.lock_id IS DISTINCT FROM p_lock_id
     OR (v_session.scope_round IS NOT NULL AND v_session.scope_round IS DISTINCT FROM p_round)
  THEN
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_challenge
  FROM public.release_lock_action_challenges
  WHERE challenge_id = p_challenge_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_CHALLENGE_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_challenge.consumed_at IS NOT NULL THEN
    RAISE EXCEPTION 'RL_CHALLENGE_REPLAYED' USING ERRCODE = 'P0002';
  END IF;
  IF v_challenge.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_CHALLENGE_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  IF v_challenge.session_id IS DISTINCT FROM v_session.session_id
     OR v_challenge.lock_id IS DISTINCT FROM p_lock_id
     OR v_challenge.version IS DISTINCT FROM v_lock.current_version
     OR v_challenge.round IS DISTINCT FROM p_round
     OR v_challenge.role IS DISTINCT FROM v_session.role
     OR v_challenge.contact_binding_id IS DISTINCT FROM v_session.contact_binding_id
     OR v_challenge.credential_id IS DISTINCT FROM p_credential_id
  THEN
    RAISE EXCEPTION 'RL_CHALLENGE_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  IF p_resolution#>>'{signoff,context,action_hash}' IS DISTINCT FROM v_challenge.action_hash
     OR p_resolution#>>'{signoff,context,principal_key_id}' IS DISTINCT FROM p_credential_id
     OR p_resolution#>>'{signoff,context,nonce}' IS DISTINCT FROM v_challenge.nonce
     OR p_resolution#>>'{signoff,context,envelope_hash}'
       IS DISTINCT FROM v_challenge.resolution_context->>'envelope_hash'
     OR p_resolution#>>'{signoff,context,initiator}'
       IS DISTINCT FROM v_challenge.resolution_context->>'initiator'
     OR p_submitted_answer_digest IS DISTINCT FROM v_challenge.answer_digest
  THEN
    RAISE EXCEPTION 'RL_APPROVAL_BINDING' USING ERRCODE = 'P0002';
  END IF;

  SELECT *
  INTO v_credential
  FROM public.release_lock_credentials
  WHERE credential_id = p_credential_id
  FOR UPDATE;
  IF NOT FOUND
     OR v_credential.revoked_at IS NOT NULL
     OR v_credential.lock_id IS DISTINCT FROM p_lock_id
     OR v_credential.role IS DISTINCT FROM v_session.role
     OR v_credential.contact_binding_id IS DISTINCT FROM v_session.contact_binding_id
  THEN
    RAISE EXCEPTION 'RL_CREDENTIAL_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF p_new_sign_count < v_credential.sign_count
     OR (
       v_credential.sign_count > 0
       AND p_new_sign_count <= v_credential.sign_count
     )
  THEN
    RAISE EXCEPTION 'RL_COUNTER_REPLAYED' USING ERRCODE = 'P0002';
  END IF;

  IF p_round = 'CO_ACCEPTED' THEN
    IF v_lock.status NOT IN ('co_pending', 'co_frozen') THEN
      RAISE EXCEPTION 'RL_ROUND_COMPLETE' USING ERRCODE = 'P0002';
    END IF;
    SELECT co_action_hash, expires_at
    INTO STRICT v_action_hash, v_action_expires_at
    FROM public.release_lock_versions
    WHERE lock_id = p_lock_id
      AND version = v_lock.current_version;
  ELSE
    IF v_lock.status NOT IN ('draw_pending', 'draw_frozen') THEN
      RAISE EXCEPTION 'RL_ROUND_COMPLETE' USING ERRCODE = 'P0002';
    END IF;
    SELECT *
    INTO STRICT v_draw
    FROM public.release_lock_draw_actions
    WHERE lock_id = p_lock_id
      AND version = v_lock.current_version;
    v_action_hash := v_draw.draw_action_hash;
    v_action_expires_at := v_draw.expires_at;
    IF NOT EXISTS (
      SELECT 1
      FROM public.release_lock_round_acceptances a
      WHERE a.lock_id = p_lock_id
        AND a.version = v_lock.current_version
        AND a.round = 'CO_ACCEPTED'
        AND a.action_hash = v_draw.accepted_co_action_hash
        AND a.acceptance_digest = v_draw.accepted_co_digest
    ) THEN
      RAISE EXCEPTION 'RL_CO_NOT_ACCEPTED' USING ERRCODE = 'P0002';
    END IF;
  END IF;
  IF v_session.scope_version IS NOT NULL
     AND (
       v_session.scope_version IS DISTINCT FROM v_lock.current_version
       OR v_session.scope_action_hash IS DISTINCT FROM v_action_hash
     )
  THEN
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  IF v_action_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_LOCK_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  IF v_action_hash IS DISTINCT FROM v_challenge.action_hash THEN
    RAISE EXCEPTION 'RL_APPROVAL_BINDING' USING ERRCODE = 'P0002';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.release_lock_decisions d
    LEFT JOIN public.release_lock_decision_invalidations i
      ON i.decision_id = d.decision_id
    WHERE d.lock_id = p_lock_id
      AND d.version = v_lock.current_version
      AND d.round = p_round
      AND d.role = v_session.role
      AND i.decision_id IS NULL
  ) THEN
    RAISE EXCEPTION 'RL_APPROVAL_REPLAYED' USING ERRCODE = 'P0002';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM public.release_lock_decisions d
    LEFT JOIN public.release_lock_decision_invalidations i
      ON i.decision_id = d.decision_id
    WHERE d.lock_id = p_lock_id
      AND d.version = v_lock.current_version
      AND d.round = p_round
      AND d.role <> v_session.role
      AND d.credential_id = p_credential_id
      AND i.decision_id IS NULL
  ) THEN
    RAISE EXCEPTION 'RL_CREDENTIAL_REUSED' USING ERRCODE = 'P0002';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM public.release_lock_decisions d
    LEFT JOIN public.release_lock_decision_invalidations i
      ON i.decision_id = d.decision_id
    WHERE d.lock_id = p_lock_id
      AND d.version = v_lock.current_version
      AND d.round = p_round
      AND d.role <> v_session.role
      AND d.contact_binding_id = v_session.contact_binding_id
      AND i.decision_id IS NULL
  ) THEN
    RAISE EXCEPTION 'RL_CONTACT_REUSED' USING ERRCODE = 'P0002';
  END IF;
  SELECT count(*)::INTEGER
  INTO v_approval_count
  FROM public.release_lock_decisions d
  LEFT JOIN public.release_lock_decision_invalidations i
    ON i.decision_id = d.decision_id
  WHERE d.lock_id = p_lock_id
    AND d.version = v_lock.current_version
    AND d.round = p_round
    AND i.decision_id IS NULL;
  IF v_approval_count >= 2 THEN
    RAISE EXCEPTION 'RL_APPROVAL_LIMIT' USING ERRCODE = 'P0002';
  END IF;

  UPDATE public.release_lock_action_challenges
  SET consumed_at = clock_timestamp()
  WHERE challenge_id = p_challenge_id
    AND consumed_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_CHALLENGE_REPLAYED' USING ERRCODE = 'P0002';
  END IF;
  UPDATE public.release_lock_credentials
  SET sign_count = p_new_sign_count
  WHERE credential_id = p_credential_id
    AND sign_count = v_credential.sign_count;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_COUNTER_REPLAYED' USING ERRCODE = 'P0002';
  END IF;
  INSERT INTO public.release_lock_decisions (
    lock_id,
    version,
    round,
    role,
    challenge_id,
    contact_binding_id,
    credential_id,
    action_hash,
    prompt_set_digest,
    answer_digest,
    submitted_answers,
    resolution,
    resolution_digest,
    sign_count
  ) VALUES (
    p_lock_id,
    v_lock.current_version,
    p_round,
    v_session.role,
    p_challenge_id,
    v_session.contact_binding_id,
    p_credential_id,
    v_action_hash,
    v_challenge.prompt_set_digest,
    v_challenge.answer_digest,
    p_submitted_answers,
    p_resolution,
    p_resolution_digest,
    p_new_sign_count
  );
  v_approval_count := v_approval_count + 1;

  IF v_approval_count = 1 THEN
    UPDATE public.release_locks
    SET status = CASE
          WHEN p_round = 'CO_ACCEPTED' THEN 'co_frozen'
          ELSE 'draw_frozen'
        END,
        frozen_version = current_version,
        frozen_round = p_round,
        updated_at = clock_timestamp()
    WHERE lock_id = p_lock_id;
    RETURN jsonb_build_object(
      'lock_id', p_lock_id,
      'version', v_lock.current_version,
      'round', p_round,
      'approval_count', 1,
      'quorum_complete', false,
      'invoke_effect', false
    );
  END IF;

  v_acceptance_digest := public.release_lock_acceptance_digest(
    p_lock_id,
    v_lock.current_version,
    p_round,
    v_action_hash
  );
  INSERT INTO public.release_lock_round_acceptances (
    lock_id,
    version,
    round,
    action_hash,
    acceptance_digest
  ) VALUES (
    p_lock_id,
    v_lock.current_version,
    p_round,
    v_action_hash,
    v_acceptance_digest
  );

  IF p_round = 'CO_ACCEPTED' THEN
    UPDATE public.release_locks
    SET status = 'co_accepted',
        frozen_version = NULL,
        frozen_round = NULL,
        updated_at = clock_timestamp()
    WHERE lock_id = p_lock_id;
    RETURN jsonb_build_object(
      'lock_id', p_lock_id,
      'version', v_lock.current_version,
      'round', p_round,
      'approval_count', 2,
      'quorum_complete', true,
      'acceptance_digest', v_acceptance_digest,
      'payment_authorized', false,
      'draw_release_required', true,
      'invoke_effect', false
    );
  END IF;

  IF v_draw.draw_action->>'custodian_eligibility'
       IS DISTINCT FROM 'after_complete_draw_release_round'
     OR v_draw.draw_action->'custodian'->>'instruction'
       IS DISTINCT FROM 'release_milestone'
     OR v_draw.draw_action->'custodian'->>'effect_reference' IS NULL
  THEN
    RAISE EXCEPTION 'RL_EFFECT_BINDING' USING ERRCODE = 'P0002';
  END IF;
  v_reservation_expires_at := clock_timestamp() + INTERVAL '2 minutes';
  INSERT INTO public.release_lock_effects (
    lock_id,
    version,
    draw_action_hash,
    draw_acceptance_digest,
    effect_reference,
    provider,
    environment,
    transaction_id,
    milestone_id,
    instruction,
    reservation_expires_at
  ) VALUES (
    p_lock_id,
    v_lock.current_version,
    v_draw.draw_action_hash,
    v_acceptance_digest,
    v_draw.draw_action->'custodian'->>'effect_reference',
    v_draw.draw_action->'custodian'->>'provider',
    v_draw.draw_action->'custodian'->>'environment',
    v_draw.draw_action->'custodian'->>'transaction_id',
    v_draw.draw_action->'custodian'->>'milestone_id',
    v_draw.draw_action->'custodian'->>'instruction',
    v_reservation_expires_at
  );
  UPDATE public.release_locks
  SET status = 'effect_reserved',
      frozen_version = current_version,
      frozen_round = 'DRAW_RELEASE',
      updated_at = clock_timestamp()
  WHERE lock_id = p_lock_id;
  RETURN jsonb_build_object(
    'lock_id', p_lock_id,
    'version', v_lock.current_version,
    'round', p_round,
    'approval_count', 2,
    'quorum_complete', true,
    'acceptance_digest', v_acceptance_digest,
    'invoke_effect', true,
    'effect', jsonb_build_object(
      'action', v_draw.draw_action,
      'draw_action_hash', v_draw.draw_action_hash,
      'draw_acceptance_digest', v_acceptance_digest,
      'effect_reference', v_draw.draw_action->'custodian'->>'effect_reference',
      'provider', v_draw.draw_action->'custodian'->>'provider',
      'environment', v_draw.draw_action->'custodian'->>'environment',
      'transaction_id', v_draw.draw_action->'custodian'->>'transaction_id',
      'milestone_id', v_draw.draw_action->'custodian'->>'milestone_id',
      'instruction', 'release_milestone',
      'reservation_expires_at', v_reservation_expires_at,
      'reservation_attempts', 1
    )
  );
EXCEPTION
  WHEN unique_violation THEN
    RAISE EXCEPTION 'RL_APPROVAL_REPLAYED' USING ERRCODE = 'P0002';
  WHEN foreign_key_violation OR check_violation OR invalid_text_representation
       OR not_null_violation THEN
    RAISE EXCEPTION 'RL_APPROVAL_BINDING' USING ERRCODE = 'P0002';
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_record_approval(
  TEXT, TEXT, TEXT, UUID, TEXT, BIGINT, JSONB, TEXT, JSONB, TEXT
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_record_approval(
  TEXT, TEXT, TEXT, UUID, TEXT, BIGINT, JSONB, TEXT, JSONB, TEXT
) TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_draw_context(
  p_lock_id TEXT,
  p_organization_id TEXT,
  p_expected_version INTEGER,
  p_actor_id TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_lock public.release_locks%ROWTYPE;
  v_version public.release_lock_versions%ROWTYPE;
  v_acceptance public.release_lock_round_acceptances%ROWTYPE;
BEGIN
  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = p_lock_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_LOCK_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.organization_id IS DISTINCT FROM p_organization_id THEN
    RAISE EXCEPTION 'RL_ORGANIZATION_MISMATCH' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.contractor_entity_id IS DISTINCT FROM p_actor_id THEN
    RAISE EXCEPTION 'RL_CONTRACTOR_MISMATCH' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.current_version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'RL_VERSION_STALE' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.max_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_LOCK_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.status IS DISTINCT FROM 'co_accepted' THEN
    IF v_lock.status IN ('draw_pending', 'draw_frozen', 'effect_reserved',
      'effect_claimed', 'effect_applied', 'effect_indeterminate') THEN
      RAISE EXCEPTION 'RL_DRAW_ALREADY_STAGED' USING ERRCODE = 'P0002';
    END IF;
    RAISE EXCEPTION 'RL_CO_NOT_ACCEPTED' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO STRICT v_version
  FROM public.release_lock_versions
  WHERE lock_id = p_lock_id
    AND version = p_expected_version;
  SELECT *
  INTO v_acceptance
  FROM public.release_lock_round_acceptances
  WHERE lock_id = p_lock_id
    AND version = p_expected_version
    AND round = 'CO_ACCEPTED'
    AND action_hash = v_version.co_action_hash;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_CO_NOT_ACCEPTED' USING ERRCODE = 'P0002';
  END IF;
  RETURN jsonb_build_object(
    'lock_id', p_lock_id,
    'version', p_expected_version,
    'lock_expires_at', v_lock.max_expires_at,
    'contractor_entity_id', v_lock.contractor_entity_id,
    'co_action', v_version.co_action,
    'co_action_hash', v_version.co_action_hash,
    'co_acceptance_digest', v_acceptance.acceptance_digest,
    'co_accepted_at', v_acceptance.accepted_at
  );
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_draw_context(TEXT, TEXT, INTEGER, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_draw_context(TEXT, TEXT, INTEGER, TEXT)
  TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_stage_draw(
  p_lock_id TEXT,
  p_organization_id TEXT,
  p_expected_version INTEGER,
  p_actor_id TEXT,
  p_draw_action JSONB,
  p_draw_action_hash TEXT,
  p_draw_material_hash TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_lock public.release_locks%ROWTYPE;
  v_version public.release_lock_versions%ROWTYPE;
  v_acceptance public.release_lock_round_acceptances%ROWTYPE;
  v_expires_at TIMESTAMPTZ;
BEGIN
  IF jsonb_typeof(p_draw_action) IS DISTINCT FROM 'object'
     OR p_draw_action->>'@version' IS DISTINCT FROM 'EP-RELEASE-LOCK-DRAW-ACTION-v1'
     OR p_draw_action->>'round' IS DISTINCT FROM 'DRAW_RELEASE'
     OR p_draw_action->>'lock_id' IS DISTINCT FROM p_lock_id
     OR p_draw_action->>'version' IS DISTINCT FROM p_expected_version::TEXT
     OR p_draw_action->>'custodian_eligibility'
       IS DISTINCT FROM 'after_complete_draw_release_round'
     OR p_draw_action->'custodian'->>'instruction' IS DISTINCT FROM 'release_milestone'
     OR p_draw_action_hash !~ '^sha256:[0-9a-f]{64}$'
     OR p_draw_material_hash !~ '^sha256:[0-9a-f]{64}$'
  THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;
  BEGIN
    v_expires_at := (p_draw_action->>'expires_at')::TIMESTAMPTZ;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END;
  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = p_lock_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_LOCK_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.organization_id IS DISTINCT FROM p_organization_id THEN
    RAISE EXCEPTION 'RL_ORGANIZATION_MISMATCH' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.contractor_entity_id IS DISTINCT FROM p_actor_id THEN
    RAISE EXCEPTION 'RL_CONTRACTOR_MISMATCH' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.current_version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'RL_VERSION_STALE' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.status IS DISTINCT FROM 'co_accepted' THEN
    IF EXISTS (
      SELECT 1
      FROM public.release_lock_draw_actions d
      WHERE d.lock_id = p_lock_id AND d.version = p_expected_version
    ) THEN
      RAISE EXCEPTION 'RL_DRAW_ALREADY_STAGED' USING ERRCODE = 'P0002';
    END IF;
    RAISE EXCEPTION 'RL_CO_NOT_ACCEPTED' USING ERRCODE = 'P0002';
  END IF;
  IF v_expires_at <= clock_timestamp() OR v_expires_at > v_lock.max_expires_at THEN
    RAISE EXCEPTION 'RL_LOCK_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO STRICT v_version
  FROM public.release_lock_versions
  WHERE lock_id = p_lock_id AND version = p_expected_version;
  SELECT *
  INTO v_acceptance
  FROM public.release_lock_round_acceptances
  WHERE lock_id = p_lock_id
    AND version = p_expected_version
    AND round = 'CO_ACCEPTED'
    AND action_hash = v_version.co_action_hash;
  IF NOT FOUND
     OR p_draw_action->'accepted_change_order'->>'action_hash'
       IS DISTINCT FROM v_version.co_action_hash
     OR p_draw_action->'accepted_change_order'->>'acceptance_digest'
       IS DISTINCT FROM v_acceptance.acceptance_digest
     OR p_draw_action->'accepted_change_order'->>'version'
       IS DISTINCT FROM p_expected_version::TEXT
  THEN
    RAISE EXCEPTION 'RL_CO_NOT_ACCEPTED' USING ERRCODE = 'P0002';
  END IF;

  INSERT INTO public.release_lock_draw_actions (
    lock_id,
    version,
    draw_action,
    draw_action_hash,
    draw_material_hash,
    accepted_co_action_hash,
    accepted_co_digest,
    completion_digest,
    lien_waiver_digests,
    draw_document_digests,
    expires_at,
    created_by
  ) VALUES (
    p_lock_id,
    p_expected_version,
    p_draw_action,
    p_draw_action_hash,
    p_draw_material_hash,
    v_version.co_action_hash,
    v_acceptance.acceptance_digest,
    p_draw_action->'evidence_hashes'->>'completion_evidence_hash',
    p_draw_action->'evidence_hashes'->'lien_waiver_hashes',
    p_draw_action->'evidence_hashes'->'draw_document_hashes',
    v_expires_at,
    p_actor_id
  );
  UPDATE public.release_locks
  SET status = 'draw_pending',
      frozen_version = NULL,
      frozen_round = NULL,
      updated_at = clock_timestamp()
  WHERE lock_id = p_lock_id;
  RETURN jsonb_build_object(
    'lock_id', p_lock_id,
    'version', p_expected_version,
    'round', 'DRAW_RELEASE',
    'draw_action_hash', p_draw_action_hash,
    'accepted_co_action_hash', v_version.co_action_hash,
    'accepted_co_digest', v_acceptance.acceptance_digest,
    'status', 'draw_pending',
    'expires_at', v_expires_at
  );
EXCEPTION
  WHEN unique_violation THEN
    RAISE EXCEPTION 'RL_DRAW_ALREADY_STAGED' USING ERRCODE = 'P0002';
  WHEN foreign_key_violation OR check_violation OR invalid_text_representation
       OR not_null_violation THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_stage_draw(
  TEXT, TEXT, INTEGER, TEXT, JSONB, TEXT, TEXT
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_stage_draw(
  TEXT, TEXT, INTEGER, TEXT, JSONB, TEXT, TEXT
) TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_amendment_context(
  p_lock_id TEXT,
  p_organization_id TEXT,
  p_expected_version INTEGER,
  p_actor_id TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_lock public.release_locks%ROWTYPE;
  v_version public.release_lock_versions%ROWTYPE;
  v_contacts JSONB;
BEGIN
  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = p_lock_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_LOCK_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.organization_id IS DISTINCT FROM p_organization_id THEN
    RAISE EXCEPTION 'RL_ORGANIZATION_MISMATCH' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.contractor_entity_id IS DISTINCT FROM p_actor_id THEN
    RAISE EXCEPTION 'RL_CONTRACTOR_MISMATCH' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.current_version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'RL_VERSION_STALE' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.max_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_LOCK_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.status NOT IN (
    'co_pending', 'co_frozen', 'co_accepted', 'draw_pending', 'draw_frozen', 'effect_refused'
  ) THEN
    RAISE EXCEPTION 'RL_VERSION_FROZEN' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO STRICT v_version
  FROM public.release_lock_versions
  WHERE lock_id = p_lock_id AND version = p_expected_version;
  SELECT jsonb_agg(jsonb_build_object(
    'role', c.role,
    'identifier_digest', c.identifier_digest
  ) ORDER BY c.role)
  INTO v_contacts
  FROM public.release_lock_contact_bindings c
  WHERE c.lock_id = p_lock_id;
  RETURN jsonb_build_object(
    'lock_id', p_lock_id,
    'version', p_expected_version,
    'next_version', p_expected_version + 1,
    'status', v_lock.status,
    'lock_expires_at', v_lock.max_expires_at,
    'co_action', v_version.co_action,
    'co_material_hash', v_version.co_material_hash,
    'contact_bindings', v_contacts
  );
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_amendment_context(TEXT, TEXT, INTEGER, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_amendment_context(TEXT, TEXT, INTEGER, TEXT)
  TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_amend(
  p_lock_id TEXT,
  p_organization_id TEXT,
  p_expected_version INTEGER,
  p_actor_id TEXT,
  p_co_action JSONB,
  p_co_action_hash TEXT,
  p_co_material_hash TEXT,
  p_document_evidence JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_lock public.release_locks%ROWTYPE;
  v_previous public.release_lock_versions%ROWTYPE;
  v_new_version INTEGER;
  v_expires_at TIMESTAMPTZ;
  v_invalidated INTEGER;
BEGIN
  IF jsonb_typeof(p_co_action) IS DISTINCT FROM 'object'
     OR p_co_action->>'@version' IS DISTINCT FROM 'EP-RELEASE-LOCK-CO-ACTION-v1'
     OR p_co_action->>'round' IS DISTINCT FROM 'CO_ACCEPTED'
     OR p_co_action->>'payment_authorization' IS DISTINCT FROM 'false'
     OR p_co_action->>'lock_id' IS DISTINCT FROM p_lock_id
     OR p_co_action_hash !~ '^sha256:[0-9a-f]{64}$'
     OR p_co_material_hash !~ '^sha256:[0-9a-f]{64}$'
     OR jsonb_typeof(p_document_evidence) IS DISTINCT FROM 'object'
  THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;
  BEGIN
    v_expires_at := (p_co_action->>'expires_at')::TIMESTAMPTZ;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END;
  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = p_lock_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_LOCK_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.organization_id IS DISTINCT FROM p_organization_id THEN
    RAISE EXCEPTION 'RL_ORGANIZATION_MISMATCH' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.contractor_entity_id IS DISTINCT FROM p_actor_id THEN
    RAISE EXCEPTION 'RL_CONTRACTOR_MISMATCH' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.current_version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'RL_VERSION_STALE' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.status NOT IN (
    'co_pending', 'co_frozen', 'co_accepted', 'draw_pending', 'draw_frozen', 'effect_refused'
  ) THEN
    RAISE EXCEPTION 'RL_VERSION_FROZEN' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.max_expires_at <= clock_timestamp()
     OR v_expires_at <= clock_timestamp()
     OR v_expires_at > v_lock.max_expires_at
  THEN
    RAISE EXCEPTION 'RL_LOCK_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO STRICT v_previous
  FROM public.release_lock_versions
  WHERE lock_id = p_lock_id AND version = p_expected_version;
  v_new_version := p_expected_version + 1;
  IF p_co_action->>'version' IS DISTINCT FROM v_new_version::TEXT
     OR p_co_action->'parties' IS DISTINCT FROM v_previous.co_action->'parties'
  THEN
    RAISE EXCEPTION 'RL_APPROVAL_BINDING' USING ERRCODE = 'P0002';
  END IF;
  IF p_co_material_hash IS NOT DISTINCT FROM v_previous.co_material_hash THEN
    RAISE EXCEPTION 'RL_AMENDMENT_IDENTICAL' USING ERRCODE = 'P0002';
  END IF;

  INSERT INTO public.release_lock_decision_invalidations (
    decision_id,
    lock_id,
    invalidated_version,
    invalidated_round,
    superseded_by_version,
    reason
  )
  SELECT
    d.decision_id,
    p_lock_id,
    p_expected_version,
    d.round,
    v_new_version,
    'amended'
  FROM public.release_lock_decisions d
  LEFT JOIN public.release_lock_decision_invalidations i
    ON i.decision_id = d.decision_id
  WHERE d.lock_id = p_lock_id
    AND d.version = p_expected_version
    AND i.decision_id IS NULL;
  GET DIAGNOSTICS v_invalidated = ROW_COUNT;

  UPDATE public.release_lock_action_challenges
  SET consumed_at = clock_timestamp()
  WHERE lock_id = p_lock_id
    AND version = p_expected_version
    AND consumed_at IS NULL;

  UPDATE public.release_lock_pairings
  SET revoked_at = clock_timestamp()
  WHERE lock_id = p_lock_id
    AND exchanged_at IS NULL
    AND revoked_at IS NULL;

  UPDATE public.release_lock_sessions
  SET revoked_at = clock_timestamp()
  WHERE lock_id = p_lock_id
    AND scope_version IS NOT NULL
    AND revoked_at IS NULL;

  INSERT INTO public.release_lock_versions (
    lock_id,
    version,
    co_action,
    co_action_hash,
    co_material_hash,
    document_provider,
    document_reference,
    document_digest,
    document_evidence,
    expires_at,
    created_by
  ) VALUES (
    p_lock_id,
    v_new_version,
    p_co_action,
    p_co_action_hash,
    p_co_material_hash,
    p_co_action->'retained_change_order'->'document'->>'provider',
    p_co_action->'retained_change_order'->'document'->>'reference',
    p_co_action->'retained_change_order'->'document'->>'digest',
    p_document_evidence,
    v_expires_at,
    p_actor_id
  );
  UPDATE public.release_locks
  SET current_version = v_new_version,
      status = 'co_pending',
      frozen_version = NULL,
      frozen_round = NULL,
      updated_at = clock_timestamp()
  WHERE lock_id = p_lock_id;
  RETURN jsonb_build_object(
    'lock_id', p_lock_id,
    'version', v_new_version,
    'round', 'CO_ACCEPTED',
    'co_action_hash', p_co_action_hash,
    'status', 'co_pending',
    'invalidated_approval_count', v_invalidated,
    'draw_staged', false,
    'co_expires_at', v_expires_at,
    'lock_expires_at', v_lock.max_expires_at
  );
EXCEPTION
  WHEN unique_violation OR foreign_key_violation OR check_violation
       OR invalid_text_representation OR not_null_violation THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_amend(
  TEXT, TEXT, INTEGER, TEXT, JSONB, TEXT, TEXT, JSONB
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_amend(
  TEXT, TEXT, INTEGER, TEXT, JSONB, TEXT, TEXT, JSONB
) TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_claim_effect_binding(
  p_effect_reference TEXT,
  p_transaction_id TEXT,
  p_milestone_id TEXT,
  p_effect_contract JSONB,
  p_effect_contract_digest TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_effect public.release_lock_effects%ROWTYPE;
  v_lock public.release_locks%ROWTYPE;
  v_draw public.release_lock_draw_actions%ROWTYPE;
BEGIN
  IF jsonb_typeof(p_effect_contract) IS DISTINCT FROM 'object'
     OR p_effect_contract_digest !~ '^sha256:[0-9a-f]{64}$'
     OR p_effect_contract->>'@version'
       IS DISTINCT FROM 'EP-RELEASE-LOCK-EFFECT-CONTRACT-v1'
  THEN
    RETURN jsonb_build_object('claimed', false);
  END IF;
  SELECT *
  INTO v_effect
  FROM public.release_lock_effects
  WHERE effect_reference = p_effect_reference
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('claimed', false);
  END IF;
  IF v_effect.transaction_id IS DISTINCT FROM p_transaction_id
     OR v_effect.milestone_id IS DISTINCT FROM p_milestone_id
     OR v_effect.instruction IS DISTINCT FROM 'release_milestone'
  THEN
    RETURN jsonb_build_object('claimed', false);
  END IF;
  SELECT *
  INTO STRICT v_draw
  FROM public.release_lock_draw_actions
  WHERE lock_id = v_effect.lock_id
    AND version = v_effect.version;
  IF p_effect_contract->>'effect_reference' IS DISTINCT FROM v_effect.effect_reference
     OR p_effect_contract->>'transaction_id' IS DISTINCT FROM v_effect.transaction_id
     OR p_effect_contract->>'milestone_id' IS DISTINCT FROM v_effect.milestone_id
     OR p_effect_contract->>'draw_action_hash' IS DISTINCT FROM v_effect.draw_action_hash
     OR p_effect_contract->>'draw_acceptance_digest'
       IS DISTINCT FROM v_effect.draw_acceptance_digest
     OR p_effect_contract->>'amount' IS DISTINCT FROM v_draw.draw_action->>'amount'
     OR p_effect_contract->>'currency' IS DISTINCT FROM v_draw.draw_action->>'currency'
     OR jsonb_typeof(p_effect_contract->'payees') IS DISTINCT FROM 'array'
     OR jsonb_array_length(p_effect_contract->'payees')
       IS DISTINCT FROM jsonb_array_length(v_draw.draw_action->'payees')
     OR NOT (p_effect_contract->'payees' @> v_draw.draw_action->'payees')
     OR NOT (p_effect_contract->'payees' <@ v_draw.draw_action->'payees')
     OR p_effect_contract#>'{evidence,completion}'
       IS DISTINCT FROM v_draw.draw_action->'completion_evidence'
     OR p_effect_contract#>'{evidence,lien_waivers}'
       IS DISTINCT FROM v_draw.draw_action->'lien_waivers'
     OR p_effect_contract#>'{evidence,draw_documents}'
       IS DISTINCT FROM v_draw.draw_action->'draw_documents'
     OR (
       v_effect.effect_contract IS NOT NULL
       AND (
         v_effect.effect_contract IS DISTINCT FROM p_effect_contract
         OR v_effect.effect_contract_digest IS DISTINCT FROM p_effect_contract_digest
       )
     )
  THEN
    RETURN jsonb_build_object('claimed', false);
  END IF;
  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = v_effect.lock_id
  FOR UPDATE;
  IF NOT FOUND
     OR v_lock.current_version IS DISTINCT FROM v_effect.version
     OR v_lock.status IS DISTINCT FROM 'effect_reserved'
     OR v_effect.status IS DISTINCT FROM 'reserved'
     OR v_effect.claimed_at IS NOT NULL
     OR v_effect.claim_attempts >= 3
     OR v_effect.reservation_expires_at <= clock_timestamp()
  THEN
    RETURN jsonb_build_object('claimed', false);
  END IF;
  UPDATE public.release_lock_effects
  SET status = 'claimed',
      claimed_at = clock_timestamp(),
      claim_attempts = claim_attempts + 1,
      effect_contract = COALESCE(effect_contract, p_effect_contract),
      effect_contract_digest = COALESCE(effect_contract_digest, p_effect_contract_digest),
      retryable = false
  WHERE effect_id = v_effect.effect_id
    AND status = 'reserved'
    AND claimed_at IS NULL;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('claimed', false);
  END IF;
  UPDATE public.release_locks
  SET status = 'effect_claimed',
      updated_at = clock_timestamp()
  WHERE lock_id = v_effect.lock_id
    AND status = 'effect_reserved';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_EFFECT_ALREADY_CLAIMED' USING ERRCODE = 'P0002';
  END IF;
  RETURN jsonb_build_object(
    'claimed', true,
    'effect_reference', v_effect.effect_reference,
    'effect_contract_digest', p_effect_contract_digest
  );
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_claim_effect_binding(
  TEXT, TEXT, TEXT, JSONB, TEXT
)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_claim_effect_binding(
  TEXT, TEXT, TEXT, JSONB, TEXT
)
  TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_recover_effect(
  p_effect_reference TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_effect public.release_lock_effects%ROWTYPE;
  v_lock public.release_locks%ROWTYPE;
  v_draw public.release_lock_draw_actions%ROWTYPE;
  v_recovery JSONB;
  v_retry_expires_at TIMESTAMPTZ;
BEGIN
  IF length(COALESCE(p_effect_reference, '')) = 0 THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;
  SELECT *
  INTO v_effect
  FROM public.release_lock_effects
  WHERE effect_reference = p_effect_reference
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_EFFECT_BINDING' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = v_effect.lock_id
  FOR UPDATE;
  IF NOT FOUND OR v_lock.current_version IS DISTINCT FROM v_effect.version THEN
    RAISE EXCEPTION 'RL_EFFECT_BINDING' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO STRICT v_draw
  FROM public.release_lock_draw_actions
  WHERE lock_id = v_effect.lock_id
    AND version = v_effect.version;

  IF v_effect.status IN ('applied', 'refused', 'released') THEN
    RETURN jsonb_build_object(
      'mode', 'terminal',
      'result', COALESCE(v_effect.provider_result, jsonb_build_object(
        '@version', 'EP-RELEASE-LOCK-CUSTODIAN-RESULT-v1',
        'kind', CASE
          WHEN v_effect.status = 'applied' THEN 'released'
          ELSE 'refused_before_effect'
        END,
        'reason_code', CASE
          WHEN v_effect.status = 'released' THEN 'RETRY_LIMIT_REACHED'
          ELSE 'TERMINAL'
        END,
        'effect_reference', v_effect.effect_reference,
        'provider', v_effect.provider,
        'environment', v_effect.environment,
        'transaction_id', v_effect.transaction_id,
        'milestone_id', v_effect.milestone_id
      ))
    );
  END IF;
  IF v_effect.status IN ('claimed', 'indeterminate') THEN
    RETURN jsonb_build_object(
      'mode', 'reconcile',
      'effect', jsonb_build_object(
        'action', v_draw.draw_action,
        'draw_action_hash', v_effect.draw_action_hash,
        'draw_acceptance_digest', v_effect.draw_acceptance_digest,
        'effect_reference', v_effect.effect_reference,
        'provider', v_effect.provider,
        'environment', v_effect.environment,
        'transaction_id', v_effect.transaction_id,
        'milestone_id', v_effect.milestone_id,
        'instruction', v_effect.instruction,
        'effect_contract', v_effect.effect_contract,
        'effect_contract_digest', v_effect.effect_contract_digest
      )
    );
  END IF;
  IF v_effect.status IS DISTINCT FROM 'reserved'
     OR v_effect.claimed_at IS NOT NULL
  THEN
    RAISE EXCEPTION 'RL_EFFECT_NOT_RECOVERABLE' USING ERRCODE = 'P0002';
  END IF;
  IF v_effect.provider_result IS NULL
     AND v_effect.reservation_expires_at > clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_EFFECT_RESERVATION_ACTIVE' USING ERRCODE = 'P0002';
  END IF;
  IF v_effect.provider_result IS NOT NULL AND v_effect.retryable IS NOT TRUE THEN
    RAISE EXCEPTION 'RL_EFFECT_NOT_RECOVERABLE' USING ERRCODE = 'P0002';
  END IF;

  v_recovery := jsonb_build_object(
    '@version', 'EP-RELEASE-LOCK-EFFECT-RECOVERY-v1',
    'effect_reference', v_effect.effect_reference,
    'outcome', 'retry_definitely_not_run',
    'basis', CASE
      WHEN v_effect.provider_result IS NULL
        THEN 'unclaimed_reservation_lease_expired'
      ELSE 'recorded_no_effect'
    END,
    'prior_result', v_effect.provider_result,
    'recorded_at', clock_timestamp()
  );
  IF v_effect.reservation_attempts >= 3 THEN
    UPDATE public.release_lock_effects
    SET status = 'released',
        retryable = false,
        released_at = clock_timestamp(),
        completed_at = clock_timestamp(),
        reconciled_at = clock_timestamp(),
        last_recovery_at = clock_timestamp(),
        recovery_evidence = COALESCE(recovery_evidence, '[]'::JSONB)
          || jsonb_build_array(v_recovery || jsonb_build_object(
            'outcome', 'release_definitely_not_run',
            'basis', 'retry_limit_reached'
          ))
    WHERE effect_id = v_effect.effect_id
      AND status = 'reserved'
      AND claimed_at IS NULL;
    UPDATE public.release_locks
    SET status = 'effect_refused',
        frozen_version = NULL,
        frozen_round = NULL,
        updated_at = clock_timestamp()
    WHERE lock_id = v_effect.lock_id
      AND status = 'effect_reserved';
    RETURN jsonb_build_object(
      'mode', 'terminal',
      'result', COALESCE(v_effect.provider_result, jsonb_build_object(
        '@version', 'EP-RELEASE-LOCK-CUSTODIAN-RESULT-v1',
        'kind', 'refused_before_effect',
        'reason_code', 'RETRY_LIMIT_REACHED',
        'effect_reference', v_effect.effect_reference,
        'provider', v_effect.provider,
        'environment', v_effect.environment,
        'transaction_id', v_effect.transaction_id,
        'milestone_id', v_effect.milestone_id
      ))
    );
  END IF;

  v_retry_expires_at := clock_timestamp() + INTERVAL '2 minutes';
  UPDATE public.release_lock_effects
  SET reservation_expires_at = v_retry_expires_at,
      reservation_attempts = reservation_attempts + 1,
      retryable = false,
      provider_result = NULL,
      last_recovery_at = clock_timestamp(),
      recovery_evidence = COALESCE(recovery_evidence, '[]'::JSONB)
        || jsonb_build_array(v_recovery)
  WHERE effect_id = v_effect.effect_id
    AND status = 'reserved'
    AND claimed_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_EFFECT_NOT_RECOVERABLE' USING ERRCODE = 'P0002';
  END IF;
  RETURN jsonb_build_object(
    'mode', 'execute',
    'effect', jsonb_build_object(
      'action', v_draw.draw_action,
      'draw_action_hash', v_effect.draw_action_hash,
      'draw_acceptance_digest', v_effect.draw_acceptance_digest,
      'effect_reference', v_effect.effect_reference,
      'provider', v_effect.provider,
      'environment', v_effect.environment,
      'transaction_id', v_effect.transaction_id,
      'milestone_id', v_effect.milestone_id,
      'instruction', v_effect.instruction,
      'reservation_expires_at', v_retry_expires_at,
      'reservation_attempts', v_effect.reservation_attempts + 1
    )
  );
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_recover_effect(TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_recover_effect(TEXT)
  TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_record_effect_outcome(
  p_effect_reference TEXT,
  p_outcome TEXT,
  p_retryable BOOLEAN,
  p_provider_result JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_effect public.release_lock_effects%ROWTYPE;
  v_lock public.release_locks%ROWTYPE;
  v_recovery JSONB;
BEGIN
  IF p_outcome NOT IN ('no_effect', 'unknown_effect', 'applied')
     OR p_retryable IS NULL
     OR jsonb_typeof(p_provider_result) IS DISTINCT FROM 'object'
     OR p_provider_result->>'@version' IS NULL
     OR (p_outcome <> 'no_effect' AND p_retryable)
  THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;
  SELECT *
  INTO v_effect
  FROM public.release_lock_effects
  WHERE effect_reference = p_effect_reference
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_EFFECT_BINDING' USING ERRCODE = 'P0002';
  END IF;
  IF p_provider_result->>'effect_reference' IS DISTINCT FROM p_effect_reference
     OR p_provider_result->>'provider' IS DISTINCT FROM v_effect.provider
     OR p_provider_result->>'environment' IS DISTINCT FROM v_effect.environment
     OR p_provider_result->>'transaction_id' IS DISTINCT FROM v_effect.transaction_id
     OR p_provider_result->>'milestone_id' IS DISTINCT FROM v_effect.milestone_id
     OR (
       v_effect.effect_contract_digest IS NOT NULL
       AND p_provider_result->>'effect_contract_digest' IS NOT NULL
       AND p_provider_result->>'effect_contract_digest'
         IS DISTINCT FROM v_effect.effect_contract_digest
     )
  THEN
    RAISE EXCEPTION 'RL_EFFECT_BINDING' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = v_effect.lock_id
  FOR UPDATE;
  IF NOT FOUND OR v_lock.current_version IS DISTINCT FROM v_effect.version THEN
    RAISE EXCEPTION 'RL_EFFECT_BINDING' USING ERRCODE = 'P0002';
  END IF;

  IF p_outcome = 'applied' THEN
    IF v_effect.status NOT IN ('claimed', 'indeterminate')
       OR v_effect.effect_contract IS NULL
    THEN
      RAISE EXCEPTION 'RL_EFFECT_ALREADY_CLAIMED' USING ERRCODE = 'P0002';
    END IF;
    UPDATE public.release_lock_effects
    SET status = 'applied',
        retryable = false,
        provider_result = p_provider_result,
        completed_at = clock_timestamp(),
        reconciled_at = CASE
          WHEN v_effect.status = 'indeterminate' THEN clock_timestamp()
          ELSE reconciled_at
        END
    WHERE effect_id = v_effect.effect_id;
    UPDATE public.release_locks
    SET status = 'effect_applied',
        updated_at = clock_timestamp()
    WHERE lock_id = v_effect.lock_id;
  ELSIF p_outcome = 'unknown_effect' THEN
    IF v_effect.status NOT IN ('reserved', 'claimed', 'indeterminate') THEN
      RAISE EXCEPTION 'RL_EFFECT_NOT_RECONCILABLE' USING ERRCODE = 'P0002';
    END IF;
    UPDATE public.release_lock_effects
    SET status = 'indeterminate',
        retryable = false,
        provider_result = p_provider_result,
        last_recovery_at = clock_timestamp()
    WHERE effect_id = v_effect.effect_id;
    UPDATE public.release_locks
    SET status = 'effect_indeterminate',
        updated_at = clock_timestamp()
    WHERE lock_id = v_effect.lock_id;
  ELSE
    IF v_effect.status NOT IN ('reserved', 'claimed', 'indeterminate') THEN
      RAISE EXCEPTION 'RL_EFFECT_NOT_RECOVERABLE' USING ERRCODE = 'P0002';
    END IF;
    v_recovery := jsonb_build_object(
      '@version', 'EP-RELEASE-LOCK-EFFECT-RECOVERY-v1',
      'effect_reference', v_effect.effect_reference,
      'outcome', CASE
        WHEN p_retryable THEN 'retry_definitely_not_run'
        ELSE 'release_definitely_not_run'
      END,
      'basis', 'authoritative_provider_no_effect',
      'provider_result', p_provider_result,
      'recorded_at', clock_timestamp()
    );
    IF p_retryable THEN
      UPDATE public.release_lock_effects
      SET status = 'reserved',
          claimed_at = NULL,
          retryable = true,
          provider_result = p_provider_result,
          reservation_expires_at = clock_timestamp(),
          last_recovery_at = clock_timestamp(),
          recovery_evidence = COALESCE(recovery_evidence, '[]'::JSONB)
            || jsonb_build_array(v_recovery)
      WHERE effect_id = v_effect.effect_id;
      UPDATE public.release_locks
      SET status = 'effect_reserved',
          updated_at = clock_timestamp()
      WHERE lock_id = v_effect.lock_id;
    ELSE
      UPDATE public.release_lock_effects
      SET status = 'released',
          claimed_at = NULL,
          retryable = false,
          provider_result = p_provider_result,
          released_at = clock_timestamp(),
          completed_at = clock_timestamp(),
          reconciled_at = clock_timestamp(),
          last_recovery_at = clock_timestamp(),
          recovery_evidence = COALESCE(recovery_evidence, '[]'::JSONB)
            || jsonb_build_array(v_recovery)
      WHERE effect_id = v_effect.effect_id;
      UPDATE public.release_locks
      SET status = 'effect_refused',
          frozen_version = NULL,
          frozen_round = NULL,
          updated_at = clock_timestamp()
      WHERE lock_id = v_effect.lock_id;
    END IF;
  END IF;
  RETURN jsonb_build_object(
    'lock_id', v_effect.lock_id,
    'version', v_effect.version,
    'effect_reference', p_effect_reference,
    'status', p_outcome,
    'retryable', p_retryable
  );
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_record_effect_outcome(
  TEXT, TEXT, BOOLEAN, JSONB
)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_record_effect_outcome(
  TEXT, TEXT, BOOLEAN, JSONB
)
  TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_reconciliation_context(
  p_effect_reference TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_effect public.release_lock_effects%ROWTYPE;
  v_draw public.release_lock_draw_actions%ROWTYPE;
BEGIN
  SELECT *
  INTO v_effect
  FROM public.release_lock_effects
  WHERE effect_reference = p_effect_reference;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_EFFECT_BINDING' USING ERRCODE = 'P0002';
  END IF;
  IF v_effect.status NOT IN ('claimed', 'indeterminate') THEN
    RAISE EXCEPTION 'RL_EFFECT_NOT_RECONCILABLE' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO STRICT v_draw
  FROM public.release_lock_draw_actions
  WHERE lock_id = v_effect.lock_id
    AND version = v_effect.version;
  RETURN jsonb_build_object(
    'lock_id', v_effect.lock_id,
    'version', v_effect.version,
    'action', v_draw.draw_action,
    'draw_action_hash', v_effect.draw_action_hash,
    'draw_acceptance_digest', v_effect.draw_acceptance_digest,
    'effect_reference', v_effect.effect_reference,
    'provider', v_effect.provider,
    'environment', v_effect.environment,
    'transaction_id', v_effect.transaction_id,
    'milestone_id', v_effect.milestone_id,
    'instruction', v_effect.instruction,
    'status', v_effect.status,
    'reserved_at', v_effect.reserved_at,
    'reservation_expires_at', v_effect.reservation_expires_at,
    'reservation_attempts', v_effect.reservation_attempts,
    'claimed_at', v_effect.claimed_at,
    'last_recovery_at', v_effect.last_recovery_at,
    'recovery_evidence', v_effect.recovery_evidence
  );
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_reconciliation_context(TEXT)
  FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.release_lock_record_reconciliation(
  p_effect_reference TEXT,
  p_status TEXT,
  p_provider_result JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_effect public.release_lock_effects%ROWTYPE;
BEGIN
  IF p_status NOT IN ('applied', 'refused', 'indeterminate')
     OR jsonb_typeof(p_provider_result) IS DISTINCT FROM 'object'
  THEN
    RAISE EXCEPTION 'RL_ARGUMENT_INVALID' USING ERRCODE = 'P0001';
  END IF;
  SELECT *
  INTO v_effect
  FROM public.release_lock_effects
  WHERE effect_reference = p_effect_reference
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_EFFECT_BINDING' USING ERRCODE = 'P0002';
  END IF;
  IF v_effect.status NOT IN ('claimed', 'indeterminate') THEN
    RAISE EXCEPTION 'RL_EFFECT_NOT_RECONCILABLE' USING ERRCODE = 'P0002';
  END IF;
  IF p_provider_result->>'effect_reference' IS DISTINCT FROM p_effect_reference
     OR p_provider_result->>'provider' IS DISTINCT FROM v_effect.provider
     OR p_provider_result->>'environment' IS DISTINCT FROM v_effect.environment
     OR p_provider_result->>'transaction_id' IS DISTINCT FROM v_effect.transaction_id
     OR p_provider_result->>'milestone_id' IS DISTINCT FROM v_effect.milestone_id
  THEN
    RAISE EXCEPTION 'RL_EFFECT_BINDING' USING ERRCODE = 'P0002';
  END IF;
  UPDATE public.release_lock_effects
  SET status = p_status,
      provider_result = p_provider_result,
      completed_at = CASE WHEN p_status = 'indeterminate' THEN completed_at ELSE clock_timestamp() END,
      reconciled_at = clock_timestamp()
  WHERE effect_id = v_effect.effect_id;
  UPDATE public.release_locks
  SET status = 'effect_' || p_status,
      updated_at = clock_timestamp()
  WHERE lock_id = v_effect.lock_id
    AND current_version = v_effect.version;
  RETURN jsonb_build_object(
    'lock_id', v_effect.lock_id,
    'version', v_effect.version,
    'effect_reference', p_effect_reference,
    'status', p_status,
    'reconciled', true
  );
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_record_reconciliation(TEXT, TEXT, JSONB)
  FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.release_lock_evidence(
  p_lock_id TEXT,
  p_organization_id TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_lock public.release_locks%ROWTYPE;
  v_versions JSONB;
  v_draws JSONB;
  v_contacts JSONB;
  v_credentials JSONB;
  v_decisions JSONB;
  v_acceptances JSONB;
  v_effects JSONB;
BEGIN
  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = p_lock_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_LOCK_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.organization_id IS DISTINCT FROM p_organization_id THEN
    RAISE EXCEPTION 'RL_ORGANIZATION_MISMATCH' USING ERRCODE = 'P0002';
  END IF;
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'version', v.version,
    'co_action', v.co_action,
    'co_action_hash', v.co_action_hash,
    'co_material_hash', v.co_material_hash,
    'document_evidence', v.document_evidence,
    'expires_at', v.expires_at,
    'created_by', v.created_by,
    'created_at', v.created_at
  ) ORDER BY v.version), '[]'::JSONB)
  INTO v_versions
  FROM public.release_lock_versions v
  WHERE v.lock_id = p_lock_id;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'version', d.version,
    'draw_action', d.draw_action,
    'draw_action_hash', d.draw_action_hash,
    'draw_material_hash', d.draw_material_hash,
    'accepted_co_action_hash', d.accepted_co_action_hash,
    'accepted_co_digest', d.accepted_co_digest,
    'expires_at', d.expires_at,
    'created_by', d.created_by,
    'created_at', d.created_at
  ) ORDER BY d.version), '[]'::JSONB)
  INTO v_draws
  FROM public.release_lock_draw_actions d
  WHERE d.lock_id = p_lock_id;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'contact_binding_id', c.contact_binding_id,
    'role', c.role,
    'channel', c.channel,
    'identifier_digest', c.identifier_digest,
    'verification_provider', c.verification_provider,
    'verification_reference', c.verification_reference,
    'verification_proof_digest', c.verification_proof_digest,
    'verified_at', c.verified_at,
    'verification_expires_at', c.verification_expires_at,
    'authority_provider', c.authority_provider,
    'authority_key_id', c.authority_key_id,
    'authority_reference', c.authority_reference,
    'authority_assertion', c.authority_assertion,
    'authority_signature', c.authority_signature,
    'authority_assertion_digest', c.authority_assertion_digest,
    'authority_subject_digest', c.authority_subject_digest,
    'authority_contact_binding_digest', c.authority_contact_binding_digest,
    'authority_verified_at', c.authority_verified_at,
    'authority_expires_at', c.authority_expires_at,
    'external_identity_proof_required', true
  ) ORDER BY c.role), '[]'::JSONB)
  INTO v_contacts
  FROM public.release_lock_contact_bindings c
  WHERE c.lock_id = p_lock_id;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'credential_id', c.credential_id,
    'role', c.role,
    'contact_binding_id', c.contact_binding_id,
    'public_key_spki', c.public_key_spki,
    'sign_count', c.sign_count,
    'device_type', c.device_type,
    'backed_up', c.backed_up,
    'attestation_format', c.attestation_format,
    'rp_id', c.rp_id,
    'origin', c.origin,
    'enrolled_at', c.enrolled_at,
    'revoked_at', c.revoked_at
  ) ORDER BY c.role), '[]'::JSONB)
  INTO v_credentials
  FROM public.release_lock_credentials c
  WHERE c.lock_id = p_lock_id;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'decision_id', d.decision_id,
    'version', d.version,
    'round', d.round,
    'role', d.role,
    'challenge_id', d.challenge_id,
    'contact_binding_id', d.contact_binding_id,
    'credential_id', d.credential_id,
    'action_hash', d.action_hash,
    'prompt_set_digest', d.prompt_set_digest,
    'answer_digest', d.answer_digest,
    'submitted_answers', d.submitted_answers,
    'action_check', jsonb_build_object(
      'prompt_set', h.prompt_set,
      'prompt_set_digest', h.prompt_set_digest,
      'answer_digest', h.answer_digest,
      'binding_moment', h.binding_moment,
      'random_nonce', h.random_nonce,
      'nonce', h.nonce,
      'resolution_context', h.resolution_context,
      'challenge', h.challenge,
      'issued_at', h.issued_at,
      'expires_at', h.expires_at,
      'consumed_at', h.consumed_at
    ),
    'resolution', d.resolution,
    'resolution_digest', d.resolution_digest,
    'sign_count', d.sign_count,
    'decided_at', d.decided_at,
    'invalidation', CASE WHEN i.decision_id IS NULL THEN NULL ELSE jsonb_build_object(
      'reason', i.reason,
      'superseded_by_version', i.superseded_by_version,
      'invalidated_at', i.invalidated_at
    ) END
  ) ORDER BY d.version, d.round, d.role), '[]'::JSONB)
  INTO v_decisions
  FROM public.release_lock_decisions d
  JOIN public.release_lock_action_challenges h
    ON h.challenge_id = d.challenge_id
  LEFT JOIN public.release_lock_decision_invalidations i
    ON i.decision_id = d.decision_id
  WHERE d.lock_id = p_lock_id;

  SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY a.version, a.round), '[]'::JSONB)
  INTO v_acceptances
  FROM public.release_lock_round_acceptances a
  WHERE a.lock_id = p_lock_id;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'effect_id', e.effect_id,
    'version', e.version,
    'draw_action_hash', e.draw_action_hash,
    'draw_acceptance_digest', e.draw_acceptance_digest,
    'effect_reference', e.effect_reference,
    'provider', e.provider,
    'environment', e.environment,
    'transaction_id', e.transaction_id,
    'milestone_id', e.milestone_id,
    'instruction', e.instruction,
    'effect_contract', e.effect_contract,
    'effect_contract_digest', e.effect_contract_digest,
    'status', e.status,
    'provider_result', e.provider_result,
    'reserved_at', e.reserved_at,
    'reservation_expires_at', e.reservation_expires_at,
    'reservation_attempts', e.reservation_attempts,
    'claim_attempts', e.claim_attempts,
    'retryable', e.retryable,
    'claimed_at', e.claimed_at,
    'released_at', e.released_at,
    'last_recovery_at', e.last_recovery_at,
    'recovery_evidence', e.recovery_evidence,
    'completed_at', e.completed_at,
    'reconciled_at', e.reconciled_at
  ) ORDER BY e.version), '[]'::JSONB)
  INTO v_effects
  FROM public.release_lock_effects e
  WHERE e.lock_id = p_lock_id;

  RETURN jsonb_build_object(
    'lock', jsonb_build_object(
      'lock_id', v_lock.lock_id,
      'organization_id', v_lock.organization_id,
      'contractor_entity_id', v_lock.contractor_entity_id,
      'current_version', v_lock.current_version,
      'frozen_version', v_lock.frozen_version,
      'frozen_round', v_lock.frozen_round,
      'status', v_lock.status,
      'max_expires_at', v_lock.max_expires_at,
      'created_at', v_lock.created_at,
      'updated_at', v_lock.updated_at
    ),
    'change_order_versions', v_versions,
    'draw_release_actions', v_draws,
    'contact_bindings', v_contacts,
    'credentials', v_credentials,
    'decisions', v_decisions,
    'round_acceptances', v_acceptances,
    'effects', v_effects
  );
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_evidence(TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_evidence(TEXT, TEXT)
  TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_participant_view(
  p_session_digest TEXT,
  p_lock_id TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_session public.release_lock_sessions%ROWTYPE;
  v_lock public.release_locks%ROWTYPE;
  v_version public.release_lock_versions%ROWTYPE;
  v_draw public.release_lock_draw_actions%ROWTYPE;
  v_decisions JSONB;
  v_acceptances JSONB;
  v_effect JSONB;
  v_credential_enrolled BOOLEAN;
  v_scoped_status TEXT;
BEGIN
  IF p_session_digest !~ '^hmac-sha256:[0-9a-f]{64}$'
     OR p_lock_id !~ '^rlk_[a-f0-9]{32}$'
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_session
  FROM public.release_lock_sessions
  WHERE token_digest = p_session_digest;
  IF NOT FOUND
     OR v_session.lock_id IS DISTINCT FROM p_lock_id
     OR v_session.revoked_at IS NOT NULL
     OR v_session.expires_at <= clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = p_lock_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_LOCK_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.max_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_LOCK_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO STRICT v_version
  FROM public.release_lock_versions
  WHERE lock_id = p_lock_id
    AND version = v_lock.current_version;
  IF v_session.scope_version IS NOT NULL
     AND (
       v_session.scope_version IS DISTINCT FROM v_lock.current_version
       OR (
         v_session.scope_round = 'CO_ACCEPTED'
         AND v_session.scope_action_hash IS DISTINCT FROM v_version.co_action_hash
       )
     )
  THEN
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  IF v_session.scope_round IS NULL OR v_session.scope_round = 'DRAW_RELEASE' THEN
    SELECT *
    INTO v_draw
    FROM public.release_lock_draw_actions
    WHERE lock_id = p_lock_id
      AND version = v_lock.current_version;
    IF v_session.scope_round = 'DRAW_RELEASE'
       AND (
         v_draw.lock_id IS NULL
         OR v_session.scope_action_hash IS DISTINCT FROM v_draw.draw_action_hash
       )
    THEN
      RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
    END IF;
  END IF;

  SELECT EXISTS (
    SELECT 1
    FROM public.release_lock_credentials c
    WHERE c.lock_id = p_lock_id
      AND c.role = v_session.role
      AND c.contact_binding_id = v_session.contact_binding_id
      AND c.revoked_at IS NULL
  )
  INTO v_credential_enrolled;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'round', d.round,
    'role', d.role,
    'credential_id', d.credential_id,
    'action_hash', d.action_hash,
    'resolution_digest', d.resolution_digest,
    'decided_at', d.decided_at,
    'invalidated', i.decision_id IS NOT NULL
  ) ORDER BY d.round, d.role), '[]'::JSONB)
  INTO v_decisions
  FROM public.release_lock_decisions d
  LEFT JOIN public.release_lock_decision_invalidations i
    ON i.decision_id = d.decision_id
  WHERE d.lock_id = p_lock_id
    AND d.version = v_lock.current_version
    AND (v_session.scope_round IS NULL OR d.round = v_session.scope_round);

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'round', a.round,
    'action_hash', a.action_hash,
    'acceptance_digest', a.acceptance_digest,
    'accepted_at', a.accepted_at
  ) ORDER BY a.round), '[]'::JSONB)
  INTO v_acceptances
  FROM public.release_lock_round_acceptances a
  WHERE a.lock_id = p_lock_id
    AND a.version = v_lock.current_version
    AND (v_session.scope_round IS NULL OR a.round = v_session.scope_round);

  IF v_session.scope_round IS NULL OR v_session.scope_round = 'DRAW_RELEASE' THEN
    SELECT jsonb_build_object(
      'status', e.status,
      'effect_reference', e.effect_reference,
      'provider', e.provider,
      'environment', e.environment,
      'transaction_id', e.transaction_id,
      'milestone_id', e.milestone_id,
      'reserved_at', e.reserved_at,
      'reservation_expires_at', e.reservation_expires_at,
      'reservation_attempts', e.reservation_attempts,
      'claim_attempts', e.claim_attempts,
      'retryable', e.retryable,
      'claimed_at', e.claimed_at,
      'released_at', e.released_at,
      'last_recovery_at', e.last_recovery_at,
      'completed_at', e.completed_at,
      'reconciled_at', e.reconciled_at
    )
    INTO v_effect
    FROM public.release_lock_effects e
    WHERE e.lock_id = p_lock_id
      AND e.version = v_lock.current_version;
  END IF;

  v_scoped_status := CASE
    WHEN v_session.scope_round = 'CO_ACCEPTED'
         AND v_lock.status NOT IN ('co_pending', 'co_frozen', 'co_accepted')
      THEN 'co_scope_complete'
    ELSE v_lock.status
  END;

  RETURN jsonb_build_object(
    'role', v_session.role,
    'scope_round', v_session.scope_round,
    'scope_version', v_session.scope_version,
    'scope_action_hash', v_session.scope_action_hash,
    'session_expires_at', v_session.expires_at,
    'credential_enrolled', v_credential_enrolled,
    'lock', jsonb_build_object(
      'lock_id', v_lock.lock_id,
      'current_version', v_lock.current_version,
      'status', v_scoped_status,
      'max_expires_at', v_lock.max_expires_at,
      'created_at', v_lock.created_at,
      'updated_at', v_lock.updated_at
    ),
    'change_order', jsonb_build_object(
      'action', v_version.co_action,
      'action_hash', v_version.co_action_hash,
      'document_evidence', v_version.document_evidence,
      'expires_at', v_version.expires_at
    ),
    'draw_release', CASE
      WHEN v_session.scope_round = 'CO_ACCEPTED' OR v_draw.lock_id IS NULL THEN NULL
      ELSE jsonb_build_object(
      'action', v_draw.draw_action,
      'action_hash', v_draw.draw_action_hash,
      'expires_at', v_draw.expires_at
    ) END,
    'decisions', v_decisions,
    'round_acceptances', v_acceptances,
    'effect', v_effect
  );
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_participant_view(TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_participant_view(TEXT, TEXT)
  TO service_role;

CREATE OR REPLACE FUNCTION public.release_lock_participant_evidence(
  p_session_digest TEXT,
  p_lock_id TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_session public.release_lock_sessions%ROWTYPE;
  v_lock public.release_locks%ROWTYPE;
  v_current_action_hash TEXT;
  v_evidence JSONB;
  v_scoped_decisions JSONB;
  v_scoped_acceptances JSONB;
BEGIN
  IF p_session_digest !~ '^hmac-sha256:[0-9a-f]{64}$'
     OR p_lock_id !~ '^rlk_[a-f0-9]{32}$'
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_session
  FROM public.release_lock_sessions
  WHERE token_digest = p_session_digest;
  IF NOT FOUND
     OR v_session.lock_id IS DISTINCT FROM p_lock_id
     OR v_session.revoked_at IS NOT NULL
     OR v_session.expires_at <= clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = p_lock_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_LOCK_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.max_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_LOCK_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  IF v_session.scope_version IS NOT NULL THEN
    IF v_session.scope_version IS DISTINCT FROM v_lock.current_version THEN
      RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
    END IF;
    IF v_session.scope_round = 'CO_ACCEPTED' THEN
      SELECT co_action_hash
      INTO STRICT v_current_action_hash
      FROM public.release_lock_versions
      WHERE lock_id = p_lock_id
        AND version = v_session.scope_version;
    ELSE
      SELECT draw_action_hash
      INTO STRICT v_current_action_hash
      FROM public.release_lock_draw_actions
      WHERE lock_id = p_lock_id
        AND version = v_session.scope_version;
    END IF;
    IF v_current_action_hash IS DISTINCT FROM v_session.scope_action_hash THEN
      RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
    END IF;
  END IF;

  v_evidence := public.release_lock_evidence(p_lock_id, v_lock.organization_id);
  IF v_session.scope_round IS NULL THEN
    RETURN v_evidence;
  END IF;
  SELECT COALESCE(jsonb_agg(value), '[]'::JSONB)
  INTO v_scoped_decisions
  FROM jsonb_array_elements(v_evidence->'decisions')
  WHERE value->>'round' = v_session.scope_round;
  SELECT COALESCE(jsonb_agg(value), '[]'::JSONB)
  INTO v_scoped_acceptances
  FROM jsonb_array_elements(v_evidence->'round_acceptances')
  WHERE value->>'round' = v_session.scope_round;
  v_evidence := v_evidence || jsonb_build_object(
    'participant_scope', jsonb_build_object(
      'role', v_session.role,
      'round', v_session.scope_round,
      'version', v_session.scope_version,
      'action_hash', v_session.scope_action_hash
    ),
    'decisions', v_scoped_decisions,
    'round_acceptances', v_scoped_acceptances
  );
  IF v_session.scope_round = 'CO_ACCEPTED' THEN
    v_evidence := v_evidence || jsonb_build_object(
      'lock', (v_evidence->'lock') || jsonb_build_object(
        'status', CASE
          WHEN v_lock.status IN ('co_pending', 'co_frozen', 'co_accepted')
            THEN v_lock.status
          ELSE 'co_scope_complete'
        END
      ),
      'draw_release_actions', '[]'::JSONB,
      'effects', '[]'::JSONB
    );
  END IF;
  RETURN v_evidence;
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_participant_evidence(TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_participant_evidence(TEXT, TEXT)
  TO service_role;
