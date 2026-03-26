-- ============================================================================
-- Emilia Eye — Lightweight warning protocol
--
-- Three tables:
--   eye_observations  — Normalized warning-relevant facts from trusted sources
--   eye_advisories    — Short-lived, explainable warning results (append-only)
--   eye_suppressions  — Enterprise/local suppression controls
-- ============================================================================

-- ── Table 1: eye_observations ───────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS eye_observations (
  observation_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_type       TEXT NOT NULL,
  source_ref        TEXT NOT NULL,
  subject_ref       TEXT NOT NULL,
  actor_ref         TEXT NOT NULL,
  action_type       TEXT NOT NULL,
  target_ref        TEXT,
  issuer_ref        TEXT,
  workflow_ref      TEXT,
  context_hash      TEXT NOT NULL,
  payload_hash      TEXT,
  observation_type  TEXT NOT NULL,
  severity_hint     TEXT NOT NULL DEFAULT 'medium' CHECK (severity_hint IN ('low', 'medium', 'high', 'critical')),
  evidence_hash     TEXT,
  observed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at        TIMESTAMPTZ NOT NULL,
  metadata          JSONB DEFAULT '{}'::jsonb,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE eye_observations IS 'Emilia Eye: normalized warning-relevant facts from trusted sources. Each row is an atomic observation used as input to advisory evaluation.';

CREATE INDEX idx_eye_observations_subject_action ON eye_observations (subject_ref, action_type);
CREATE INDEX idx_eye_observations_actor ON eye_observations (actor_ref);
CREATE INDEX idx_eye_observations_type ON eye_observations (observation_type);
CREATE INDEX idx_eye_observations_expires ON eye_observations (expires_at);

-- ── Table 2: eye_advisories (append-only) ───────────────────────────────────

CREATE TABLE IF NOT EXISTS eye_advisories (
  advisory_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_ref              TEXT NOT NULL,
  actor_ref                TEXT NOT NULL,
  action_type              TEXT NOT NULL,
  target_ref               TEXT,
  issuer_ref               TEXT,
  context_hash             TEXT NOT NULL,
  scope_binding_hash       TEXT NOT NULL,
  status                   TEXT NOT NULL CHECK (status IN ('clear', 'caution', 'elevated', 'review_required')),
  reason_codes             TEXT[] NOT NULL DEFAULT '{}',
  recommended_policy_action TEXT NOT NULL CHECK (recommended_policy_action IN (
    'allow_normal_flow', 'require_ep_handshake', 'require_strict_ep_handshake',
    'require_accountable_signoff', 'hold_for_manual_review'
  )),
  evidence_refs            TEXT[] NOT NULL DEFAULT '{}',
  issued_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at               TIMESTAMPTZ NOT NULL,
  advisory_hash            TEXT NOT NULL,
  version                  INTEGER NOT NULL DEFAULT 1,
  created_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE eye_advisories IS 'Emilia Eye: short-lived, explainable warning results. Append-only — once issued, advisories cannot be updated or deleted. New versions are inserted as new rows.';

CREATE INDEX idx_eye_advisories_subject_action ON eye_advisories (subject_ref, action_type);
CREATE INDEX idx_eye_advisories_actor ON eye_advisories (actor_ref);
CREATE INDEX idx_eye_advisories_status ON eye_advisories (status);
CREATE INDEX idx_eye_advisories_scope ON eye_advisories (scope_binding_hash);
CREATE INDEX idx_eye_advisories_expires ON eye_advisories (expires_at);

-- Append-only enforcement (same pattern as handshake_events)
CREATE OR REPLACE FUNCTION prevent_eye_advisory_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'EVENT_IMMUTABILITY_VIOLATION: eye_advisories is append-only. Cannot % advisory %',
    TG_OP, COALESCE(OLD.advisory_id::text, 'unknown');
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_eye_advisories_no_update
  BEFORE UPDATE ON eye_advisories
  FOR EACH ROW EXECUTE FUNCTION prevent_eye_advisory_mutation();

CREATE TRIGGER enforce_eye_advisories_no_delete
  BEFORE DELETE ON eye_advisories
  FOR EACH ROW EXECUTE FUNCTION prevent_eye_advisory_mutation();

-- ── Table 3: eye_suppressions ───────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS eye_suppressions (
  suppression_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scope_binding_hash  TEXT NOT NULL,
  reason_code         TEXT NOT NULL,
  approved_by         TEXT NOT NULL,
  justification       TEXT NOT NULL,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at          TIMESTAMPTZ NOT NULL,
  status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked'))
);

COMMENT ON TABLE eye_suppressions IS 'Emilia Eye: enterprise/local suppression controls. Allows authorized actors to suppress specific reason codes within a scope, with mandatory justification and expiry.';

CREATE INDEX idx_eye_suppressions_scope ON eye_suppressions (scope_binding_hash);
CREATE INDEX idx_eye_suppressions_reason ON eye_suppressions (reason_code);
