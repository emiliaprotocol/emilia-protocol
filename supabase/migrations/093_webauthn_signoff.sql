-- 093_webauthn_signoff.sql
-- Class A signoff: approver-held WebAuthn keys (docs/WEBAUTHN-SIGNOFF.md,
-- standards/ draft §5). Three additive tables; service-role access only —
-- all access goes through server routes, never the anon key.

-- ── Approver credentials (the enrolled device keys) ─────────────────────────
CREATE TABLE IF NOT EXISTS approver_credentials (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  approver_id      TEXT NOT NULL,             -- ep:approver:...
  approver_name    TEXT,                      -- display name for receipts
  credential_id    TEXT NOT NULL UNIQUE,      -- b64u WebAuthn credential id
  public_key_cose  TEXT NOT NULL,             -- b64u COSE key (as registered)
  public_key_spki  TEXT NOT NULL,             -- b64u P-256 SPKI DER — what the
                                              -- zero-dep offline verifier uses
  key_class        TEXT NOT NULL DEFAULT 'A',
  sign_count       BIGINT NOT NULL DEFAULT 0,
  transports       TEXT[],
  attestation_fmt  TEXT,
  -- Second-party attestation (draft §5.2 MUST when the EP operator runs the
  -- directory): the authenticated org-admin entity that confirmed enrollment.
  attested_by      TEXT,
  valid_from       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  valid_to         TIMESTAMPTZ,
  revoked_at       TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_approver_credentials_approver
  ON approver_credentials (approver_id) WHERE revoked_at IS NULL;

-- ── Single-use WebAuthn challenges (registration + signoff signing) ─────────
-- For signing, the challenge IS the context hash: SHA-256(JCS(Authorization
-- Context)), so the canonical context is persisted here and the approve route
-- verifies against these exact bytes (WYSIWYS + single-use by construction).
CREATE TABLE IF NOT EXISTS webauthn_challenges (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind          TEXT NOT NULL CHECK (kind IN ('registration', 'signoff')),
  approver_id   TEXT NOT NULL,
  signoff_id    TEXT,                          -- sig_<32hex> for kind='signoff'
  challenge     TEXT NOT NULL,                 -- b64u challenge bytes
  context       JSONB,                         -- canonical Authorization Context
  context_hash  TEXT,                          -- sha256 hex of JCS(context)
  expires_at    TIMESTAMPTZ NOT NULL,
  consumed_at   TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_signoff
  ON webauthn_challenges (signoff_id, created_at DESC);

-- ── Pilot telemetry (draft §11.8) — the actual deliverable ──────────────────
-- time_to_sign_ms is THE number: near-floor latencies indicate approval
-- without review. planted_mismatch marks consented render-mismatch drills.
CREATE TABLE IF NOT EXISTS signoff_metrics (
  signoff_id        TEXT PRIMARY KEY,
  receipt_id        TEXT,
  approver_id       TEXT,
  rendered_at       TIMESTAMPTZ,
  signed_at         TIMESTAMPTZ,
  time_to_sign_ms   INTEGER,
  decision          TEXT,                      -- approved | rejected | expired
  key_class         TEXT,
  planted_mismatch  BOOLEAN NOT NULL DEFAULT FALSE,
  mismatch_caught   BOOLEAN,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Service-role only: enable RLS with no policies so anon/authenticated get
-- nothing; the service key bypasses RLS by design.
ALTER TABLE approver_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_challenges  ENABLE ROW LEVEL SECURITY;
ALTER TABLE signoff_metrics      ENABLE ROW LEVEL SECURITY;
