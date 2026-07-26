CREATE TABLE IF NOT EXISTS authorities (
  authority_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key_id          TEXT NOT NULL UNIQUE,
  public_key      TEXT NOT NULL,
  algorithm       TEXT NOT NULL DEFAULT 'Ed25519',
  role            TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'retired')),
  valid_from      TIMESTAMPTZ NOT NULL DEFAULT now(),
  valid_to        TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at      TIMESTAMPTZ,
  metadata_json   JSONB DEFAULT '{}'::jsonb,
  organization_id TEXT,
  subject_type    TEXT,
  subject_ref     TEXT,
  assurance_class TEXT
);

CREATE INDEX IF NOT EXISTS idx_authorities_key_id  ON authorities (key_id);
CREATE INDEX IF NOT EXISTS idx_authorities_status  ON authorities (status, valid_from, valid_to);
CREATE INDEX IF NOT EXISTS idx_authorities_subject ON authorities (subject_type, subject_ref, organization_id, status);

COMMENT ON TABLE authorities IS 'Authority registry: credentials prove control, authorities prove permission. Resolved by key_id (protocol signers/issuers) and by (subject_type, subject_ref, organization_id) (human approvers).';

ALTER TABLE authorities ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_all" ON authorities;
CREATE POLICY "service_role_all" ON authorities
  FOR ALL TO service_role USING (true) WITH CHECK (true);;
