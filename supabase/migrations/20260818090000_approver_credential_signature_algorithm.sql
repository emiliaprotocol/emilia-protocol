-- SPDX-License-Identifier: Apache-2.0
-- Record the signature algorithm of each Class A credential, so ONE approver
-- can hold a classical and a post-quantum credential at the same time.
--
-- WHY THIS IS NEEDED. Hybrid human authorization at the WebAuthn layer is not
-- something FIDO will hand EP: both live W3C proposals (Microsoft PR 2437,
-- open; the Google explainer merged via PR 2449) specify SINGLE-algorithm
-- post-quantum credentials and explicitly leave hybrid to the relying party.
-- So hybrid here means what EP can actually build: TWO enrolled credentials
-- per approver, one ES256 and one ML-DSA-65, with a quorum policy requiring a
-- signoff from each (EP-QUORUM-v1 `policy.required_algorithms`, default off).
-- `approver_credentials` had no way to say which algorithm a row is for, so
-- the two credentials were indistinguishable in the directory. This column is
-- that distinction.
--
-- THIS DOES NOT MEAN EP SUPPORTS POST-QUANTUM WEBAUTHN. No browser, platform
-- passkey provider, or certified authenticator produces an ML-DSA WebAuthn
-- credential today, and the FIDO Registry of Predefined Values v2.3 defines no
-- ALG_SIGN constant for ML-DSA, so certified hardware cannot even declare the
-- capability. No 'ML-DSA-65' row can be created by a real enrollment yet. The
-- relying-party half -- EP's own verification code, which was never
-- FIDO-gated -- is ready ahead of it; the schema is the last piece that was
-- missing on EP's side.
--
-- THE STORED KEY REMAINS THE AUTHORITY. `alg` is a directory label used to
-- SELECT the right credential; it is not trusted as the algorithm to verify
-- under. The verifier reads the algorithm out of `public_key_spki` itself
-- (packages/verify webauthnSignatureAlgorithm), so a mislabeled row cannot
-- steer verification -- it fails to satisfy the algorithm it claims.
--
-- ADDITIVE AND NULLABLE. No default: a writer that has not thought about the
-- algorithm records nothing rather than asserting something. Existing rows are
-- backfilled to 'ES256', which is true by construction, not by assumption:
-- registration pins `supportedAlgorithmIDs: [-7]`
-- (app/api/v1/approvers/webauthn/register-options/route.ts) and enrollment
-- converts the COSE key through coseToSpkiP256, which throws on any
-- kty/alg/crv other than EC2 / ES256 / P-256 (lib/webauthn.ts). Every row that
-- exists before this migration is therefore an ES256/P-256 credential.
--
-- WHAT IS NOT DONE HERE, said plainly: the enrollment writer does not populate
-- this column yet. public.complete_webauthn_registration_atomic (added in
-- 20260802231000_restore_webauthn_directory_anchor.sql) enumerates its INSERT
-- columns explicitly and does not list `alg`, so rows created AFTER this
-- migration are NULL until that function and the register-verify route are
-- updated together. Nothing is unsafe in the meantime: the verifier never
-- consults this column, it reads the algorithm out of public_key_spki.

ALTER TABLE public.approver_credentials
  ADD COLUMN IF NOT EXISTS alg TEXT COLLATE "C";

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint
    WHERE conname = 'approver_credentials_alg_chk'
  ) THEN
    ALTER TABLE public.approver_credentials
      ADD CONSTRAINT approver_credentials_alg_chk
      CHECK (alg IS NULL OR alg IN ('ES256', 'ML-DSA-65'));
  END IF;
END $$;

COMMENT ON COLUMN public.approver_credentials.alg IS
  'Signature algorithm of this Class A credential: ES256 or ML-DSA-65. Lets one approver hold a classical and a post-quantum credential simultaneously, which is what hybrid human authorization means at this layer (EP-QUORUM-v1 policy.required_algorithms). A directory label for selection only: the verifier reads the algorithm from public_key_spki, never from this column. NULL means unstated.';

-- Backfill: see the header. Every pre-existing row is ES256/P-256 because both
-- the registration options and the COSE conversion pinned it.
UPDATE public.approver_credentials
  SET alg = 'ES256'
  WHERE alg IS NULL;

-- Credential lookup is per (approver, algorithm) once an approver can hold
-- more than one: a hybrid quorum has to fetch the ES256 row and the ML-DSA-65
-- row separately. NOT unique -- an approver may legitimately enroll several
-- passkeys under the same algorithm.
CREATE INDEX IF NOT EXISTS idx_approver_credentials_approver_alg
  ON public.approver_credentials (approver_id, alg)
  WHERE revoked_at IS NULL;
