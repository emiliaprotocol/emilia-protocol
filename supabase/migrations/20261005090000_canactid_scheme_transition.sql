-- SPDX-License-Identifier: Apache-2.0
-- Phase A of the forward-only transition from the historical `caid:` scheme
-- spelling to the IANA-provisionally-registered `canactid:` spelling defined
-- by CAID-05.
--
-- This expand migration is deliberately safe for a mixed-version rollout:
-- stored identifiers remain byte-for-byte unchanged, constraints admit both
-- spellings, and the active database validators accept both. Deploy this
-- migration before any current-only issuer. After every issuer is verified to
-- emit `canactid:`, a separate protected-main Phase B migration may install
-- current-only write guards. Do not collapse the two phases into one batch.

-- Supabase may execute with a managed migration role over a different wire
-- login. Save the effective migration role before temporarily assuming the
-- separately owned open-exposure custody role below.
SELECT pg_catalog.set_config(
  'ep.canactid_migration_role',
  CURRENT_USER,
  TRUE
);

ALTER TABLE public.mobile_action_groups
  DROP CONSTRAINT IF EXISTS mobile_action_groups_current_action_caid_check;
ALTER TABLE public.mobile_action_groups
  ADD CONSTRAINT mobile_action_groups_current_action_caid_check
  CHECK (
    current_action_caid ~ '^(caid|canactid):1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$'
  ) NOT VALID;

ALTER TABLE public.mobile_action_revisions
  DROP CONSTRAINT IF EXISTS mobile_action_revisions_action_caid_check;
ALTER TABLE public.mobile_action_revisions
  ADD CONSTRAINT mobile_action_revisions_action_caid_check
  CHECK (
    action_caid ~ '^(caid|canactid):1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$'
  ) NOT VALID;
ALTER TABLE public.mobile_action_revisions
  DROP CONSTRAINT IF EXISTS mobile_action_revision_supersession;
ALTER TABLE public.mobile_action_revisions
  ADD CONSTRAINT mobile_action_revision_supersession
  CHECK (
    (supersedes_revision IS NULL AND supersedes_action_caid IS NULL AND revision = 1)
    OR (
      supersedes_revision IS NOT NULL
      AND supersedes_revision >= 1
      AND supersedes_revision < revision
      AND supersedes_action_caid ~ '^(caid|canactid):1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$'
    )
  ) NOT VALID;

ALTER TABLE public.mobile_action_challenges
  DROP CONSTRAINT IF EXISTS mobile_action_challenges_action_caid_check;
ALTER TABLE public.mobile_action_challenges
  ADD CONSTRAINT mobile_action_challenges_action_caid_check
  CHECK (
    action_caid IS NULL
    OR action_caid ~ '^(caid|canactid):1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$'
  ) NOT VALID;

ALTER TABLE public.mobile_action_operations
  DROP CONSTRAINT IF EXISTS mobile_action_operations_action_caid_check;
ALTER TABLE public.mobile_action_operations
  ADD CONSTRAINT mobile_action_operations_action_caid_check
  CHECK (
    action_caid ~ '^(caid|canactid):1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$'
  ) NOT VALID;

ALTER TABLE public.approval_acquisition_requests
  DROP CONSTRAINT IF EXISTS approval_acquisition_requests_action_caid_check;
ALTER TABLE public.approval_acquisition_requests
  ADD CONSTRAINT approval_acquisition_requests_action_caid_check
  CHECK (
    action_caid ~ '^(caid|canactid):1:payment[.]release[.]1:jcs-sha256:[A-Za-z0-9_-]{43}$'
  ) NOT VALID;

ALTER TABLE trust_program_private.trust_roots
  DROP CONSTRAINT IF EXISTS trust_roots_root_caid_check;
ALTER TABLE trust_program_private.trust_roots
  ADD CONSTRAINT trust_roots_root_caid_check
  CHECK (
    root_caid ~ '^(caid|canactid):1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$'
  ) NOT VALID;

ALTER TABLE public.arena_attempts
  DROP CONSTRAINT IF EXISTS arena_attempts_caid_check;
ALTER TABLE public.arena_attempts
  ADD CONSTRAINT arena_attempts_caid_check
  CHECK (
    caid ~ '^(caid|canactid):1:arena\.resource\.allocate\.1:jcs-sha256:[A-Za-z0-9_-]{43}$'
  ) NOT VALID;

-- Widen only the active CAID-validation functions. CREATE OR REPLACE keeps
-- their signatures, owners, grants, security posture, and pinned search paths.
-- No function is allowed to stay legacy-only after the expand migration.
DO $canactid_function_expand$
DECLARE
  v_definition text;
BEGIN
  FOR v_definition IN
    SELECT pg_catalog.pg_get_functiondef(proc.oid)
    FROM pg_catalog.pg_proc AS proc
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = proc.pronamespace
    WHERE (
      (namespace.nspname = 'public' AND proc.proname IN (
        'create_mobile_demo_action_v2',
        'create_grace_mobile_action_group_v2',
        'supersede_mobile_action',
        'attempt_arena_action'
      ))
      OR (namespace.nspname = 'trust_program_private' AND proc.proname = 'validate_state')
    )
    AND pg_catalog.strpos(pg_catalog.pg_get_functiondef(proc.oid), '^caid:1:') > 0
  LOOP
    EXECUTE pg_catalog.replace(v_definition, '^caid:1:', '^(caid|canactid):1:');
  END LOOP;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS proc
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = proc.pronamespace
    WHERE (
      (namespace.nspname = 'public' AND proc.proname IN (
        'create_mobile_demo_action_v2',
        'create_grace_mobile_action_group_v2',
        'supersede_mobile_action',
        'attempt_arena_action'
      ))
      OR (namespace.nspname = 'trust_program_private' AND proc.proname = 'validate_state')
    )
    AND pg_catalog.strpos(pg_catalog.pg_get_functiondef(proc.oid), '^caid:1:') > 0
  ) THEN
    RAISE EXCEPTION 'active CAID database function remains legacy-only';
  END IF;
END
$canactid_function_expand$;

-- The open-exposure store is deliberately owned by a separate NOLOGIN role.
-- The migration role retains ADMIN but not SET membership, so grant itself
-- temporary SET membership, perform only the owner-required changes, restore
-- the saved effective role, and remove that membership before commit.
GRANT ep_open_exposure_store_owner TO CURRENT_USER
  WITH INHERIT FALSE, SET TRUE;
SET ROLE ep_open_exposure_store_owner;

ALTER TABLE open_exposure_private.exposures
  DROP CONSTRAINT IF EXISTS exposures_caid_check;
ALTER TABLE open_exposure_private.exposures
  ADD CONSTRAINT exposures_caid_check
  CHECK (
    caid ~ '^(caid|canactid):1:[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$'
  ) NOT VALID;

DO $open_exposure_canactid_function_expand$
DECLARE
  v_definition text;
BEGIN
  FOR v_definition IN
    SELECT pg_catalog.pg_get_functiondef(proc.oid)
    FROM pg_catalog.pg_proc AS proc
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = proc.pronamespace
    WHERE namespace.nspname = 'open_exposure_private'
      AND proc.proname IN ('reserve', 'begin_invocation')
      AND pg_catalog.strpos(pg_catalog.pg_get_functiondef(proc.oid), '^caid:1:') > 0
  LOOP
    EXECUTE pg_catalog.replace(v_definition, '^caid:1:', '^(caid|canactid):1:');
  END LOOP;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS proc
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = proc.pronamespace
    WHERE namespace.nspname = 'open_exposure_private'
      AND proc.proname IN ('reserve', 'begin_invocation')
      AND pg_catalog.strpos(pg_catalog.pg_get_functiondef(proc.oid), '^caid:1:') > 0
  ) THEN
    RAISE EXCEPTION 'open-exposure CAID database function remains legacy-only';
  END IF;
END
$open_exposure_canactid_function_expand$;

DO $restore_canactid_migration_role$
BEGIN
  EXECUTE pg_catalog.format(
    'SET ROLE %I',
    pg_catalog.current_setting('ep.canactid_migration_role')
  );
END
$restore_canactid_migration_role$;
REVOKE ep_open_exposure_store_owner FROM CURRENT_USER;
