-- Migration version: 20260718084127
-- Cover every Release Lock foreign-key path used by deletion, recovery, and
-- participant-scoped lookups.

CREATE INDEX IF NOT EXISTS release_lock_action_challenges_contact_binding_idx
  ON public.release_lock_action_challenges (contact_binding_id, lock_id, role);

CREATE INDEX IF NOT EXISTS release_lock_action_challenges_credential_idx
  ON public.release_lock_action_challenges (credential_id);

CREATE INDEX IF NOT EXISTS release_lock_action_challenges_session_idx
  ON public.release_lock_action_challenges (session_id);

CREATE INDEX IF NOT EXISTS release_lock_credentials_contact_binding_idx
  ON public.release_lock_credentials (contact_binding_id, lock_id, role);

CREATE INDEX IF NOT EXISTS release_lock_decisions_contact_binding_idx
  ON public.release_lock_decisions (contact_binding_id, lock_id, role);

CREATE INDEX IF NOT EXISTS release_lock_decisions_credential_idx
  ON public.release_lock_decisions (credential_id);

CREATE INDEX IF NOT EXISTS release_lock_invitations_contact_binding_idx
  ON public.release_lock_invitations (contact_binding_id, lock_id, role);

CREATE INDEX IF NOT EXISTS release_lock_pairings_contact_binding_idx
  ON public.release_lock_pairings (contact_binding_id, lock_id, role);

CREATE INDEX IF NOT EXISTS release_lock_pairings_version_idx
  ON public.release_lock_pairings (lock_id, version);

CREATE INDEX IF NOT EXISTS release_lock_registration_challenges_contact_binding_idx
  ON public.release_lock_registration_challenges (contact_binding_id, lock_id, role);

CREATE INDEX IF NOT EXISTS release_lock_registration_challenges_lock_idx
  ON public.release_lock_registration_challenges (lock_id);

CREATE INDEX IF NOT EXISTS release_lock_registration_challenges_session_idx
  ON public.release_lock_registration_challenges (session_id);

CREATE INDEX IF NOT EXISTS release_lock_sessions_contact_binding_idx
  ON public.release_lock_sessions (contact_binding_id, lock_id, role);

CREATE INDEX IF NOT EXISTS release_lock_sessions_invitation_idx
  ON public.release_lock_sessions (invitation_id);

CREATE INDEX IF NOT EXISTS release_lock_sessions_version_idx
  ON public.release_lock_sessions (lock_id, scope_version);
