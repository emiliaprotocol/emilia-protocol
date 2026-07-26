-- 126_revoke_public_grants_on_entity_secrets.sql
--
-- Operational-boundary hardening (least privilege on key material).
--
-- entities.private_key_encrypted (mig 078, sealed Ed25519 key material) and
-- entities.api_key_hash carried column-level SELECT/INSERT/UPDATE/REFERENCES
-- grants for the `anon` and `authenticated` PostgREST roles. RLS is enabled on
-- entities, but a column grant is a second, independent gate: any RLS policy
-- that lets those roles read an entity row would expose the sealed key column,
-- and the roles should never write it either. The application reads/writes this
-- material ONLY via service_role (server-side receipt signing at
-- app/api/receipt/route.js and sealing at entity creation), so the public and
-- authenticated roles need no access at all.
--
-- Revoke the two sensitive columns from anon + authenticated. service_role and
-- postgres retain their grants (the legitimate signing/sealing path is
-- unaffected). This is defense-in-depth alongside migration 125 (which stops the
-- auth RPC from returning the columns): 125 closes the app-layer disclosure; 126
-- closes the DB-layer reachability, so the exposure is gone even under RLS-policy
-- drift or a future SELECT * on a public-role connection.
--
-- Idempotent: REVOKE on an already-revoked privilege is a no-op.

REVOKE SELECT, INSERT, UPDATE, REFERENCES (private_key_encrypted)
  ON public.entities FROM anon, authenticated;

REVOKE SELECT, INSERT, UPDATE, REFERENCES (api_key_hash)
  ON public.entities FROM anon, authenticated;
