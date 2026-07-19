-- Contract phase for accountable policy-rollout activation.
--
-- Apply only after the application version that calls
-- activate_policy_rollout_authorized(...) is live and verified. This removes
-- the legacy direct-write path, leaving the locked SECURITY DEFINER function as
-- the only service-role mutation boundary.

REVOKE INSERT, UPDATE, DELETE, TRUNCATE
  ON TABLE public.policy_rollouts
  FROM PUBLIC, anon, authenticated, service_role;

GRANT SELECT ON TABLE public.policy_rollouts TO service_role;
