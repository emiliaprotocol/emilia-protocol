DO $disable_canaries$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'ep_canary_executor_20260723'
  ) THEN
    EXECUTE 'ALTER ROLE ep_canary_executor_20260723 NOLOGIN PASSWORD NULL';
    EXECUTE 'REVOKE ep_aeb_executor, proposal_to_effect_executor, ep_aeb_recovery, proposal_to_effect_recovery FROM ep_canary_executor_20260723';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'ep_canary_recovery_20260723'
  ) THEN
    EXECUTE 'ALTER ROLE ep_canary_recovery_20260723 NOLOGIN PASSWORD NULL';
    EXECUTE 'REVOKE ep_aeb_executor, proposal_to_effect_executor, ep_aeb_recovery, proposal_to_effect_recovery FROM ep_canary_recovery_20260723';
  END IF;
END;
$disable_canaries$;
