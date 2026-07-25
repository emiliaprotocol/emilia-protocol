DO $$
DECLARE
  fn regprocedure;
  target_names TEXT[] := ARRAY[
    'approve_attestation_atomic',
    'bulk_update_receipt_anchors',
    'consume_handshake_atomic',
    'consume_signoff_atomic',
    'create_handshake_atomic',
    'create_test_fixtures',
    'issue_challenge_atomic',
    'present_handshake_writes',
    'resolve_authenticated_actor',
    'verify_handshake_writes'
  ];
BEGIN
  FOR fn IN
    SELECT p.oid::regprocedure
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND p.prosecdef
      AND p.proname = ANY (target_names)
  LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, anon, authenticated;', fn);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role;', fn);
    RAISE NOTICE 'locked %', fn;
  END LOOP;
END $$;;
