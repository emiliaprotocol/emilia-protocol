DO $$
DECLARE
  fixes TEXT[][] := ARRAY[
    ARRAY['api_keys',        'API keys via service role only'],
    ARRAY['entities',        'Service role can insert entities'],
    ARRAY['entities',        'Service role can update entities'],
    ARRAY['receipts',        'Receipts can be inserted'],
    ARRAY['score_history',   'Score history can be inserted'],
    ARRAY['needs',           'Needs can be inserted'],
    ARRAY['needs',           'Needs can be updated'],
    ARRAY['anchor_batches',  'anchor_batches_insert'],
    ARRAY['waitlist',        'waitlist_read']
  ];
  f TEXT[];
BEGIN
  FOREACH f SLICE 1 IN ARRAY fixes LOOP
    IF EXISTS (
      SELECT 1 FROM pg_policy p
      JOIN pg_class c ON c.oid = p.polrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname='public' AND c.relname = f[1] AND p.polname = f[2]
    ) THEN
      EXECUTE format('ALTER POLICY %I ON public.%I TO service_role;', f[2], f[1]);
      RAISE NOTICE 'rescoped %.% -> service_role', f[1], f[2];
    ELSE
      RAISE NOTICE 'skip (absent): %.%', f[1], f[2];
    END IF;
  END LOOP;
END $$;;
