-- Trust Desk bootstrap tokens are one-time credentials. Store only the hash so
-- a database read cannot recover the configured operator bearer.

CREATE TABLE IF NOT EXISTS trust_desk_bootstrap_consumptions (
  token_hash TEXT PRIMARY KEY,
  consumed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE trust_desk_bootstrap_consumptions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.trust_desk_bootstrap_consumptions FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION public.consume_trust_desk_bootstrap_atomic(p_token_hash TEXT)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
BEGIN
  IF p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
    RETURN jsonb_build_object('consumed', false, 'reason', 'invalid_token_hash');
  END IF;

  INSERT INTO trust_desk_bootstrap_consumptions (token_hash)
  VALUES (p_token_hash)
  ON CONFLICT (token_hash) DO NOTHING;

  IF FOUND THEN
    RETURN jsonb_build_object('consumed', true);
  END IF;
  RETURN jsonb_build_object('consumed', false, 'reason', 'bootstrap_replayed');
END;
$function$;

REVOKE EXECUTE ON FUNCTION public.consume_trust_desk_bootstrap_atomic(TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_trust_desk_bootstrap_atomic(TEXT) TO service_role;
