REVOKE SELECT, INSERT, UPDATE, REFERENCES (private_key_encrypted)
  ON public.entities FROM anon, authenticated;

REVOKE SELECT, INSERT, UPDATE, REFERENCES (api_key_hash)
  ON public.entities FROM anon, authenticated;;
