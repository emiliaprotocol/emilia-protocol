REVOKE SELECT, INSERT, UPDATE (private_key_encrypted, api_key_hash)
  ON public.entities FROM anon, authenticated;
REVOKE SELECT, INSERT, UPDATE (key_hash)
  ON public.api_keys FROM anon, authenticated;
REVOKE SELECT, INSERT, UPDATE (key_hash)
  ON public.tenant_api_keys FROM anon, authenticated;
REVOKE SELECT, INSERT, UPDATE (oidc_client_secret)
  ON public.sso_connections FROM anon, authenticated;
REVOKE SELECT, INSERT, UPDATE (secret)
  ON public.webhook_endpoints FROM anon, authenticated;;
