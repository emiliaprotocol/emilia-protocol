ALTER TABLE public.ep_capability_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ep_capability_operations ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.ep_capability_state FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.ep_capability_operations FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.ep_capability_state TO service_role;
GRANT ALL ON TABLE public.ep_capability_operations TO service_role;;
