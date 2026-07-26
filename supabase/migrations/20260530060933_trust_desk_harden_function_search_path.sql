-- Harden the trigger function: pin search_path to '' (Supabase advisor
-- function_search_path_mutable). NOW() resolves via pg_catalog regardless.
CREATE OR REPLACE FUNCTION public.trust_desk_touch_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;;
