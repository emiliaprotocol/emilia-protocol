-- SPDX-License-Identifier: Apache-2.0
-- Migration version: 20260725011000
--
-- Forward-only Fortress reassertion for the consequence-actuator envelope
-- store. The actuator executor reaches the state only through the two narrow
-- SECURITY DEFINER functions; Supabase API roles and service_role retain no
-- direct table authority.

GRANT consequence_actuator_store_owner TO CURRENT_USER;

ALTER SCHEMA consequence_actuator_private
  OWNER TO consequence_actuator_store_owner;
ALTER TABLE consequence_actuator_private.tenant_principals
  OWNER TO consequence_actuator_store_owner;
ALTER TABLE public.consequence_actuator_envelopes
  OWNER TO consequence_actuator_store_owner;

ALTER TABLE consequence_actuator_private.tenant_principals
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE consequence_actuator_private.tenant_principals
  FORCE ROW LEVEL SECURITY;
ALTER TABLE public.consequence_actuator_envelopes
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.consequence_actuator_envelopes
  FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE consequence_actuator_private.tenant_principals
  FROM PUBLIC, anon, authenticated, service_role, consequence_actuator_executor;
REVOKE ALL ON TABLE public.consequence_actuator_envelopes
  FROM PUBLIC, anon, authenticated, service_role, consequence_actuator_executor;
REVOKE ALL ON SCHEMA consequence_actuator_private
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA consequence_actuator_private
  FROM PUBLIC, anon, authenticated, service_role, consequence_actuator_executor;

DROP POLICY IF EXISTS consequence_actuator_principal_owner_all
  ON consequence_actuator_private.tenant_principals;
CREATE POLICY consequence_actuator_principal_owner_all
  ON consequence_actuator_private.tenant_principals
  FOR ALL
  TO consequence_actuator_store_owner USING (TRUE) WITH CHECK (TRUE);

DROP POLICY IF EXISTS consequence_actuator_envelope_owner_all
  ON public.consequence_actuator_envelopes;
CREATE POLICY consequence_actuator_envelope_owner_all
  ON public.consequence_actuator_envelopes
  FOR ALL
  TO consequence_actuator_store_owner USING (TRUE) WITH CHECK (TRUE);

ALTER FUNCTION consequence_actuator_private.assert_tenant_principal(TEXT)
  OWNER TO consequence_actuator_store_owner;
ALTER FUNCTION consequence_actuator_private.reserve_envelope(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
  TIMESTAMPTZ, TIMESTAMPTZ, TEXT
) OWNER TO consequence_actuator_store_owner;
ALTER FUNCTION consequence_actuator_private.consume_envelope(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) OWNER TO consequence_actuator_store_owner;

GRANT USAGE ON SCHEMA consequence_actuator_private
  TO consequence_actuator_executor;
GRANT EXECUTE ON FUNCTION consequence_actuator_private.reserve_envelope(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
  TIMESTAMPTZ, TIMESTAMPTZ, TEXT
),
consequence_actuator_private.consume_envelope(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
)
TO consequence_actuator_executor;

REVOKE consequence_actuator_store_owner FROM CURRENT_USER;
