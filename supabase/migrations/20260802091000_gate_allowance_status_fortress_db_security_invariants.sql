-- SPDX-License-Identifier: Apache-2.0
-- Migration version: 20260802091000
--
-- Forward-only Fortress reassertion for the authoritative Gate Allowance
-- status head. Client roles must never read or advance this state directly;
-- only the customer-controlled service path participates in currentness CAS.

ALTER TABLE public.ep_gate_allowance_status
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ep_gate_allowance_status
  FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.ep_gate_allowance_status
  FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.ep_gate_allowance_status
  TO service_role;
