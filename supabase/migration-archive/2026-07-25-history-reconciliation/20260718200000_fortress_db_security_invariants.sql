-- SPDX-License-Identifier: Apache-2.0
-- Migration version: 20260718200000
--
-- Fortress database security invariants — capability-store reassertion.
--
-- Forward-only continuation of 20260718145410_fortress_db_security_invariants.sql
-- for the service-only tables added after it: the Marvel durable capability
-- store (ep_capability_state, ep_capability_operations, migration 20260718190000).
-- Idempotent reassertion of the same access model those tables already carry —
-- RLS on, no anon/authenticated/PUBLIC table grant. Unlike the Release Lock
-- tables (RPC-only), the capability store is queried directly by the service-role
-- durable store, so service_role KEEPS its table grant here.

-- ── Reassert RLS ─────────────────────────────────────────────────────────────
ALTER TABLE public.ep_capability_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ep_capability_operations ENABLE ROW LEVEL SECURITY;

-- ── Reassert no public/anon/authenticated table ACL (service_role retained) ──
REVOKE ALL ON TABLE public.ep_capability_state FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.ep_capability_operations FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.ep_capability_state TO service_role;
GRANT ALL ON TABLE public.ep_capability_operations TO service_role;
