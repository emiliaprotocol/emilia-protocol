-- 130_consumed_gate_refs.sql
--
-- One-time-use ledger for /api/trust/gate 'allow' decisions.
--
-- Security audit finding (2026-07-07): /api/commit/issue validated a gate_ref
-- (a prior gate 'allow' commit) for high-stakes actions but never marked it
-- consumed, so a single 'allow' decision could authorize UNLIMITED high-stakes
-- issuances (gate-bypass via replay). commits is append-only/immutable by
-- trigger, so consumption cannot live on the commit row; this table is the
-- one-time ledger. The PRIMARY KEY on gate_ref makes the claim atomic: the first
-- issuance INSERTs the gate_ref, any replay hits a unique_violation and is
-- refused. Reached only via the service-role client (getGuardedClient), so RLS +
-- a service_role policy match the 114/129 pattern.

CREATE TABLE IF NOT EXISTS consumed_gate_refs (
  gate_ref            TEXT PRIMARY KEY,
  consumed_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  consumed_by_entity  TEXT,
  consumed_for_action TEXT
);

ALTER TABLE consumed_gate_refs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_all" ON consumed_gate_refs;
CREATE POLICY "service_role_all" ON consumed_gate_refs
  FOR ALL TO service_role USING (true) WITH CHECK (true);

COMMENT ON TABLE consumed_gate_refs IS
  'One-time-use ledger: a gate_ref (a /api/trust/gate allow commit) may authorize at most one /api/commit/issue for a high-stakes action. PK on gate_ref enforces the exactly-once gate invariant.';
