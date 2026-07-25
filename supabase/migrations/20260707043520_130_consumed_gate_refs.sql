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
  'One-time-use ledger: a gate_ref (a /api/trust/gate allow commit) may authorize at most one /api/commit/issue for a high-stakes action. PK on gate_ref enforces the exactly-once gate invariant.';;
