-- 045_consumption_enforcement.sql
-- HARD GATE: Once consumed_at is set on a binding, it can never be cleared.
-- This prevents any code path — including direct SQL — from reversing consumption.

CREATE OR REPLACE FUNCTION prevent_consumption_reversal()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS NULL THEN
    RAISE EXCEPTION 'CONSUMPTION_IRREVERSIBLE: Cannot clear consumed_at once set on binding %', OLD.id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_consumption_irreversible
  BEFORE UPDATE ON handshake_bindings
  FOR EACH ROW
  EXECUTE FUNCTION prevent_consumption_reversal();
