-- 133_receipt_chain_fork_guard.sql
--
-- A hash chain is not linear merely because every row names a predecessor.
-- Without a database constraint, two concurrent writers can both read the same
-- head and append different children. Enforce one child per predecessor for
-- every entity, including exactly one root row.
--
-- Deployment note: CREATE UNIQUE INDEX intentionally fails if historical forks
-- already exist. Operators must investigate and reconcile those forks rather
-- than silently bless one branch.

CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_single_child_per_parent
  ON receipts (entity_id, COALESCE(previous_hash, 'root'));

COMMENT ON INDEX idx_receipts_single_child_per_parent IS
  'Prevents concurrent receipt writers from forking an entity hash chain at the same predecessor.';
