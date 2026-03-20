-- System-level idempotency for receipts.
-- Every receipt write must include an idempotency_key.
-- The database enforces uniqueness — application code is defense-in-depth only.

ALTER TABLE receipts
ADD COLUMN IF NOT EXISTS idempotency_key TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_idempotency_key
ON receipts (idempotency_key)
WHERE idempotency_key IS NOT NULL;

-- Also add composite uniqueness for submitter + transaction
CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_submitter_tx_type
ON receipts (submitted_by, transaction_ref, transaction_type)
WHERE submitted_by IS NOT NULL AND transaction_ref IS NOT NULL;

COMMENT ON COLUMN receipts.idempotency_key IS 'Application-generated idempotency key. DB uniqueness is the primary replay protection.';
