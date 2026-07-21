-- Reference / experimental. Not production audited.
-- Run as the schema owner, then grant only SELECT, INSERT to the dedicated
-- edge-auth service role. Do not grant DELETE or UPDATE: consumption is final.

CREATE TABLE IF NOT EXISTS ep_edge_receipt_consumptions (
  action text NOT NULL,
  receipt_id text NOT NULL,
  consumed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (action, receipt_id),
  CHECK (length(action) BETWEEN 1 AND 256),
  CHECK (length(receipt_id) BETWEEN 1 AND 128)
);

REVOKE ALL ON TABLE ep_edge_receipt_consumptions FROM PUBLIC;

