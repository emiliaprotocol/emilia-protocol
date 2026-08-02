-- SPDX-License-Identifier: Apache-2.0
-- Put allowance currentness in the same PostgreSQL transaction domain as spend reservation.

ALTER TABLE public.ep_capability_state
  ADD COLUMN IF NOT EXISTS allowance_profile_id TEXT,
  ADD COLUMN IF NOT EXISTS allowance_digest TEXT
    CHECK (allowance_digest ~ '^sha256:[0-9a-f]{64}$');

ALTER TABLE public.ep_capability_operations
  ADD COLUMN IF NOT EXISTS allowance_revision BIGINT CHECK (allowance_revision > 0),
  ADD COLUMN IF NOT EXISTS allowance_status_epoch BIGINT CHECK (allowance_status_epoch > 0),
  ADD COLUMN IF NOT EXISTS allowance_status_head_digest TEXT
    CHECK (allowance_status_head_digest ~ '^sha256:[0-9a-f]{64}$');

CREATE TABLE IF NOT EXISTS public.ep_gate_allowance_status (
  allowance_profile_id TEXT PRIMARY KEY,
  allowance_digest TEXT NOT NULL
    CHECK (allowance_digest ~ '^sha256:[0-9a-f]{64}$'),
  revision BIGINT NOT NULL CHECK (revision > 0),
  status_epoch BIGINT NOT NULL CHECK (status_epoch > 0),
  status_head_digest TEXT NOT NULL
    CHECK (status_head_digest ~ '^sha256:[0-9a-f]{64}$'),
  status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.ep_gate_allowance_status ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.ep_gate_allowance_status FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.ep_gate_allowance_status TO service_role;

COMMENT ON TABLE public.ep_gate_allowance_status IS
  'Authoritative allowance lineage head locked and compared inside capability spend reservation.';
COMMENT ON COLUMN public.ep_capability_operations.allowance_status_head_digest IS
  'Allowance status head validated under the reservation transaction row lock.';
