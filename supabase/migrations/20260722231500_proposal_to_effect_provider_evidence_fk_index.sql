-- SPDX-License-Identifier: Apache-2.0
-- Cover the provider-evidence foreign-key lookup used when consequence
-- attempts are reconciled or deleted under owner-controlled maintenance.

CREATE INDEX IF NOT EXISTS proposal_to_effect_provider_evidence_attempt_fk_idx
  ON proposal_to_effect_private.provider_evidence (
    tenant_id,
    provider_id,
    provider_account_id,
    environment,
    attempt_id,
    attempt_digest
  );
