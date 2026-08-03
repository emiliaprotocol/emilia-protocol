-- Fence capability operations on the ACTION, not only on the operation id.
--
-- Before this, ep_capability_operations was unique on (operation_namespace,
-- operation_id). A caller that retried a request-for-approval received a fresh
-- operation id, and both requests carried the same action_digest, so both could
-- reserve and both could execute. The same merge, payout, or delete was
-- authorizable twice under two ids. A budget masked it whenever an amount was
-- attached and masked nothing at all for a zero-amount irreversible action.
--
-- reserveSpend now reads the holder inside its transaction with FOR UPDATE,
-- which serializes two concurrent reservations for one action. This index is
-- the backstop for anything reaching the table outside that path, and it makes
-- the invariant a property of the database rather than of one code path.
--
-- Scoped to operation_namespace on purpose. The namespace is the authorization
-- domain, defaulting to the capability id. Two DIFFERENT capabilities may each
-- hold the same action digest, which is what multi-party quorum requires: N
-- principals independently authorizing one action. A globally unique index
-- would silently make quorum unsatisfiable.
--
-- 'released' is excluded. A released operation carries outcome 'not_entered',
-- meaning the provider provably never received it, so re-authorizing that same
-- action is a genuine retry and must remain possible.

CREATE UNIQUE INDEX IF NOT EXISTS ep_capability_operations_live_action_uniq
  ON ep_capability_operations (operation_namespace, action_digest)
  WHERE status IN ('reserved', 'provider_entered', 'committed');

COMMENT ON INDEX ep_capability_operations_live_action_uniq IS
  'At most one live (reserved/provider_entered/committed) operation per action digest per authorization namespace. Released operations are excluded so a proven non-entry can be retried. Scoped per namespace so quorum across distinct capabilities stays possible.';
