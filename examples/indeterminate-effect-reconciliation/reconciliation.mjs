// SPDX-License-Identifier: Apache-2.0

import {
  canonicalize,
  hashCanonical,
  reconcileCapabilityOperation,
} from '../../packages/gate/index.js';

import { verifySignedProviderEvidence } from './provider.mjs';

export const RECONCILIATION_RECORD_VERSION = 'EP-INDETERMINATE-EFFECT-RECONCILIATION-v1';

function clone(value) {
  return structuredClone(value);
}

export function createReconciliationLedger() {
  const records = new Map();
  return Object.freeze({
    append(record) {
      const current = records.get(record.operation_id);
      if (current) {
        if (canonicalize(current) !== canonicalize(record)) {
          throw new Error('conflicting reconciliation record');
        }
        return clone(current);
      }
      records.set(record.operation_id, clone(record));
      return clone(record);
    },

    get(operationId) {
      const record = records.get(operationId);
      return record ? clone(record) : null;
    },
  });
}

export async function reconcileIndeterminateEffect({
  capabilityStore,
  capabilityId,
  operationId,
  action,
  providerEvidence,
  pinnedProviderKey,
  expectedProviderId,
  ledger,
  now = () => '2026-07-19T04:00:10.000Z',
} = {}) {
  if (!capabilityStore || typeof capabilityStore.getOperation !== 'function') {
    throw new Error('capability operation reader required');
  }
  if (!ledger || typeof ledger.append !== 'function') {
    throw new Error('reconciliation ledger required');
  }

  const operation = capabilityStore.getOperation(operationId);
  if (!operation
      || operation.capability_id !== capabilityId
      || operation.status !== 'committed'
      || operation.outcome !== 'indeterminate') {
    throw new Error('operation is not a committed indeterminate capability spend');
  }
  if (operation.amount !== action.amount || operation.currency !== action.currency) {
    throw new Error('capability operation does not match expected action');
  }
  const expectedActionDigest = `sha256:${hashCanonical(action)}`;
  if (operation.action_digest !== expectedActionDigest) {
    throw new Error('capability operation is not bound to the expected action digest');
  }

  let verified = null;
  const durableReconciliation = await reconcileCapabilityOperation({
    store: capabilityStore,
    capabilityId,
    operationId,
    action,
    evidence: providerEvidence,
    now: () => Date.parse(now()),
    verifyEvidence: (presented) => {
      verified = verifySignedProviderEvidence(presented, {
        pinnedProviderKey,
        expectedProviderId,
        expectedOperationId: operationId,
        expectedAction: action,
      });
      return {
        valid: verified.ok === true,
        outcome: 'executed',
        action_digest: verified.action_digest,
        evidence_digest: verified.evidence_digest,
      };
    },
  });
  if (!durableReconciliation.ok) throw new Error(`capability reconciliation refused: ${durableReconciliation.reason}`);
  const recordBody = {
    '@version': RECONCILIATION_RECORD_VERSION,
    operation_id: operationId,
    capability_id: capabilityId,
    capability_outcome: 'indeterminate',
    outcome: 'executed',
    action_digest: verified.action_digest,
    provider_id: expectedProviderId,
    provider_effect_id: verified.effect_id,
    provider_committed_at: verified.committed_at,
    provider_evidence_digest: verified.evidence_digest,
    authenticated_provider_evidence: true,
    reexecuted: false,
    capability_reconciliation_idempotent: durableReconciliation.idempotent,
    reconciled_at: now(),
  };
  const record = {
    ...recordBody,
    record_digest: `sha256:${hashCanonical(recordBody)}`,
  };
  ledger.append(record);
  return Object.freeze({ ok: true, ...record });
}
