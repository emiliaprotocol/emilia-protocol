// SPDX-License-Identifier: Apache-2.0

import {
  canonicalize,
  hashCanonical,
  reconcileCapabilityOperation,
} from '../../packages/gate/index.js';

import { verifySignedProviderEvidence } from './provider.mts';

export const RECONCILIATION_RECORD_VERSION = 'EP-INDETERMINATE-EFFECT-RECONCILIATION-v1';

function clone(value: any): any {
  return structuredClone(value);
}

export function createReconciliationLedger(): {
  append(record: any): any;
  get(operationId: string): any;
} {
  const records = new Map();
  return Object.freeze({
    append(record: any): any {
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

    get(operationId: string): any {
      const record = records.get(operationId);
      return record ? clone(record) : null;
    },
  });
}

type VerifiedProviderEvidence = {
  ok: true;
  action_digest: string;
  evidence_digest: string;
  effect_id: string;
  committed_at: string;
};

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
}: {
  capabilityStore?: { getOperation: (operationId: string) => any };
  capabilityId?: string;
  operationId?: string;
  action?: { amount?: number; currency?: string; [key: string]: any };
  providerEvidence?: any;
  pinnedProviderKey?: string;
  expectedProviderId?: string;
  ledger?: { append: (record: any) => any };
  now?: () => string;
} = {}): Promise<any> {
  if (!capabilityStore || typeof capabilityStore.getOperation !== 'function') {
    throw new Error('capability operation reader required');
  }
  if (!ledger || typeof ledger.append !== 'function') {
    throw new Error('reconciliation ledger required');
  }
  if (!action || typeof action !== 'object') {
    throw new Error('expected action required to reconcile against the committed spend');
  }

  const operation = capabilityStore.getOperation(operationId as string);
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

  let verified: VerifiedProviderEvidence | null = null;
  const durableReconciliation = await reconcileCapabilityOperation({
    store: capabilityStore,
    capabilityId,
    operationId,
    action,
    evidence: providerEvidence,
    now: () => Date.parse(now()),
    verifyEvidence: (presented: any): any => {
      verified = verifySignedProviderEvidence(presented, {
        pinnedProviderKey,
        expectedProviderId,
        expectedOperationId: operationId,
        expectedAction: action,
      });
      return {
        valid: verified!.ok === true,
        outcome: 'executed',
        action_digest: verified!.action_digest,
        evidence_digest: verified!.evidence_digest,
      };
    },
  });
  if (!durableReconciliation.ok) throw new Error(`capability reconciliation refused: ${durableReconciliation.reason}`);
  // durableReconciliation.ok is only reachable if verifyEvidence returned
  // normally above, which only happens after `verified` was assigned a real
  // VerifiedProviderEvidence (verifySignedProviderEvidence never returns a
  // falsy value; it either throws or returns one). TS's control-flow
  // analysis can't see that closure-captured narrowing across the awaited
  // call, so it still types `verified` as its declaration-site type here.
  const verifiedEvidence = verified as unknown as VerifiedProviderEvidence;
  const recordBody = {
    '@version': RECONCILIATION_RECORD_VERSION,
    operation_id: operationId,
    capability_id: capabilityId,
    capability_outcome: 'indeterminate',
    outcome: 'executed',
    action_digest: verifiedEvidence.action_digest,
    provider_id: expectedProviderId,
    provider_effect_id: verifiedEvidence.effect_id,
    provider_committed_at: verifiedEvidence.committed_at,
    provider_evidence_digest: verifiedEvidence.evidence_digest,
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
