// SPDX-License-Identifier: Apache-2.0
/** Runtime trace that projects the memory exposure implementation into the bounded risk-plane model. */
import {
  createMemoryOpenExposureLedger,
  type OpenExposureAuth,
  type OpenExposureCeilingInput,
} from '../../../packages/gate/src/open-exposure-ledger.js';
import { evaluateRelianceRiskState } from '../../../formal/reliance-risk-plane.model.mjs';

const D = (c: string) => `sha256:${c.repeat(64)}` as `sha256:${string}`;
const START = '2026-07-01T00:00:00.000Z';
const END = '2026-08-01T00:00:00.000Z';
const token = `open-exposure-op:v1:${'x'.repeat(32)}`;

function auth(role: OpenExposureAuth['role'], authorityId: string): OpenExposureAuth {
  return { role, authorityId, credential: `tenant-a:${role}:${authorityId}` };
}

export async function runRelianceRiskRefinementTrace() {
  const ledger = createMemoryOpenExposureLedger({
    authenticate: ({ tenantId, auth: input }) => input.credential === `${tenantId}:${input.role}:${input.authorityId}`,
  });
  const scopes = [
    ['TENANT', '*'], ['PROGRAM', 'program-a'], ['COUNTERPARTY', 'merchant-a'], ['ACTION_CLASS', 'payment.release'],
  ] as const;
  for (const [scope, scopeValue] of scopes) {
    const ceiling: OpenExposureCeilingInput = {
      tenantId: 'tenant-a', ceilingId: `ceiling-${scope.toLowerCase()}`, scope, scopeValue,
      currency: 'USD', windowStart: START, windowEnd: END, limitMinor: 100n, policyDigest: D('1'),
    };
    const registered = await ledger.registerCeiling(ceiling, auth('POLICY_ADMIN', 'policy-admin'));
    if (!registered.ok) throw new Error(`ceiling setup failed: ${registered.reason}`);
  }
  const reservation = {
    tenantId: 'tenant-a', exposureId: 'exposure-refinement', operationToken: token,
    programId: 'program-a', counterpartyId: 'merchant-a', actionClass: 'payment.release',
    amountMinor: 60n, currency: 'USD', windowStart: START, windowEnd: END,
    reservedAt: '2026-07-28T12:00:00.000Z', invokeBy: '2026-07-28T12:05:00.000Z',
    reconcileBy: '2026-07-28T13:00:00.000Z', originAuthorityId: 'origin-a',
    executorAuthorityId: 'executor-a', reconciliationAuthorityId: 'reconciler-a',
    reservationEvidenceDigest: D('2'),
  };
  const reserved = await ledger.reserve(reservation, auth('ORIGIN', 'origin-a'));
  const invoking = await ledger.beginInvocation({
    tenantId: 'tenant-a', exposureId: reservation.exposureId, operationToken: token,
    invokedAt: '2026-07-28T12:01:00.000Z',
  }, auth('EXECUTOR', 'executor-a'));
  const uncertain = await ledger.markIndeterminate({
    tenantId: 'tenant-a', exposureId: reservation.exposureId, operationToken: token,
    evidenceDigest: D('3'), observedAt: '2026-07-28T12:02:00.000Z',
  }, auth('EXECUTOR', 'executor-a'));
  const blindRetry = await ledger.beginInvocation({
    tenantId: 'tenant-a', exposureId: reservation.exposureId, operationToken: token,
    invokedAt: '2026-07-28T12:03:00.000Z',
  }, auth('EXECUTOR', 'executor-a'));
  const wrongReconciler = await ledger.reconcile({
    tenantId: 'tenant-a', exposureId: reservation.exposureId, operationToken: token,
    reconciliationToken: `open-exposure-reconcile:v1:${'w'.repeat(32)}`,
    outcome: 'PROVEN_NOT_COMMITTED', evidenceDigest: D('4'), observedAt: '2026-07-28T12:10:00.000Z',
  }, auth('RECONCILER', 'executor-a'));
  const reconciled = await ledger.reconcile({
    tenantId: 'tenant-a', exposureId: reservation.exposureId, operationToken: token,
    reconciliationToken: `open-exposure-reconcile:v1:${'r'.repeat(32)}`,
    outcome: 'PROVEN_NOT_COMMITTED', evidenceDigest: D('5'), observedAt: '2026-07-28T12:11:00.000Z',
  }, auth('RECONCILER', 'reconciler-a'));

  const model = evaluateRelianceRiskState({
    program_accepted: true, authorization_accepted: true, capacity_available: true,
    exposure_reserved: reserved.ok, indeterminate: uncertain.ok,
    exposure_open: uncertain.ok && uncertain.record.status === 'INDETERMINATE',
    blind_retry_requested: true, reconciler_independent: true,
    refusal_present: false, loss_schedule_present: false,
    coverage_attestation_present: false, external_population_completeness_proof: false,
    terminal: false, supersession_requested: false,
  });
  return Object.freeze({
    version: 'EP-RELIANCE-RISK-PLANE-REFINEMENT-TRACE-v1',
    reserved, invoking, uncertain, blindRetry, wrongReconciler, reconciled, model,
  });
}

