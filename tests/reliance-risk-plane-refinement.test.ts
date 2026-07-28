// SPDX-License-Identifier: Apache-2.0
import { expect, test } from 'vitest';
import { runRelianceRiskRefinementTrace } from '../conformance/refinement/adapters/reliance-risk-plane.mts';

test('runtime exposure transitions refine the bounded no-blind-retry composition', async () => {
  const trace = await runRelianceRiskRefinementTrace();
  expect(trace.reserved.ok).toBe(true);
  expect(trace.invoking.ok).toBe(true);
  expect(trace.exactProgramBound).toBe(true);
  expect(trace.exactAuthorizationBound).toBe(true);
  expect(trace.uncertain.ok).toBe(true);
  expect(trace.blindRetry).toEqual({ ok: false, reason: 'reconciliation_required' });
  expect(trace.wrongReconciler).toEqual({ ok: false, reason: 'wrong_authority' });
  expect(trace.reconciled.ok).toBe(true);
  if (trace.reconciled.ok) expect(trace.reconciled.record.status).toBe('CLOSED_PROVEN_NOT_COMMITTED');
  expect(trace.model.uncertain_still_open).toBe(true);
  expect(trace.model.invoke).toBe(false);
});

test('generated standalone refinement runtime imports and executes under plain Node semantics', async () => {
  // This import deliberately targets the generated runtime, not the TypeScript source.
  // @ts-expect-error Generated .mjs has no separate declaration file.
  const runtime = await import('../conformance/refinement/adapters/reliance-risk-plane.mjs');
  const trace = await runtime.runRelianceRiskRefinementTrace();
  expect(trace.reserved.ok).toBe(true);
  expect(trace.invoking.ok).toBe(true);
  expect(trace.exactProgramBound).toBe(true);
  expect(trace.exactAuthorizationBound).toBe(true);
});
