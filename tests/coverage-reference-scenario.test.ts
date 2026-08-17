import { describe, expect, it } from 'vitest';

import { buildCoverageReferenceScenario } from '../lib/coverage-reference-scenario.js';

describe('coverage reconciliation reference scenario', () => {
  it('runs the real signed reconciliation and exposes the bypass finding', () => {
    const scenario = buildCoverageReferenceScenario(new Date('2026-07-29T12:00:00Z'));

    expect(scenario.ok).toBe(true);
    expect(scenario.reference_only).toBe(true);
    expect(scenario.summary).toEqual({
      matched: 1,
      observed_without_receipt: 1,
      receipted_without_observation: 1,
      indeterminate: 1,
      excluded: 1,
      exception: 1,
    });
    expect(scenario.bypass.record_id).toBe('pas:effect:PA-1002');
    expect(scenario.bypass.caid).toMatch(/^caid:1:/);
    expect(scenario.sources.system_of_record.operator_id)
      .not.toBe(scenario.sources.receipt_population.operator_id);
    expect(scenario.report_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(scenario.claim_boundary).toContain('not_source_completeness');
  });
});
