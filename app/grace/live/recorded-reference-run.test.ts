// SPDX-License-Identifier: Apache-2.0
//
// /grace/live replays a recorded response of GET /api/v1/grace/reference-scenario.
// The live route cannot run in production: createGraceReferenceRuntime refuses
// NODE_ENV=production on purpose, so the public page ships one recorded run
// instead. This test keeps that recording honest: every value the page shows
// that does not depend on the per-run reference keys must match a fresh run of
// the same circuit.
//
// Re-record after a deliberate circuit change:
//   GRACE_RECORD_REFERENCE_RUN=1 npx vitest run app/grace/live/recorded-reference-run.test.ts
import { writeFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import recorded from './recorded-reference-run.json';

async function freshRun(): Promise<any> {
  const { GET } = await import('@/app/api/v1/grace/reference-scenario/route.js');
  const response = await GET(new Request('https://ep.test/api/v1/grace/reference-scenario'));
  expect(response.status).toBe(200);
  return response.json();
}

function keyIndependentView(run: any) {
  return {
    ok: run.ok,
    reference_only: run.reference_only,
    physical_claim: run.physical_claim,
    description: run.description,
    action: run.action,
    action_hash: run.action_hash,
    authorization_valid: run.authorization.valid,
    authorization_checks: run.authorization.checks,
    approver_count: run.authorization.members.length,
    adapter: run.acknowledgment.adapter,
    simulated_ack: run.acknowledgment.simulation,
    meter: {
      baseline_mw: run.meter_statement.baseline_mw,
      intervals: run.meter_statement.intervals,
      measurement_class: run.meter_statement.measurement_class,
      simulation: run.meter_statement.simulation,
    },
    compliance: run.compliance,
    settled: run.settlement.settled,
    attacks: run.attacks,
  };
}

describe('/grace/live recorded reference run', () => {
  it('matches a fresh run of the reference circuit on every key-independent field', async () => {
    const fresh = await freshRun();
    if (process.env.GRACE_RECORD_REFERENCE_RUN === '1') {
      writeFileSync(new URL('./recorded-reference-run.json', import.meta.url), `${JSON.stringify(fresh, null, 2)}\n`);
      return;
    }
    expect(keyIndependentView(recorded)).toEqual(keyIndependentView(fresh));
  });

  it('is labelled as a simulation with no physical claim', () => {
    expect(recorded).toMatchObject({ ok: true, reference_only: true, physical_claim: false });
    expect(recorded.meter_statement.measurement_class).toBe('reference_simulation');
    expect(Object.values(recorded.attacks).every((attack: any) => attack.refused === true)).toBe(true);
  });
});
