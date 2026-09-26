// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import YAML from 'yaml';

const ROOT = resolve(import.meta.dirname, '..');
const source = readFileSync(resolve(ROOT, '.github/workflows/schema-security.yml'), 'utf8');
const workflow = YAML.parse(source);
const job = workflow.jobs['candidate-reconciliation'];
const candidateCheckout = job.steps.find(
  (step: { name?: string }) => step.name === 'Check out candidate migration bytes as data only',
);
const parserStep = job.steps.find(
  (step: { name?: string }) => step.name === 'Parse candidate ledger and SQL only with trusted base code',
);

describe('fork-safe schema candidate workflow contract', () => {
  it('limits the explicit fork checkout exception to inert migration data', () => {
    expect(workflow.permissions).toEqual({ contents: 'read' });
    expect(job.if).toBe("github.event_name == 'pull_request_target' || github.event_name == 'merge_group'");
    expect(candidateCheckout.uses).toMatch(/^actions\/checkout@[0-9a-f]{40}$/);
    expect(candidateCheckout.with.ref).toBe(
      '${{ github.event.pull_request.head.sha || github.event.merge_group.head_sha }}',
    );
    expect(candidateCheckout.with['persist-credentials']).toBe(false);
    expect(candidateCheckout.with['allow-unsafe-pr-checkout']).toBe(true);
    expect(candidateCheckout.with.path).toBe('candidate-data');
    expect(candidateCheckout.with['sparse-checkout-cone-mode']).toBe(false);
    expect(candidateCheckout.with['sparse-checkout'].trim().split(/\s+/)).toEqual([
      'supabase/migrations',
      'supabase/migration-history.v1.json',
      'supabase/migration-archive/2026-07-25-history-reconciliation',
    ]);
    expect(candidateCheckout.with).not.toHaveProperty('token');
  });

  it('executes only the trusted parser against the candidate data tree', () => {
    expect(parserStep).not.toHaveProperty('working-directory');
    expect(parserStep.run).toContain(
      'node trusted-base/scripts/schema-pr-candidate-reconcile.mjs',
    );
    expect(parserStep.run).toContain('--base-root trusted-base');
    expect(parserStep.run).toContain('--candidate-root candidate-data');
    expect(parserStep.run).not.toMatch(/(?:node|bash|sh|npm|npx)\s+candidate-data(?:\/|\s)/);
    expect(JSON.stringify(job)).not.toContain('secrets.');
  });

  it('never runs the secret-using live leg on merge_group, and binds it to the main-only environment', () => {
    const live = workflow.jobs['live-schema-contract'];
    // On merge_group GitHub reads this file from the candidate, so the job
    // that can read the schema-gate secret must not run there at all.
    expect(live.if).toBe("github.event_name != 'merge_group'");
    expect(live.environment).toBe('schema-gate');
    const liveCheckout = live.steps.find((step: { uses?: string }) => step.uses?.startsWith('actions/checkout@'));
    expect(liveCheckout.with.ref).toBe('${{ github.event.pull_request.base.sha || github.sha }}');
    for (const [name, other] of Object.entries(workflow.jobs)) {
      if (name === 'live-schema-contract') continue;
      expect(JSON.stringify(other), name).not.toContain('secrets.');
    }
    const aggregator = workflow.jobs['schema-contract'].steps[0].run;
    expect(aggregator).toContain('if [[ "$EVENT_NAME" == merge_group ]]; then');
    expect(aggregator).toContain('[[ "$LIVE_RESULT" == skipped ]]');
    expect(aggregator).toContain('[[ "$LIVE_RESULT" == success ]]');
  });
});
