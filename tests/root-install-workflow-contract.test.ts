// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import YAML from 'yaml';

type Step = {
  name?: string;
  uses?: string;
  with?: Record<string, unknown>;
  run?: string;
  'working-directory'?: string;
};
type Workflow = {
  jobs: Record<string, {
    defaults?: { run?: { 'working-directory'?: string } };
    steps?: Step[];
  }>;
};

function readWorkflow(name: string): Workflow {
  return YAML.parse(readFileSync(`.github/workflows/${name}`, 'utf8'));
}

describe('root installation workflow toolchain', () => {
  it.each(['ci.yml', 'security-scan.yml'])('installs the root lock with the supported development runtime in %s', (name) => {
    const minimumNode = Number(readFileSync('.nvmrc', 'utf8').trim());
    let rootInstalls = 0;
    for (const [jobName, job] of Object.entries(readWorkflow(name).jobs)) {
      let nodeVersion: unknown;
      for (const step of job.steps ?? []) {
        if (step.uses?.startsWith('actions/setup-node@')) {
          nodeVersion = step.with?.['node-version'];
        }
        const directory = step['working-directory'] ?? job.defaults?.run?.['working-directory'] ?? '.';
        const installsRoot = ['.', './'].includes(directory) && step.run?.split('\n').some(
          (line) => /^\s*npm ci(?:\s|$)/u.test(line) && !/\s--prefix(?:\s|=)/u.test(line),
        );
        if (!installsRoot) continue;
        rootInstalls += 1;
        // Root tooling needs Node 24/npm 11; the package runtime floors are
        // separate lanes that need not install the root development graph.
        expect(Number.parseInt(String(nodeVersion), 10), `${name}: ${jobName}`).toBeGreaterThanOrEqual(minimumNode);
      }
    }
    expect(rootInstalls).toBeGreaterThan(0);
  });

  it('keeps the declared minimum-Node Gate proof and bundled MCP smoke on Node 20', () => {
    const workflow = readWorkflow('ci.yml');
    const runtimeChecks = [
      ['gate-product-suite', 'Run the Gate reference proof on minimum Node'],
      ['mcp-server-pack', 'Smoke test — verify entry point loads'],
    ];
    for (const [jobName, stepName] of runtimeChecks) {
      let nodeVersion: unknown;
      let found = false;
      for (const step of workflow.jobs[jobName].steps ?? []) {
        if (step.uses?.startsWith('actions/setup-node@')) nodeVersion = step.with?.['node-version'];
        if (step.name !== stepName) continue;
        found = true;
        expect(Number.parseInt(String(nodeVersion), 10), stepName).toBe(20);
      }
      expect(found, stepName).toBe(true);
    }
  });
});
