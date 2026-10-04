// SPDX-License-Identifier: Apache-2.0

import { readFileSync, readdirSync } from 'node:fs';
import { posix } from 'node:path';
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
  defaults?: { run?: { 'working-directory'?: string } };
  jobs: Record<string, {
    defaults?: { run?: { 'working-directory'?: string } };
    steps?: Step[];
  }>;
};

function readWorkflow(name: string): Workflow {
  return YAML.parse(readFileSync(`.github/workflows/${name}`, 'utf8'));
}

describe('root installation workflow toolchain', () => {
  it('installs every workflow root lock with the supported development runtime', () => {
    const minimumNode = Number(readFileSync('.nvmrc', 'utf8').trim());
    const obsoleteInstalls: string[] = [];
    let rootInstalls = 0;
    for (const name of readdirSync('.github/workflows').filter((file) => /\.ya?ml$/u.test(file))) {
      const workflow = readWorkflow(name);
      for (const [jobName, job] of Object.entries(workflow.jobs)) {
        let nodeVersion: unknown;
        const checkoutRoots = new Set(['.']);
        for (const step of job.steps ?? []) {
          if (step.uses?.startsWith('actions/checkout@') && typeof step.with?.path === 'string') {
            checkoutRoots.add(posix.normalize(step.with.path));
          }
        }
        for (const step of job.steps ?? []) {
          if (step.uses?.startsWith('actions/setup-node@')) nodeVersion = step.with?.['node-version'];
          let directory = posix.normalize(step['working-directory']
            ?? job.defaults?.run?.['working-directory']
            ?? workflow.defaults?.run?.['working-directory'] ?? '.');
          for (const line of step.run?.split('\n') ?? []) {
            const cd = line.match(/^\s*cd\s+["']?([^"'\s;&]+)["']?\s*$/u);
            if (cd) directory = posix.normalize(posix.join(directory, cd[1]));
            if (!/^\s*npm ci(?:\s|$)/u.test(line)) continue;
            const prefix = line.match(/\s--prefix(?:\s+|=)(?:"([^"]+)"|'([^']+)'|([^\s;&]+))/u);
            const installDirectory = prefix
              ? posix.normalize(posix.join(directory, prefix[1] ?? prefix[2] ?? prefix[3]))
              : directory;
            if (!checkoutRoots.has(installDirectory)) continue;
            rootInstalls += 1;
            // Root tooling needs Node 24/npm 11; scoped app/SDK installs and
            // minimum-runtime probes do not install this development graph.
            const major = Number.parseInt(String(nodeVersion), 10);
            if (!Number.isFinite(major) || major < minimumNode) {
              obsoleteInstalls.push(`${name}: ${jobName}: Node ${String(nodeVersion)}`);
            }
          }
        }
      }
    }
    expect(rootInstalls).toBeGreaterThan(0);
    expect(obsoleteInstalls).toEqual([]);
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

  it('keeps mobile portable checks and Expo execution on their supported Node 20.19.5 runtime', () => {
    const workflow = readWorkflow('mobile-apps.yml');
    const runtimeChecks = [
      ['protocol-and-server', 'Run server-side mobile conformance'],
      ['secure-app', 'Validate Expo dependency compatibility'],
      ['secure-app', 'Export deterministic iOS and Android bundles'],
      ['secure-app-ios-native', 'Generate disposable iOS native project'],
      ['secure-app-android-native', 'Generate disposable Android native project'],
    ];
    for (const [jobName, stepName] of runtimeChecks) {
      let nodeVersion: unknown;
      let found = false;
      for (const step of workflow.jobs[jobName].steps ?? []) {
        if (step.uses?.startsWith('actions/setup-node@')) nodeVersion = step.with?.['node-version'];
        if (step.name !== stepName) continue;
        found = true;
        expect(String(nodeVersion), stepName).toBe('20.19.5');
      }
      expect(found, stepName).toBe(true);
    }
  });
});
