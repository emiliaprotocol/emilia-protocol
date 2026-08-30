// SPDX-License-Identifier: Apache-2.0
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const read = (path: string): string => readFileSync(resolve(ROOT, path), 'utf8');
const readJson = (path: string): any => JSON.parse(read(path));

describe('public runtime release pins', () => {
  it('keeps the fire-drill action and its documentation on the same exact release', () => {
    const action = read('.github/actions/fire-drill/action.yml');
    const documentation = read('docs/FIRE-DRILL-GITHUB-ACTION.md');
    const versions = (source: string): string[] => [
      ...source.matchAll(/@emilia-protocol\/fire-drill@(\d+\.\d+\.\d+)/g),
    ].map((match) => match[1]);

    expect(versions(action)).toEqual(['0.5.2']);
    expect(versions(documentation)).toEqual(['0.5.2']);
  });

  it('runs the demo receipt through current repository-local verifier source', () => {
    const result = spawnSync(process.execPath, ['scripts/verify-demo-receipt.js'], {
      cwd: ROOT,
      encoding: 'utf8',
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain('current repository-local packages/verify/index.js');
    expect(result.stdout).not.toMatch(/published|verify@1\.0\.1/i);
    expect(read('scripts/verify-demo-receipt.ts')).not.toMatch(/published|verify@1\.0\.1/i);
  });

  it('keeps local consequence-service locks aligned with linked package manifests', () => {
    const gate = readJson('packages/gate/package.json');
    const requireReceipt = readJson('packages/require-receipt/package.json');
    const verify = readJson('packages/verify/package.json');

    for (const lockPath of [
      'apps/consequence-actuator-service/package-lock.json',
      'apps/consequence-control-service/package-lock.json',
    ]) {
      const lock = readJson(lockPath);
      const linkedGate = lock.packages['../../packages/gate'];
      const linkedRequireReceipt = lock.packages['../../packages/require-receipt'];
      const linkedVerify = lock.packages['../../packages/verify'];

      expect(linkedGate.version, lockPath).toBe(gate.version);
      expect(linkedGate.dependencies['@emilia-protocol/require-receipt'], lockPath)
        .toBe(requireReceipt.version);
      expect(linkedGate.dependencies['@emilia-protocol/verify'], lockPath)
        .toBe(verify.version);
      expect(linkedGate.bin['ep-protect'], lockPath).toBe('bin/ep-protect.mjs');
      expect(linkedRequireReceipt.version, lockPath).toBe(requireReceipt.version);
      expect(linkedVerify.version, lockPath).toBe(verify.version);
    }
  });

  it('keeps active verifier and Gate documentation on the prepared release surface', () => {
    const verify = readJson('packages/verify/package.json');
    const adapterLock = readJson('conformance/composition/aeb-adapter-v1.lock.json');
    const gate = readJson('packages/gate/package.json');
    const demoSources = [
      read('lib/demo-receipt.ts'),
      read('lib/demo-receipt.js'),
      read('app/api/demo/trust-receipts/[receiptId]/evidence/route.ts'),
    ].join('\n');
    const gateReadme = read('packages/gate/README.md');

    expect(adapterLock.verify_package_version).toBe(verify.version);
    expect(demoSources).not.toMatch(/@emilia-protocol\/verify@1\.0\.1/);
    expect(gateReadme).toContain(`@emilia-protocol/gate@${gate.version}`);
    expect(gateReadme).not.toContain('@emilia-protocol/gate@0.23.13');
  });
});
