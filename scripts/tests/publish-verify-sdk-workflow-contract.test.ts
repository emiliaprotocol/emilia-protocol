// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import YAML from 'yaml';

const WORKFLOW_PATH = path.join(
  process.cwd(),
  '.github',
  'workflows',
  'publish-verify-sdk.yml',
);

describe('Verify SDK trusted-publisher caller contract', () => {
  it('keeps trusted-publisher identity on the direct caller and delegates the split chain', () => {
    const workflow = YAML.parse(fs.readFileSync(WORKFLOW_PATH, 'utf8'));
    expect(Object.keys(workflow.jobs)).toEqual(['publish']);
    expect(workflow.jobs.publish.uses).toBe('./.github/workflows/_publish-npm-package.yml');
    expect(workflow.jobs.publish.permissions).toEqual({
      contents: 'read',
      'id-token': 'write',
      attestations: 'write',
    });
    expect(workflow.jobs.publish.with).toMatchObject({
      package_dir: 'packages/verify',
      package_name: '@emilia-protocol/verify',
      artifact_id: 'verify',
      tag_prefix: 'verify-v',
    });
    expect(workflow.jobs.publish.environment).toBeUndefined();
    expect(workflow.jobs.publish.steps).toBeUndefined();
  });

  it('has no caller-side code execution or detached approval job', () => {
    const text = fs.readFileSync(WORKFLOW_PATH, 'utf8');
    const workflow = YAML.parse(text);
    expect(text).not.toContain('runs-on:');
    expect(text).not.toContain('steps:');
    expect(workflow.jobs.approval).toBeUndefined();
  });
});
