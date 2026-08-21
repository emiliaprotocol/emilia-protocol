// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { checkArtifactLifecycle } from '../scripts/check-artifact-lifecycle.mjs';

describe('artifact lifecycle registry', () => {
  it('classifies every public name with no implementation backing', async () => {
    const report = await checkArtifactLifecycle({ root: process.cwd() });
    expect(report.errors).toEqual([]);
    expect(report.classified).toBe(report.documentation_only);
  });

  it('fails when a new documentation-only or escaped retired tag appears', async () => {
    const root = await mkdtemp(join(tmpdir(), 'emilia-artifact-lifecycle-'));
    try {
      await Promise.all([
        mkdir(join(root, 'docs', 'current'), { recursive: true }),
        mkdir(join(root, 'docs', 'archive'), { recursive: true }),
        mkdir(join(root, 'packages'), { recursive: true }),
        mkdir(join(root, 'governance'), { recursive: true }),
      ]);
      await writeFile(join(root, 'docs', 'archive', 'old.md'), 'EP-OLD-v1');
      await writeFile(join(root, 'docs', 'current', 'bad.md'), 'EP-OLD-v1 EP-UNCLASSIFIED-v1');
      await writeFile(join(root, 'governance', 'artifact-lifecycle.v1.json'), JSON.stringify({
        '@version': 'EP-ARTIFACT-LIFECYCLE-REGISTRY-v1',
        claim_boundary: 'repository_name_classification_not_runtime_existence_conformance_adoption_or_deployment',
        entries: [{
          tag: 'EP-OLD-v1',
          status: 'retired',
          evidence_paths: ['docs/archive/old.md'],
          allowed_paths: ['docs/archive/old.md'],
        }],
      }));
      const report = await checkArtifactLifecycle({ root });
      expect(report.errors).toContain('unclassified documentation-only artifact: EP-UNCLASSIFIED-v1');
      expect(report.errors).toContain('EP-OLD-v1: retired tag escaped historical paths into docs/current/bad.md');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
