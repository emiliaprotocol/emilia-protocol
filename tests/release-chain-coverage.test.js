// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  auditReleaseChain,
  validateCredentialRotationGuideText,
  validateReusableNpmWorkflowText,
} from '../scripts/check-release-chain.mjs';

describe('release-chain coverage', () => {
  it('every declared npm and PyPI package uses the complete verifiable release chain', () => {
    expect(auditReleaseChain()).toEqual({ packages: 11, npm: 8, pypi: 3 });
  });

  it('refuses a reusable publisher with its post-registry byte comparison removed', () => {
    const workflow = readFileSync('.github/workflows/_publish-npm-package.yml', 'utf8');
    const weakened = workflow.replace('cmp "$TESTED_TARBALL" "registry-copy/$REGISTRY_TARBALL"', 'true # comparison removed');
    expect(() => validateReusableNpmWorkflowText(weakened)).toThrow(/registry-copy/);
  });

  it('refuses credential-rotation guidance that restores a manual publish token', () => {
    const guide = readFileSync('docs/operations/CREDENTIAL-ROTATION-CHECKLIST.md', 'utf8');
    const weakened = guide.replace(
      'a replacement publish token.',
      'a fresh Granular Access Token.',
    );
    expect(() => validateCredentialRotationGuideText(weakened)).toThrow(/credential rotation guide/);
  });
});
