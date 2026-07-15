// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  auditReleaseChain,
  validateCredentialRotationGuideText,
  validateNpmLockData,
  validateReusableNpmWorkflowText,
  validateReusablePypiWorkflowText,
} from '../scripts/check-release-chain.mjs';

describe('release-chain coverage', () => {
  it('every declared npm and PyPI package uses the complete verifiable release chain', () => {
    expect(auditReleaseChain()).toEqual({ packages: 24, npm: 19, pypi: 5 });
  });

  it('refuses a reusable PyPI publisher with its post-registry byte comparison removed', () => {
    const workflow = readFileSync('.github/workflows/_publish-pypi-package.yml', 'utf8');
    const weakened = workflow.replace('cmp "${{ steps.build.outputs.wheel }}" "$REGISTRY_WHEEL"', 'true # comparison removed');
    expect(() => validateReusablePypiWorkflowText(weakened)).toThrow(/REGISTRY_WHEEL/);
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

  it('refuses a package lock that names older package bytes than its manifest', () => {
    const metadata = JSON.parse(readFileSync('cli/package.json', 'utf8'));
    const lock = JSON.parse(readFileSync('cli/package-lock.json', 'utf8'));
    lock.packages['node_modules/@emilia-protocol/verify'].version = '3.9.0';
    expect(() => validateNpmLockData(metadata, lock, 'cli/package-lock.json')).toThrow(/security floor/);
  });
});
