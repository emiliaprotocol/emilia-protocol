// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  auditReleaseChain,
  discoverReleaseSurfaces,
  validateCredentialRotationGuideText,
  validateGoTagWorkflowText,
  validateNpmLockData,
  validateReusableNpmWorkflowText,
  validateReusablePypiWorkflowText,
} from '../scripts/check-release-chain.mjs';

describe('release-chain coverage', () => {
  it('every declared package uses its complete verifiable release chain', () => {
    expect(auditReleaseChain()).toEqual({ packages: 25, npm: 19, pypi: 5, go: 1 });
  });

  it('every declared npm and PyPI package uses reproducible registry-byte verification', () => {
    const result = auditReleaseChain();
    expect(result).toMatchObject({ npm: 19, pypi: 5 });
  });

  it('Go release isolates tag write authority and verifies the public proxy origin', () => {
    const workflow = readFileSync('.github/workflows/publish-go-verify.yml', 'utf8');
    expect(validateGoTagWorkflowText(workflow)).toBe(true);
  });

  it('refuses a Go tag publisher without public-proxy source comparison', () => {
    const workflow = readFileSync('.github/workflows/publish-go-verify.yml', 'utf8');
    const weakened = workflow.replace('diff -ru packages/go-verify "$PROXY_DIR"', 'true # comparison removed');
    expect(() => validateGoTagWorkflowText(weakened)).toThrow(/PROXY_DIR/);
  });

  it('refuses Go release code execution in the contents-write tag job', () => {
    const workflow = readFileSync('.github/workflows/publish-go-verify.yml', 'utf8');
    const weakened = workflow.replace(
      'uses: actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3',
      'run: node scripts/require-release-approval.mjs',
    );
    expect(() => validateGoTagWorkflowText(weakened)).toThrow(/only a commit-pinned GitHub API action/);
  });

  it('refuses a Go release checkout that follows mutable main or keeps credentials', () => {
    const workflow = readFileSync('.github/workflows/publish-go-verify.yml', 'utf8');
    const mutable = workflow.replaceAll('ref: ${{ github.sha }}', 'ref: main');
    expect(() => validateGoTagWorkflowText(mutable)).toThrow(/github\.sha/);
    const credentialed = workflow.replace('persist-credentials: false', 'persist-credentials: true');
    expect(() => validateGoTagWorkflowText(credentialed)).toThrow(/persisted credentials/);
  });

  it('refuses slash-bearing Go release artifact names derived from the tag', () => {
    const workflow = readFileSync('.github/workflows/publish-go-verify.yml', 'utf8');
    const weakened = workflow.replace(
      'go-verify-v${{ steps.metadata.outputs.version }}-preflight',
      '${{ inputs.release_tag }}-preflight',
    );
    expect(() => validateGoTagWorkflowText(weakened)).toThrow(/slash-free/);
  });

  it('refuses an unclassified Go module even when its release manifest is absent', () => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'ep-go-module-discovery-'));
    try {
      const moduleRoot = path.join(root, 'packages', 'hidden-go-module');
      mkdirSync(moduleRoot, { recursive: true });
      writeFileSync(path.join(moduleRoot, 'go.mod'), 'module example.test/hidden/v2\n\ngo 1.21\n');
      expect(() => discoverReleaseSurfaces(root)).toThrow(/go-release\.json classification/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
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
