// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  auditReleaseChain,
  discoverReleaseSurfaces,
  validateCredentialRotationGuideText,
  validateGateNpmWorkflowText,
  validateGoTagWorkflowText,
  validateNpmDirect,
  validateNpmLockData,
  validatePypiDirect,
  validateReusableNpmCallerText,
  validateReusableNpmWorkflowText,
  validateReusablePypiWorkflowText,
} from '../scripts/check-release-chain.mjs';
import YAML from 'yaml';

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

  it('requires the protected environment on the job that receives the PyPI OIDC token', () => {
    const workflow = readFileSync('.github/workflows/publish-crewai.yml', 'utf8');
    expect(validatePypiDirect(workflow, 'publish-crewai.yml')).toBe(true);
    const detached = workflow.replace(
      '    environment: registry-publishing-approval',
      '    # environment: registry-publishing-approval',
    );
    expect(() => validatePypiDirect(detached, 'publish-crewai.yml')).toThrow(/protected approval environment/);
  });

  it('runs Verify and Gate OIDC publication inside the protected environment job', () => {
    for (const name of ['publish-verify-sdk.yml', 'publish-gate.yml']) {
      const text = readFileSync(path.join('.github/workflows', name), 'utf8');
      const workflow = YAML.parse(text);
      const publish = workflow?.jobs?.publish;
      expect(workflow?.jobs?.approval, `${name} must not use a detached empty approval job`).toBeUndefined();
      expect(publish?.environment, `${name} publish job must be protected`).toBe('registry-publishing-approval');
      expect(publish?.permissions?.['id-token'], `${name} protected job must own OIDC`).toBe('write');
      expect(
        publish?.steps?.some((step) => typeof step?.run === 'string' && step.run.includes('npm publish')),
        `${name} protected job must execute npm publish`,
      ).toBe(true);
    }
  });

  it('protects the reusable OIDC publisher and removes detached approval from every npm caller', () => {
    const workflowDirectory = path.join('.github', 'workflows');
    const reusableText = readFileSync(
      path.join(workflowDirectory, '_publish-npm-package.yml'),
      'utf8',
    );
    const reusable = YAML.parse(reusableText);
    expect(reusable?.jobs?.approval).toBeUndefined();
    expect(reusable?.jobs?.publish?.environment).toBe('registry-publishing-approval');
    expect(reusable?.jobs?.publish?.permissions?.['id-token']).toBe('write');

    const callers = readdirSync(workflowDirectory)
      .filter((name) => {
        const text = readFileSync(path.join(workflowDirectory, name), 'utf8');
        return text.includes('uses: ./.github/workflows/_publish-npm-package.yml');
      })
      .sort();
    expect(callers).toHaveLength(17);
    for (const name of callers) {
      const text = readFileSync(path.join(workflowDirectory, name), 'utf8');
      const workflow = YAML.parse(text);
      expect(validateReusableNpmCallerText(text, name)).toBe(true);
      expect(workflow?.jobs?.approval, `${name} has a detached approval job`).toBeUndefined();
      expect(workflow?.jobs?.publish?.needs, `${name} still depends on detached approval`).toBeUndefined();
      expect(workflow?.jobs?.publish?.uses).toBe('./.github/workflows/_publish-npm-package.yml');
      expect(workflow?.jobs?.publish?.permissions?.['id-token']).toBe('write');
    }
  });

  it('binds every reusable npm caller to protected-main selection in the called publisher', () => {
    const reusable = readFileSync('.github/workflows/_publish-npm-package.yml', 'utf8');
    expect(reusable).toContain('ref: ${{ github.sha }}');
    expect(reusable).not.toContain('ref: ${{ inputs.release_tag }}');
    expect(reusable).toContain('--expected-commit "$GITHUB_SHA"');
    expect(reusable).toContain('--expected-ref "$GITHUB_REF"');
    expect(reusable).toContain('--revalidate-remote');
  });

  it('fails closed on existing npm versions and revalidates refs in the publishing step', () => {
    for (const name of [
      '_publish-npm-package.yml',
      'publish-gate.yml',
      'publish-verify-sdk.yml',
    ]) {
      const text = readFileSync(path.join('.github/workflows', name), 'utf8');
      const workflow = YAML.parse(text);
      const publishRun = workflow?.jobs?.publish?.steps?.find(
        (step) => typeof step?.run === 'string' && step.run.includes('npm publish '),
      )?.run;
      expect(publishRun, `${name} must contain a publishing step`).toBeTypeOf('string');
      const preflightIndex = publishRun.indexOf('response.status === 404');
      const remoteIndex = publishRun.indexOf('--revalidate-remote');
      const hashIndex = publishRun.lastIndexOf('sha256sum -c "$TESTED_TARBALL.sha256"');
      const publishIndex = publishRun.indexOf('npm publish ');
      expect(preflightIndex).toBeLessThan(remoteIndex);
      expect(remoteIndex, `${name} must revalidate refs in the publish step`).toBeGreaterThan(-1);
      expect(remoteIndex).toBeLessThan(hashIndex);
      expect(hashIndex).toBeLessThan(publishIndex);
      const registryRun = workflow?.jobs?.publish?.steps?.find(
        (step) => step?.name === 'Verify registry bytes match the attested tarball',
      )?.run;
      expect(registryRun, `${name} must contain a registry comparison step`).toBeTypeOf('string');
      const registrySelectionIndex = registryRun.indexOf('REGISTRY_TARBALL=');
      const registryRehashIndex = registryRun.lastIndexOf('sha256sum -c "$TESTED_TARBALL.sha256"');
      const registryCompareIndex = registryRun.indexOf('cmp "$TESTED_TARBALL"');
      expect(registrySelectionIndex).toBeLessThan(registryRehashIndex);
      expect(registryRehashIndex).toBeLessThan(registryCompareIndex);
      expect(text).toContain('already exists; refusing to publish');
      expect(text).toContain('response.status === 404');
      expect(text).not.toContain('already exists; continuing to mandatory byte verification');
    }
  });

  it('binds Verify and Gate checkout and release approval to the dispatch SHA and main ref', () => {
    for (const name of ['publish-verify-sdk.yml', 'publish-gate.yml']) {
      const text = readFileSync(path.join('.github/workflows', name), 'utf8');
      expect(text).toContain('ref: ${{ github.sha }}');
      expect(text).not.toContain('ref: ${{ inputs.release_tag }}');
      expect(text).toContain('--expected-commit "$GITHUB_SHA"');
      expect(text).toContain('--expected-ref "$GITHUB_REF"');
    }
  });

  it('refuses detached approval and branch-selected checkout regressions for Verify and Gate', () => {
    const cases = [
      {
        name: 'publish-verify-sdk.yml',
        validate: (text: string) => validateNpmDirect(text, 'publish-verify-sdk.yml'),
      },
      {
        name: 'publish-gate.yml',
        validate: (text: string) => validateGateNpmWorkflowText(text),
      },
    ];
    for (const { name, validate } of cases) {
      const text = readFileSync(path.join('.github/workflows', name), 'utf8');
      expect(validate(text)).toBe(true);

      const unprotected = text
        .replace('    environment: registry-publishing-approval\n', '')
        .replace(
          'jobs:\n  publish:',
          'jobs:\n'
          + '  approval:\n'
          + '    runs-on: ubuntu-latest\n'
          + '    environment: registry-publishing-approval\n'
          + '    permissions: {}\n'
          + '    steps:\n'
          + '      - run: echo "detached approval"\n\n'
          + '  publish:\n'
          + '    needs: approval',
        );
      expect(() => validate(unprotected)).toThrow(/OIDC publisher.*protected approval environment/);

      const branchSelected = text.replace('ref: ${{ github.sha }}', 'ref: ${{ inputs.release_tag }}');
      expect(() => validate(branchSelected)).toThrow(/github\.sha/);

      const forgedRef = text.replaceAll('--expected-ref "$GITHUB_REF"', '--expected-ref "refs/heads/main"');
      expect(() => validate(forgedRef)).toThrow(/expected-ref/);
    }
  });

  it('refuses a reusable publisher with its post-registry byte comparison removed', () => {
    const workflow = readFileSync('.github/workflows/_publish-npm-package.yml', 'utf8');
    const weakened = workflow.replace('cmp "$TESTED_TARBALL" "registry-copy/$REGISTRY_TARBALL"', 'true # comparison removed');
    expect(() => validateReusableNpmWorkflowText(weakened)).toThrow(/registry-copy/);
  });

  it('refuses npm release workflows without the pinned TLA+ runtime required by the security case', () => {
    const reusable = readFileSync('.github/workflows/_publish-npm-package.yml', 'utf8');
    const reusableWithoutJava17 = reusable.replace("java-version: '17'", "java-version: '21'");
    expect(() => validateReusableNpmWorkflowText(reusableWithoutJava17)).toThrow(/TLA\+ execution guard/);

    const direct = readFileSync('.github/workflows/publish-verify-sdk.yml', 'utf8');
    const directWithoutPinnedTla = direct.replace(
      '936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88',
      'checksum-removed',
    );
    expect(() => validateNpmDirect(directWithoutPinnedTla, 'publish-verify-sdk.yml')).toThrow(/TLA\+/);
  });

  it('refuses reusable npm publication without a pre-publication internal dependency registry guard', () => {
    const workflow = readFileSync('.github/workflows/_publish-npm-package.yml', 'utf8');
    const weakened = workflow.replaceAll(
      'node scripts/check-npm-package-dependencies.mjs "$PACKAGE_DIR"',
      'true # dependency registry guard removed',
    );
    expect(() => validateReusableNpmWorkflowText(weakened)).toThrow(/check-npm-package-dependencies/);

    const misplaced = weakened.replace(
      'npm publish "${{ steps.pack.outputs.tarball }}" --access public --provenance',
      'npm publish "${{ steps.pack.outputs.tarball }}" --access public --provenance\n'
      + '          node scripts/check-npm-package-dependencies.mjs "$PACKAGE_DIR"',
    );
    expect(() => validateReusableNpmWorkflowText(misplaced)).toThrow(/must run.*before.*npm publish/);
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
