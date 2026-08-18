// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  mkdtempSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  auditReleaseChain,
  discoverReleaseSurfaces,
  isCanonicalNpmRepositoryUrl,
  validateCredentialRotationGuideText,
  validateGoTagWorkflowText,
  validateNpmDirect,
  validateNpmLockData,
  validatePypiDirect,
  validateReusableNpmWorkflowText,
  validateReusablePypiWorkflowText,
} from '../scripts/check-release-chain.mjs';
import YAML from 'yaml';

describe('release-chain coverage', () => {
  it('accepts only the canonical EMILIA npm repository URL and its standard git transport form', () => {
    expect(isCanonicalNpmRepositoryUrl('https://github.com/emiliaprotocol/emilia-protocol.git')).toBe(true);
    expect(isCanonicalNpmRepositoryUrl('git+https://github.com/emiliaprotocol/emilia-protocol.git')).toBe(true);
    expect(isCanonicalNpmRepositoryUrl('https://github.com/emiliaprotocol/emilia-protocol')).toBe(false);
    expect(isCanonicalNpmRepositoryUrl('git+ssh://git@github.com/emiliaprotocol/emilia-protocol.git')).toBe(false);
    expect(isCanonicalNpmRepositoryUrl('https://github.com/attacker/emilia-protocol.git')).toBe(false);
  });

  it('keeps every governed workflow on the reviewed upstream action revisions', () => {
    const helper = readFileSync('scripts/pin-action-shas.ts', 'utf8');
    for (const [tag, pinned] of Object.entries({
      'actions/checkout@v7': 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1',
      'actions/setup-node@v7': 'actions/setup-node@820762786026740c76f36085b0efc47a31fe5020  # v7.0.0',
      'actions/setup-python@v7': 'actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97  # v7.0.0',
      'actions/upload-artifact@v7': 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a  # v7.0.1',
      'actions/setup-java@v5': 'actions/setup-java@b6effb05e454b25005698d916606bdc6ffcbf961  # v5.7.0',
      'actions/attest@v4': 'actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6  # v4.2.2',
      'github/codeql-action/init@v4': 'github/codeql-action/init@ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd  # v4.37.7',
      'pypa/gh-action-pypi-publish@release/v1': 'pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33  # v1.14.2',
    })) {
      expect(helper).toContain(`'${tag}'`);
      expect(helper).toContain(`'${pinned}'`);
    }
    expect(helper).not.toContain('SHA pins as of 2026-04-02');

    const expectedRefs = {
      'actions/checkout': '3d3c42e5aac5ba805825da76410c181273ba90b1',
      'actions/setup-java': 'b6effb05e454b25005698d916606bdc6ffcbf961',
      'actions/attest': '1e69f48acb82d1966a394da916b4c1698aa569d6',
      'pypa/gh-action-pypi-publish': 'dc37677b2e1c63e2034f94d8a5b11f265b73ba33',
    };
    const workflows = readdirSync('.github/workflows')
      .filter((name) => name.endsWith('.yml') || name.endsWith('.yaml'))
      .map((name) => readFileSync(path.join('.github/workflows', name), 'utf8'))
      .join('\n');

    for (const [action, expectedRef] of Object.entries(expectedRefs)) {
      const escaped = action.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const refs = [...workflows.matchAll(new RegExp(`${escaped}@([^\\s#"']+)`, 'gu'))]
        .map((match) => match[1]);
      expect(refs.length, action).toBeGreaterThan(0);
      expect(new Set(refs), action).toEqual(new Set([expectedRef]));
    }
  });

  it('forbids ambiguous generic tag provenance in favor of exact package publishers', () => {
    expect(existsSync('.github/workflows/release.yml')).toBe(false);
    expect(auditReleaseChain()).toEqual({ packages: 27, npm: 21, pypi: 5, go: 1 });
  });

  it('every declared package uses its complete verifiable release chain', () => {
    expect(auditReleaseChain()).toEqual({ packages: 27, npm: 21, pypi: 5, go: 1 });
  });

  it('every declared npm and PyPI package uses reproducible registry-byte verification', () => {
    const result = auditReleaseChain();
    expect(result).toMatchObject({ npm: 21, pypi: 5 });
  });

  it('keeps all npm package code in an unprivileged job and OIDC only in the protected publisher', () => {
    const reusableText = readFileSync('.github/workflows/_publish-npm-package.yml', 'utf8');
    const reusable = YAML.parse(reusableText);
    expect(Object.keys(reusable.jobs)).toEqual(['build', 'publisher']);

    const build = reusable.jobs.build;
    expect(build.environment).toBeUndefined();
    expect(build.permissions).toEqual({ contents: 'read' });
    expect(build.steps.some((step) => step.uses?.startsWith('actions/checkout@'))).toBe(true);
    expect(build.steps.some((step) => step.run?.includes('npm test'))).toBe(true);
    expect(build.steps.some((step) => step.run?.includes('check:security-case'))).toBe(true);
    expect(build.steps.some((step) => step.run?.includes('conformance:manifest:check'))).toBe(true);
    expect(build.steps.some((step) => step.run?.includes('verify-reproducible-package.mts'))).toBe(true);
    expect(build.steps.some((step) => step.uses?.startsWith('actions/upload-artifact@'))).toBe(true);

    const publisher = reusable.jobs.publisher;
    expect(publisher.needs).toBe('build');
    expect(publisher.environment).toBe('registry-publishing-approval');
    expect(publisher.permissions).toEqual({
      contents: 'read',
      'id-token': 'write',
      attestations: 'write',
    });
    expect(publisher.steps.some((step) => step.uses?.startsWith('actions/download-artifact@'))).toBe(true);
    expect(publisher.steps.some((step) => step.run?.includes('npm publish'))).toBe(true);
    expect(publisher.steps.some((step) => step.uses?.startsWith('actions/checkout@'))).toBe(false);
    expect(publisher.steps.every((step) => !step.run?.includes('scripts/'))).toBe(true);
    expect(publisher.steps.every((step) => !/\bnpm (?:test|run|ci|install|exec)\b/u.test(step.run ?? ''))).toBe(true);
  });

  it('downloads one immutable artifact ID and rejects unsafe or inexact publisher inputs', () => {
    const reusableText = readFileSync('.github/workflows/_publish-npm-package.yml', 'utf8');
    const reusable = YAML.parse(reusableText);
    const download = reusable.jobs.publisher.steps.find(
      (step) => step.uses?.startsWith('actions/download-artifact@'),
    );
    expect(download.with?.['artifact-ids']).toBe('${{ needs.build.outputs.release_artifact_id }}');
    expect(download.with?.name).toBeUndefined();
    const validation = reusable.jobs.publisher.steps.find(
      (step) => step.name === 'Validate exact inert release artifact',
    )?.run;
    expect(validation).toContain('lstatSync');
    expect(validation).toContain('isSymbolicLink');
    expect(validation).toContain('isFile');
    expect(validation).toContain('duplicate release artifact path');
    expect(validation).toContain('release artifact path escapes');
    expect(validation).toContain('unexpected release artifact inventory');
    expect(validation).toContain("entryPath === 'package/package.json'");
    expect(validation).toContain('tarball package/package.json bytes differ from approved reviewed Git object');
    expect(validation).toContain('manifest_sha256');
    expect(validation).toContain('package_json_sha256');
    expect(validation).toContain('tarball member bytes differ from reviewed source-and-recipe manifest');
    expect(validation).toContain('manifest dependency evidence differs');
  });

  it('delegates Verify, Gate, and every other npm trusted-publisher caller to the same split workflow', () => {
    const registry = JSON.parse(readFileSync('release/release-packages.v1.json', 'utf8'));
    const npmEntries = registry.packages.filter((entry) => entry.ecosystem === 'npm');
    expect(npmEntries).toHaveLength(21);
    for (const entry of npmEntries) {
      const text = readFileSync(path.join('.github/workflows', entry.workflow), 'utf8');
      const workflow = YAML.parse(text);
      expect(Object.keys(workflow.jobs), entry.workflow).toEqual(['publish']);
      expect(workflow.jobs.publish.uses, entry.workflow)
        .toBe('./.github/workflows/_publish-npm-package.yml');
      expect(workflow.jobs.publish.permissions, entry.workflow).toEqual({
        contents: 'read',
        'id-token': 'write',
        attestations: 'write',
      });
    }
  });

  it('uses the fixed canonical GitHub repository immediately before the irreversible publish', () => {
    const text = readFileSync('.github/workflows/_publish-npm-package.yml', 'utf8');
    const workflow = YAML.parse(text);
    const publishRun = workflow.jobs.publisher.steps.find(
      (step) => step.run?.includes('npm publish'),
    )?.run;
    expect(publishRun).toContain(
      'git ls-remote --exit-code https://github.com/emiliaprotocol/emilia-protocol.git',
    );
    expect(publishRun).not.toMatch(/\bgit ls-remote\b[^\n]*(?:origin|remote\.origin|git config)/u);
    expect(publishRun.indexOf('git ls-remote')).toBeLessThan(publishRun.lastIndexOf('sha256sum'));
    expect(publishRun.lastIndexOf('sha256sum')).toBeLessThan(publishRun.indexOf('npm publish'));
  });

  it('rejects OIDC leakage, publisher checkout, mutable artifact selection, and unsafe extraction', () => {
    const text = readFileSync('.github/workflows/_publish-npm-package.yml', 'utf8');
    const oidcBuild = text.replace(
      '  build:\n    name: Build and verify ${{ inputs.package_name }}\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read',
      '  build:\n    name: Build and verify ${{ inputs.package_name }}\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n      id-token: write',
    );
    expect(() => validateReusableNpmWorkflowText(oidcBuild)).toThrow(/build job is not unprivileged/);

    const publisherCheckout = text.replace(
      '    steps:\n      - name: Setup Node.js for npm OIDC',
      '    steps:\n'
      + '      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n'
      + '      - name: Setup Node.js for npm OIDC',
    );
    expect(() => validateReusableNpmWorkflowText(publisherCheckout)).toThrow(/inert protected OIDC job/);

    const mutableDownload = text.replace(
      'artifact-ids: ${{ needs.build.outputs.release_artifact_id }}',
      'name: npm-release-${{ inputs.artifact_id }}-${{ github.sha }}',
    );
    expect(() => validateReusableNpmWorkflowText(mutableDownload)).toThrow(
      /artifact ID|missing release controls/,
    );

    const unsafeExtraction = text.replace(
      'release artifact symlink is forbidden',
      'symlink accepted',
    );
    expect(() => validateReusableNpmWorkflowText(unsafeExtraction)).toThrow(/release controls/);
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

  it('refuses a caller-side detached approval or extra executable job', () => {
    const caller = readFileSync('.github/workflows/publish-verify-sdk.yml', 'utf8');
    const detached = caller.replace(
      'jobs:\n  publish:',
      'jobs:\n'
      + '  approval:\n'
      + '    runs-on: ubuntu-latest\n'
      + '    environment: registry-publishing-approval\n'
      + '    permissions: {}\n'
      + '    steps:\n'
      + '      - run: echo detached\n'
      + '  publish:',
    );
    expect(() => validateNpmDirect(detached, 'publish-verify-sdk.yml')).toThrow(
      /delegate only/,
    );
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
  });

  it('refuses stale checkout, Java, attestation, and PyPI publish action revisions', () => {
    const npm = readFileSync('.github/workflows/_publish-npm-package.yml', 'utf8');
    expect(() => validateReusableNpmWorkflowText(npm.replace(
      'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
      'actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803',
    ))).toThrow(/checkout action/);
    expect(() => validateReusableNpmWorkflowText(npm.replace(
      'actions/setup-java@b6effb05e454b25005698d916606bdc6ffcbf961',
      'actions/setup-java@03ad4de0992f5dab5e18fcb136590ce7c4a0ac95',
    ))).toThrow(/TLA\+ execution guard/);
    expect(() => validateReusableNpmWorkflowText(npm.replace(
      'actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6',
      'actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6',
    ))).toThrow(/attestation action/);

    const pypi = readFileSync('.github/workflows/_publish-pypi-package.yml', 'utf8');
    expect(() => validateReusablePypiWorkflowText(pypi.replace(
      'pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33',
      'pypa/gh-action-pypi-publish@ba38be9e461d3875417946c167d0b5f3d385a247',
    ))).toThrow(/release controls/);
  });

  it('refuses PyPI release workflows without the pinned TLA+ runtime required by the security case', () => {
    const reusable = readFileSync('.github/workflows/_publish-pypi-package.yml', 'utf8');
    const reusableWithoutOracle = reusable.replace(
      'TLA_SHA256: 936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88',
      'TLA_SHA256: removed',
    );
    expect(() => validateReusablePypiWorkflowText(reusableWithoutOracle)).toThrow(/TLA\+ execution guard/);

    const direct = readFileSync('.github/workflows/publish-python-verify.yml', 'utf8');
    const directWithoutOracle = direct.replace('TLA2TOOLS_JAR: ${{ github.workspace }}/tla2tools.jar', 'TLA2TOOLS_JAR: missing');
    expect(() => validatePypiDirect(directWithoutOracle, 'publish-python-verify.yml')).toThrow(/TLA\+ execution guard/);
  });

  it('refuses Go release workflows without the pinned TLA+ runtime required by the security case', () => {
    const workflow = readFileSync('.github/workflows/publish-go-verify.yml', 'utf8');
    const weakened = workflow.replace('TLA_VERSION: v1.7.4', 'TLA_VERSION: latest');
    expect(() => validateGoTagWorkflowText(weakened)).toThrow(/TLA\+ execution guard/);
  });

  it('refuses reusable npm publication without a pre-publication internal dependency registry guard', () => {
    const workflow = readFileSync('.github/workflows/_publish-npm-package.yml', 'utf8');
    const weakened = workflow.replace(
      'internal dependency unavailable from npm',
      'dependency check removed',
    );
    expect(() => validateReusableNpmWorkflowText(weakened)).toThrow(/dependency/);
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
