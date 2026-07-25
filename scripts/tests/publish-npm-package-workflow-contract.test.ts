// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import YAML from 'yaml';

const WORKFLOW_PATH = path.join(
  process.cwd(),
  '.github',
  'workflows',
  '_publish-npm-package.yml',
);

function workflow(): any {
  return YAML.parse(fs.readFileSync(WORKFLOW_PATH, 'utf8'));
}

describe('reusable npm release workflow byte contract', () => {
  it('separates untrusted build code from the protected OIDC publisher', () => {
    const jobs = workflow().jobs;
    expect(Object.keys(jobs)).toEqual(['build', 'publisher']);
    expect(jobs.build.permissions).toEqual({ contents: 'read' });
    expect(jobs.build.environment).toBeUndefined();
    expect(jobs.publisher.needs).toBe('build');
    expect(jobs.publisher.environment).toBe('registry-publishing-approval');
    expect(jobs.publisher.permissions).toEqual({
      contents: 'read',
      'id-token': 'write',
      attestations: 'write',
    });
    expect(jobs.publisher.steps.some((step) => step.uses?.startsWith('actions/checkout@')))
      .toBe(false);
    expect(jobs.publisher.steps.every((step) => !step.run?.includes('scripts/'))).toBe(true);
  });

  it('downloads only the immutable build artifact ID and validates an exact safe inventory', () => {
    const jobs = workflow().jobs;
    const download = jobs.publisher.steps.find(
      (step) => step.uses?.startsWith('actions/download-artifact@'),
    );
    expect(download.with).toMatchObject({
      'artifact-ids': '${{ needs.build.outputs.release_artifact_id }}',
      path: 'publisher-input',
    });
    expect(download.with.name).toBeUndefined();

    const validate = jobs.publisher.steps.find(
      (step) => step.name === 'Validate exact inert release artifact',
    );
    expect(validate.run).toContain('unexpected release artifact inventory');
    expect(validate.run).toContain('duplicate release artifact path');
    expect(validate.run).toContain('release artifact path escapes extraction root');
    expect(validate.run).toContain('release artifact symlink is forbidden');
    expect(validate.run).toContain('duplicate npm tarball path');
    expect(validate.run).toContain('npm tarball links are forbidden');
  });

  it('binds source package.json raw bytes, manifest, tarball, dependencies, and registry bytes', () => {
    const jobs = workflow().jobs;
    const buildPack = jobs.build.steps.find((step) => step.id === 'pack');
    expect(buildPack.run).toContain('APPROVED_PACKAGE_JSON_SHA256');
    expect(buildPack.run).toContain('manifest.artifact?.package_json_sha256');
    expect(buildPack.run).toContain('source-package.json');
    expect(buildPack.run).toContain('dependency-pins.json');

    const validate = jobs.publisher.steps.find((step) => step.id === 'validate');
    expect(validate.run).toContain(
      'tarball package/package.json bytes differ from approved source package.json',
    );
    expect(validate.run).toContain('manifest_sha256');
    expect(validate.run).toContain('dependency-pins.json differs');
    expect(validate.run).toContain('pinned dependency bytes differ');
    expect(validate.run).toContain('internal dependency unavailable from npm');
  });

  it('rehashes after fixed canonical refs, publishes without scripts, and compares registry bytes', () => {
    const jobs = workflow().jobs;
    const publish = jobs.publisher.steps.find((step) => step.run?.includes('npm publish'));
    const registry = jobs.publisher.steps.find(
      (step) => step.name === 'Verify registry bytes match exact tested tarball',
    );
    expect(publish.run).toContain('already exists; refusing to publish');
    expect(publish.run).toContain(
      'git ls-remote --exit-code https://github.com/emiliaprotocol/emilia-protocol.git',
    );
    expect(publish.run.indexOf('git ls-remote')).toBeLessThan(
      publish.run.lastIndexOf('sha256sum'),
    );
    expect(publish.run.lastIndexOf('sha256sum')).toBeLessThan(
      publish.run.indexOf('npm publish'),
    );
    expect(publish.run).toContain(
      'npm publish "$TESTED_TARBALL" --access public --provenance --ignore-scripts',
    );
    expect(registry.run).toContain('--ignore-scripts');
    expect(registry.run).toContain('archives.length !== 1');
    expect(registry.run).toContain('cmp "$TESTED_TARBALL" "registry-copy/$REGISTRY_TARBALL"');
  });
});
