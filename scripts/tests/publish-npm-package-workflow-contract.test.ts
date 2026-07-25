// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import YAML from 'yaml';

interface WorkflowStep {
  name?: string;
  id?: string;
  run?: string;
  env?: Record<string, string>;
  with?: Record<string, string>;
}

const WORKFLOW_PATH = path.join(
  process.cwd(),
  '.github',
  'workflows',
  '_publish-npm-package.yml',
);

function loadPublishSteps(): WorkflowStep[] {
  const workflow = YAML.parse(fs.readFileSync(WORKFLOW_PATH, 'utf8'));
  return workflow?.jobs?.publish?.steps ?? [];
}

function requireStep(steps: WorkflowStep[], name: string): WorkflowStep {
  const step = steps.find((candidate) => candidate.name === name);
  expect(step, `missing workflow step: ${name}`).toBeDefined();
  return step!;
}

describe('reusable npm release workflow byte contract', () => {
  it('puts the OIDC-capable publisher itself inside the protected environment', () => {
    const workflow = YAML.parse(fs.readFileSync(WORKFLOW_PATH, 'utf8'));
    expect(workflow?.jobs?.approval).toBeUndefined();
    expect(workflow?.jobs?.publish?.environment).toBe('registry-publishing-approval');
    expect(workflow?.jobs?.publish?.permissions?.['id-token']).toBe('write');
  });

  it('consumes only the filename and SHA emitted by the reproducibility manifest', () => {
    const steps = loadPublishSteps();
    const pack = steps.find((step) => step.id === 'pack');
    expect(pack).toBeDefined();
    expect(pack?.run).not.toMatch(/\bfind\b/);
    expect(pack?.run).toContain('EP-REPRODUCIBLE-NPM-ARTIFACT-v1');
    expect(pack?.run).toContain('manifest.artifact.filename');
    expect(pack?.run).toContain('manifest.artifact.sha256');
    expect(pack?.run).toContain('approvedVersion');
    expect(pack?.run).toContain('approvedFilename');
    expect(pack?.run).toContain('archives.length !== 1');
    expect(pack?.run).toContain('archive !== filename');
    expect(pack?.run).toContain('actualSha256 !== expectedSha256');
    expect(pack?.run).toContain('tarball=${tarballPath}');
    expect(pack?.run).toContain('sha256=${expectedSha256}');
  });

  it('attests, uploads, publishes, and compares the same SHA-checked path', () => {
    const steps = loadPublishSteps();
    const canonicalTarball = '${{ steps.pack.outputs.tarball }}';
    const canonicalSha256 = '${{ steps.pack.outputs.sha256 }}';

    const attest = requireStep(steps, 'Attest exact npm package bytes');
    expect(attest.with?.['subject-path']).toBe(canonicalTarball);

    const upload = requireStep(steps, 'Upload exact release evidence');
    expect(upload.with?.path).toContain(canonicalTarball);
    expect(upload.with?.path).toContain(`${canonicalTarball}.sha256`);

    const publish = requireStep(steps, 'Publish the attested tarball through npm OIDC');
    expect(publish.env?.TESTED_TARBALL).toBe(canonicalTarball);
    expect(publish.env?.EXPECTED_SHA256).toBe(canonicalSha256);
    expect(publish.run).toContain('sha256sum -c "$TESTED_TARBALL.sha256"');
    expect(publish.run).toContain('--revalidate-remote');
    expect(publish.run).toContain('response.status === 404');
    expect(publish.run).toContain('already exists; refusing to publish');
    expect(publish.run).toContain(
      'npm publish "${{ steps.pack.outputs.tarball }}" --access public --provenance',
    );

    const registry = requireStep(steps, 'Verify registry bytes match the attested tarball');
    expect(registry.env?.TESTED_TARBALL).toBe(canonicalTarball);
    expect(registry.env?.EXPECTED_SHA256).toBe(canonicalSha256);
    expect(registry.run).toContain('sha256sum -c "$TESTED_TARBALL.sha256"');
    expect(registry.run).toMatch(/archives\.length\s*!==\s*1/);
    expect(registry.run).toContain('REGISTRY_SHA256');
    expect(registry.run).toContain('test "$REGISTRY_SHA256" = "$EXPECTED_SHA256"');
    expect(registry.run).toContain(
      'cmp "$TESTED_TARBALL" "registry-copy/$REGISTRY_TARBALL"',
    );
  });

  it('materializes pinned registry dependencies before tests and re-verifies them before publish', () => {
    const steps = loadPublishSteps();
    const materializeIndex = steps.findIndex(
      (step) => step.name === 'Materialize pinned registry dependency bytes',
    );
    const testIndex = steps.findIndex((step) => step.name === 'Test package');
    const verifyIndex = steps.findIndex(
      (step) => step.name === 'Require every internal dependency to resolve from npm',
    );
    const publishIndex = steps.findIndex(
      (step) => step.name === 'Publish the attested tarball through npm OIDC',
    );

    expect(materializeIndex).toBeGreaterThan(-1);
    expect(materializeIndex).toBeLessThan(testIndex);
    expect(steps[materializeIndex]?.run).toContain('--install-pinned');
    expect(verifyIndex).toBeGreaterThan(testIndex);
    expect(verifyIndex).toBeLessThan(publishIndex);
  });
});
