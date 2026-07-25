// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import YAML from 'yaml';

interface WorkflowStep {
  name?: string;
  id?: string;
  run?: string;
  uses?: string;
  with?: Record<string, string>;
  env?: Record<string, string>;
  'working-directory'?: string;
}

const WORKFLOW_PATH = path.join(
  process.cwd(),
  '.github',
  'workflows',
  'publish-verify-sdk.yml',
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

describe('Verify SDK release workflow artifact contract', () => {
  it('uses the canonical reproducibility artifact for attestation, upload, publish, and comparison', () => {
    const steps = loadPublishSteps();
    const pack = steps.find((step) => step.id === 'pack');
    expect(pack).toBeDefined();
    expect(pack?.['working-directory']).toBe('${{ github.workspace }}');
    expect(pack?.run).toContain('npm run release:verify:reproducible --');
    expect(pack?.run).toContain('ARTIFACT_DIR="release-artifacts/verify"');
    expect(pack?.run).toContain('MANIFEST_PATH="release-artifacts/verify-reproducible.json"');
    expect(pack?.run).toContain('--outdir "$ARTIFACT_DIR"');
    expect(pack?.run).toContain('--emit "$MANIFEST_PATH"');
    expect(pack?.run).toContain("manifest['@version'] !== 'EP-REPRODUCIBLE-NPM-ARTIFACT-v1'");
    expect(pack?.run).toContain('manifestSha256 !== actualManifestSha256');
    expect(pack?.run).toContain('approvedVersion');
    expect(pack?.run).toContain('approvedFilename');
    expect(pack?.run).toContain('archives.length !== 1');
    expect(pack?.run).toContain('actualSha256 !== expectedSha256');
    expect(pack?.run).toContain('tarball=${tarballPath}');
    expect(pack?.run).toContain('sha256=${expectedSha256}');

    const canonicalTarball = '${{ steps.pack.outputs.tarball }}';
    const attest = requireStep(steps, 'Attest exact package bytes');
    expect(attest.with?.['subject-path']).toBe(canonicalTarball);

    const upload = requireStep(steps, 'Upload exact package and checksum');
    expect(upload.with?.path).toContain(canonicalTarball);
    expect(upload.with?.path).toContain('release-artifacts/verify-reproducible.json');

    const publish = requireStep(steps, 'Publish the attested tarball (OIDC + npm provenance)');
    expect(publish.env?.EXPECTED_SHA256).toBe('${{ steps.pack.outputs.sha256 }}');
    expect(publish.run).toContain('--revalidate-remote');
    expect(publish.run).toContain('sha256sum -c "$TESTED_TARBALL.sha256"');
    expect(publish.run).toContain('response.status === 404');
    expect(publish.run).toContain('already exists; refusing to publish');
    expect(publish.run).toContain(
      `npm publish "${canonicalTarball}" --access public --provenance`,
    );

    const registry = requireStep(steps, 'Verify registry bytes match the attested tarball');
    expect(registry.env?.EXPECTED_SHA256).toBe('${{ steps.pack.outputs.sha256 }}');
    expect(registry.run).toContain('sha256sum -c "$TESTED_TARBALL.sha256"');
    expect(registry.run).toMatch(/archives\.length\s*!==\s*1/);
    expect(registry.run).toContain(
      'cmp "$TESTED_TARBALL" "registry-copy/$REGISTRY_TARBALL"',
    );
  });

  it('allows npm pack only for fetching registry bytes after publication', () => {
    const packCommands = loadPublishSteps()
      .flatMap((step) => step.run?.split('\n') ?? [])
      .map((line) => line.trim())
      .filter((line) => /\bnpm pack\b/.test(line));

    expect(packCommands).toHaveLength(1);
    expect(packCommands[0]).toContain('npm pack "@emilia-protocol/verify@$VERSION"');
    expect(packCommands[0]).toContain('--pack-destination registry-copy');
  });
});
