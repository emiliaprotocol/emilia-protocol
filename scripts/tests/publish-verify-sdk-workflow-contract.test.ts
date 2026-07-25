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
    expect(pack?.run).toContain('--outdir release-artifacts');
    expect(pack?.run).toContain('--emit release-artifacts/verify-reproducible.json');
    expect(pack?.run).toContain(
      "require('./release-artifacts/verify-reproducible.json')",
    );
    expect(pack?.run).toContain('TARBALL_PATH="release-artifacts/$TARBALL"');
    expect(pack?.run).toContain('sha256sum -c "$TARBALL_PATH.sha256"');
    expect(pack?.run).toContain('echo "tarball=$TARBALL" >> "$GITHUB_OUTPUT"');

    const canonicalTarball = 'release-artifacts/${{ steps.pack.outputs.tarball }}';
    const attest = requireStep(steps, 'Attest exact package bytes');
    expect(attest.with?.['subject-path']).toBe(canonicalTarball);

    const upload = requireStep(steps, 'Upload exact package and checksum');
    expect(upload.with?.path).toContain(canonicalTarball);
    expect(upload.with?.path).toContain('release-artifacts/verify-reproducible.json');

    const publish = requireStep(steps, 'Publish the attested tarball (OIDC + npm provenance)');
    expect(publish.run).toContain(
      `npm publish "../../${canonicalTarball}" --access public --provenance`,
    );

    const registry = requireStep(steps, 'Verify registry bytes match the attested tarball');
    expect(registry.run).toContain(
      `cmp "../../${canonicalTarball}" "../../registry-copy/$REGISTRY_TARBALL"`,
    );
  });

  it('allows npm pack only for fetching registry bytes after publication', () => {
    const packCommands = loadPublishSteps()
      .flatMap((step) => step.run?.split('\n') ?? [])
      .map((line) => line.trim())
      .filter((line) => /\bnpm pack\b/.test(line));

    expect(packCommands).toHaveLength(1);
    expect(packCommands[0]).toContain('npm pack "@emilia-protocol/verify@$VERSION"');
    expect(packCommands[0]).toContain('--pack-destination ../../registry-copy');
  });
});
