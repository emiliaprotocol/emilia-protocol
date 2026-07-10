// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { assertArtifactBytesMatch, verifyReproduciblePackage } from '../scripts/verify-reproducible-package.mjs';

describe('release byte reproducibility', () => {
  it('packs @emilia-protocol/verify twice to byte-identical tarballs', () => {
    const result = verifyReproduciblePackage('packages/verify');
    expect(result.name).toBe('@emilia-protocol/verify');
    expect(result.filename).toBe(`emilia-protocol-verify-${result.version}.tgz`);
    expect(result.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(result.fileCount).toBeGreaterThan(0);
  });

  it('accepts a registry artifact only when every published byte matches', () => {
    const artifact = Buffer.from('tested-release-artifact');
    expect(assertArtifactBytesMatch(artifact, Buffer.from(artifact))).toMatch(/^[0-9a-f]{64}$/);
  });

  it('rejects a one-byte registry artifact substitution', () => {
    expect(() => assertArtifactBytesMatch(
      Buffer.from('tested-release-artifact'),
      Buffer.from('tested-release-artifacu'),
    )).toThrow(/published artifact bytes differ/);
  });

  it('publish workflow attests, publishes, and registry-compares the same tarball', () => {
    const workflow = readFileSync('.github/workflows/publish-verify-sdk.yml', 'utf8');
    expect(workflow).toContain('subject-path: release-artifacts/${{ steps.pack.outputs.tarball }}');
    expect(workflow).toContain('npm publish "../../release-artifacts/${{ steps.pack.outputs.tarball }}" --access public --provenance');
    expect(workflow).toContain('cmp "../../release-artifacts/${{ steps.pack.outputs.tarball }}" "../../registry-copy/$REGISTRY_TARBALL"');
    expect(workflow).toContain('actions/attest@a1948c3f048ba23858d222213b7c278aabede763');
  });
});
