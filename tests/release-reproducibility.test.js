// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { assertArtifactBytesMatch, verifyReproduciblePackage } from '../scripts/verify-reproducible-package.mjs';
import { assertPythonArtifactBytesMatch } from '../scripts/python-artifact-integrity.mjs';

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

  it('accepts a PyPI wheel only when every published byte matches', () => {
    const wheel = Buffer.from('tested-python-wheel');
    expect(assertPythonArtifactBytesMatch(wheel, Buffer.from(wheel))).toMatch(/^[0-9a-f]{64}$/);
  });

  it('rejects a one-byte PyPI wheel substitution', () => {
    expect(() => assertPythonArtifactBytesMatch(
      Buffer.from('tested-python-wheel'),
      Buffer.from('tested-python-wheek'),
    )).toThrow(/published Python artifact bytes differ/);
  });

  it('accepts a PyPI sdist only when every published byte matches', () => {
    const sdist = Buffer.from('tested-python-sdist');
    expect(assertPythonArtifactBytesMatch(sdist, Buffer.from(sdist))).toMatch(/^[0-9a-f]{64}$/);
  });

  it('rejects a one-byte PyPI sdist substitution', () => {
    expect(() => assertPythonArtifactBytesMatch(
      Buffer.from('tested-python-sdist'),
      Buffer.from('tested-python-sdisu'),
    )).toThrow(/published Python artifact bytes differ/);
  });

  it('publish workflow attests, publishes, and registry-compares the same tarball', () => {
    const workflow = readFileSync('.github/workflows/publish-verify-sdk.yml', 'utf8');
    expect(workflow).toContain('subject-path: release-artifacts/${{ steps.pack.outputs.tarball }}');
    expect(workflow).toContain('npm publish "../../release-artifacts/${{ steps.pack.outputs.tarball }}" --access public --provenance');
    expect(workflow).toContain('cmp "../../release-artifacts/${{ steps.pack.outputs.tarball }}" "../../registry-copy/$REGISTRY_TARBALL"');
    expect(workflow).toContain('actions/attest@a1948c3f048ba23858d222213b7c278aabede763');
  });

  it('PyPI workflow builds twice, attests, publishes, and registry-compares the same wheel and sdist', () => {
    const workflow = readFileSync('.github/workflows/publish-python-verify.yml', 'utf8');
    expect(workflow).toContain('verify-reproducible-wheel.mjs packages/python-verify');
    expect(workflow).toContain('subject-path: ${{ steps.build.outputs.wheel }}');
    expect(workflow).toContain('subject-path: ${{ steps.build.outputs.sdist }}');
    expect(workflow).toContain('packages-dir: release-artifacts/python-verify/');
    expect(workflow).toContain('cmp "${{ steps.build.outputs.wheel }}" "$REGISTRY_WHEEL"');
    expect(workflow).toContain('cmp "${{ steps.build.outputs.sdist }}" "$REGISTRY_SDIST"');
  });
});
