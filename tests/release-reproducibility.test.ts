// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { gzipSync } from 'node:zlib';
import {
  assertArtifactBytesMatch,
  canonicalizeNpmTarball,
  verifyReproduciblePackage,
} from '../scripts/verify-reproducible-package.mjs';
import { assertPythonArtifactBytesMatch } from '../scripts/python-artifact-integrity.mjs';

describe('release byte reproducibility', () => {
  it('packs @emilia-protocol/verify twice to byte-identical tarballs', () => {
    const result = verifyReproduciblePackage('packages/verify');
    expect(result.name).toBe('@emilia-protocol/verify');
    expect(result.filename).toBe(`emilia-protocol-verify-${result.version}.tgz`);
    expect(result.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(result.fileCount).toBeGreaterThan(0);
  }, 90_000);

  it('normalizes source file modes across independent package checkouts', () => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'ep-pack-modes-'));
    const makePackage = (name, sourceMode, binMode) => {
      const target = path.join(root, name);
      mkdirSync(target);
      writeFileSync(path.join(target, 'package.json'), JSON.stringify({
        name: 'mode-stability-fixture',
        version: '1.0.0',
        files: ['index.js', 'cli.js'],
        bin: { fixture: 'cli.js' },
      }));
      writeFileSync(path.join(target, 'index.js'), 'export const value = 1;\n');
      writeFileSync(path.join(target, 'cli.js'), '#!/usr/bin/env node\nconsole.log("ok");\n');
      chmodSync(path.join(target, 'index.js'), sourceMode);
      chmodSync(path.join(target, 'cli.js'), binMode);
      return target;
    };
    try {
      const restricted = makePackage('restricted', 0o600, 0o700);
      const conventional = makePackage('conventional', 0o644, 0o755);
      const first = verifyReproduciblePackage(restricted);
      const second = verifyReproduciblePackage(conventional);
      expect(first.sha256).toBe(second.sha256);
      expect(statSync(path.join(restricted, 'index.js')).mode & 0o777).toBe(0o600);
      expect(statSync(path.join(restricted, 'cli.js')).mode & 0o777).toBe(0o700);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('rejects nondeterministic output from independent clean package builds', () => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'ep-pack-nondeterministic-'));
    const dependencyRoot = path.join(root, 'fixture-dependencies');
    const generatedPath = path.join(root, 'dist', 'generated.js');
    mkdirSync(dependencyRoot);
    mkdirSync(path.dirname(generatedPath));
    writeFileSync(path.join(root, 'package.json'), JSON.stringify({
      name: 'nondeterministic-build-fixture',
      version: '1.0.0',
      files: ['dist'],
      scripts: {
        build: 'node build.mjs',
        prepack: 'npm run build',
      },
    }));
    writeFileSync(path.join(root, 'build.mjs'), [
      "import { mkdirSync, writeFileSync } from 'node:fs';",
      "import { randomBytes } from 'node:crypto';",
      "mkdirSync('dist', { recursive: true });",
      "writeFileSync('dist/generated.js', `export default '${randomBytes(32).toString('hex')}';\\n`);",
      '',
    ].join('\n'));
    writeFileSync(generatedPath, 'export default "injected-frozen-output";\n');

    try {
      expect(() => verifyReproduciblePackage(root, { dependencyRoot })).toThrow(
        /package build|package (file manifests|bytes) differ/,
      );
      expect(readFileSync(generatedPath, 'utf8')).toBe('export default "injected-frozen-output";\n');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('rejects randomness shared through a writable repository dependency tree', () => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'ep-pack-shared-seed-'));
    const dependencyRoot = path.join(root, 'fixture-dependencies');
    const seedName = `.ep-hostile-seed-${process.pid}-${Date.now()}`;
    const repositorySeedPath = path.join(process.cwd(), 'node_modules', seedName);
    mkdirSync(dependencyRoot);
    writeFileSync(path.join(root, 'package.json'), JSON.stringify({
      name: 'shared-seed-build-fixture',
      version: '1.0.0',
      files: ['dist'],
      scripts: {
        build: 'node build.mjs',
      },
    }));
    writeFileSync(path.join(root, 'build.mjs'), [
      "import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';",
      "import { randomBytes } from 'node:crypto';",
      `const seedPath = 'node_modules/${seedName}';`,
      'let seed;',
      'try {',
      "  seed = readFileSync(seedPath, 'utf8');",
      '} catch {',
      "  seed = randomBytes(32).toString('hex');",
      "  writeFileSync(seedPath, seed);",
      '}',
      "mkdirSync('dist', { recursive: true });",
      "writeFileSync('dist/generated.js', `export default '${seed}';\\n`);",
      '',
    ].join('\n'));

    try {
      expect(() => verifyReproduciblePackage(root, { dependencyRoot })).toThrow(
        /package build|package (file manifests|bytes) differ/,
      );
      expect(() => readFileSync(repositorySeedPath, 'utf8')).toThrow();
    } finally {
      rmSync(repositorySeedPath, { force: true });
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('rejects a deterministic build-time package version rewrite', () => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'ep-pack-version-rewrite-'));
    const dependencyRoot = path.join(root, 'fixture-dependencies');
    mkdirSync(dependencyRoot);
    writeFileSync(path.join(root, 'package.json'), JSON.stringify({
      name: 'version-rewrite-fixture',
      version: '1.0.0',
      files: ['dist'],
      scripts: {
        build: 'node build.mjs',
      },
    }));
    writeFileSync(path.join(root, 'build.mjs'), [
      "import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';",
      "const metadata = JSON.parse(readFileSync('package.json', 'utf8'));",
      "metadata.version = '9.9.9';",
      "writeFileSync('package.json', `${JSON.stringify(metadata, null, 2)}\\n`);",
      "mkdirSync('dist', { recursive: true });",
      "writeFileSync('dist/index.js', 'export const value = 1;\\n');",
      '',
    ].join('\n'));

    try {
      expect(() => verifyReproduciblePackage(root, { dependencyRoot })).toThrow(
        /mutated package\.json|package identity/i,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('canonicalizes different host gzip streams to identical publish bytes', () => {
    const tarPayload = Buffer.from('stable tar payload'.repeat(64));
    const fastHostArchive = gzipSync(tarPayload, { level: 1, mtime: 0 });
    const compactHostArchive = gzipSync(tarPayload, { level: 9, mtime: 0 });

    expect(fastHostArchive.equals(compactHostArchive)).toBe(false);
    expect(canonicalizeNpmTarball(fastHostArchive)).toEqual(
      canonicalizeNpmTarball(compactHostArchive),
    );
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
    expect(workflow).toContain('subject-path: ${{ steps.pack.outputs.tarball }}');
    expect(workflow).toContain('npm publish "${{ steps.pack.outputs.tarball }}" --access public --provenance');
    expect(workflow).toContain('cmp "$TESTED_TARBALL" "registry-copy/$REGISTRY_TARBALL"');
    expect(workflow).toContain('actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6');
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
