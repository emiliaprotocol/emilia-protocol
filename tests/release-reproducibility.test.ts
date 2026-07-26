// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { gzipSync } from 'node:zlib';
import {
  assertArtifactBytesMatch,
  canonicalizeNpmTarball,
  validatePackedPackageIdentity,
  verifyReproduciblePackage,
} from '../scripts/verify-reproducible-package.mjs';
import { assertPythonArtifactBytesMatch } from '../scripts/python-artifact-integrity.mjs';

describe('release byte reproducibility', () => {
  const commitFixture = (root: string): string => {
    execFileSync('git', ['init', '-q'], { cwd: root });
    execFileSync('git', ['config', 'user.name', 'Release Fixture'], { cwd: root });
    execFileSync('git', ['config', 'user.email', 'release-fixture@example.test'], { cwd: root });
    execFileSync('git', ['add', '--all'], { cwd: root });
    execFileSync('git', ['commit', '-q', '-m', 'fixture'], { cwd: root });
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
  };

  const verifyFixture = (root: string, options: { outDir?: string | null } = {}) => {
    const reviewedCommit = commitFixture(root);
    return verifyReproduciblePackage(root, {
      ...options,
      repositoryRoot: root,
      reviewedCommit,
    });
  };

  it('packs @emilia-protocol/verify twice to byte-identical tarballs', () => {
    const result = verifyReproduciblePackage('packages/verify');
    expect(result.name).toBe('@emilia-protocol/verify');
    expect(result.filename).toBe(`emilia-protocol-verify-${result.version}.tgz`);
    expect(result.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(result.fileCount).toBeGreaterThan(0);
    expect(result.source.commit_sha).toBe(execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim());
    expect(result.recipe['@version']).toBe('EP-NPM-PACK-RECIPE-v2');
    expect(result.members).toHaveLength(result.fileCount);
  }, 300_000);

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
      const first = verifyFixture(restricted);
      const second = verifyFixture(conventional);
      expect(first.sha256).toBe(second.sha256);
      expect(statSync(path.join(restricted, 'index.js')).mode & 0o777).toBe(0o600);
      expect(statSync(path.join(restricted, 'cli.js')).mode & 0o777).toBe(0o700);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 60_000);

  it('rejects nondeterministic output from independent clean package builds', () => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'ep-pack-nondeterministic-'));
    const generatedPath = path.join(root, 'dist', 'generated.js');
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
      expect(() => verifyFixture(root)).toThrow(
        /package build|package (?:file|member) manifests differ|package bytes differ/,
      );
      expect(readFileSync(generatedPath, 'utf8')).toBe('export default "injected-frozen-output";\n');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('rejects randomness shared through a writable repository dependency tree', () => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'ep-pack-shared-seed-'));
    const seedName = `.ep-hostile-seed-${process.pid}-${Date.now()}`;
    const repositorySeedPath = path.join(process.cwd(), 'node_modules', seedName);
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
      expect(() => verifyFixture(root)).toThrow(
        /package build|package (?:file|member) manifests differ|package bytes differ/,
      );
      expect(() => readFileSync(repositorySeedPath, 'utf8')).toThrow();
    } finally {
      rmSync(repositorySeedPath, { force: true });
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('rejects randomness shared through an inherited RUNNER_TEMP', () => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'ep-pack-runner-temp-seed-'));
    const sharedRunnerTemp = path.join(root, 'host-runner-temp');
    const priorRunnerTemp = process.env.RUNNER_TEMP;
    mkdirSync(sharedRunnerTemp);
    writeFileSync(path.join(root, 'package.json'), JSON.stringify({
      name: 'runner-temp-seed-build-fixture',
      version: '1.0.0',
      files: ['dist'],
      scripts: {
        build: 'node build.mjs',
      },
    }));
    writeFileSync(path.join(root, 'build.mjs'), [
      "import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';",
      "import { randomBytes } from 'node:crypto';",
      "import path from 'node:path';",
      "const seedPath = path.join(process.env.RUNNER_TEMP, 'hostile-seed');",
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

    process.env.RUNNER_TEMP = sharedRunnerTemp;
    try {
      expect(() => verifyFixture(root)).toThrow(
        /package build|package (?:file|member) manifests differ|package bytes differ/,
      );
      expect(() => readFileSync(path.join(sharedRunnerTemp, 'hostile-seed'), 'utf8')).toThrow();
    } finally {
      if (priorRunnerTemp === undefined) delete process.env.RUNNER_TEMP;
      else process.env.RUNNER_TEMP = priorRunnerTemp;
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('removes an inherited GITHUB_WORKSPACE from both independent builds', () => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'ep-pack-workspace-seed-'));
    const hostWorkspace = path.join(root, 'host-workspace');
    const priorWorkspace = process.env.GITHUB_WORKSPACE;
    mkdirSync(hostWorkspace);
    writeFileSync(path.join(root, 'package.json'), JSON.stringify({
      name: 'workspace-seed-build-fixture',
      version: '1.0.0',
      files: ['dist'],
      scripts: {
        build: 'node build.mjs',
      },
    }));
    writeFileSync(path.join(root, 'build.mjs'), [
      "import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';",
      "import { randomBytes } from 'node:crypto';",
      "import path from 'node:path';",
      "const seedPath = process.env.GITHUB_WORKSPACE",
      "  ? path.join(process.env.GITHUB_WORKSPACE, 'hostile-seed')",
      '  : null;',
      'let seed;',
      'try {',
      "  seed = seedPath ? readFileSync(seedPath, 'utf8') : null;",
      '} catch {}',
      "if (!seed) seed = randomBytes(32).toString('hex');",
      'if (seedPath) writeFileSync(seedPath, seed);',
      "mkdirSync('dist', { recursive: true });",
      "writeFileSync('dist/generated.js', `export default '${seed}';\\n`);",
      '',
    ].join('\n'));

    process.env.GITHUB_WORKSPACE = hostWorkspace;
    try {
      expect(() => verifyFixture(root)).toThrow(
        /package build|package (?:file|member) manifests differ|package bytes differ/,
      );
      expect(() => readFileSync(path.join(hostWorkspace, 'hostile-seed'), 'utf8')).toThrow();
    } finally {
      if (priorWorkspace === undefined) delete process.env.GITHUB_WORKSPACE;
      else process.env.GITHUB_WORKSPACE = priorWorkspace;
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('rejects a deterministic build-time package version rewrite', () => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'ep-pack-version-rewrite-'));
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
      expect(() => verifyFixture(root)).toThrow(
        /mutated package\.json|package identity/i,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it.each([
    ['dependency', { dependencies: { hostile: '9.9.9' } }],
    ['export', { exports: { '.': './hostile.js' } }],
    ['script', { scripts: { postinstall: 'node hostile.js' } }],
  ])('rejects a tarball package.json %s mutation even when name/version match', (_label, mutation) => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'ep-pack-package-json-raw-'));
    const outDir = path.join(root, 'out');
    const sourceMetadata = {
      name: 'raw-package-json-fixture',
      version: '1.0.0',
      files: ['index.js', 'hostile.js'],
    };
    const mutatedMetadata = { ...sourceMetadata, ...mutation };
    writeFileSync(path.join(root, 'package.json'), `${JSON.stringify(mutatedMetadata, null, 2)}\n`);
    writeFileSync(path.join(root, 'index.js'), 'export const value = 1;\n');
    writeFileSync(path.join(root, 'hostile.js'), 'throw new Error("must never run");\n');
    try {
      const packed = verifyFixture(root, { outDir });
      expect(() => validatePackedPackageIdentity(
        readFileSync(packed.artifactPath),
        sourceMetadata.name,
        sourceMetadata.version,
        Buffer.from(`${JSON.stringify(sourceMetadata, null, 2)}\n`),
      )).toThrow(/package\/package\.json bytes differ/i);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('fails closed when tracked checkout bytes differ from the reviewed commit', () => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'ep-pack-checkout-mutation-'));
    writeFileSync(path.join(root, 'package.json'), JSON.stringify({
      name: 'checkout-mutation-fixture',
      version: '1.0.0',
      files: ['index.js'],
    }));
    writeFileSync(path.join(root, 'index.js'), 'export const value = "reviewed";\n');
    const reviewedCommit = commitFixture(root);
    writeFileSync(path.join(root, 'index.js'), 'export const value = "mutated-after-review";\n');
    try {
      expect(() => verifyReproduciblePackage(root, {
        repositoryRoot: root,
        reviewedCommit,
      })).toThrow(/working checkout differs from the reviewed commit/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('keeps prepack and postpack restoration hooks inert', () => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'ep-pack-inert-hooks-'));
    writeFileSync(path.join(root, 'package.json'), JSON.stringify({
      name: 'inert-hook-fixture',
      version: '1.0.0',
      files: ['index.js'],
      scripts: {
        prepack: 'node hook.mjs prepack',
        postpack: 'node hook.mjs postpack',
      },
    }));
    const reviewedBytes = Buffer.from('export const value = "reviewed";\n');
    writeFileSync(path.join(root, 'index.js'), reviewedBytes);
    writeFileSync(path.join(root, 'hook.mjs'), [
      "import { writeFileSync } from 'node:fs';",
      "if (process.argv[2] === 'prepack') writeFileSync('index.js', 'export const value = \\\"hostile\\\";\\n');",
      "else writeFileSync('index.js', 'export const value = \\\"reviewed\\\";\\n');",
      "writeFileSync(`hook-${process.argv[2]}.ran`, 'yes');",
      '',
    ].join('\n'));
    try {
      const packed = verifyFixture(root);
      const member = packed.members.find((entry) => entry.path === 'index.js');
      expect(member.sha256).toBe(crypto.createHash('sha256').update(reviewedBytes).digest('hex'));
      expect(() => readFileSync(path.join(root, 'hook-prepack.ran'))).toThrow();
      expect(() => readFileSync(path.join(root, 'hook-postpack.ran'))).toThrow();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('rejects a reviewed Git tree containing a symlink', () => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'ep-pack-source-symlink-'));
    writeFileSync(path.join(root, 'package.json'), JSON.stringify({
      name: 'source-symlink-fixture',
      version: '1.0.0',
      files: ['index.js', 'linked.js'],
    }));
    writeFileSync(path.join(root, 'index.js'), 'export const value = 1;\n');
    symlinkSync('index.js', path.join(root, 'linked.js'));
    try {
      const reviewedCommit = commitFixture(root);
      expect(() => verifyReproduciblePackage(root, {
        repositoryRoot: root,
        reviewedCommit,
      })).toThrow(/symlink, submodule, or unsupported mode/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('rejects a build that injects a symlink into package runtime output', () => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'ep-pack-build-symlink-'));
    writeFileSync(path.join(root, 'package.json'), JSON.stringify({
      name: 'build-symlink-fixture',
      version: '1.0.0',
      files: ['dist'],
      scripts: { build: 'node build.mjs' },
    }));
    writeFileSync(path.join(root, 'index.js'), 'export const value = 1;\n');
    writeFileSync(path.join(root, 'build.mjs'), [
      "import { mkdirSync, symlinkSync } from 'node:fs';",
      "mkdirSync('dist', { recursive: true });",
      "symlinkSync('../index.js', 'dist/index.js');",
      '',
    ].join('\n'));
    try {
      expect(() => verifyFixture(root)).toThrow(/regular file|symlink|links/i);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('rejects symbolic refs and alternate-ref bytes instead of silently packing them', () => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'ep-pack-alternate-ref-'));
    writeFileSync(path.join(root, 'package.json'), JSON.stringify({
      name: 'alternate-ref-fixture',
      version: '1.0.0',
      files: ['index.js'],
    }));
    writeFileSync(path.join(root, 'index.js'), 'export const value = "main";\n');
    const reviewedCommit = commitFixture(root);
    execFileSync('git', ['switch', '-q', '-c', 'alternate'], { cwd: root });
    writeFileSync(path.join(root, 'index.js'), 'export const value = "alternate";\n');
    execFileSync('git', ['add', 'index.js'], { cwd: root });
    execFileSync('git', ['commit', '-q', '-m', 'alternate bytes'], { cwd: root });
    const alternateCommit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
    execFileSync('git', ['checkout', '-q', reviewedCommit], { cwd: root });
    try {
      expect(() => verifyReproduciblePackage(root, {
        repositoryRoot: root,
        reviewedCommit: 'alternate',
      })).toThrow(/exact full-length Git object id/);
      expect(() => verifyReproduciblePackage(root, {
        repositoryRoot: root,
        reviewedCommit: alternateCommit,
      })).toThrow(/working checkout differs from the reviewed commit/);
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
    const workflow = readFileSync('.github/workflows/_publish-npm-package.yml', 'utf8');
    expect(workflow).toContain('subject-path: ${{ steps.validate.outputs.tarball }}');
    expect(workflow).toContain(
      'npm publish "$TESTED_TARBALL" --access public --provenance --ignore-scripts',
    );
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
