// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  assertInternalDependenciesPublished,
  collectInternalRegistryDependencies,
  collectRegistryDependencyTarballPins,
  verifyRegistryDependencyTarball,
} from '../scripts/check-npm-package-dependencies.mjs';

const GATE_METADATA = JSON.parse(readFileSync('packages/gate/package.json', 'utf8'));
const QUALIFY_METADATA = JSON.parse(readFileSync('packages/qualify/package.json', 'utf8'));
const RELEASE_REGISTRY = JSON.parse(readFileSync('release/release-packages.v1.json', 'utf8'));

function registryFetcher(
  bytes: Buffer,
  {
    filename = 'emilia-protocol-verify-3.15.1.tgz',
    extraArchives = [],
    report = null,
  }: {
    filename?: string;
    extraArchives?: string[];
    report?: unknown;
  } = {},
) {
  return (_spec: string, destination: string) => {
    if (filename === path.basename(filename)) {
      writeFileSync(path.join(destination, filename), bytes);
    }
    for (const archive of extraArchives) {
      writeFileSync(path.join(destination, archive), Buffer.from('hostile extra archive'));
    }
    return {
      status: 0,
      stdout: JSON.stringify(report ?? [{ filename }]),
      stderr: '',
    };
  };
}

describe('npm internal dependency registry guard', () => {
  it('requires pinned Verify 3.16.0 registry bytes before Gate or ep-qualify can release', () => {
    const expectedPin = {
      spec: '@emilia-protocol/verify@3.16.0',
      sha256: '50caa243b057708a30d459839b0ca02292aa297c1f7523ee77f3559492e08fea',
    };
    const downstream = [
      { metadata: GATE_METADATA, directory: 'packages/gate', version: '0.18.1' },
      { metadata: QUALIFY_METADATA, directory: 'packages/qualify', version: '0.1.0' },
    ];

    for (const { metadata, directory, version } of downstream) {
      const pins = collectRegistryDependencyTarballPins(
        metadata,
        directory,
        RELEASE_REGISTRY,
      );
      const requested: string[] = [];
      const verified: Array<{ spec: string; sha256: string }> = [];
      const dependencies = assertInternalDependenciesPublished(
        metadata,
        (spec: string) => {
          requested.push(spec);
          return true;
        },
        pins,
        (dependency, pin) => {
          verified.push({ spec: dependency.spec, sha256: pin.sha256 });
        },
      );

      expect(metadata.version).toBe(version);
      expect(metadata.dependencies['@emilia-protocol/verify']).toBe('3.16.0');
      expect(pins).toEqual([expectedPin]);
      expect(requested).not.toContain('@emilia-protocol/verify@3.16.0');
      expect(verified).toEqual([expectedPin]);
      expect(dependencies.map(({ spec }) => spec))
        .toContain('@emilia-protocol/verify@3.16.0');

      expect(() => assertInternalDependenciesPublished(
        metadata,
        () => true,
        pins,
        () => {
          throw new Error('registry tarball unavailable for @emilia-protocol/verify@3.16.0');
        },
      )).toThrow(/registry tarball unavailable.*3\.16\.0/);
    }
  });

  it('covers dependencies, optional dependencies, and peer dependencies', () => {
    const dependencies = collectInternalRegistryDependencies({
      name: '@emilia-protocol/example',
      dependencies: { '@emilia-protocol/verify': '3.15.0' },
      optionalDependencies: { '@emilia-protocol/optional': '^1.2.3' },
      peerDependencies: { '@emilia-protocol/peer': '>=2.0.0 <3.0.0' },
    });

    expect(dependencies.map(({ spec }) => spec)).toEqual([
      '@emilia-protocol/optional@^1.2.3',
      '@emilia-protocol/peer@>=2.0.0 <3.0.0',
      '@emilia-protocol/verify@3.15.0',
    ]);
  });

  it('fails closed when any declared internal dependency does not resolve', () => {
    expect(() => assertInternalDependenciesPublished(
      {
        name: '@emilia-protocol/gate',
        dependencies: {
          '@emilia-protocol/require-receipt': '0.7.0',
          '@emilia-protocol/verify': '3.15.0',
        },
      },
      (spec: string) => spec !== '@emilia-protocol/verify@3.15.0',
    )).toThrow(/@emilia-protocol\/verify@3\.15\.0 \(dependencies\)/);
  });

  it('refuses malformed, duplicate, or undeclared dependency byte pins', () => {
    const gateEntry = RELEASE_REGISTRY.packages.find(
      (entry: any) => entry.ecosystem === 'npm' && entry.package === '@emilia-protocol/gate',
    );
    const withPins = (pins: unknown[]) => ({
      ...RELEASE_REGISTRY,
      packages: RELEASE_REGISTRY.packages.map((entry: any) => (
        entry === gateEntry ? { ...entry, registry_dependency_tarballs: pins } : entry
      )),
    });

    expect(() => collectRegistryDependencyTarballPins(
      GATE_METADATA,
      'packages/gate',
      withPins([{ spec: '@emilia-protocol/verify@3.16.0', sha256: 'not-a-sha256' }]),
    )).toThrow(/invalid sha256/);

    const validPin = {
      spec: '@emilia-protocol/verify@3.16.0',
      sha256: 'a'.repeat(64),
    };
    expect(() => collectRegistryDependencyTarballPins(
      GATE_METADATA,
      'packages/gate',
      withPins([validPin, validPin]),
    )).toThrow(/duplicate registry dependency tarball pin/);

    expect(() => collectRegistryDependencyTarballPins(
      GATE_METADATA,
      'packages/gate',
      withPins([{
        spec: '@emilia-protocol/verify@3.14.0',
        sha256: 'a'.repeat(64),
      }]),
    )).toThrow(/does not match an exact declared dependency/);
  });

  it('refuses hash drift, path traversal, multiple reports, and extra registry archives', () => {
    const bytes = Buffer.from('canonical registry tarball');
    const dependency = {
      field: 'dependencies',
      name: '@emilia-protocol/verify',
      range: '3.15.0',
      spec: '@emilia-protocol/verify@3.15.0',
    };
    const pin = {
      spec: dependency.spec,
      sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
    };

    expect(() => verifyRegistryDependencyTarball(
      dependency,
      { ...pin, sha256: '0'.repeat(64) },
      { fetcher: registryFetcher(bytes) },
    )).toThrow(/sha256 mismatch/);

    expect(() => verifyRegistryDependencyTarball(
      dependency,
      pin,
      { fetcher: registryFetcher(bytes, { filename: '../escape.tgz' }) },
    )).toThrow(/unsafe filename/);

    expect(() => verifyRegistryDependencyTarball(
      dependency,
      pin,
      {
        fetcher: registryFetcher(bytes, {
          report: [
            { filename: 'emilia-protocol-verify-3.15.0.tgz' },
            { filename: 'second.tgz' },
          ],
        }),
      },
    )).toThrow(/exactly one tarball/);

    expect(() => verifyRegistryDependencyTarball(
      dependency,
      pin,
      { fetcher: registryFetcher(bytes, { extraArchives: ['substitute.tgz'] }) },
    )).toThrow(/unexpected registry archives/);
  });

  it('materializes tests from the verified registry tarball only after its hash matches', () => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'ep-gate-registry-test-'));
    const bytes = Buffer.from('canonical registry tarball');
    const dependency = {
      field: 'dependencies',
      name: '@emilia-protocol/verify',
      range: '3.15.0',
      spec: '@emilia-protocol/verify@3.15.0',
    };
    const pin = {
      spec: dependency.spec,
      sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
    };
    let installedTarball: string | null = null;
    const installer = (tarballPath: string, packageDirectory: string) => {
      installedTarball = tarballPath;
      const installedDirectory = path.join(
        packageDirectory,
        'node_modules',
        '@emilia-protocol',
        'verify',
      );
      mkdirSync(installedDirectory, { recursive: true });
      writeFileSync(
        path.join(installedDirectory, 'package.json'),
        JSON.stringify({ name: dependency.name, version: dependency.range }),
      );
      return { status: 0, stdout: '', stderr: '' };
    };

    try {
      const result = verifyRegistryDependencyTarball(dependency, pin, {
        fetcher: registryFetcher(bytes),
        installDirectory: root,
        installer,
      });
      expect(installedTarball).toMatch(/emilia-protocol-verify-3\.15\.1\.tgz$/);
      expect(result).toMatchObject({
        spec: dependency.spec,
        sha256: pin.sha256,
        installed: true,
      });

      installedTarball = null;
      expect(() => verifyRegistryDependencyTarball(
        dependency,
        { ...pin, sha256: '0'.repeat(64) },
        {
          fetcher: registryFetcher(bytes),
          installDirectory: root,
          installer,
        },
      )).toThrow(/sha256 mismatch/);
      expect(installedTarball).toBeNull();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
