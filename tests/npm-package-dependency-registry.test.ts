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
const CLI_METADATA = JSON.parse(readFileSync('cli/package.json', 'utf8'));
const ATTEST_METADATA = JSON.parse(readFileSync('packages/attest/package.json', 'utf8'));
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
  it('requires each downstream package to pin its exact published Verify registry bytes', () => {
    const downstream = [
      {
        metadata: GATE_METADATA,
        directory: 'packages/gate',
        version: '0.24.0',
        expectedPins: [
          {
            spec: '@emilia-protocol/require-receipt@0.8.1',
            sha256: '0d4a0a0b8f0ab7775d0c90eb91b57cfcd5e159e52844af35ada0ded5351a7bef',
          },
          {
            spec: '@emilia-protocol/verify@3.21.0',
            sha256: 'fb60903a33c49a7952646ddc3ca65c9c44706dbb41051feb7d5ef47e946774ed',
          },
        ],
      },
      {
        metadata: QUALIFY_METADATA,
        directory: 'packages/qualify',
        version: '0.1.4',
        expectedPins: [{
          spec: '@emilia-protocol/verify@3.21.0',
          sha256: 'fb60903a33c49a7952646ddc3ca65c9c44706dbb41051feb7d5ef47e946774ed',
        }],
      },
      {
        metadata: CLI_METADATA,
        directory: 'cli',
        version: '0.2.7',
        expectedPins: [{
          spec: '@emilia-protocol/verify@3.21.0',
          sha256: 'fb60903a33c49a7952646ddc3ca65c9c44706dbb41051feb7d5ef47e946774ed',
        }],
      },
      {
        metadata: ATTEST_METADATA,
        directory: 'packages/attest',
        version: '0.3.0',
        expectedPins: [
          {
            spec: '@emilia-protocol/issue@0.7.0',
            sha256: '0fbb002ae0d4a2ea6d39caed442ce7d81779c1ab016313654ffc40da06b117fb',
          },
          {
            spec: '@emilia-protocol/verify@3.21.0',
            sha256: 'fb60903a33c49a7952646ddc3ca65c9c44706dbb41051feb7d5ef47e946774ed',
          },
        ],
      },
    ];

    for (const {
      metadata,
      directory,
      version,
      expectedPins,
    } of downstream) {
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
      expect(pins).toEqual(expectedPins);
      for (const expectedPin of expectedPins) {
        expect(requested).not.toContain(expectedPin.spec);
        expect(verified).toContainEqual(expectedPin);
        expect(dependencies.map(({ spec }) => spec)).toContain(expectedPin.spec);
      }

      expect(() => assertInternalDependenciesPublished(
        metadata,
        () => true,
        pins,
        () => {
          throw new Error(`registry tarball unavailable for ${expectedPins[0].spec}`);
        },
      )).toThrow(/registry tarball unavailable/);
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
      withPins([{ spec: '@emilia-protocol/verify@3.21.0', sha256: 'not-a-sha256' }]),
    )).toThrow(/invalid sha256/);

    const validPin = {
      spec: '@emilia-protocol/verify@3.21.0',
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

  it('accepts npm 12 keyed pack reports without weakening the single-package boundary', () => {
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
    const filename = 'emilia-protocol-verify-3.15.0.tgz';

    expect(verifyRegistryDependencyTarball(
      dependency,
      pin,
      {
        fetcher: registryFetcher(bytes, {
          filename,
          report: { [dependency.name]: { filename } },
        }),
      },
    )).toMatchObject({ filename, sha256: pin.sha256 });

    expect(() => verifyRegistryDependencyTarball(
      dependency,
      pin,
      {
        fetcher: registryFetcher(bytes, {
          filename,
          report: { '@emilia-protocol/substitute': { filename } },
        }),
      },
    )).toThrow(/exactly one tarball/);
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
