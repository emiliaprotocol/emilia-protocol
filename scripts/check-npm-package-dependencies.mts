#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const INTERNAL_SCOPE: string = '@emilia-protocol/';
const RELEASE_REGISTRY: string = 'release/release-packages.v1.json';
const REGISTRY_DEPENDENCY_FIELDS: string[] = [
  'dependencies',
  'optionalDependencies',
  'peerDependencies',
];

interface PackageMetadata {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

interface ReleasePackageEntry {
  package?: string;
  ecosystem?: string;
  path?: string;
  registry_dependency_tarballs?: unknown;
}

interface ReleasePackageRegistry {
  '@version'?: string;
  packages?: ReleasePackageEntry[];
}

export interface RegistryDependency {
  field: string;
  name: string;
  range: string;
  spec: string;
}

export interface RegistryDependencyTarballPin {
  spec: string;
  sha256: string;
}

export interface RegistryCommandResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

export interface RegistryDependencyTarballVerification {
  spec: string;
  filename: string;
  sha256: string;
  bytes: number;
  installed: boolean;
}

export type RegistryResolver = (spec: string) => boolean;
export type RegistryTarballFetcher = (
  spec: string,
  destination: string,
) => RegistryCommandResult;
export type RegistryTarballInstaller = (
  tarballPath: string,
  packageDirectory: string,
) => RegistryCommandResult;
export type RegistryTarballVerifier = (
  dependency: RegistryDependency,
  pin: RegistryDependencyTarballPin,
) => unknown;

function normalizePackageDirectory(packageDirectory: string): string {
  const normalized: string = packageDirectory.split(path.sep).join('/').replace(/^\.\//, '').replace(/\/+$/, '');
  if (!normalized
    || path.isAbsolute(packageDirectory)
    || normalized.split('/').some((segment: string) => segment === '' || segment === '.' || segment === '..')) {
    throw new Error(`invalid release package directory: ${packageDirectory}`);
  }
  return normalized;
}

function exactObjectKeys(value: unknown, expected: string[]): boolean {
  return Boolean(value)
    && typeof value === 'object'
    && !Array.isArray(value)
    && JSON.stringify(Object.keys(value as object).sort()) === JSON.stringify([...expected].sort());
}

export function collectInternalRegistryDependencies(metadata: PackageMetadata): RegistryDependency[] {
  const dependencies: RegistryDependency[] = [];
  for (const field of REGISTRY_DEPENDENCY_FIELDS) {
    const declared: Record<string, string> = metadata[field as keyof PackageMetadata] as Record<string, string> ?? {};
    for (const [name, range] of Object.entries(declared)) {
      if (!name.startsWith(INTERNAL_SCOPE)) continue;
      if (!/^@emilia-protocol\/[a-z0-9][a-z0-9._-]*$/u.test(name)) {
        throw new Error(`${metadata.name ?? 'package'} declares an invalid internal package name: ${name}`);
      }
      if (typeof range !== 'string' || !range.trim()) {
        throw new Error(`${metadata.name ?? 'package'} declares an invalid ${field} range for ${name}`);
      }
      dependencies.push({ field, name, range, spec: `${name}@${range}` });
    }
  }
  return dependencies.sort((a: RegistryDependency, b: RegistryDependency) => a.spec.localeCompare(b.spec));
}

export function collectRegistryDependencyTarballPins(
  metadata: PackageMetadata,
  packageDirectory: string,
  registry: ReleasePackageRegistry,
): RegistryDependencyTarballPin[] {
  if (registry?.['@version'] !== 'EP-RELEASE-PACKAGE-REGISTRY-v1' || !Array.isArray(registry.packages)) {
    throw new Error('release package registry is malformed');
  }
  if (typeof metadata.name !== 'string' || typeof metadata.version !== 'string') {
    throw new Error('release package metadata must declare an exact name and version');
  }
  const normalizedDirectory: string = normalizePackageDirectory(packageDirectory);
  const entries: ReleasePackageEntry[] = registry.packages.filter(
    (entry: ReleasePackageEntry) => entry?.ecosystem === 'npm' && entry.package === metadata.name,
  );
  if (entries.length !== 1 || entries[0].path !== normalizedDirectory) {
    throw new Error(
      `${metadata.name}@${metadata.version} is not bound to ${normalizedDirectory} in the npm release registry`,
    );
  }

  const rawPins: unknown = entries[0].registry_dependency_tarballs ?? [];
  if (!Array.isArray(rawPins)) {
    throw new Error(`${metadata.name}@${metadata.version} registry dependency tarball pins must be an array`);
  }
  const declaredBySpec: Map<string, RegistryDependency> = new Map(
    collectInternalRegistryDependencies(metadata).map(
      (dependency: RegistryDependency) => [dependency.spec, dependency],
    ),
  );
  const seen: Set<string> = new Set();
  const pins: RegistryDependencyTarballPin[] = [];
  for (const rawPin of rawPins) {
    if (!exactObjectKeys(rawPin, ['spec', 'sha256'])) {
      throw new Error(`${metadata.name}@${metadata.version} has a malformed registry dependency tarball pin`);
    }
    const pin: RegistryDependencyTarballPin = rawPin as RegistryDependencyTarballPin;
    if (typeof pin.spec !== 'string' || !declaredBySpec.has(pin.spec)) {
      throw new Error(
        `${metadata.name}@${metadata.version} registry dependency tarball pin `
        + `${String(pin.spec)} does not match an exact declared dependency`,
      );
    }
    const dependency: RegistryDependency = declaredBySpec.get(pin.spec)!;
    if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(dependency.range)) {
      throw new Error(`${pin.spec} must use an exact version before its registry bytes can be pinned`);
    }
    if (typeof pin.sha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(pin.sha256)) {
      throw new Error(`${pin.spec} has an invalid sha256 registry tarball pin`);
    }
    if (seen.has(pin.spec)) {
      throw new Error(`${metadata.name}@${metadata.version} has a duplicate registry dependency tarball pin: ${pin.spec}`);
    }
    seen.add(pin.spec);
    pins.push({ spec: pin.spec, sha256: pin.sha256 });
  }
  return pins.sort(
    (a: RegistryDependencyTarballPin, b: RegistryDependencyTarballPin) => a.spec.localeCompare(b.spec),
  );
}

export function resolveFromNpm(spec: string): boolean {
  const result = spawnSync(
    'npm',
    ['view', spec, 'version', '--json', '--min-release-age=0'],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  if (result.status !== 0) return false;
  try {
    const resolved: unknown = JSON.parse(result.stdout);
    return typeof resolved === 'string'
      ? resolved.length > 0
      : Array.isArray(resolved) && resolved.length > 0
        && resolved.every((version: unknown) => typeof version === 'string');
  } catch {
    return false;
  }
}

export function fetchRegistryTarball(
  spec: string,
  destination: string,
): RegistryCommandResult {
  const result = spawnSync(
    'npm',
    ['pack', spec, '--min-release-age=0', '--json', '--pack-destination', destination],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

export function installRegistryTarball(
  tarballPath: string,
  packageDirectory: string,
): RegistryCommandResult {
  const result = spawnSync(
    'npm',
    [
      'install',
      '--no-save',
      '--package-lock=false',
      '--ignore-scripts',
      '--no-audit',
      '--no-fund',
      '--workspaces=false',
      tarballPath,
    ],
    {
      cwd: packageDirectory,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

export function verifyRegistryDependencyTarball(
  dependency: RegistryDependency,
  pin: RegistryDependencyTarballPin,
  {
    fetcher = fetchRegistryTarball,
    installDirectory = null,
    installer = installRegistryTarball,
  }: {
    fetcher?: RegistryTarballFetcher;
    installDirectory?: string | null;
    installer?: RegistryTarballInstaller;
  } = {},
): RegistryDependencyTarballVerification {
  if (pin.spec !== dependency.spec || !/^[0-9a-f]{64}$/u.test(pin.sha256)) {
    throw new Error(`invalid registry tarball pin for ${dependency.spec}`);
  }
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(dependency.range)) {
    throw new Error(`${dependency.spec} must use an exact version before its registry bytes can be verified`);
  }

  const scratch: string = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-registry-dependency-'));
  try {
    const fetched: RegistryCommandResult = fetcher(dependency.spec, scratch);
    if (fetched.status !== 0) {
      throw new Error(
        `npm registry tarball unavailable for ${dependency.spec}: ${fetched.stderr || fetched.stdout}`.trim(),
      );
    }
    let report: unknown;
    try {
      report = JSON.parse(fetched.stdout);
    } catch {
      throw new Error(`npm pack returned invalid JSON for ${dependency.spec}`);
    }
    const reportEntries: unknown[] = Array.isArray(report)
      ? report
      : report !== null
        && typeof report === 'object'
        && Object.keys(report).length === 1
        && Object.keys(report)[0] === dependency.name
        ? [(report as Record<string, unknown>)[dependency.name]]
        : [];
    if (reportEntries.length !== 1) {
      throw new Error(`npm pack must return exactly one tarball for ${dependency.spec}`);
    }
    const filename: unknown = (reportEntries[0] as any)?.filename;
    if (typeof filename !== 'string'
      || filename !== path.basename(filename)
      || !/^[a-z0-9][a-z0-9._-]*\.tgz$/u.test(filename)) {
      throw new Error(`npm pack returned an unsafe filename for ${dependency.spec}`);
    }
    const archives: string[] = fs.readdirSync(scratch)
      .filter((entry: string) => entry.endsWith('.tgz'))
      .sort();
    if (archives.length !== 1 || archives[0] !== filename) {
      throw new Error(
        `npm pack left unexpected registry archives for ${dependency.spec}: ${archives.join(', ') || 'none'}`,
      );
    }
    const tarballPath: string = path.join(scratch, filename);
    if (!fs.lstatSync(tarballPath).isFile()) {
      throw new Error(`npm pack did not produce a regular tarball for ${dependency.spec}`);
    }
    const bytes: Buffer = fs.readFileSync(tarballPath);
    const actualSha256: string = crypto.createHash('sha256').update(bytes).digest('hex');
    if (actualSha256 !== pin.sha256) {
      throw new Error(
        `${dependency.spec} registry tarball sha256 mismatch: expected ${pin.sha256}, got ${actualSha256}`,
      );
    }

    let installed: boolean = false;
    if (installDirectory !== null) {
      const packageRoot: string = path.resolve(installDirectory);
      if (!fs.statSync(packageRoot).isDirectory()) {
        throw new Error(`dependency install directory is not a directory: ${packageRoot}`);
      }
      const installResult: RegistryCommandResult = installer(tarballPath, packageRoot);
      if (installResult.status !== 0) {
        throw new Error(
          `failed to materialize ${dependency.spec} from verified registry bytes: `
          + `${installResult.stderr || installResult.stdout}`.trim(),
        );
      }
      const installedMetadataPath: string = path.join(
        packageRoot,
        'node_modules',
        ...dependency.name.split('/'),
        'package.json',
      );
      if (!fs.existsSync(installedMetadataPath) || !fs.statSync(installedMetadataPath).isFile()) {
        throw new Error(`verified registry dependency was not installed: ${dependency.spec}`);
      }
      const installedMetadata: PackageMetadata = JSON.parse(
        fs.readFileSync(installedMetadataPath, 'utf8'),
      );
      if (installedMetadata.name !== dependency.name || installedMetadata.version !== dependency.range) {
        throw new Error(
          `installed registry dependency identity mismatch for ${dependency.spec}: `
          + `${installedMetadata.name ?? 'unknown'}@${installedMetadata.version ?? 'unknown'}`,
        );
      }
      installed = true;
    }

    return {
      spec: dependency.spec,
      filename,
      sha256: actualSha256,
      bytes: bytes.length,
      installed,
    };
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

export function assertInternalDependenciesPublished(
  metadata: PackageMetadata,
  resolver: RegistryResolver = resolveFromNpm,
  pins: RegistryDependencyTarballPin[] = [],
  verifier: RegistryTarballVerifier = verifyRegistryDependencyTarball,
): RegistryDependency[] {
  const dependencies: RegistryDependency[] = collectInternalRegistryDependencies(metadata);
  const dependenciesBySpec: Map<string, RegistryDependency> = new Map(
    dependencies.map((dependency: RegistryDependency) => [dependency.spec, dependency]),
  );
  const pinsBySpec: Map<string, RegistryDependencyTarballPin> = new Map();
  for (const pin of pins) {
    if (pinsBySpec.has(pin.spec)) {
      throw new Error(`${metadata.name ?? 'package'} has a duplicate registry dependency tarball pin: ${pin.spec}`);
    }
    if (!dependenciesBySpec.has(pin.spec)) {
      throw new Error(
        `${metadata.name ?? 'package'} registry dependency tarball pin `
        + `${pin.spec} does not match an exact declared dependency`,
      );
    }
    pinsBySpec.set(pin.spec, pin);
  }

  const unavailable: RegistryDependency[] = [];
  for (const dependency of dependencies) {
    const pin: RegistryDependencyTarballPin | undefined = pinsBySpec.get(dependency.spec);
    if (pin) {
      verifier(dependency, pin);
    } else if (!resolver(dependency.spec)) {
      unavailable.push(dependency);
    }
  }
  if (unavailable.length) {
    throw new Error(
      `${metadata.name ?? 'package'} has @emilia-protocol dependencies unavailable from npm: `
      + unavailable.map(({ spec, field }: RegistryDependency) => `${spec} (${field})`).join(', '),
    );
  }
  return dependencies;
}

function main(): void {
  const args: string[] = process.argv.slice(2);
  const installPinned: boolean = args.includes('--install-pinned');
  const packageArguments: string[] = args.filter((value: string) => value !== '--install-pinned');
  const packageDirectory: string | undefined = packageArguments[0];
  if (!packageDirectory || packageArguments.length !== 1 || args.length !== (installPinned ? 2 : 1)) {
    throw new Error(
      'usage: node scripts/check-npm-package-dependencies.mjs '
      + '[--install-pinned] <package-directory>',
    );
  }
  const packagePath: string = path.resolve(process.cwd(), packageDirectory, 'package.json');
  const metadata: PackageMetadata = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
  const registryPath: string = path.resolve(process.cwd(), RELEASE_REGISTRY);
  const registry: ReleasePackageRegistry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
  const pins: RegistryDependencyTarballPin[] = collectRegistryDependencyTarballPins(
    metadata,
    packageDirectory,
    registry,
  );
  const verified: Map<string, RegistryDependencyTarballVerification> = new Map();
  const dependencies: RegistryDependency[] = assertInternalDependenciesPublished(
    metadata,
    resolveFromNpm,
    pins,
    (dependency: RegistryDependency, pin: RegistryDependencyTarballPin) => {
      const result: RegistryDependencyTarballVerification = verifyRegistryDependencyTarball(
        dependency,
        pin,
        { installDirectory: installPinned ? path.dirname(packagePath) : null },
      );
      verified.set(dependency.spec, result);
    },
  );
  if (dependencies.length === 0) {
    console.log(`${metadata.name ?? packageDirectory}: no @emilia-protocol registry dependencies declared`);
    return;
  }
  for (const dependency of dependencies) {
    const result: RegistryDependencyTarballVerification | undefined = verified.get(dependency.spec);
    if (result) {
      console.log(
        `verified ${dependency.spec} registry tarball sha256:${result.sha256} `
        + `(${dependency.field}${result.installed ? ', materialized for tests' : ''})`,
      );
    } else {
      console.log(`resolved ${dependency.spec} from npm (${dependency.field})`);
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
