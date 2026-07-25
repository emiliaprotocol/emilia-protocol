#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const INTERNAL_SCOPE: string = '@emilia-protocol/';
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

export interface RegistryDependency {
  field: string;
  name: string;
  range: string;
  spec: string;
}

export type RegistryResolver = (spec: string) => boolean;

export function collectInternalRegistryDependencies(metadata: PackageMetadata): RegistryDependency[] {
  const dependencies: RegistryDependency[] = [];
  for (const field of REGISTRY_DEPENDENCY_FIELDS) {
    const declared: Record<string, string> = metadata[field as keyof PackageMetadata] as Record<string, string> ?? {};
    for (const [name, range] of Object.entries(declared)) {
      if (!name.startsWith(INTERNAL_SCOPE)) continue;
      if (typeof range !== 'string' || !range.trim()) {
        throw new Error(`${metadata.name ?? 'package'} declares an invalid ${field} range for ${name}`);
      }
      dependencies.push({ field, name, range, spec: `${name}@${range}` });
    }
  }
  return dependencies.sort((a: RegistryDependency, b: RegistryDependency) => a.spec.localeCompare(b.spec));
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
      : Array.isArray(resolved) && resolved.length > 0 && resolved.every((version: unknown) => typeof version === 'string');
  } catch {
    return false;
  }
}

export function assertInternalDependenciesPublished(
  metadata: PackageMetadata,
  resolver: RegistryResolver = resolveFromNpm,
): RegistryDependency[] {
  const dependencies: RegistryDependency[] = collectInternalRegistryDependencies(metadata);
  const unavailable: RegistryDependency[] = dependencies.filter(({ spec }: RegistryDependency) => !resolver(spec));
  if (unavailable.length) {
    throw new Error(
      `${metadata.name ?? 'package'} has @emilia-protocol dependencies unavailable from npm: `
      + unavailable.map(({ spec, field }: RegistryDependency) => `${spec} (${field})`).join(', '),
    );
  }
  return dependencies;
}

function main(): void {
  const packageDirectory: string | undefined = process.argv[2];
  if (!packageDirectory || process.argv.length !== 3) {
    throw new Error('usage: node scripts/check-npm-package-dependencies.mjs <package-directory>');
  }
  const packagePath: string = path.resolve(process.cwd(), packageDirectory, 'package.json');
  const metadata: PackageMetadata = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
  const dependencies: RegistryDependency[] = assertInternalDependenciesPublished(metadata);
  if (dependencies.length === 0) {
    console.log(`${metadata.name ?? packageDirectory}: no @emilia-protocol registry dependencies declared`);
    return;
  }
  for (const dependency of dependencies) {
    console.log(`resolved ${dependency.spec} from npm (${dependency.field})`);
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
