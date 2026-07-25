#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from check-npm-package-dependencies.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const INTERNAL_SCOPE = '@emilia-protocol/';
const REGISTRY_DEPENDENCY_FIELDS = [
    'dependencies',
    'optionalDependencies',
    'peerDependencies',
];
export function collectInternalRegistryDependencies(metadata) {
    const dependencies = [];
    for (const field of REGISTRY_DEPENDENCY_FIELDS) {
        const declared = metadata[field] ?? {};
        for (const [name, range] of Object.entries(declared)) {
            if (!name.startsWith(INTERNAL_SCOPE))
                continue;
            if (typeof range !== 'string' || !range.trim()) {
                throw new Error(`${metadata.name ?? 'package'} declares an invalid ${field} range for ${name}`);
            }
            dependencies.push({ field, name, range, spec: `${name}@${range}` });
        }
    }
    return dependencies.sort((a, b) => a.spec.localeCompare(b.spec));
}
export function resolveFromNpm(spec) {
    const result = spawnSync('npm', ['view', spec, 'version', '--json', '--min-release-age=0'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    if (result.status !== 0)
        return false;
    try {
        const resolved = JSON.parse(result.stdout);
        return typeof resolved === 'string'
            ? resolved.length > 0
            : Array.isArray(resolved) && resolved.length > 0 && resolved.every((version) => typeof version === 'string');
    }
    catch {
        return false;
    }
}
export function assertInternalDependenciesPublished(metadata, resolver = resolveFromNpm) {
    const dependencies = collectInternalRegistryDependencies(metadata);
    const unavailable = dependencies.filter(({ spec }) => !resolver(spec));
    if (unavailable.length) {
        throw new Error(`${metadata.name ?? 'package'} has @emilia-protocol dependencies unavailable from npm: `
            + unavailable.map(({ spec, field }) => `${spec} (${field})`).join(', '));
    }
    return dependencies;
}
function main() {
    const packageDirectory = process.argv[2];
    if (!packageDirectory || process.argv.length !== 3) {
        throw new Error('usage: node scripts/check-npm-package-dependencies.mjs <package-directory>');
    }
    const packagePath = path.resolve(process.cwd(), packageDirectory, 'package.json');
    const metadata = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    const dependencies = assertInternalDependenciesPublished(metadata);
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
    }
    catch (error) {
        console.error(error instanceof Error ? error.message : error);
        process.exitCode = 1;
    }
}
