#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from check-npm-package-dependencies.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const INTERNAL_SCOPE = '@emilia-protocol/';
const RELEASE_REGISTRY = 'release/release-packages.v1.json';
const REGISTRY_DEPENDENCY_FIELDS = [
    'dependencies',
    'optionalDependencies',
    'peerDependencies',
];
function normalizePackageDirectory(packageDirectory) {
    const normalized = packageDirectory.split(path.sep).join('/').replace(/^\.\//, '').replace(/\/+$/, '');
    if (!normalized
        || path.isAbsolute(packageDirectory)
        || normalized.split('/').some((segment) => segment === '' || segment === '.' || segment === '..')) {
        throw new Error(`invalid release package directory: ${packageDirectory}`);
    }
    return normalized;
}
function exactObjectKeys(value, expected) {
    return Boolean(value)
        && typeof value === 'object'
        && !Array.isArray(value)
        && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}
export function collectInternalRegistryDependencies(metadata) {
    const dependencies = [];
    for (const field of REGISTRY_DEPENDENCY_FIELDS) {
        const declared = metadata[field] ?? {};
        for (const [name, range] of Object.entries(declared)) {
            if (!name.startsWith(INTERNAL_SCOPE))
                continue;
            if (!/^@emilia-protocol\/[a-z0-9][a-z0-9._-]*$/u.test(name)) {
                throw new Error(`${metadata.name ?? 'package'} declares an invalid internal package name: ${name}`);
            }
            if (typeof range !== 'string' || !range.trim()) {
                throw new Error(`${metadata.name ?? 'package'} declares an invalid ${field} range for ${name}`);
            }
            dependencies.push({ field, name, range, spec: `${name}@${range}` });
        }
    }
    return dependencies.sort((a, b) => a.spec.localeCompare(b.spec));
}
export function collectRegistryDependencyTarballPins(metadata, packageDirectory, registry) {
    if (registry?.['@version'] !== 'EP-RELEASE-PACKAGE-REGISTRY-v1' || !Array.isArray(registry.packages)) {
        throw new Error('release package registry is malformed');
    }
    if (typeof metadata.name !== 'string' || typeof metadata.version !== 'string') {
        throw new Error('release package metadata must declare an exact name and version');
    }
    const normalizedDirectory = normalizePackageDirectory(packageDirectory);
    const entries = registry.packages.filter((entry) => entry?.ecosystem === 'npm' && entry.package === metadata.name);
    if (entries.length !== 1 || entries[0].path !== normalizedDirectory) {
        throw new Error(`${metadata.name}@${metadata.version} is not bound to ${normalizedDirectory} in the npm release registry`);
    }
    const rawPins = entries[0].registry_dependency_tarballs ?? [];
    if (!Array.isArray(rawPins)) {
        throw new Error(`${metadata.name}@${metadata.version} registry dependency tarball pins must be an array`);
    }
    const declaredBySpec = new Map(collectInternalRegistryDependencies(metadata).map((dependency) => [dependency.spec, dependency]));
    const seen = new Set();
    const pins = [];
    for (const rawPin of rawPins) {
        if (!exactObjectKeys(rawPin, ['spec', 'sha256'])) {
            throw new Error(`${metadata.name}@${metadata.version} has a malformed registry dependency tarball pin`);
        }
        const pin = rawPin;
        if (typeof pin.spec !== 'string' || !declaredBySpec.has(pin.spec)) {
            throw new Error(`${metadata.name}@${metadata.version} registry dependency tarball pin `
                + `${String(pin.spec)} does not match an exact declared dependency`);
        }
        const dependency = declaredBySpec.get(pin.spec);
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
    return pins.sort((a, b) => a.spec.localeCompare(b.spec));
}
export function resolveFromNpm(spec) {
    const result = spawnSync('npm', ['view', spec, 'version', '--json', '--min-release-age=0'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    if (result.status !== 0)
        return false;
    try {
        const resolved = JSON.parse(result.stdout);
        return typeof resolved === 'string'
            ? resolved.length > 0
            : Array.isArray(resolved) && resolved.length > 0
                && resolved.every((version) => typeof version === 'string');
    }
    catch {
        return false;
    }
}
export function fetchRegistryTarball(spec, destination) {
    const result = spawnSync('npm', ['pack', spec, '--min-release-age=0', '--json', '--pack-destination', destination], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return {
        status: result.status,
        stdout: result.stdout ?? '',
        stderr: result.stderr ?? '',
    };
}
export function installRegistryTarball(tarballPath, packageDirectory) {
    const result = spawnSync('npm', [
        'install',
        '--no-save',
        '--package-lock=false',
        '--ignore-scripts',
        '--no-audit',
        '--no-fund',
        '--workspaces=false',
        tarballPath,
    ], {
        cwd: packageDirectory,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
    });
    return {
        status: result.status,
        stdout: result.stdout ?? '',
        stderr: result.stderr ?? '',
    };
}
export function verifyRegistryDependencyTarball(dependency, pin, { fetcher = fetchRegistryTarball, installDirectory = null, installer = installRegistryTarball, } = {}) {
    if (pin.spec !== dependency.spec || !/^[0-9a-f]{64}$/u.test(pin.sha256)) {
        throw new Error(`invalid registry tarball pin for ${dependency.spec}`);
    }
    if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(dependency.range)) {
        throw new Error(`${dependency.spec} must use an exact version before its registry bytes can be verified`);
    }
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-registry-dependency-'));
    try {
        const fetched = fetcher(dependency.spec, scratch);
        if (fetched.status !== 0) {
            throw new Error(`npm registry tarball unavailable for ${dependency.spec}: ${fetched.stderr || fetched.stdout}`.trim());
        }
        let report;
        try {
            report = JSON.parse(fetched.stdout);
        }
        catch {
            throw new Error(`npm pack returned invalid JSON for ${dependency.spec}`);
        }
        if (!Array.isArray(report) || report.length !== 1) {
            throw new Error(`npm pack must return exactly one tarball for ${dependency.spec}`);
        }
        const filename = report[0]?.filename;
        if (typeof filename !== 'string'
            || filename !== path.basename(filename)
            || !/^[a-z0-9][a-z0-9._-]*\.tgz$/u.test(filename)) {
            throw new Error(`npm pack returned an unsafe filename for ${dependency.spec}`);
        }
        const archives = fs.readdirSync(scratch)
            .filter((entry) => entry.endsWith('.tgz'))
            .sort();
        if (archives.length !== 1 || archives[0] !== filename) {
            throw new Error(`npm pack left unexpected registry archives for ${dependency.spec}: ${archives.join(', ') || 'none'}`);
        }
        const tarballPath = path.join(scratch, filename);
        if (!fs.lstatSync(tarballPath).isFile()) {
            throw new Error(`npm pack did not produce a regular tarball for ${dependency.spec}`);
        }
        const bytes = fs.readFileSync(tarballPath);
        const actualSha256 = crypto.createHash('sha256').update(bytes).digest('hex');
        if (actualSha256 !== pin.sha256) {
            throw new Error(`${dependency.spec} registry tarball sha256 mismatch: expected ${pin.sha256}, got ${actualSha256}`);
        }
        let installed = false;
        if (installDirectory !== null) {
            const packageRoot = path.resolve(installDirectory);
            if (!fs.statSync(packageRoot).isDirectory()) {
                throw new Error(`dependency install directory is not a directory: ${packageRoot}`);
            }
            const installResult = installer(tarballPath, packageRoot);
            if (installResult.status !== 0) {
                throw new Error(`failed to materialize ${dependency.spec} from verified registry bytes: `
                    + `${installResult.stderr || installResult.stdout}`.trim());
            }
            const installedMetadataPath = path.join(packageRoot, 'node_modules', ...dependency.name.split('/'), 'package.json');
            if (!fs.existsSync(installedMetadataPath) || !fs.statSync(installedMetadataPath).isFile()) {
                throw new Error(`verified registry dependency was not installed: ${dependency.spec}`);
            }
            const installedMetadata = JSON.parse(fs.readFileSync(installedMetadataPath, 'utf8'));
            if (installedMetadata.name !== dependency.name || installedMetadata.version !== dependency.range) {
                throw new Error(`installed registry dependency identity mismatch for ${dependency.spec}: `
                    + `${installedMetadata.name ?? 'unknown'}@${installedMetadata.version ?? 'unknown'}`);
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
    }
    finally {
        fs.rmSync(scratch, { recursive: true, force: true });
    }
}
export function assertInternalDependenciesPublished(metadata, resolver = resolveFromNpm, pins = [], verifier = verifyRegistryDependencyTarball) {
    const dependencies = collectInternalRegistryDependencies(metadata);
    const dependenciesBySpec = new Map(dependencies.map((dependency) => [dependency.spec, dependency]));
    const pinsBySpec = new Map();
    for (const pin of pins) {
        if (pinsBySpec.has(pin.spec)) {
            throw new Error(`${metadata.name ?? 'package'} has a duplicate registry dependency tarball pin: ${pin.spec}`);
        }
        if (!dependenciesBySpec.has(pin.spec)) {
            throw new Error(`${metadata.name ?? 'package'} registry dependency tarball pin `
                + `${pin.spec} does not match an exact declared dependency`);
        }
        pinsBySpec.set(pin.spec, pin);
    }
    const unavailable = [];
    for (const dependency of dependencies) {
        const pin = pinsBySpec.get(dependency.spec);
        if (pin) {
            verifier(dependency, pin);
        }
        else if (!resolver(dependency.spec)) {
            unavailable.push(dependency);
        }
    }
    if (unavailable.length) {
        throw new Error(`${metadata.name ?? 'package'} has @emilia-protocol dependencies unavailable from npm: `
            + unavailable.map(({ spec, field }) => `${spec} (${field})`).join(', '));
    }
    return dependencies;
}
function main() {
    const packageDirectory = process.argv[2];
    const installPinned = process.argv[3] === '--install-pinned';
    if (!packageDirectory || process.argv.length !== (installPinned ? 4 : 3)) {
        throw new Error('usage: node scripts/check-npm-package-dependencies.mjs '
            + '<package-directory> [--install-pinned]');
    }
    const packagePath = path.resolve(process.cwd(), packageDirectory, 'package.json');
    const metadata = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    const registryPath = path.resolve(process.cwd(), RELEASE_REGISTRY);
    const registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
    const pins = collectRegistryDependencyTarballPins(metadata, packageDirectory, registry);
    const verified = new Map();
    const dependencies = assertInternalDependenciesPublished(metadata, resolveFromNpm, pins, (dependency, pin) => {
        const result = verifyRegistryDependencyTarball(dependency, pin, { installDirectory: installPinned ? path.dirname(packagePath) : null });
        verified.set(dependency.spec, result);
    });
    if (dependencies.length === 0) {
        console.log(`${metadata.name ?? packageDirectory}: no @emilia-protocol registry dependencies declared`);
        return;
    }
    for (const dependency of dependencies) {
        const result = verified.get(dependency.spec);
        if (result) {
            console.log(`verified ${dependency.spec} registry tarball sha256:${result.sha256} `
                + `(${dependency.field}${result.installed ? ', materialized for tests' : ''})`);
        }
        else {
            console.log(`resolved ${dependency.spec} from npm (${dependency.field})`);
        }
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
