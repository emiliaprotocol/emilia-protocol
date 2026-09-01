#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from verify-reproducible-package.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { gzip, ungzip } from 'pako';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const git = process.platform === 'win32' ? 'git.exe' : 'git';
export function npmArtifactFilename(packageName, version) {
    if (typeof packageName !== 'string'
        || typeof version !== 'string'
        || !/^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/u.test(packageName)
        || !/^[0-9A-Za-z][0-9A-Za-z.+-]*$/u.test(version)) {
        throw new Error('package identity is malformed');
    }
    return `${packageName.replace(/^@/u, '').replace(/\//gu, '-')}-${version}.tgz`;
}
export function assertArtifactBytesMatch(expected, observed) {
    const left = Buffer.isBuffer(expected) ? expected : Buffer.from(expected ?? []);
    const right = Buffer.isBuffer(observed) ? observed : Buffer.from(observed ?? []);
    if (!left.equals(right)) {
        const expectedHash = crypto.createHash('sha256').update(left).digest('hex');
        const observedHash = crypto.createHash('sha256').update(right).digest('hex');
        throw new Error(`published artifact bytes differ: ${expectedHash} != ${observedHash}`);
    }
    return crypto.createHash('sha256').update(left).digest('hex');
}
/**
 * npm delegates gzip compression to the host Node/zlib toolchain. The tar
 * payload is stable, but npm 10/Node 20 and npm 11/Node 25 can emit different
 * DEFLATE streams for the same payload. Recompress with a pinned pure-JS
 * implementation so the bytes we attest and publish are toolchain-independent.
 *
 * @param {Buffer|Uint8Array} archive
 */
export function canonicalizeNpmTarball(archive) {
    const tarBytes = ungzip(archive);
    const gzipBytes = Buffer.from(gzip(tarBytes, {
        level: 9,
    }));
    // Pako 3 no longer exposes the v1 `header` option.  Normalize the two
    // gzip header fields that are allowed to vary by runtime: MTIME and OS.
    gzipBytes.writeUInt32LE(0, 4);
    gzipBytes[9] = 0xff;
    return gzipBytes;
}
function tarString(block, offset, length) {
    const field = block.subarray(offset, offset + length);
    const terminator = field.indexOf(0);
    return field.subarray(0, terminator >= 0 ? terminator : field.length).toString('utf8');
}
function tarSize(block) {
    const value = tarString(block, 124, 12).trim();
    if (!/^[0-7]+$/u.test(value))
        throw new Error('npm tarball contains an unsupported entry size');
    const size = Number.parseInt(value, 8);
    if (!Number.isSafeInteger(size) || size < 0)
        throw new Error('npm tarball contains an unsafe entry size');
    return size;
}
function tarMode(block) {
    const value = tarString(block, 100, 8).trim();
    if (!/^[0-7]+$/u.test(value))
        throw new Error('npm tarball contains an unsupported entry mode');
    const mode = Number.parseInt(value, 8);
    if (!Number.isSafeInteger(mode) || mode < 0)
        throw new Error('npm tarball contains an unsafe entry mode');
    return mode & 0o777;
}
export function inspectPackedPackageMembers(archive) {
    const tarBytes = Buffer.from(ungzip(archive));
    const members = [];
    const seen = new Set();
    let offset = 0;
    let reachedEnd = false;
    while (offset + 512 <= tarBytes.length) {
        const header = tarBytes.subarray(offset, offset + 512);
        if (header.every((value) => value === 0)) {
            reachedEnd = true;
            break;
        }
        const name = tarString(header, 0, 100);
        const prefix = tarString(header, 345, 155);
        const entryPath = prefix ? `${prefix}/${name}` : name;
        const segments = entryPath.split('/');
        const size = tarSize(header);
        const dataOffset = offset + 512;
        const nextOffset = dataOffset + Math.ceil(size / 512) * 512;
        if (!entryPath.startsWith('package/')
            || entryPath.startsWith('/')
            || entryPath.includes('\\')
            || segments.some((segment) => !segment || segment === '.' || segment === '..')
            || nextOffset > tarBytes.length) {
            throw new Error(`npm tarball contains an unsafe entry path: ${entryPath}`);
        }
        if (seen.has(entryPath))
            throw new Error(`npm tarball contains a duplicate entry: ${entryPath}`);
        seen.add(entryPath);
        const type = header[156];
        if (type !== 0 && type !== 0x30) {
            throw new Error(`npm tarball links and non-regular entries are forbidden: ${entryPath}`);
        }
        const bytes = tarBytes.subarray(dataOffset, dataOffset + size);
        members.push({
            path: entryPath.slice('package/'.length),
            mode: tarMode(header),
            bytes: size,
            sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
        });
        offset = nextOffset;
    }
    if (!reachedEnd || tarBytes.subarray(offset).some((value) => value !== 0)) {
        throw new Error('npm tarball has a missing or non-zero trailer');
    }
    return members.sort((left, right) => left.path.localeCompare(right.path));
}
export function validatePackedPackageIdentity(archive, expectedName, expectedVersion, expectedPackageJsonBytes) {
    const tarBytes = Buffer.from(ungzip(archive));
    const identities = [];
    const packageJsonEntries = [];
    for (let offset = 0; offset + 512 <= tarBytes.length;) {
        const header = tarBytes.subarray(offset, offset + 512);
        if (header.every((value) => value === 0))
            break;
        const name = tarString(header, 0, 100);
        const prefix = tarString(header, 345, 155);
        const entryPath = prefix ? `${prefix}/${name}` : name;
        const size = tarSize(header);
        const dataOffset = offset + 512;
        const nextOffset = dataOffset + Math.ceil(size / 512) * 512;
        if (nextOffset > tarBytes.length)
            throw new Error('npm tarball entry extends beyond the archive');
        if (entryPath === 'package/package.json') {
            const type = header[156];
            if (type !== 0 && type !== 0x30) {
                throw new Error('npm tarball package/package.json is not a regular file');
            }
            const packageJsonBytes = tarBytes.subarray(dataOffset, dataOffset + size);
            packageJsonEntries.push(packageJsonBytes);
            try {
                identities.push(JSON.parse(packageJsonBytes.toString('utf8')));
            }
            catch {
                throw new Error('npm tarball package/package.json is not valid JSON');
            }
        }
        offset = nextOffset;
    }
    if (identities.length !== 1) {
        throw new Error(`npm tarball must contain exactly one package/package.json; found ${identities.length}`);
    }
    const [identity] = identities;
    if (identity?.name !== expectedName || identity?.version !== expectedVersion) {
        throw new Error(`npm tarball package identity differs from approved ${expectedName}@${expectedVersion}`);
    }
    const expectedBytes = Buffer.from(expectedPackageJsonBytes);
    const [actualBytes] = packageJsonEntries;
    if (!actualBytes.equals(expectedBytes)) {
        const expectedSha256 = crypto.createHash('sha256').update(expectedBytes).digest('hex');
        const actualSha256 = crypto.createHash('sha256').update(actualBytes).digest('hex');
        throw new Error(`npm tarball package/package.json bytes differ from source package.json: `
            + `${actualSha256} != ${expectedSha256}`);
    }
    return {
        name: identity.name,
        version: identity.version,
        packageJsonSha256: crypto.createHash('sha256').update(actualBytes).digest('hex'),
    };
}
const SPAWN_DIAGNOSTIC_LIMIT = 8_192;
function boundedSpawnText(value) {
    const raw = Buffer.isBuffer(value)
        ? value.toString('utf8')
        : typeof value === 'string'
            ? value
            : value === undefined || value === null
                ? ''
                : String(value);
    const redacted = raw
        .replace(/(https?:\/\/)[^\s/:@]+:[^\s/@]+@/giu, '$1[redacted]@')
        .replace(/([?&](?:access_token|auth|credential|key|password|secret|signature|sig|token|x-amz-(?:credential|security-token|signature)|x-goog-(?:credential|signature))=)[^&\s]+/giu, '$1[redacted]')
        .replace(/\bBearer\s+[a-z0-9._~+/-]+=*/giu, 'Bearer [redacted]')
        .replace(/\b(?:npm|gh[oprsu])_[a-z0-9]{8,}\b/giu, '[redacted-token]')
        .replace(/((?:authorization|_authToken)\s*[:=]\s*)[^\r\n]*/giu, '$1[redacted]')
        .replace(/((?:GH_TOKEN|GITHUB_TOKEN|NODE_AUTH_TOKEN|NPM_TOKEN)\s*=\s*)\S+/giu, '$1[redacted]');
    if (!redacted)
        return '(empty)';
    if (redacted.length <= SPAWN_DIAGNOSTIC_LIMIT)
        return redacted;
    return `[truncated to last ${SPAWN_DIAGNOSTIC_LIMIT} characters]\n${redacted.slice(-SPAWN_DIAGNOSTIC_LIMIT)}`;
}
export function formatSpawnFailure(label, result) {
    const spawnError = result?.error
        ? `${result.error.name || 'Error'}${result.error.code ? ` [${result.error.code}]` : ''}: ${result.error.message || String(result.error)}`
        : '(none)';
    return [
        `${label} failed`,
        `status: ${result?.status ?? 'null'}`,
        `signal: ${result?.signal ?? 'null'}`,
        `spawn error: ${boundedSpawnText(spawnError)}`,
        `stdout: ${boundedSpawnText(result?.stdout)}`,
        `stderr: ${boundedSpawnText(result?.stderr)}`,
    ].join('\n');
}
/**
 * @param {string} [packagePath]
 * @param {{ outDir?: string | null, repositoryRoot?: string | null, reviewedCommit?: string | null }} [options]
 */
export function verifyReproduciblePackage(packagePath = 'packages/verify', { outDir = null, repositoryRoot = null, reviewedCommit = null, } = {}) {
    const root = path.resolve(repositoryRoot || ROOT);
    const packageDir = path.resolve(root, packagePath);
    const packageRelative = path.relative(root, packageDir).split(path.sep).join('/');
    if (path.isAbsolute(packageRelative)
        || packageRelative === '..'
        || packageRelative.startsWith('../')) {
        throw new Error('package path must be a repository-relative directory');
    }
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-repro-pack-'));
    try {
        function run(command, args, label, options = {}) {
            const result = spawnSync(command, args, {
                cwd: options.cwd || root,
                encoding: options.encoding ?? 'utf8',
                env: options.env,
                maxBuffer: 128 * 1024 * 1024,
            });
            if (result.status !== 0) {
                throw new Error(`${label} failed:\n${result.stderr || result.stdout}`);
            }
            return result;
        }
        const objectFormat = String(run(git, ['rev-parse', '--show-object-format'], 'git object-format lookup').stdout).trim();
        const objectLength = objectFormat === 'sha1' ? 40 : objectFormat === 'sha256' ? 64 : 0;
        if (!objectLength)
            throw new Error(`unsupported git object format: ${objectFormat}`);
        if (reviewedCommit !== null
            && !new RegExp(`^[0-9a-f]{${objectLength}}$`, 'u').test(reviewedCommit)) {
            throw new Error('reviewed commit must be an exact full-length Git object id, not a ref');
        }
        const commit = String(run(git, ['rev-parse', '--verify', `${reviewedCommit || 'HEAD'}^{commit}`], 'reviewed commit resolution').stdout).trim();
        if (!new RegExp(`^[0-9a-f]{${objectLength}}$`, 'u').test(commit)
            || (reviewedCommit !== null && commit !== reviewedCommit)) {
            throw new Error('reviewed commit did not resolve to the exact requested Git object');
        }
        for (const args of [
            ['diff', '--quiet', commit, '--'],
            ['diff', '--cached', '--quiet', commit, '--'],
        ]) {
            const comparison = spawnSync(git, args, { cwd: root, encoding: 'utf8' });
            if (comparison.status !== 0) {
                throw new Error('working checkout differs from the reviewed commit');
            }
        }
        const treeOid = String(run(git, ['rev-parse', '--verify', `${commit}^{tree}`], 'reviewed tree resolution').stdout).trim();
        const packageTreeOid = packageRelative
            ? String(run(git, ['rev-parse', '--verify', `${commit}:${packageRelative}`], 'reviewed package-tree resolution').stdout).trim()
            : treeOid;
        const sourceTree = run(git, ['ls-tree', '-rz', '--full-tree', commit], 'reviewed source-tree inventory', { encoding: 'buffer' }).stdout;
        const trackedPaths = new Set();
        for (const rawRecord of sourceTree.toString('utf8').split('\0').filter(Boolean)) {
            const match = rawRecord.match(/^(\d{6}) ([a-z]+) ([0-9a-f]+)\t(.+)$/u);
            if (!match)
                throw new Error(`malformed reviewed Git tree record: ${rawRecord}`);
            const [, mode, type, , relative] = match;
            const segments = relative.split('/');
            if (relative.startsWith('/')
                || relative.includes('\\')
                || segments.some((segment) => !segment || segment === '.' || segment === '..')) {
                throw new Error(`reviewed Git tree contains an unsafe path: ${relative}`);
            }
            if (type !== 'blob' || (mode !== '100644' && mode !== '100755')) {
                throw new Error(`reviewed Git tree contains a symlink, submodule, or unsupported mode: ${relative} (${mode} ${type})`);
            }
            trackedPaths.add(relative);
        }
        const packageJsonRelative = packageRelative ? `${packageRelative}/package.json` : 'package.json';
        if (!trackedPaths.has(packageJsonRelative)) {
            throw new Error(`reviewed package.json is not tracked at ${packageJsonRelative}`);
        }
        for (const relative of [...trackedPaths].filter((entry) => path.posix.basename(entry) === '.gitattributes')) {
            const attributes = run(git, ['show', `${commit}:${relative}`], `reviewed attributes lookup for ${relative}`, { encoding: 'buffer' }).stdout;
            if (/\bexport-(?:ignore|subst)\b/u.test(attributes.toString('utf8'))) {
                throw new Error(`reviewed Git attributes may not transform or omit source archive bytes: ${relative}`);
            }
        }
        const snapshotRoot = path.join(scratch, 'reviewed-source');
        const sourceArchive = path.join(scratch, 'reviewed-source.tar');
        fs.mkdirSync(snapshotRoot, { recursive: true, mode: 0o700 });
        run(git, ['archive', '--format=tar', `--output=${sourceArchive}`, commit], 'reviewed source archive');
        const sourceArchiveBytes = fs.readFileSync(sourceArchive);
        run('tar', ['-xf', sourceArchive, '-C', snapshotRoot], 'reviewed source extraction');
        const materializedPaths = new Set();
        const inspectMaterialized = (directory) => {
            for (const name of fs.readdirSync(directory).sort()) {
                const absolute = path.join(directory, name);
                const relative = path.relative(snapshotRoot, absolute).split(path.sep).join('/');
                const stat = fs.lstatSync(absolute);
                if (stat.isSymbolicLink())
                    throw new Error(`reviewed source extraction produced a symlink: ${relative}`);
                if (stat.isDirectory())
                    inspectMaterialized(absolute);
                else if (stat.isFile())
                    materializedPaths.add(relative);
                else
                    throw new Error(`reviewed source extraction produced an unsupported entry: ${relative}`);
            }
        };
        inspectMaterialized(snapshotRoot);
        if (trackedPaths.size !== materializedPaths.size
            || [...trackedPaths].some((relative) => !materializedPaths.has(relative))) {
            throw new Error('reviewed source extraction does not exactly match the Git tree');
        }
        const packageJsonPath = path.join(snapshotRoot, packageJsonRelative);
        const packageJsonBytes = fs.readFileSync(packageJsonPath);
        const metadata = JSON.parse(packageJsonBytes.toString('utf8'));
        const expectedFilename = npmArtifactFilename(metadata.name, metadata.version);
        const packageJsonBlobOid = String(run(git, ['rev-parse', '--verify', `${commit}:${packageJsonRelative}`], 'reviewed package.json blob resolution').stdout).trim();
        const setTreeWritable = (directory, writable) => {
            for (const name of fs.readdirSync(directory)) {
                const absolute = path.join(directory, name);
                const stat = fs.lstatSync(absolute);
                if (stat.isSymbolicLink())
                    throw new Error(`isolated source contains a symlink: ${absolute}`);
                if (stat.isDirectory()) {
                    if (writable)
                        fs.chmodSync(absolute, 0o755);
                    setTreeWritable(absolute, writable);
                    if (!writable)
                        fs.chmodSync(absolute, 0o555);
                }
                else if (stat.isFile()) {
                    const executable = (stat.mode & 0o111) !== 0;
                    fs.chmodSync(absolute, writable ? (executable ? 0o755 : 0o644) : (executable ? 0o555 : 0o444));
                }
                else {
                    throw new Error(`isolated source contains an unsupported entry: ${absolute}`);
                }
            }
            fs.chmodSync(directory, writable ? 0o755 : 0o555);
        };
        function isolatedEnv(label, ignoreScripts, workingDirectory) {
            const safeLabel = label.replace(/[^a-z0-9._-]+/giu, '-');
            const environmentRoot = path.join(scratch, `${safeLabel}-environment`);
            const home = path.join(environmentRoot, 'home');
            const cache = path.join(environmentRoot, 'npm-cache');
            const temporary = path.join(environmentRoot, 'tmp');
            const prefix = path.join(environmentRoot, 'npm-prefix');
            const userConfig = path.join(environmentRoot, 'npmrc');
            for (const directory of [home, cache, temporary, prefix]) {
                fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
            }
            fs.writeFileSync(userConfig, '', { mode: 0o600 });
            const controlledPath = [
                path.dirname(process.execPath),
                ...(process.platform === 'win32'
                    ? [
                        path.join(process.env.SYSTEMROOT || 'C:\\Windows', 'System32'),
                        process.env.SYSTEMROOT || 'C:\\Windows',
                    ]
                    : ['/usr/bin', '/bin']),
            ].join(path.delimiter);
            const environment = {
                HOME: home,
                USERPROFILE: home,
                XDG_CACHE_HOME: cache,
                PATH: controlledPath,
                PWD: workingDirectory,
                INIT_CWD: workingDirectory,
                RUNNER_TEMP: temporary,
                npm_config_cache: cache,
                npm_config_prefix: prefix,
                npm_config_userconfig: userConfig,
                npm_config_ignore_scripts: ignoreScripts ? 'true' : 'false',
                npm_config_audit: 'false',
                npm_config_fund: 'false',
                npm_config_update_notifier: 'false',
                TMPDIR: temporary,
                TMP: temporary,
                TEMP: temporary,
            };
            for (const key of ['CI', 'LANG', 'LC_ALL', 'SOURCE_DATE_EPOCH', 'TZ']) {
                if (process.env[key] !== undefined)
                    environment[key] = process.env[key];
            }
            if (process.platform === 'win32') {
                for (const key of ['COMSPEC', 'PATHEXT', 'SYSTEMROOT', 'WINDIR']) {
                    if (process.env[key] !== undefined)
                        environment[key] = process.env[key];
                }
            }
            return environment;
        }
        function runPack(args, label, workingDirectory) {
            const run = spawnSync(npm, ['pack', ...args, '--json'], {
                cwd: workingDirectory,
                encoding: 'utf8',
                env: isolatedEnv(`${label}-pack`, true, workingDirectory),
            });
            if (run.status !== 0) {
                throw new Error(`npm pack ${label} failed:\n${run.stderr || run.stdout}`);
            }
            let report;
            try {
                report = JSON.parse(run.stdout);
            }
            catch {
                throw new Error(`npm pack ${label} did not return JSON: ${run.stdout}`);
            }
            const entries = Array.isArray(report)
                ? report
                : report && typeof report === 'object'
                    ? Object.values(report)
                    : [];
            if (entries.length !== 1 || typeof entries[0]?.filename !== 'string') {
                throw new Error(`npm pack ${label} returned an unexpected report`);
            }
            const [entry] = entries;
            if (entry.name !== metadata.name
                || entry.version !== metadata.version
                || entry.filename !== expectedFilename) {
                throw new Error(`npm pack ${label} package identity differs from approved ${metadata.name}@${metadata.version} (${expectedFilename})`);
            }
            return entry;
        }
        function cloneDependencyTree(sourceRoot, targetRoot) {
            const activeDirectories = new Set();
            const cloneEntry = (source, target) => {
                const sourceLstat = fs.lstatSync(source);
                const resolvedSource = sourceLstat.isSymbolicLink() ? fs.realpathSync(source) : source;
                if (sourceLstat.isSymbolicLink()) {
                    const realSourceRoot = fs.realpathSync(sourceRoot);
                    const isInternalLink = resolvedSource === realSourceRoot
                        || resolvedSource.startsWith(`${realSourceRoot}${path.sep}`);
                    if (isInternalLink) {
                        const clonedTarget = path.join(targetRoot, path.relative(realSourceRoot, resolvedSource));
                        const relativeTarget = path.relative(path.dirname(target), clonedTarget) || '.';
                        fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o755 });
                        fs.symlinkSync(relativeTarget, target, fs.statSync(resolvedSource).isDirectory()
                            ? (process.platform === 'win32' ? 'junction' : 'dir')
                            : 'file');
                        return;
                    }
                }
                const sourceStat = sourceLstat.isSymbolicLink() ? fs.statSync(source) : sourceLstat;
                if (sourceStat.isDirectory()) {
                    const realDirectory = fs.realpathSync(resolvedSource);
                    if (activeDirectories.has(realDirectory)) {
                        throw new Error(`dependency tree contains a symlink cycle: ${source}`);
                    }
                    activeDirectories.add(realDirectory);
                    fs.mkdirSync(target, { recursive: true, mode: sourceStat.mode & 0o777 });
                    for (const entry of fs.readdirSync(resolvedSource)) {
                        cloneEntry(path.join(resolvedSource, entry), path.join(target, entry));
                    }
                    fs.chmodSync(target, sourceStat.mode & 0o777);
                    activeDirectories.delete(realDirectory);
                    return;
                }
                if (!sourceStat.isFile()) {
                    throw new Error(`dependency tree entry is not a regular file or directory: ${source}`);
                }
                fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o755 });
                fs.copyFileSync(resolvedSource, target, fs.constants.COPYFILE_FICLONE);
                fs.chmodSync(target, sourceStat.mode & 0o777);
            };
            cloneEntry(sourceRoot, targetRoot);
        }
        const dependencyTemplate = path.join(scratch, 'dependency-template');
        fs.cpSync(snapshotRoot, dependencyTemplate, { recursive: true });
        setTreeWritable(snapshotRoot, false);
        const templatePackageDir = path.join(dependencyTemplate, packageRelative);
        for (const installDirectory of [
            fs.existsSync(path.join(dependencyTemplate, 'package-lock.json')) ? dependencyTemplate : null,
            fs.existsSync(path.join(templatePackageDir, 'package-lock.json')) ? templatePackageDir : null,
        ].filter((value) => value !== null)) {
            const install = spawnSync(npm, ['ci', '--ignore-scripts', '--min-release-age=0'], {
                cwd: installDirectory,
                encoding: 'utf8',
                env: isolatedEnv(`dependencies-${path.relative(dependencyTemplate, installDirectory) || 'root'}`, true, installDirectory),
                killSignal: 'SIGTERM',
                maxBuffer: 128 * 1024 * 1024,
                stdio: ['ignore', 'pipe', 'pipe'],
                timeout: 600_000,
            });
            if (install.status !== 0) {
                throw new Error(formatSpawnFailure('locked dependency installation', install));
            }
        }
        function isolateBuildDependencies(buildRoot, buildPackageDir) {
            const repositoryNodeModules = path.join(dependencyTemplate, 'node_modules');
            const packageNodeModules = path.join(templatePackageDir, 'node_modules');
            if (fs.existsSync(repositoryNodeModules)) {
                cloneDependencyTree(repositoryNodeModules, path.join(buildRoot, 'node_modules'));
            }
            if (buildPackageDir !== buildRoot && fs.existsSync(packageNodeModules)) {
                cloneDependencyTree(packageNodeModules, path.join(buildPackageDir, 'node_modules'));
            }
        }
        function buildPackage(label) {
            const buildRoot = path.join(scratch, `${label}-build`);
            fs.cpSync(snapshotRoot, buildRoot, { recursive: true });
            setTreeWritable(buildRoot, true);
            const buildPackageDir = path.join(buildRoot, packageRelative);
            if (typeof metadata.scripts?.build === 'string') {
                fs.rmSync(path.join(buildPackageDir, 'dist'), { recursive: true, force: true });
                isolateBuildDependencies(buildRoot, buildPackageDir);
                const run = spawnSync(npm, ['run', '--ignore-scripts', 'build'], {
                    cwd: buildPackageDir,
                    encoding: 'utf8',
                    env: isolatedEnv(`${label}-build`, false, buildPackageDir),
                });
                if (run.status !== 0) {
                    throw new Error(`package build ${label} failed:\nstdout:\n${run.stdout}\nstderr:\n${run.stderr}`);
                }
                const builtPackageJson = fs.readFileSync(path.join(buildPackageDir, 'package.json'));
                if (!builtPackageJson.equals(packageJsonBytes)) {
                    throw new Error(`package build ${label} mutated package.json`);
                }
            }
            const rejectPackageSymlinks = (directory) => {
                for (const name of fs.readdirSync(directory)) {
                    if (name === 'node_modules')
                        continue;
                    const absolute = path.join(directory, name);
                    const stat = fs.lstatSync(absolute);
                    if (stat.isSymbolicLink()) {
                        throw new Error(`package build ${label} produced a forbidden symlink: ${path.relative(buildPackageDir, absolute)}`);
                    }
                    if (stat.isDirectory())
                        rejectPackageSymlinks(absolute);
                    else if (!stat.isFile())
                        throw new Error(`package build ${label} produced an unsupported entry: ${absolute}`);
                }
            };
            rejectPackageSymlinks(buildPackageDir);
            for (const relative of trackedPaths) {
                if (packageRelative
                    && relative !== packageRelative
                    && !relative.startsWith(`${packageRelative}/`))
                    continue;
                const reviewedPath = path.join(snapshotRoot, relative);
                const builtPath = path.join(buildRoot, relative);
                const builtStat = fs.lstatSync(builtPath);
                if (!builtStat.isFile() || builtStat.isSymbolicLink()
                    || !fs.readFileSync(reviewedPath).equals(fs.readFileSync(builtPath))) {
                    throw new Error(`package build ${label} mutated reviewed source bytes: ${relative}`);
                }
            }
            return buildPackageDir;
        }
        function stageCanonicalPackage(builtPackageDir, label) {
            const inventory = runPack([builtPackageDir, '--dry-run'], `${label} inventory`, builtPackageDir);
            const stage = path.join(scratch, `${label}-canonical-input`);
            const binValues = typeof metadata.bin === 'string'
                ? [metadata.bin]
                : metadata.bin && typeof metadata.bin === 'object'
                    ? Object.values(metadata.bin)
                    : [];
            const executablePaths = new Set(binValues.map((value) => String(value).replace(/^\.\//, '')));
            fs.mkdirSync(stage, { recursive: true, mode: 0o755 });
            for (const entry of inventory.files || []) {
                if (!entry || typeof entry.path !== 'string' || path.isAbsolute(entry.path)) {
                    throw new Error('npm pack inventory contains a malformed path');
                }
                const relative = entry.path.split('/').join(path.sep);
                const source = path.resolve(builtPackageDir, relative);
                if (!source.startsWith(`${builtPackageDir}${path.sep}`)) {
                    throw new Error(`npm pack inventory escapes package root: ${entry.path}`);
                }
                const sourceStat = fs.lstatSync(source);
                if (!sourceStat.isFile()) {
                    throw new Error(`npm pack inventory requires a regular file: ${entry.path}`);
                }
                const target = path.join(stage, relative);
                fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o755 });
                fs.copyFileSync(source, target);
                fs.chmodSync(target, executablePaths.has(entry.path) ? 0o755 : 0o644);
            }
            return stage;
        }
        function pack(packageInput, label) {
            const destination = path.join(scratch, label);
            fs.mkdirSync(destination);
            const report = runPack([packageInput, '--pack-destination', destination], label, packageInput);
            const bytes = canonicalizeNpmTarball(fs.readFileSync(path.join(destination, report.filename)));
            const identity = validatePackedPackageIdentity(bytes, metadata.name, metadata.version, packageJsonBytes);
            const members = inspectPackedPackageMembers(bytes);
            return {
                bytes,
                filename: report.filename,
                members,
                sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
                packageJsonSha256: identity.packageJsonSha256,
            };
        }
        const first = pack(stageCanonicalPackage(buildPackage('first'), 'first'), 'first');
        const second = pack(stageCanonicalPackage(buildPackage('second'), 'second'), 'second');
        if (first.filename !== second.filename)
            throw new Error('pack filenames differ');
        if (JSON.stringify(first.members) !== JSON.stringify(second.members))
            throw new Error('package member manifests differ');
        if (!first.bytes.equals(second.bytes)) {
            throw new Error(`package bytes differ: ${first.sha256} != ${second.sha256}`);
        }
        let artifactPath = null;
        if (outDir) {
            const destination = path.resolve(root, outDir);
            fs.mkdirSync(destination, { recursive: true });
            artifactPath = path.join(destination, first.filename);
            fs.writeFileSync(artifactPath, first.bytes);
        }
        const recipe = {
            '@version': 'EP-NPM-PACK-RECIPE-v2',
            source_materialization: 'git-object-exact-commit',
            dependency_install: 'npm-ci-lockfile-ignore-scripts',
            build_command: typeof metadata.scripts?.build === 'string' ? 'npm-run-build-ignore-lifecycle' : 'none',
            build_script: typeof metadata.scripts?.build === 'string' ? metadata.scripts.build : null,
            pack_command: 'npm-pack-ignore-scripts',
            canonical_gzip: 'pako-3-level-9-mtime-0-os-255',
            node: process.versions.node,
            npm: String(run(npm, ['--version'], 'npm version lookup').stdout).trim(),
        };
        const recipeSha256 = crypto.createHash('sha256')
            .update(JSON.stringify(recipe))
            .digest('hex');
        const releaseRegistryPath = path.join(snapshotRoot, 'release/release-packages.v1.json');
        let dependencyEvidence = null;
        let releaseRegistrySha256 = null;
        if (fs.existsSync(releaseRegistryPath)) {
            const registryBytes = fs.readFileSync(releaseRegistryPath);
            const registry = JSON.parse(registryBytes.toString('utf8'));
            const entries = registry.packages?.filter((entry) => entry?.ecosystem === 'npm' && entry.package === metadata.name);
            if (registry['@version'] !== 'EP-RELEASE-PACKAGE-REGISTRY-v1'
                || entries?.length !== 1
                || entries[0].path !== packageRelative) {
                throw new Error('release registry does not bind the reviewed npm package');
            }
            const fields = ['dependencies', 'optionalDependencies', 'peerDependencies'];
            const internalDependencies = fields.flatMap((field) => Object.entries(metadata[field] ?? {})
                .filter(([name]) => name.startsWith('@emilia-protocol/'))
                .map(([name, range]) => ({ field, name, range, spec: `${name}@${range}` })))
                .sort((left, right) => `${left.field}:${left.spec}`.localeCompare(`${right.field}:${right.spec}`));
            releaseRegistrySha256 = crypto.createHash('sha256').update(registryBytes).digest('hex');
            dependencyEvidence = {
                internal_dependencies: internalDependencies,
                pins: [...(entries[0].registry_dependency_tarballs ?? [])]
                    .sort((left, right) => left.spec.localeCompare(right.spec)),
            };
        }
        return {
            name: metadata.name,
            version: metadata.version,
            packagePath: packageRelative,
            filename: first.filename,
            sha256: first.sha256,
            bytes: first.bytes.length,
            fileCount: first.members.length,
            members: first.members,
            fileManifestSha256: crypto.createHash('sha256').update(JSON.stringify(first.members)).digest('hex'),
            packageJsonSha256: first.packageJsonSha256,
            source: {
                object_format: objectFormat,
                commit_sha: commit,
                tree_oid: treeOid,
                package_tree_oid: packageTreeOid,
                package_json_blob_oid: packageJsonBlobOid,
                archive_sha256: crypto.createHash('sha256').update(sourceArchiveBytes).digest('hex'),
                release_registry_sha256: releaseRegistrySha256,
            },
            recipe,
            recipeSha256,
            dependencyEvidence,
            ...(artifactPath ? { artifactPath } : {}),
        };
    }
    finally {
        const makeRemovable = (entry) => {
            const stat = fs.lstatSync(entry);
            if (stat.isDirectory() && !stat.isSymbolicLink()) {
                fs.chmodSync(entry, 0o700);
                for (const name of fs.readdirSync(entry))
                    makeRemovable(path.join(entry, name));
            }
            else if (!stat.isSymbolicLink()) {
                fs.chmodSync(entry, 0o600);
            }
        };
        if (fs.existsSync(scratch))
            makeRemovable(scratch);
        fs.rmSync(scratch, { recursive: true, force: true });
    }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        const argv = process.argv.slice(2);
        let packagePath = null;
        let outDir = null;
        let emitPath = null;
        let reviewedCommit = null;
        for (let index = 0; index < argv.length; index += 1) {
            const value = argv[index];
            if (value === '--outdir' || value === '--emit' || value === '--commit') {
                const next = argv[index + 1];
                if (!next)
                    throw new Error(`${value} requires a path`);
                if (value === '--outdir')
                    outDir = next;
                else if (value === '--emit')
                    emitPath = next;
                else
                    reviewedCommit = next;
                index += 1;
            }
            else if (value.startsWith('--')) {
                throw new Error(`unknown option: ${value}`);
            }
            else if (packagePath === null) {
                packagePath = value;
            }
            else {
                throw new Error(`unexpected argument: ${value}`);
            }
        }
        const result = verifyReproduciblePackage(packagePath || 'packages/verify', { outDir, reviewedCommit });
        const manifest = {
            '@version': 'EP-REPRODUCIBLE-NPM-ARTIFACT-v2',
            package_path: result.packagePath,
            package: result.name,
            version: result.version,
            source: result.source,
            recipe: result.recipe,
            recipe_sha256: result.recipeSha256,
            dependency_evidence: result.dependencyEvidence,
            artifact: {
                filename: result.filename,
                sha256: result.sha256,
                bytes: result.bytes,
                files: result.fileCount,
                file_manifest_sha256: result.fileManifestSha256,
                package_json_sha256: result.packageJsonSha256,
                members: result.members,
            },
        };
        manifest.manifest_sha256 = crypto.createHash('sha256').update(JSON.stringify(manifest)).digest('hex');
        if (emitPath) {
            const target = path.resolve(ROOT, emitPath);
            fs.mkdirSync(path.dirname(target), { recursive: true });
            fs.writeFileSync(target, `${JSON.stringify(manifest, null, 2)}\n`);
        }
        console.log(`reproducible package: ${result.name}@${result.version}`);
        console.log(`tarball: ${result.filename}`);
        console.log(`sha256: ${result.sha256}`);
        console.log(`files: ${result.fileCount}`);
    }
    catch (error) {
        console.error(`reproducibility check failed: ${error.message}`);
        process.exitCode = 1;
    }
}
