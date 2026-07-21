#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from build-clean-room-kit.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const KIT_PREFIX = 'emilia-clean-room-kit-v1/';
const SPEC_PATH = 'conformance/clean-room/specification-bundle.v1.json';
const VECTOR_BUNDLE_PATH = 'conformance/clean-room/bundle.v1.json';
const FROZEN_PREFIX = 'conformance/clean-room/frozen-v1/';
const REQUIRED_INPUTS = Object.freeze([
    'LICENSE',
    'conformance/clean-room/EXTERNAL-CHALLENGE.md',
    'conformance/clean-room/README.md',
    SPEC_PATH,
    VECTOR_BUNDLE_PATH,
    'conformance/clean-room/submission.schema.json',
]);
const FORBIDDEN_PREFIXES = Object.freeze([
    'app/',
    'lib/',
    'packages/',
    'conformance/runners/',
]);
function sha256(bytes) {
    return crypto.createHash('sha256').update(bytes).digest('hex');
}
function git(args, options = {}) {
    return execFileSync('git', args, {
        cwd: ROOT,
        encoding: options.encoding,
        maxBuffer: 32 * 1024 * 1024,
        ...options,
    });
}
function assertSafePath(value) {
    if (typeof value !== 'string' || value.length === 0 || value.includes('\\')) {
        throw new Error(`unsafe kit path: ${JSON.stringify(value)}`);
    }
    const normalized = path.posix.normalize(value);
    if (normalized !== value || normalized.startsWith('/') || normalized === '..' || normalized.startsWith('../')) {
        throw new Error(`unsafe kit path: ${JSON.stringify(value)}`);
    }
    if (FORBIDDEN_PREFIXES.some((prefix) => value.startsWith(prefix))) {
        throw new Error(`reference implementation path is forbidden from the clean-room kit: ${value}`);
    }
    return value;
}
function readAt(commit, filePath) {
    return git(['show', `${commit}:${assertSafePath(filePath)}`], { encoding: null });
}
function parseJsonAt(commit, filePath) {
    try {
        return JSON.parse((readAt(commit, filePath)).toString('utf8'));
    }
    catch (error) {
        throw new Error(`cannot parse ${filePath} at ${commit}: ${error.message}`);
    }
}
function verifyDeclaredFile(commit, entry, source) {
    const filePath = assertSafePath(entry?.path);
    const sourcePath = assertSafePath(`${FROZEN_PREFIX}${filePath}`);
    if (!/^[0-9a-f]{64}$/.test(entry?.sha256 ?? '')) {
        throw new Error(`${source} has an invalid SHA-256 for ${filePath}`);
    }
    const bytes = readAt(commit, sourcePath);
    const actual = sha256(bytes);
    if (actual !== entry.sha256) {
        throw new Error(`${source} hash mismatch for ${filePath}: declared ${entry.sha256}, got ${actual}`);
    }
    if (entry.bytes !== undefined && entry.bytes !== bytes.length) {
        throw new Error(`${source} byte count mismatch for ${filePath}: declared ${entry.bytes}, got ${bytes.length}`);
    }
    return { filePath, sourcePath };
}
export function collectCleanRoomKitFiles(ref = 'HEAD') {
    const commit = git(['rev-parse', '--verify', `${ref}^{commit}`], { encoding: 'utf8' }).trim();
    if (!/^[0-9a-f]{40}$/.test(commit))
        throw new Error(`could not resolve commit for ${ref}`);
    const specification = parseJsonAt(commit, SPEC_PATH);
    if (specification?.['@version'] !== 'EP-CLEAN-ROOM-SPECIFICATION-BUNDLE-v1') {
        throw new Error(`unsupported specification bundle version: ${specification?.['@version']}`);
    }
    if (specification?.policy?.reference_source_permitted !== false) {
        throw new Error('specification bundle does not prohibit reference-source access');
    }
    const vectorBundle = parseJsonAt(commit, VECTOR_BUNDLE_PATH);
    if (vectorBundle?.['@version'] !== 'EP-CLEAN-ROOM-VECTOR-BUNDLE-v1') {
        throw new Error(`unsupported vector bundle version: ${vectorBundle?.['@version']}`);
    }
    const sources = new Map(REQUIRED_INPUTS.map((filePath) => {
        const safe = assertSafePath(filePath);
        return [safe, safe];
    }));
    for (const entry of specification.documents ?? []) {
        const { filePath, sourcePath } = verifyDeclaredFile(commit, entry, SPEC_PATH);
        sources.set(filePath, sourcePath);
    }
    for (const entry of vectorBundle.suites ?? []) {
        const { filePath, sourcePath } = verifyDeclaredFile(commit, entry, VECTOR_BUNDLE_PATH);
        sources.set(filePath, sourcePath);
    }
    const files = [...sources].sort(([left], [right]) => left.localeCompare(right)).map(([filePath, sourcePath]) => {
        const modeLine = git(['ls-tree', commit, '--', sourcePath], { encoding: 'utf8' }).trim();
        if (!/^100(?:644|755) blob [0-9a-f]{40}\t/.test(modeLine)) {
            throw new Error(`kit input is not a regular tracked file at ${commit}: ${sourcePath}`);
        }
        const bytes = readAt(commit, sourcePath);
        return {
            path: filePath,
            sourcePath,
            mode: modeLine.slice(0, 6),
            bytes: bytes.length,
            sha256: sha256(bytes),
        };
    });
    return { commit, files };
}
function buildArchiveCommit(sourceCommit, files, temporary) {
    const indexPath = path.join(temporary, 'archive.index');
    const env = { ...process.env, GIT_INDEX_FILE: indexPath };
    git(['read-tree', '--empty'], { env, encoding: 'utf8' });
    for (const file of files) {
        const bytes = readAt(sourceCommit, file.sourcePath);
        const oid = git(['hash-object', '-w', '--stdin'], { input: bytes, encoding: 'utf8' }).trim();
        git(['update-index', '--add', '--cacheinfo', `${file.mode},${oid},${file.path}`], { env, encoding: 'utf8' });
    }
    const tree = git(['write-tree'], { env, encoding: 'utf8' }).trim();
    const timestamp = git(['show', '-s', '--format=%ct', sourceCommit], { encoding: 'utf8' }).trim();
    const identity = {
        ...env,
        GIT_AUTHOR_NAME: 'EMILIA Clean Room Kit',
        GIT_AUTHOR_EMAIL: 'security@emiliaprotocol.ai',
        GIT_COMMITTER_NAME: 'EMILIA Clean Room Kit',
        GIT_COMMITTER_EMAIL: 'security@emiliaprotocol.ai',
        GIT_AUTHOR_DATE: `${timestamp} +0000`,
        GIT_COMMITTER_DATE: `${timestamp} +0000`,
    };
    return git(['commit-tree', tree, '-m', `Frozen clean-room kit from ${sourceCommit}`], {
        env: identity,
        encoding: 'utf8',
    }).trim();
}
function archive(commit, paths, output) {
    git([
        'archive',
        '--format=tar.gz',
        `--prefix=${KIT_PREFIX}`,
        `--output=${output}`,
        commit,
        '--',
        ...paths,
    ]);
}
function archiveFiles(output) {
    const entries = execFileSync('tar', ['-tzf', output], {
        encoding: 'utf8',
        maxBuffer: 8 * 1024 * 1024,
    }).trim().split('\n').filter(Boolean);
    return entries.filter((entry) => !entry.endsWith('/'));
}
export function buildCleanRoomKit({ ref = 'HEAD', output } = {}) {
    const target = path.resolve(output ?? path.join(ROOT, 'release-artifacts/emilia-clean-room-kit-v1.tar.gz'));
    const manifestTarget = `${target}.manifest.json`;
    fs.mkdirSync(path.dirname(target), { recursive: true });
    const { commit, files } = collectCleanRoomKitFiles(ref);
    const filePaths = files.map((entry) => entry.path);
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-clean-room-kit-'));
    const second = path.join(temporary, 'second.tar.gz');
    try {
        const archiveCommit = buildArchiveCommit(commit, files, temporary);
        archive(archiveCommit, filePaths, target);
        archive(archiveCommit, filePaths, second);
        const firstHash = sha256(fs.readFileSync(target));
        const secondHash = sha256(fs.readFileSync(second));
        if (firstHash !== secondHash)
            throw new Error('clean-room archive is not reproducible');
        const expectedEntries = filePaths.map((filePath) => `${KIT_PREFIX}${filePath}`).sort();
        const actualEntries = archiveFiles(target).sort();
        if (JSON.stringify(actualEntries) !== JSON.stringify(expectedEntries)) {
            throw new Error('clean-room archive content differs from the byte-pinned allowlist');
        }
        const reportFiles = files.map(({ path: filePath, bytes, sha256: digest }) => ({
            path: filePath,
            bytes,
            sha256: digest,
        }));
        const report = {
            '@version': 'EP-CLEAN-ROOM-KIT-REPORT-v1',
            source_commit: commit,
            archive: {
                file: path.basename(target),
                bytes: fs.statSync(target).size,
                sha256: firstHash,
                reproducible: true,
            },
            reference_implementation_included: false,
            files: reportFiles,
        };
        fs.writeFileSync(manifestTarget, `${JSON.stringify(report, null, 2)}\n`);
        return { target, manifestTarget, ...report };
    }
    finally {
        fs.rmSync(temporary, { recursive: true, force: true });
    }
}
function parseArgs(argv) {
    const options = {};
    for (let index = 0; index < argv.length; index += 1) {
        if (argv[index] === '--ref')
            options.ref = argv[++index];
        else if (argv[index] === '--out')
            options.output = argv[++index];
        else
            throw new Error(`unknown argument: ${argv[index]}`);
    }
    return options;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        const report = buildCleanRoomKit(parseArgs(process.argv.slice(2)));
        console.log(`CLEAN-ROOM KIT: PASS (${report.files.length} files; ${report.archive.sha256}; ${report.target})`);
    }
    catch (error) {
        console.error(`CLEAN-ROOM KIT: FAIL: ${error.message}`);
        process.exitCode = 1;
    }
}
