#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from build-clean-room-kit-v2.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256V2, validateBundleDefinitionV2, } from './verify-clean-room-submission-v2.mjs';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const KIT_PREFIX = 'emilia-clean-room-kit-v2/';
const CONTROL_INPUTS = Object.freeze([
    'LICENSE',
    'conformance/clean-room/v2/README.md',
    'conformance/clean-room/v2/bundle.v2.json',
    'conformance/clean-room/v2/submission.schema.json',
    'conformance/clean-room/v2/independent-attestation.schema.json',
    'conformance/clean-room/v2/trusted-attestors.schema.json',
    'docs/conformance/CLEAN-ROOM-V2.md',
]);
const FORBIDDEN_PREFIXES = Object.freeze([
    'app/',
    'lib/',
    'packages/',
    'scripts/',
    'conformance/runners/',
]);
function errorMessage(error) {
    return error instanceof Error ? error.message : String(error);
}
function git(args, options = {}) {
    const encoding = Object.hasOwn(options, 'encoding') ? options.encoding : 'utf8';
    return execFileSync('git', args, {
        cwd: ROOT,
        encoding,
        maxBuffer: 64 * 1024 * 1024,
        ...options,
    });
}
function safeKitPath(value) {
    if (typeof value !== 'string'
        || value === ''
        || value.includes('\\')
        || path.posix.normalize(value) !== value
        || value.startsWith('/')
        || value === '..'
        || value.startsWith('../')) {
        throw new Error(`unsafe v2 kit path: ${JSON.stringify(value)}`);
    }
    if (FORBIDDEN_PREFIXES.some((prefix) => value.startsWith(prefix))) {
        throw new Error(`source or runner path is forbidden from the v2 kit: ${value}`);
    }
    return value;
}
function readAt(commit, filePath) {
    return git(['show', `${commit}:${safeKitPath(filePath)}`], { encoding: null });
}
function modeAt(commit, filePath) {
    const line = String(git(['ls-tree', commit, '--', safeKitPath(filePath)])).trim();
    if (!/^100(?:644|755) blob [0-9a-f]{40}\t/.test(line)) {
        throw new Error(`v2 kit data input is not a regular tracked file: ${filePath}`);
    }
    return line.slice(0, 6);
}
function trackedFile(commit, filePath) {
    const safe = safeKitPath(filePath);
    const content = readAt(commit, safe);
    return {
        path: safe,
        mode: modeAt(commit, safe),
        bytes: content.length,
        sha256: sha256V2(content),
        content,
    };
}
export function collectCleanRoomKitV2Files(ref = 'HEAD') {
    const commit = String(git(['rev-parse', '--verify', `${ref}^{commit}`])).trim();
    if (!/^[0-9a-f]{40}$/.test(commit))
        throw new Error(`could not resolve immutable commit ${ref}`);
    const bundleBytes = readAt(commit, 'conformance/clean-room/v2/bundle.v2.json');
    let bundle;
    try {
        bundle = JSON.parse(bundleBytes.toString('utf8'));
    }
    catch (error) {
        throw new Error(`v2 bundle at ${commit} is not valid JSON: ${errorMessage(error)}`);
    }
    validateBundleDefinitionV2(bundle);
    const expectedHashes = new Map([
        [bundle.source_manifest.path, bundle.source_manifest.sha256],
    ]);
    for (const suite of bundle.suites) {
        expectedHashes.set(suite.path, suite.sha256);
        if (suite.execution_path) {
            expectedHashes.set(suite.execution_path, suite.execution_sha256);
        }
    }
    const files = new Map();
    for (const controlPath of CONTROL_INPUTS) {
        const entry = trackedFile(commit, controlPath);
        files.set(entry.path, entry);
    }
    for (const [filePath, expectedHash] of expectedHashes) {
        const safe = safeKitPath(filePath);
        const content = readAt(commit, safe);
        const actual = sha256V2(content);
        if (actual !== expectedHash) {
            throw new Error(`v2 kit pin mismatch at ${commit}:${safe}: expected ${expectedHash}, got ${actual}`);
        }
        files.set(safe, trackedFile(commit, safe));
    }
    const sorted = [...files.values()].sort((left, right) => left.path.localeCompare(right.path));
    if (sorted.length !== 30) {
        throw new Error(`v2 kit allowlist must contain exactly 30 files, got ${sorted.length}`);
    }
    return { commit, files: sorted };
}
function buildArchiveCommit(sourceCommit, files, temporary) {
    const indexPath = path.join(temporary, 'archive.index');
    const env = {
        ...process.env,
        GIT_INDEX_FILE: indexPath,
    };
    git(['read-tree', '--empty'], { env });
    for (const file of files) {
        const oid = String(git(['hash-object', '-w', '--stdin'], { input: file.content })).trim();
        git(['update-index', '--add', '--cacheinfo', `${file.mode},${oid},${file.path}`], { env });
    }
    const tree = String(git(['write-tree'], { env })).trim();
    const timestamp = String(git(['show', '-s', '--format=%ct', sourceCommit])).trim();
    const identity = {
        ...env,
        GIT_AUTHOR_NAME: 'EMILIA Clean Room Kit v2',
        GIT_AUTHOR_EMAIL: 'security@emiliaprotocol.ai',
        GIT_COMMITTER_NAME: 'EMILIA Clean Room Kit v2',
        GIT_COMMITTER_EMAIL: 'security@emiliaprotocol.ai',
        GIT_AUTHOR_DATE: `${timestamp} +0000`,
        GIT_COMMITTER_DATE: `${timestamp} +0000`,
    };
    return String(git(['commit-tree', tree, '-m', `Source-free clean-room kit v2 from ${sourceCommit}`], { env: identity })).trim();
}
function writeArchive(commit, files, target) {
    git([
        'archive',
        '--format=tar.gz',
        `--prefix=${KIT_PREFIX}`,
        `--output=${target}`,
        commit,
        '--',
        ...files.map((file) => file.path),
    ]);
}
function archiveMembers(target) {
    return String(execFileSync('tar', ['-tzf', target], {
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
    })).trim().split('\n').filter((entry) => entry && !entry.endsWith('/'));
}
export function buildCleanRoomKitV2({ ref = 'HEAD', output, } = {}) {
    const target = path.resolve(output ?? path.join(ROOT, 'release-artifacts/emilia-clean-room-kit-v2.tar.gz'));
    const manifestTarget = `${target}.manifest.json`;
    fs.mkdirSync(path.dirname(target), { recursive: true });
    const { commit, files } = collectCleanRoomKitV2Files(ref);
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-clean-room-v2-kit-build-'));
    try {
        const archiveCommit = buildArchiveCommit(commit, files, temporary);
        const second = path.join(temporary, 'second.tar.gz');
        writeArchive(archiveCommit, files, target);
        writeArchive(archiveCommit, files, second);
        const archiveSha256 = sha256V2(fs.readFileSync(target));
        if (archiveSha256 !== sha256V2(fs.readFileSync(second))) {
            throw new Error('v2 clean-room archive is not byte-for-byte reproducible');
        }
        const expectedMembers = files
            .map((file) => `${KIT_PREFIX}${file.path}`)
            .sort();
        const actualMembers = archiveMembers(target).sort();
        if (JSON.stringify(actualMembers) !== JSON.stringify(expectedMembers)) {
            throw new Error('v2 clean-room archive differs from its source-free allowlist');
        }
        const fileByPath = new Map(files.map((file) => [file.path, file]));
        const bundleFile = fileByPath.get('conformance/clean-room/v2/bundle.v2.json');
        const sourceManifest = fileByPath.get('conformance/conformance-manifest.json');
        if (!bundleFile || !sourceManifest) {
            throw new Error('v2 clean-room archive omitted a required manifest');
        }
        const bundle = JSON.parse(bundleFile.content.toString('utf8'));
        const authority = bundle.suites.find((suite) => suite.execution_path);
        const reportFiles = files.map((file) => ({
            path: file.path,
            bytes: file.bytes,
            sha256: file.sha256,
        }));
        const report = {
            '@version': 'EP-CLEAN-ROOM-KIT-REPORT-v2',
            source_commit: commit,
            pins: {
                vector_bundle_sha256: bundleFile.sha256,
                conformance_manifest_sha256: sourceManifest.sha256,
                conformance_manifest_claim_sha256: bundle.source_manifest.manifest_sha256,
                authority_document_execution_companion_sha256: authority.execution_sha256,
                suites: 21,
                vectors: 329,
            },
            archive: {
                file: path.basename(target),
                bytes: fs.statSync(target).size,
                sha256: archiveSha256,
                reproducible: true,
            },
            reference_implementation_included: false,
            source_files_included: false,
            files: reportFiles,
        };
        fs.writeFileSync(manifestTarget, `${JSON.stringify(report, null, 2)}\n`);
        return {
            target,
            manifestTarget,
            ...report,
        };
    }
    finally {
        fs.rmSync(temporary, { recursive: true, force: true });
    }
}
function cliOptions(argv) {
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
if (process.argv[1]
    && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        const report = buildCleanRoomKitV2(cliOptions(process.argv.slice(2)));
        console.log(`CLEAN-ROOM KIT V2: PASS (${report.files.length} files; `
            + `${report.archive.sha256}; ${report.target})`);
    }
    catch (error) {
        console.error(`CLEAN-ROOM KIT V2: FAIL: ${errorMessage(error)}`);
        process.exitCode = 1;
    }
}
