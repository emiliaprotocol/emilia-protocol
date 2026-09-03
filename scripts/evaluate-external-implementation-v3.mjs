#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from evaluate-external-implementation-v3.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalizeV3, sha256V3, verifyCleanRoomSubmissionV3, } from './verify-clean-room-submission-v3.mjs';
function errorMessage(error) {
    return error instanceof Error ? error.message : String(error);
}
function readManifest(target) {
    try {
        return JSON.parse(fs.readFileSync(target, 'utf8'));
    }
    catch (error) {
        throw new Error(`submission manifest is not valid JSON: ${errorMessage(error)}`);
    }
}
function git(checkout, ...args) {
    return execFileSync('git', ['-C', checkout, ...args], {
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
    }).trim();
}
function gitBytes(checkout, ...args) {
    return execFileSync('git', ['-C', checkout, ...args], {
        encoding: null,
        maxBuffer: 256 * 1024 * 1024,
    });
}
function resolveImplementationRoot(sourceRoot, treePath) {
    const candidate = path.resolve(sourceRoot, treePath);
    if (candidate !== sourceRoot && !candidate.startsWith(`${sourceRoot}${path.sep}`)) {
        throw new Error('implementation source tree path escapes the source checkout');
    }
    return fs.realpathSync(candidate);
}
export function evaluateExternalImplementationV3({ manifestPath, sourcePath, runnerPath, attestationPath, trustedAttestorsPath, emitPath, allowUnsafeLocalExecution = false, }) {
    if (allowUnsafeLocalExecution !== true) {
        throw new Error('external runner execution refused: explicit unsafe-local-execution acknowledgement is required');
    }
    const manifestAbsolute = path.resolve(manifestPath);
    const sourceRoot = fs.realpathSync(path.resolve(sourcePath));
    const runnerReal = fs.realpathSync(path.resolve(runnerPath));
    const manifest = readManifest(manifestAbsolute);
    if (/emilia/i.test(String(manifest.implementation?.organization ?? ''))
        || /emilia/i.test(String(manifest.implementation?.team_id ?? ''))) {
        throw new Error('external evaluation refused: implementation is EMILIA-affiliated');
    }
    const head = git(sourceRoot, 'rev-parse', 'HEAD');
    if (head !== manifest.implementation?.source_commit) {
        throw new Error(`external source commit drift: expected ${manifest.implementation?.source_commit}, got ${head}`);
    }
    const trackedStatus = git(sourceRoot, 'status', '--porcelain', '--untracked-files=no');
    if (trackedStatus !== '') {
        throw new Error('external source checkout has modified tracked files');
    }
    const treePath = manifest.implementation?.source_tree_path;
    const implementationRoot = resolveImplementationRoot(sourceRoot, treePath);
    const treeSpec = treePath === '.'
        ? `${head}^{tree}`
        : `${head}:${treePath}`;
    const treeOid = git(sourceRoot, 'rev-parse', treeSpec);
    if (treeOid !== manifest.implementation?.source_tree_oid) {
        throw new Error(`external source tree drift: expected ${manifest.implementation?.source_tree_oid}, got ${treeOid}`);
    }
    if (runnerReal !== implementationRoot
        && !runnerReal.startsWith(`${implementationRoot}${path.sep}`)) {
        throw new Error('external runner is outside the immutable implementation tree scope');
    }
    const runnerRelative = path.relative(implementationRoot, runnerReal);
    if (runnerRelative === '' || runnerRelative.startsWith('../') || path.isAbsolute(runnerRelative)) {
        throw new Error('external runner path cannot be projected into the pinned source tree');
    }
    const isolated = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-clean-room-v3-source-'));
    let evaluation;
    try {
        const archivePath = path.join(isolated, 'source-tree.tar');
        const exportedRoot = path.join(isolated, 'source');
        fs.mkdirSync(exportedRoot);
        fs.writeFileSync(archivePath, gitBytes(sourceRoot, 'archive', '--format=tar', treeSpec));
        execFileSync('tar', ['-xf', archivePath, '-C', exportedRoot], {
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        fs.rmSync(archivePath);
        // The commit export excludes every untracked file and every tracked path
        // outside source_tree_path. Overlay only the submitted runner artifact so
        // build outputs may remain untracked without admitting untracked helpers.
        const isolatedRunner = path.resolve(exportedRoot, runnerRelative);
        if (!isolatedRunner.startsWith(`${exportedRoot}${path.sep}`)) {
            throw new Error('isolated runner path escapes the pinned source export');
        }
        fs.mkdirSync(path.dirname(isolatedRunner), { recursive: true });
        fs.copyFileSync(runnerReal, isolatedRunner);
        fs.chmodSync(isolatedRunner, 0o555);
        evaluation = verifyCleanRoomSubmissionV3({
            manifestPath: manifestAbsolute,
            runnerPath: isolatedRunner,
            attestationPath: path.resolve(attestationPath),
            trustedAttestorsPath: path.resolve(trustedAttestorsPath),
            requireAcceptance: true,
            allowUnsafeLocalExecution: true,
        });
    }
    finally {
        fs.rmSync(isolated, { recursive: true, force: true });
    }
    const report = {
        ...evaluation,
        '@version': 'EP-EXTERNAL-CONFORMANCE-EVALUATION-v3',
        source_verification: {
            checkout_head: head,
            tree_path: treePath,
            tree_oid: treeOid,
            tracked_worktree_clean: true,
            runner_within_tree_scope: true,
            isolated_pinned_tree_export: true,
            untracked_source_files_included: false,
            tracked_files_outside_tree_scope_included: false,
            submitted_runner_only_overlay: true,
            runner_dependency_closure_verified: false,
            fixed_argument_targets_pinned: false,
            entrypoint_path_toctou_excluded: false,
            operator_acknowledged_unsafe_local_execution: true,
            inherited_environment: false,
            network_sandbox: false,
            filesystem_read_sandbox: false,
            system_dependency_isolation: false,
        },
    };
    delete report.report_sha256;
    report.report_sha256 = sha256V3(Buffer.from(canonicalizeV3(report), 'utf8'));
    const target = path.resolve(emitPath);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, `${JSON.stringify(report, null, 2)}\n`);
    return report;
}
function cliOptions(argv) {
    const allowed = new Set([
        '--manifest',
        '--source',
        '--runner',
        '--attestation',
        '--trusted-attestors',
        '--emit',
        '--allow-unsafe-local-execution',
    ]);
    const values = new Map();
    let allowUnsafeLocalExecution = false;
    for (let index = 0; index < argv.length; index += 1) {
        const argument = argv[index];
        if (!allowed.has(argument))
            throw new Error(`unknown argument: ${argument}`);
        if (argument === '--allow-unsafe-local-execution') {
            allowUnsafeLocalExecution = true;
            continue;
        }
        const value = argv[++index];
        if (!value)
            throw new Error(`${argument} requires a value`);
        values.set(argument, value);
    }
    for (const key of [...allowed].filter((entry) => entry !== '--allow-unsafe-local-execution')) {
        if (!values.get(key)) {
            throw new Error('usage: evaluate-external-implementation-v3 --manifest FILE --source CHECKOUT '
                + '--runner EXECUTABLE --attestation FILE --trusted-attestors FILE --emit FILE '
                + '--allow-unsafe-local-execution');
        }
    }
    return {
        manifestPath: values.get('--manifest'),
        sourcePath: values.get('--source'),
        runnerPath: values.get('--runner'),
        attestationPath: values.get('--attestation'),
        trustedAttestorsPath: values.get('--trusted-attestors'),
        emitPath: values.get('--emit'),
        allowUnsafeLocalExecution,
    };
}
if (process.argv[1]
    && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        const report = evaluateExternalImplementationV3(cliOptions(process.argv.slice(2)));
        console.log(`EXTERNAL CONFORMANCE V3: PASS (${report.conformance.suites} suites, `
            + `${report.conformance.vectors} vectors; acceptance=${report.acceptance.accepted}; `
            + `sha256:${report.report_sha256})`);
    }
    catch (error) {
        console.error(`EXTERNAL CONFORMANCE V3: FAIL: ${errorMessage(error)}`);
        process.exitCode = 1;
    }
}
