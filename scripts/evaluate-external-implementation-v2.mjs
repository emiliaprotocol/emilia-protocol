#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from evaluate-external-implementation-v2.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalizeV2, sha256V2, verifyCleanRoomSubmissionV2, } from './verify-clean-room-submission-v2.mjs';
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
function resolveImplementationRoot(sourceRoot, treePath) {
    const candidate = path.resolve(sourceRoot, treePath);
    if (candidate !== sourceRoot && !candidate.startsWith(`${sourceRoot}${path.sep}`)) {
        throw new Error('implementation source tree path escapes the source checkout');
    }
    return fs.realpathSync(candidate);
}
export function evaluateExternalImplementationV2({ manifestPath, sourcePath, runnerPath, attestationPath, trustedAttestorsPath, emitPath, }) {
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
    const evaluation = verifyCleanRoomSubmissionV2({
        manifestPath: manifestAbsolute,
        runnerPath: runnerReal,
        attestationPath: path.resolve(attestationPath),
        trustedAttestorsPath: path.resolve(trustedAttestorsPath),
        requireAcceptance: true,
    });
    const report = {
        ...evaluation,
        '@version': 'EP-EXTERNAL-CONFORMANCE-EVALUATION-v2',
        source_verification: {
            checkout_head: head,
            tree_path: treePath,
            tree_oid: treeOid,
            tracked_worktree_clean: true,
            runner_within_tree_scope: true,
        },
    };
    delete report.report_sha256;
    report.report_sha256 = sha256V2(Buffer.from(canonicalizeV2(report), 'utf8'));
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
    ]);
    const values = new Map();
    for (let index = 0; index < argv.length; index += 1) {
        const argument = argv[index];
        if (!allowed.has(argument))
            throw new Error(`unknown argument: ${argument}`);
        const value = argv[++index];
        if (!value)
            throw new Error(`${argument} requires a value`);
        values.set(argument, value);
    }
    for (const key of allowed) {
        if (!values.get(key)) {
            throw new Error('usage: evaluate-external-implementation-v2 --manifest FILE --source CHECKOUT '
                + '--runner EXECUTABLE --attestation FILE --trusted-attestors FILE --emit FILE');
        }
    }
    return {
        manifestPath: values.get('--manifest'),
        sourcePath: values.get('--source'),
        runnerPath: values.get('--runner'),
        attestationPath: values.get('--attestation'),
        trustedAttestorsPath: values.get('--trusted-attestors'),
        emitPath: values.get('--emit'),
    };
}
if (process.argv[1]
    && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        const report = evaluateExternalImplementationV2(cliOptions(process.argv.slice(2)));
        console.log(`EXTERNAL CONFORMANCE V2: PASS (${report.conformance.suites} suites, `
            + `${report.conformance.vectors} vectors; acceptance=${report.acceptance.accepted}; `
            + `sha256:${report.report_sha256})`);
    }
    catch (error) {
        console.error(`EXTERNAL CONFORMANCE V2: FAIL: ${errorMessage(error)}`);
        process.exitCode = 1;
    }
}
