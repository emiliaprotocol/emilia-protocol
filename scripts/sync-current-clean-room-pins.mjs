#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from sync-current-clean-room-pins.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { validateBundleDefinitionV2 } from './verify-clean-room-submission-v2.mjs';
import { validateBundleDefinitionV3 } from './verify-clean-room-submission-v3.mjs';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MANIFEST = 'conformance/conformance-manifest.json';
const BUNDLES = ['conformance/clean-room/v2/bundle.v2.json', 'conformance/clean-room/v3/bundle.v3.json'];
// This refreshes implementation-derived manifest pins only. A changed vector
// contract needs a separate reviewed corpus revision, not an automatic refresh.
export function planCurrentCleanRoomPinRefresh(root = ROOT) {
    const read = (name) => fs.readFileSync(path.join(root, name), 'utf8');
    const bytes = read(MANIFEST);
    const manifest = JSON.parse(bytes);
    const bundles = BUNDLES.map(name => JSON.parse(read(name)));
    validateBundleDefinitionV2(bundles[0]);
    validateBundleDefinitionV3(bundles[1]);
    const previous = bundles[0].source_manifest;
    if (!isDeepStrictEqual(previous, bundles[1].source_manifest)) {
        throw new Error('current v2/v3 manifest pins disagree');
    }
    for (const bundle of bundles) {
        if (manifest.totals.suites !== bundle.totals.suites
            || manifest.totals.vectors !== bundle.totals.vectors
            || manifest.suites.length !== bundle.suites.length) {
            throw new Error('corpus revision required: suite or vector totals changed');
        }
        for (let index = 0; index < bundle.suites.length; index += 1) {
            for (const field of ['path', 'sha256', 'vectors', 'execution_path', 'execution_sha256']) {
                if (bundle.suites[index][field] !== manifest.suites[index][field]) {
                    throw new Error(`corpus revision required: suite ${index}.${field} changed`);
                }
            }
        }
    }
    const next = {
        path: MANIFEST,
        sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
        manifest_sha256: manifest.manifest_sha256,
    };
    const edits = new Map();
    bundles.forEach((bundle, index) => {
        edits.set(BUNDLES[index], `${JSON.stringify({ ...bundle, source_manifest: next }, null, 2)}\n`);
    });
    const sourcePath = 'scripts/verify-clean-room-submission-v2.mts';
    let source = read(sourcePath);
    for (const [name, value, old] of [
        ['EXPECTED_MANIFEST_SHA256', next.sha256, previous.sha256],
        ['EXPECTED_MANIFEST_CLAIM_SHA256', next.manifest_sha256, previous.manifest_sha256],
    ]) {
        const pattern = new RegExp(`(const ${name} =\\s*)'([a-f0-9]{64})';`, 'g');
        const matches = [...source.matchAll(pattern)];
        if (matches.length !== 1 || matches[0][2] !== old) {
            throw new Error(`source pin mismatch: ${name}`);
        }
        source = source.replace(pattern, `$1'${value}';`);
    }
    edits.set(sourcePath, source);
    const docPath = 'docs/conformance/CLEAN-ROOM-V2.md';
    let docs = read(docPath);
    for (const field of ['sha256', 'manifest_sha256']) {
        if (docs.split(previous[field]).length !== 2)
            throw new Error(`documentation pin mismatch: ${field}`);
        docs = docs.replace(previous[field], next[field]);
    }
    edits.set(docPath, docs);
    return new Map([...edits].filter(([name, content]) => read(name) !== content));
}
if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
    if (process.argv.slice(2).some(arg => arg !== '--check'))
        throw new Error('only --check is supported');
    // The existing generator re-executes all three ports and verifies source,
    // vector, execution-companion and result hashes before any pin is written.
    execFileSync(process.execPath, ['scripts/generate-conformance-manifest.mjs', '--check'], {
        cwd: ROOT, stdio: 'inherit', timeout: 600_000, killSignal: 'SIGKILL',
    });
    const edits = planCurrentCleanRoomPinRefresh();
    if (process.argv.includes('--check') && edits.size) {
        throw new Error('current clean-room manifest pins are stale; run sync:clean-room-pins');
    }
    if (!process.argv.includes('--check')) {
        for (const [name, content] of edits)
            fs.writeFileSync(path.join(ROOT, name), content);
    }
    console.log(`CURRENT CLEAN-ROOM PINS: PASS (${edits.size} refreshed files; frozen v1 unchanged)`);
}
