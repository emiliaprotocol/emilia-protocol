// SPDX-License-Identifier: Apache-2.0
// Generated from crossing-lab-cli.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync, } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { initCrossingLab, sealCrossingLab } from './dist/crossing-lab.js';
const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(HERE, 'cli.js');
const CROSSING_LAB_RUNTIME_SUPPORTED = process.allowedNodeEnvironmentFlags.has('--allow-net')
    && (process.allowedNodeEnvironmentFlags.has('--permission')
        || process.allowedNodeEnvironmentFlags.has('--experimental-permission'));
const runtimeTest = CROSSING_LAB_RUNTIME_SUPPORTED ? test : test.skip;
function freshWorkspace() {
    const parent = mkdtempSync(join(tmpdir(), 'emilia-crossing-lab-cli-'));
    const target = join(parent, 'workspace');
    initCrossingLab(target);
    return target;
}
function runCli(args) {
    return spawnSync(process.execPath, [CLI, ...args], {
        encoding: 'utf8',
        maxBuffer: 4 * 1024 * 1024,
    });
}
function workspaceWithDifferentPinnedCaid() {
    const root = freshWorkspace();
    const path = join(root, 'workspace.json');
    const workspace = JSON.parse(readFileSync(path, 'utf8'));
    const candidateCaid = workspace.evaluation.caid;
    const final = candidateCaid.at(-1);
    const pinnedCaid = `${candidateCaid.slice(0, -1)}${final === 'A' ? 'B' : 'A'}`;
    workspace.evaluation.caid = pinnedCaid;
    writeFileSync(path, `${JSON.stringify(workspace, null, 2)}\n`);
    sealCrossingLab(root);
    return { root, candidateCaid, pinnedCaid };
}
test('crossing-lab run strictly rejects malformed --out and extra operands', () => {
    const root = freshWorkspace();
    const invalidArguments = [
        [root, '--out'],
        [root, '--out', join(dirname(root), 'first.json'), '--out', join(dirname(root), 'second.json')],
        [root, '--out', '--dash-prefixed.json'],
        [root, 'extra-operand'],
    ];
    for (const args of invalidArguments) {
        const result = runCli(['crossing-lab', 'run', ...args]);
        assert.equal(result.status, 1, `args=${JSON.stringify(args)} stderr=${result.stderr}`);
        assert.match(result.stderr, /usage: verify crossing-lab run/);
        assert.equal(result.stdout, '');
    }
});
runtimeTest('failed run with --out preserves the report and prints bounded actionable diagnostics', () => {
    const { root, candidateCaid, pinnedCaid } = workspaceWithDifferentPinnedCaid();
    const reportPath = join(dirname(root), 'failed-report.json');
    const result = runCli(['crossing-lab', 'run', root, '--out', reportPath]);
    assert.equal(result.status, 2, result.stderr);
    assert.equal(existsSync(reportPath), true);
    const report = JSON.parse(readFileSync(reportPath, 'utf8'));
    assert.equal(report.lab_passed, false);
    assert.match(result.stdout, /Crossing Lab FAILED/);
    assert.match(result.stdout, /failed adapter row native-artifact-through:/);
    assert.match(result.stdout, /native=VERIFIED, acceptance=ACCEPTED, mapping=MATCH/);
    assert.match(result.stdout, /freshness=FRESH, satisfaction=UNSATISFIED, evaluation_valid=false/);
    assert.match(result.stdout, new RegExp(`candidate mapped CAID ${candidateCaid.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
    assert.match(result.stdout, new RegExp(`workspace evaluation CAID ${pinnedCaid.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
    assert.match(result.stdout, /Review it against the pinned mapping profile/);
    assert.match(result.stdout, /deliberately update workspace\.evaluation\.caid/);
    assert.match(result.stdout, /crossing-lab seal, then rerun crossing-lab run/);
    const rowLine = result.stdout.split('\n').find((line) => line.startsWith('failed adapter row native-artifact-through:'));
    assert.ok(rowLine);
    const reasons = rowLine.split('reasons=')[1]?.replace(/ \(\+\d+ more\)$/, '').split(', ') ?? [];
    assert.ok(reasons.length <= 3, rowLine);
});
runtimeTest('failed run without --out keeps stdout as parseable report JSON and diagnostics on stderr', () => {
    const { root, candidateCaid } = workspaceWithDifferentPinnedCaid();
    const result = runCli(['crossing-lab', 'run', root]);
    assert.equal(result.status, 2, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.lab_passed, false);
    assert.doesNotMatch(result.stdout, /failed adapter row/);
    assert.match(result.stderr, /failed adapter row native-artifact-through:/);
    assert.match(result.stderr, new RegExp(`candidate mapped CAID ${candidateCaid.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
});
test('a runtime without governed network denial fails operationally before adapter evaluation', {
    skip: CROSSING_LAB_RUNTIME_SUPPORTED,
}, () => {
    const root = freshWorkspace();
    const result = runCli(['crossing-lab', 'run', root]);
    assert.equal(result.status, 1, result.stderr);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /requires a Node permission runtime with --allow-net support/);
    assert.doesNotMatch(result.stderr, /Crossing Lab FAILED|failed adapter row/);
});
