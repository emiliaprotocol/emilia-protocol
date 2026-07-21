// SPDX-License-Identifier: Apache-2.0
// Generated from test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
test('scaffold pins official packages and keeps trust roots outside receipts', () => {
    const cwd = mkdtempSync(join(tmpdir(), 'create-ep-app-'));
    const result = spawnSync(process.execPath, [join(import.meta.dirname, 'index.js'), 'secure-demo'], {
        cwd,
        encoding: 'utf8',
    });
    assert.equal(result.status, 0, result.stderr);
    const root = join(cwd, 'secure-demo');
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.dependencies['@emilia-protocol/verify'], '3.10.0');
    assert.equal(pkg.dependencies['@emilia-protocol/issue'], '0.6.1');
    const verifier = readFileSync(join(root, 'verify-receipt.mjs'), 'utf8');
    assert.match(verifier, /relying-party-trust/);
    assert.match(verifier, /strictJsonGate/);
    assert.doesNotMatch(verifier, /doc\.signature.*public_key|createPublicKey|crypto\.verify/);
    const demo = readFileSync(join(root, 'demo.mjs'), 'utf8');
    assert.match(demo, /tampered receipt was accepted/);
    assert.doesNotMatch(JSON.stringify(pkg), /latest/);
});
test('scaffold refuses path traversal and existing destinations', () => {
    const cwd = mkdtempSync(join(tmpdir(), 'create-ep-app-'));
    for (const name of ['../escape', '.hidden', 'a/b']) {
        const result = spawnSync(process.execPath, [join(import.meta.dirname, 'index.js'), name], { cwd, encoding: 'utf8' });
        assert.notEqual(result.status, 0, name);
    }
    assert.equal(spawnSync(process.execPath, [join(import.meta.dirname, 'index.js'), 'demo'], { cwd }).status, 0);
    assert.notEqual(spawnSync(process.execPath, [join(import.meta.dirname, 'index.js'), 'demo'], { cwd }).status, 0);
});
