// SPDX-License-Identifier: Apache-2.0
// Generated from package-boundary.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Guard: every JS module shipped in the npm tarball must resolve its relative
// imports INSIDE the package root. A relative import that escapes the root
// (e.g. ../../../lib/canonical-json.js) works in a repo checkout but makes the
// published package unloadable for every consumer, and the in-repo test suite
// is blind to it. This test is the tripwire.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const pkgRoot = path.dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(fs.readFileSync(path.join(pkgRoot, 'package.json'), 'utf8'));
const IMPORT_RE = /(?:^|\n)\s*(?:import\s[^'"]*|export\s[^'"]*from\s*|import\s*\(\s*)['"]([^'"]+)['"]/g;
test('no file shipped in the package imports outside the package root', () => {
    const shippedJs = (pkg.files || []).filter((f) => f.endsWith('.js') || f.endsWith('.mjs'));
    assert.ok(shippedJs.length > 0, 'expected package.json files[] to list JS modules');
    const offenders = [];
    for (const rel of shippedJs) {
        const abs = path.join(pkgRoot, rel);
        if (!fs.existsSync(abs)) {
            offenders.push(`${rel}: listed in files[] but missing on disk`);
            continue;
        }
        const src = fs.readFileSync(abs, 'utf8');
        for (const m of src.matchAll(IMPORT_RE)) {
            const spec = m[1];
            if (!spec.startsWith('.'))
                continue;
            const resolved = path.resolve(path.dirname(abs), spec);
            if (!resolved.startsWith(pkgRoot + path.sep) && resolved !== pkgRoot) {
                offenders.push(`${rel}: imports '${spec}' which escapes the package root`);
            }
        }
    }
    assert.deepEqual(offenders, [], `package-root escapes found:\n${offenders.join('\n')}`);
});
test('every shipped bare import is declared as an exact runtime dependency', () => {
    const shippedJs = (pkg.files || []).filter((f) => f.endsWith('.js') || f.endsWith('.mjs'));
    const offenders = [];
    for (const rel of shippedJs) {
        const abs = path.join(pkgRoot, rel);
        if (!fs.existsSync(abs))
            continue;
        const src = fs.readFileSync(abs, 'utf8');
        for (const match of src.matchAll(IMPORT_RE)) {
            const specifier = match[1];
            if (specifier.startsWith('.') || specifier.startsWith('node:'))
                continue;
            const packageName = specifier.startsWith('@')
                ? specifier.split('/').slice(0, 2).join('/')
                : specifier.split('/')[0];
            const version = pkg.dependencies?.[packageName];
            if (typeof version !== 'string' || !/^\d+\.\d+\.\d+$/.test(version)) {
                offenders.push(`${rel}: imports undeclared or unpinned runtime package '${packageName}'`);
            }
        }
    }
    assert.deepEqual(offenders, [], `runtime dependency defects found:\n${offenders.join('\n')}`);
});
test('the package-local strict JSON gate matches the shared carrier gate byte-for-byte', () => {
    const local = fs.readFileSync(path.join(pkgRoot, 'strict-json.js'), 'utf8');
    const shared = fs.readFileSync(path.join(pkgRoot, '../require-receipt/strict-json.js'), 'utf8');
    assert.equal(local, shared);
});
