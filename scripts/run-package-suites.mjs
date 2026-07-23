// SPDX-License-Identifier: Apache-2.0
// Generated from run-package-suites.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Runs the standalone package suites that no other CI job covers.
//
// The failure mode this exists to prevent: an explicit file list in ci.yml
// silently dropped 8 of 11 verify suites until 2026-07-02, and eight whole
// packages (langchain, openai-guard, openai-agents, scan, ep-verify,
// crash-test, fire-drill, fire-drill-mcp) ran in NO runner until 2026-07-19.
// Both are the same bug: coverage was enumerated, so anything added later was
// born ungated.
//
// The rule here is inverted. Discovery is the default: every packages/* that
// declares a `test` script IS RUN unless it appears in COVERED_ELSEWHERE with
// a reason. A new package with tests is therefore gated the moment it lands —
// nobody has to remember to add it. Dropping one requires writing down which
// job took over, and a stale entry (package or its test script gone) fails
// this script rather than quietly shrinking coverage.
//
// Each package is invoked through its own `npm test`, not a root-level glob,
// so the package's declared entrypoint stays authoritative. That matters:
// `node --test packages/gate/*.test.js` collects 533 tests while gate's own
// bare `node --test` collects 645, because the glob misses `test.js` files and
// subdirectory suites.
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
const PACKAGES_DIR = fileURLToPath(new URL('../packages/', import.meta.url));
/**
 * Packages deliberately not run here, each mapped to the job that does run it.
 * Adding an entry is a coverage handoff, never a deletion.
 */
const COVERED_ELSEWHERE = {
    verify: 'ci.yml — "Verify package suites (node:test)" step',
    issue: 'ci.yml — "Verify package suites (node:test)" step',
    attest: 'ci.yml — "Verify package suites (node:test)" step',
    'require-receipt': 'ci.yml — "Verify package suites (node:test)" step',
    gate: 'ci.yml — gate-product job (npm test + SQL/Helm/Terraform/image checks)',
    'dtc-base': 'dtc-base.yml — isolated lockfile install plus the full public experimental source gate',
    // packages/mobile is deliberately NOT excluded. mobile-apps.yml does run it,
    // but only under a path filter (app/.well-known, app/api/v1/mobile,
    // app/mobile, packages/mobile). Mobile consumes the workspace-linked
    // @emilia-protocol/verify package, so a change to Verify can break it without
    // touching any filtered path. Running it here on every push closes that
    // cross-package hole.
    // Its test script shells back to the root vitest run, which the `test` job
    // already performs; running it here would duplicate that whole invocation.
    'mcp-guard': 'ci.yml — root vitest run (tests/mcp-guard-boundary.test.js)',
};
/** Returns package directory names that declare a test script. */
function discoverTestablePackages() {
    const names = [];
    for (const entry of readdirSync(PACKAGES_DIR, { withFileTypes: true })) {
        if (!entry.isDirectory())
            continue;
        let manifest;
        try {
            manifest = JSON.parse(readFileSync(join(PACKAGES_DIR, entry.name, 'package.json'), 'utf8'));
        }
        catch {
            continue; // No package.json (Python/Go packages carry their own runners).
        }
        if (manifest.scripts?.test)
            names.push(entry.name);
    }
    return names.sort();
}
const testable = discoverTestablePackages();
const testableSet = new Set(testable);
// A stale exclusion is a silent coverage hole: the package it pointed at is
// gone or stopped declaring tests, so the handoff it documents no longer holds.
const stale = Object.keys(COVERED_ELSEWHERE).filter((name) => !testableSet.has(name));
if (stale.length > 0) {
    console.error(`COVERED_ELSEWHERE lists ${stale.join(', ')}, which no longer declare a test script.\n` +
        'Remove the entry, or restore the suite it was standing in for.');
    process.exit(1);
}
const toRun = testable.filter((name) => !(name in COVERED_ELSEWHERE));
console.log(`Running ${toRun.length} package suite(s): ${toRun.join(', ')}`);
const failed = [];
for (const name of toRun) {
    console.log(`\n─── packages/${name} ───`);
    try {
        execFileSync('npm', ['test', '--prefix', join(PACKAGES_DIR, name)], { stdio: 'inherit' });
    }
    catch {
        failed.push(name);
    }
}
if (failed.length > 0) {
    console.error(`\nFAIL — package suite(s) failed: ${failed.join(', ')}`);
    process.exit(1);
}
console.log(`\nOK — ${toRun.length} package suite(s) passed.`);
