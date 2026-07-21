// SPDX-License-Identifier: Apache-2.0
// Generated from invariants.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Wraps the TLA+-invariant conformance runner (JS lane) as a vitest suite so the
// invariant corpus is exercised in the normal test run, not only in CI's
// standalone step. Each case drives the REAL production capability store and the
// REAL handshake invariant functions; a mismatch fails the suite.
//
// The runner is a standalone ESM CLI (it calls module.register + process.exit),
// so we invoke it as a subprocess and assert on its exit code and JSON report,
// rather than importing it (importing would call process.exit and register a
// loader inside the vitest worker).
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
const here = dirname(fileURLToPath(import.meta.url));
const runner = resolve(here, 'runners', 'run-invariants.mjs');
const root = resolve(here, '..');
function runInvariants() {
    const out = execFileSync('node', [runner, '--json'], { cwd: root, encoding: 'utf8' });
    return JSON.parse(out);
}
describe('CONFORMANCE: TLA+-invariant cases (JS lane, real store + guards)', () => {
    const results = runInvariants();
    it('runs a non-trivial number of invariant cases', () => {
        expect(results.length).toBeGreaterThanOrEqual(20);
    });
    for (const r of results) {
        it(`${r.id} holds (${r.spec})`, () => {
            expect(r.status, r.detail || '').toBe('hold');
        });
    }
    it('a mutated expectation is detected as a divergence (runner is not vacuous)', () => {
        // Sanity: flipping an expected refusal to a success must make the runner
        // report a divergence and exit non-zero.
        let exitCode = 0;
        try {
            execFileSync('node', ['-e', `
        const { execFileSync } = require('node:child_process');
        const fs = require('node:fs');
        const os = require('node:os');
        const path = require('node:path');
        const c = JSON.parse(fs.readFileSync(${JSON.stringify(resolve(root, 'conformance', 'invariants.json'))}, 'utf8'));
        c.invariants[0].cases[0].actions[2].expect = { ok: true };
        const p = path.join(os.tmpdir(), 'ep-invariant-mutant-' + process.pid + '.json');
        fs.writeFileSync(p, JSON.stringify(c));
        try {
          execFileSync('node', [${JSON.stringify(runner)}, p], { cwd: ${JSON.stringify(root)}, stdio: 'ignore' });
          process.exit(0);
        } catch (e) { process.exit(e.status || 1); }
        finally { try { fs.unlinkSync(p); } catch {} }
      `], { cwd: root, stdio: 'ignore' });
        }
        catch (e) {
            exitCode = e.status || 1;
        }
        expect(exitCode).toBe(1);
    });
});
