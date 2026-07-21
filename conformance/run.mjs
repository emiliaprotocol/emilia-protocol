// SPDX-License-Identifier: Apache-2.0
// Generated from run.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Cross-language conformance runner.
//
// Runs the SAME canonical vectors through the three cross-language reference
// verifiers — JavaScript, Python, and Go (one team's ports, a consistency check,
// NOT clean-room independent reimplementations) — and asserts they all agree
// with each other and with the expected outcome, across every suite. Exit 1 on
// any divergence. Suites (see the SUITES list below for the full set): receipts,
// signoffs, quorum, revocation, time-attestation, trust-receipt, provenance,
// evidence-record, canonicalization, boundary, AEC acceptance, and the opt-in profiles currency,
// initiator-attestation, consumption-proof, witness, and timestamp-proof.
//
// timestamp-proof (RFC 3161) is now in the cross-language runner: the JS minimal
// DER/CMS reader was ported faithfully to Python (pure-Python DER reader +
// `cryptography` for the RSA/ECDSA verify) and Go (pure-stdlib DER reader +
// crypto/rsa|ecdsa), so all three lanes agree over openssl-minted TimeStampTokens
// (see CONFORMANCE.md and conformance/vectors/timestamp-proof.v1.json).
//
//   node conformance/run.mjs
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { LIVE_SUITE_FILES } from './suites.mjs';
import { buildSuiteContract, compareResultRow, executionSuiteFile, validateResultRows, } from './result-contract.mjs';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SUITES = LIVE_SUITE_FILES;
const IMPLS = [
    { lang: 'JavaScript', run: (p) => execFileSync('node', ['conformance/runners/run-js.mjs', p], { cwd: root, encoding: 'utf8' }) },
    { lang: 'Python', run: (p) => execFileSync('python3', ['conformance/runners/run_py.py', p], { cwd: root, encoding: 'utf8' }) },
    { lang: 'Go', run: (p) => execFileSync('go', ['run', './cmd/conformance', p], { cwd: resolve(root, 'packages/go-verify'), encoding: 'utf8' }) },
];
const pad = (s, n) => String(s).padEnd(n);
const expectationLabel = (expect) => {
    if (typeof expect.valid === 'boolean')
        return expect.valid ? 'valid' : 'reject';
    if (typeof expect.outcome === 'string')
        return expect.outcome;
    if (typeof expect.verdict === 'string')
        return expect.verdict;
    if (typeof expect.accepted === 'boolean')
        return expect.accepted ? 'accepted' : 'refused';
    return 'typed';
};
const ALL_IMPLS = IMPLS.map((i) => i.lang);
let totalFailures = 0;
let anyRan = false;
const completedSuites = [];
// Track every impl that was skipped in ANY suite. The "three independent
// implementations agree" claim is only honest if all three actually ran on
// every suite — a skipped impl (e.g. missing go/python) must FAIL the run, not
// be silently papered over. (MED audit finding: over-claimed conformance.)
const missingImpls = new Set();
for (const suiteFile of SUITES) {
    const vectorsPath = resolve(root, 'conformance/vectors', suiteFile);
    const executionFile = executionSuiteFile(suiteFile);
    const executionPath = resolve(root, 'conformance/vectors', executionFile);
    let suite;
    let executionSuite;
    try {
        suite = JSON.parse(readFileSync(vectorsPath, 'utf8'));
        executionSuite = executionFile === suiteFile
            ? suite
            : JSON.parse(readFileSync(executionPath, 'utf8'));
    }
    catch {
        console.log(`\n⚠ ${suiteFile}: not found — skipped`);
        continue;
    }
    const contract = buildSuiteContract(suiteFile, suite, executionSuite);
    const results = {};
    const ran = [];
    for (const impl of IMPLS) {
        try {
            results[impl.lang] = validateResultRows(contract, JSON.parse(impl.run(executionPath)));
            ran.push(impl.lang);
        }
        catch (e) {
            console.log(`  ⚠ ${impl.lang}: skipped (${(e.message || '').split('\n')[0]})`);
            missingImpls.add(impl.lang);
        }
    }
    console.log(`\n${suite.suite || suiteFile} — ${suite.vectors.length} vectors`);
    if (ran.length === 0) {
        console.log('  (no implementations ran)');
        totalFailures++;
        continue;
    }
    anyRan = true;
    completedSuites.push(suite.suite || suiteFile);
    const head = `  ${pad('vector', 48)}${pad('expect', 16)}${ran.map((l) => pad(l, 12)).join('')}`;
    console.log(head);
    console.log('  ' + '─'.repeat(head.length - 2));
    for (const v of suite.vectors) {
        const exp = contract.expectations.get(v.id);
        const cells = ran.map((lang) => {
            const comparison = compareResultRow(contract, results[lang].get(v.id));
            return comparison.ok ? '✓' : `✗(${comparison.detail})`;
        });
        if (!cells.every((c) => c === '✓'))
            totalFailures++;
        console.log(`  ${pad(v.id, 48)}${pad(expectationLabel(exp), 16)}${ran.map((l, i) => pad(cells[i], 12)).join('')}`);
    }
}
if (!anyRan) {
    console.error('\nNo implementations ran.');
    process.exit(1);
}
if (totalFailures > 0) {
    console.log(`\n❌ ${totalFailures} divergence(s) across implementations — NOT conformant`);
    process.exit(1);
}
// No divergences — but a green run with a MISSING impl is NOT the multi-impl
// interop claim. Fail rather than over-claim "three independent implementations
// agree" when one (or more) never ran.
if (missingImpls.size > 0) {
    const ran = ALL_IMPLS.filter((l) => !missingImpls.has(l));
    console.error(`\n❌ incomplete: only ${ran.length}/${ALL_IMPLS.length} implementations ran (${ran.join(', ') || 'none'}). `
        + `Missing: ${[...missingImpls].join(', ')}. `
        + `Vectors agreed where run, but the cross-language interop claim requires all ${ALL_IMPLS.length} — install the missing toolchain(s) and re-run.`);
    process.exit(1);
}
console.log(`\n✅ all ${completedSuites.length} suites (${completedSuites.join(' · ')}) — all ${ALL_IMPLS.length} cross-language implementations (${ALL_IMPLS.join(', ')}) agree. One team, one repository: a consistency check, not independent reimplementations.`);
process.exit(0);
