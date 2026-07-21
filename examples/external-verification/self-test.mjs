// SPDX-License-Identifier: Apache-2.0
// Generated from self-test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// End-to-end self-test for the external-verification harness.
//
//   node examples/external-verification/self-test.mjs
//
// Everything runs in a throwaway temp directory; no key material or output
// ever touches the repository tree. Not wired into CI on purpose.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { MODE_A_PROCEDURE, MODE_B_PROCEDURE, REFERENCE_RUNNER_LIMITATION, Refusal, buildModeBStatementArgs, compareSuiteResults, loadResults, loadSuite, referenceRunnerSuites, suiteNameForResultsFile, } from './sign-statement.mjs';
import { EXACT_EXTERNAL_RESULT_KINDS, LIVE_SUITE_FILES, } from '../../conformance/suites.mjs';
import { externalVerificationDigest } from '../../packages/gate/reports/external-verification.js';
import { signExternalVerificationStatement, verifyExternalVerificationStatement, } from '../../packages/gate/reports/external-verification.js';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const NODE = process.execPath;
const SUITES_UNDER_TEST = ['receipts.v1.json', 'signoffs.v1.json'];
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-external-verification-selftest-'));
let passed = 0;
const ok = (name) => { passed++; process.stdout.write(`  ok ${passed}: ${name}\n`); };
try {
    // 1. generate-key.mjs mints a keypair into the temp dir.
    const keyDir = path.join(tmp, 'keys');
    execFileSync(NODE, [path.join(HERE, 'generate-key.mjs'), '--out', keyDir], { encoding: 'utf8' });
    const privatePath = path.join(keyDir, 'private-key.pem');
    const publicPath = path.join(keyDir, 'public.key');
    assert.ok(fs.existsSync(privatePath) && fs.existsSync(publicPath));
    const publicB64u = fs.readFileSync(publicPath, 'utf8').trim();
    crypto.createPublicKey({ key: Buffer.from(publicB64u, 'base64url'), type: 'spki', format: 'der' });
    ok('generate-key mints an Ed25519 keypair (PKCS8 PEM + SPKI base64url)');
    // 2. Re-running without --force refuses with the distinct key_exists reason.
    const rerun = spawnSync(NODE, [path.join(HERE, 'generate-key.mjs'), '--out', keyDir], { encoding: 'utf8' });
    assert.equal(rerun.status, 1);
    assert.match(rerun.stderr, /REFUSED \(key_exists\)/);
    ok('generate-key refuses to overwrite an existing key without --force');
    // 3. Fabricate CORRECT results for two real suites (valid taken from
    //    expect.valid, so the comparison passes) and sign MODE A.
    const resultsDir = path.join(tmp, 'results');
    fs.mkdirSync(resultsDir);
    for (const suiteFile of SUITES_UNDER_TEST) {
        const suite = loadSuite(suiteFile);
        const rows = [...suite.vectors.entries()].map(([id, valid]) => ({ id, valid }));
        fs.writeFileSync(path.join(resultsDir, `${suiteFile}.results.json`), JSON.stringify(rows, null, 2));
    }
    const signArgs = [
        path.join(HERE, 'sign-statement.mjs'),
        '--results', resultsDir,
        '--key', privatePath,
        '--out', tmp,
        '--verifier-id', 'ext:verifier:self-test',
        '--verifier-name', 'Harness Self-Test',
        '--org', 'example',
        '--implementation', 'fabricated-from-expect.valid (self-test only)',
    ];
    const signOut = execFileSync(NODE, signArgs, { encoding: 'utf8' });
    assert.match(signOut, /statement_digest: sha256:[0-9a-f]{64}/);
    const statementPath = path.join(tmp, 'statement.json');
    const statement = JSON.parse(fs.readFileSync(statementPath, 'utf8'));
    assert.equal(statement.procedure.id, MODE_A_PROCEDURE.id);
    assert.equal(statement.procedure.version, MODE_A_PROCEDURE.version);
    assert.equal(statement.result.status, 'verified');
    assert.equal(statement.result.checks.length, SUITES_UNDER_TEST.length);
    assert.ok(statement.result.checks.every((c) => c.ok));
    assert.equal(statement.subject.kind, 'conformance_vector_pack');
    assert.equal(statement.subject.suites, SUITES_UNDER_TEST.length);
    assert.equal(statement.inputs.implementation, 'fabricated-from-expect.valid (self-test only)');
    for (const suiteFile of SUITES_UNDER_TEST) {
        assert.match(statement.inputs.suite_digests[suiteFile], /^sha256:[0-9a-f]{64}$/);
    }
    ok('MODE A signs a verified statement over correct results for 2 real suites');
    // 4. verify-statement accepts it under the pinned public key.
    const verifyOut = execFileSync(NODE, [
        path.join(HERE, 'verify-statement.mjs'), statementPath, '--pin', publicPath,
        '--verifier-id', 'ext:verifier:self-test',
    ], { encoding: 'utf8' });
    assert.match(verifyOut, /ACCEPTED under the pinned key/);
    ok('verify-statement accepts the statement under the pinned key (exit 0)');
    // 5. A wrong pin is rejected (exit 1).
    const otherKey = crypto.generateKeyPairSync('ed25519')
        .publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const badVerify = spawnSync(NODE, [
        path.join(HERE, 'verify-statement.mjs'), statementPath, '--pin', otherKey,
        '--verifier-id', 'ext:verifier:self-test',
    ], { encoding: 'utf8' });
    assert.equal(badVerify.status, 1);
    assert.match(badVerify.stderr, /verifier_key_not_pinned/);
    ok('verify-statement rejects the statement under a different pinned key (exit 1)');
    // 6. Tamper one reported result, re-sign, and the fresh statement honestly
    //    reports divergent status (and still verifies: divergence is a finding).
    const tamperedFile = path.join(resultsDir, `${SUITES_UNDER_TEST[0]}.results.json`);
    const rows = JSON.parse(fs.readFileSync(tamperedFile, 'utf8'));
    rows[0].valid = !rows[0].valid;
    fs.writeFileSync(tamperedFile, JSON.stringify(rows, null, 2));
    execFileSync(NODE, signArgs, { encoding: 'utf8' });
    const divergent = JSON.parse(fs.readFileSync(statementPath, 'utf8'));
    assert.equal(divergent.result.status, 'divergent');
    const flipped = divergent.result.checks.find((c) => c.id === SUITES_UNDER_TEST[0]);
    const suite0 = loadSuite(SUITES_UNDER_TEST[0]);
    assert.equal(flipped.ok, false);
    assert.equal(flipped.detail, `${suite0.vectors.size - 1}/${suite0.vectors.size}`);
    const divergentVerify = verifyExternalVerificationStatement(divergent, {
        pinnedVerifierKeys: [{ verifier_id: 'ext:verifier:self-test', public_key: publicB64u }],
    });
    assert.equal(divergentVerify.accepted, true);
    assert.notEqual(divergent.signature.statement_digest, statement.signature.statement_digest);
    ok('tampered result re-signs as an honestly divergent (still verifiable) statement');
    // 7. MODE A structural refusals are distinct and fail closed.
    const suite = loadSuite(SUITES_UNDER_TEST[0]);
    const good = new Map([...suite.vectors.entries()]);
    const missing = new Map(good);
    missing.delete([...good.keys()][0]);
    assert.throws(() => compareSuiteResults(suite, missing), (e) => e instanceof Refusal && e.reason === 'missing_vector_ids');
    const extra = new Map(good);
    extra.set('vector_that_does_not_exist', true);
    assert.throws(() => compareSuiteResults(suite, extra), (e) => e instanceof Refusal && e.reason === 'unknown_vector_ids');
    assert.throws(() => loadSuite('no-such-suite.v1.json'), (e) => e instanceof Refusal && e.reason === 'unknown_suite');
    assert.throws(() => suiteNameForResultsFile('receipts.v1.json'), (e) => e instanceof Refusal && e.reason === 'results_filename_invalid');
    const typedOutcomeSuite = loadSuite('outcome-binding.v1.json');
    assert.equal(typedOutcomeSuite.vectors.get('eq_pass'), true);
    assert.equal(typedOutcomeSuite.vectors.get('eq_fail_divergent'), false);
    assert.equal(typedOutcomeSuite.vectors.get('graph_predicates_in_bounds_admissible'), true);
    const typedResultsPath = path.join(tmp, 'outcome-binding.v1.json.results.json');
    const typedRows = typedOutcomeSuite.json.vectors.map((vector) => ({
        id: vector.id,
        ...(typeof vector.expect.outcome === 'string'
            ? { outcome: vector.expect.outcome }
            : typeof vector.expect.verdict === 'string'
                ? { verdict: vector.expect.verdict }
                : { valid: vector.expect.valid }),
    }));
    fs.writeFileSync(typedResultsPath, JSON.stringify(typedRows, null, 2));
    const typedResults = loadResults(typedResultsPath).results;
    assert.equal(compareSuiteResults(typedOutcomeSuite, typedResults).ok, true);
    const normalizedOnly = new Map([...typedOutcomeSuite.vectors.entries()].map(([id, valid]) => [id, valid]));
    assert.throws(() => compareSuiteResults(typedOutcomeSuite, normalizedOnly), (e) => e instanceof Refusal && e.reason === 'typed_result_required');
    for (const [suiteFile, kind] of Object.entries(EXACT_EXTERNAL_RESULT_KINDS)) {
        const exactSuite = loadSuite(suiteFile);
        const exactResultsPath = path.join(tmp, `${suiteFile}.results.json`);
        const exactRows = exactSuite.json.vectors.map((vector) => ({
            id: vector.id,
            ...vector.expect,
        }));
        fs.writeFileSync(exactResultsPath, JSON.stringify(exactRows, null, 2));
        assert.equal(compareSuiteResults(exactSuite, loadResults(exactResultsPath).results).ok, true, suiteFile);
        const reducedRows = exactSuite.json.vectors.map((vector) => ({
            id: vector.id,
            [kind]: vector.expect[kind],
        }));
        fs.writeFileSync(exactResultsPath, JSON.stringify(reducedRows, null, 2));
        assert.equal(compareSuiteResults(exactSuite, loadResults(exactResultsPath).results).ok, false, `${suiteFile}: reduced primary result must diverge`);
        const malformedRows = structuredClone(exactRows);
        malformedRows[0].result_digest = 'not-a-digest';
        fs.writeFileSync(exactResultsPath, JSON.stringify(malformedRows, null, 2));
        assert.throws(() => loadResults(exactResultsPath), (e) => e instanceof Refusal && e.reason === 'malformed_results_entry', `${suiteFile}: malformed digest must refuse`);
    }
    const exactOutcomeSuite = loadSuite('outcome-binding.exec.v1.json');
    const booleanOnlyOutcomePath = path.join(tmp, 'outcome-binding.exec.v1.json.results.json');
    fs.writeFileSync(booleanOnlyOutcomePath, JSON.stringify(exactOutcomeSuite.json.vectors.map((vector) => ({ id: vector.id, valid: vector.expect.valid })), null, 2));
    assert.throws(() => compareSuiteResults(exactOutcomeSuite, loadResults(booleanOnlyOutcomePath).results), (e) => e instanceof Refusal && e.reason === 'typed_result_required');
    assert.deepEqual(referenceRunnerSuites(), [...LIVE_SUITE_FILES]);
    ok('MODE A requires complete typed checks, reasons, and digests for exact-result suites');
    // 8. MODE B labeling, WITHOUT executing the reference runner: the factored
    //    builder is fed a fabricated green runner outcome and must carry the
    //    reference-runner limitation and the distinct procedure id/version.
    const suiteEntries = SUITES_UNDER_TEST.map((f) => ({ suite: loadSuite(f) }));
    const modeBArgs = buildModeBStatementArgs({
        suiteEntries,
        runner: { command: 'node conformance/run.mjs', exit_code: 0, output: '(fabricated for self-test; runner not executed)' },
        verifier: { id: 'ext:verifier:self-test' },
        commit: 'unknown',
    });
    assert.equal(modeBArgs.procedure.id, MODE_B_PROCEDURE.id);
    assert.equal(modeBArgs.procedure.version, MODE_B_PROCEDURE.version);
    assert.notEqual(MODE_B_PROCEDURE.id, MODE_A_PROCEDURE.id);
    assert.ok(modeBArgs.limitations.includes(REFERENCE_RUNNER_LIMITATION));
    assert.match(REFERENCE_RUNNER_LIMITATION, /NOT an independent implementation/);
    assert.equal(modeBArgs.result.status, 'verified');
    const privateKey = crypto.createPrivateKey(fs.readFileSync(privatePath, 'utf8'));
    const modeBStatement = signExternalVerificationStatement(modeBArgs, privateKey);
    assert.ok(modeBStatement.limitations.includes(REFERENCE_RUNNER_LIMITATION));
    assert.equal(verifyExternalVerificationStatement(modeBStatement, {
        pinnedVerifierKeys: [{ verifier_id: 'ext:verifier:self-test', public_key: publicB64u }],
    }).accepted, true);
    assert.equal(verifyExternalVerificationStatement(modeBStatement, {
        pinnedVerifierKeys: [{ public_key: publicB64u }],
    }).reason, 'pin_missing_or_mismatched_verifier_id');
    ok('MODE B statement carries the reference-runner limitation (no subprocess executed)');
    // 9. MODE B fails closed on an incomplete reference run (missing toolchain).
    assert.throws(() => buildModeBStatementArgs({
        suiteEntries,
        runner: { command: 'node conformance/run.mjs', exit_code: 1, output: '❌ incomplete: only 2/3 implementations ran (JavaScript, Python).' },
        verifier: { id: 'ext:verifier:self-test' },
        commit: 'unknown',
    }), (e) => e instanceof Refusal && e.reason === 'reference_runner_incomplete');
    ok('MODE B refuses to sign an incomplete reference run (reference_runner_incomplete)');
    // 10. Golden digest test vector reproduces. This is the #1 independent-integration
    //     wall: a signer that builds the digest differently produces a statement that
    //     will never verify. digest-test-vector.json lets any implementer check their
    //     construction in isolation; this asserts it stays authoritative on our side.
    const goldenPath = path.join(path.dirname(fileURLToPath(import.meta.url)), 'digest-test-vector.json');
    const golden = JSON.parse(fs.readFileSync(goldenPath, 'utf8'));
    assert.equal(externalVerificationDigest(golden.statement), golden.expected_statement_digest, 'digest-test-vector.json expected_statement_digest is stale — regenerate it');
    ok('golden statement_digest test vector reproduces (digest-test-vector.json)');
    process.stdout.write(`\nself-test PASS (${passed} checks)\n`);
}
finally {
    fs.rmSync(tmp, { recursive: true, force: true });
}
