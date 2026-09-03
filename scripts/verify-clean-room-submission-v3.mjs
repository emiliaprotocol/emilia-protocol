#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from verify-clean-room-submission-v3.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';
import { canonicalizeV2, loadPinnedKitV2, sha256V2, validateBundleDefinitionV2, verifyIndependentAttestationV2, verifyRunnerArtifactV2, verifySubmissionManifestV2, } from './verify-clean-room-submission-v2.mjs';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BUNDLE_RELATIVE_PATH = 'conformance/clean-room/v3/bundle.v3.json';
const HANDLE_PATTERN = /^cr3_[A-Za-z0-9_-]{32}$/;
const CHALLENGE_GENERATOR = 'EP-CLEAN-ROOM-CANONICALIZATION-CHALLENGE-v1';
const CHALLENGE_PAIR_COUNT = 32;
const SESSION_RANDOMIZER = 'EP-CLEAN-ROOM-SESSION-RANDOMIZER-v1';
function plainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function errorMessage(error) {
    return error instanceof Error ? error.message : String(error);
}
function readJson(target, label) {
    try {
        const bytes = fs.readFileSync(target);
        const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        return { bytes, value: JSON.parse(text) };
    }
    catch (error) {
        throw new Error(`${label} is not valid UTF-8 JSON: ${errorMessage(error)}`);
    }
}
export const sha256V3 = sha256V2;
export const canonicalizeV3 = canonicalizeV2;
function canonicalDigest(value) {
    return sha256V3(Buffer.from(canonicalizeV3(value), 'utf8'));
}
function containsObjectKey(value, forbidden) {
    if (Array.isArray(value))
        return value.some((entry) => containsObjectKey(entry, forbidden));
    if (!plainObject(value))
        return false;
    if (Object.hasOwn(value, forbidden))
        return true;
    return Object.values(value).some((entry) => containsObjectKey(entry, forbidden));
}
export function validateBundleDefinitionV3(bundle) {
    if (!plainObject(bundle)
        || bundle['@version'] !== 'EP-CLEAN-ROOM-VECTOR-BUNDLE-v3') {
        throw new Error('unsupported clean-room vector bundle');
    }
    if (!plainObject(bundle.runner_protocol)
        || bundle.runner_protocol.version !== 'EP-CONFORMANCE-FILE-RUNNER-v3'
        || bundle.runner_protocol.invocation
            !== 'runner [fixed arguments...] /absolute/path/to/execution-suite.v3.json'
        || bundle.runner_protocol.result_shape
            !== 'array<{handle:string,result:object}>'
        || bundle.runner_protocol.result_comparison
            !== 'evaluator-side complete typed object after opaque-handle resolution'
        || bundle.runner_protocol.complete_suite_required !== true) {
        throw new Error('bundle runner protocol is not the expectation-separated v3 protocol');
    }
    // The v3 evaluation revision intentionally keeps the exact published v2
    // corpus pins. Projecting only the versioned runner contract through the v2
    // validator prevents a silent suite, count, or hash change.
    const projected = structuredClone(bundle);
    projected['@version'] = 'EP-CLEAN-ROOM-VECTOR-BUNDLE-v2';
    projected.runner_protocol.version = 'EP-CONFORMANCE-FILE-RUNNER-v2';
    projected.runner_protocol.result_shape = 'array<{id:string,result:object}>';
    validateBundleDefinitionV2(projected);
}
export function loadPinnedKitV3({ root = ROOT } = {}) {
    const absoluteRoot = path.resolve(root);
    const bundlePath = path.join(absoluteRoot, BUNDLE_RELATIVE_PATH);
    const { bytes: bundleBytes, value: bundle } = readJson(bundlePath, 'v3 vector bundle');
    validateBundleDefinitionV3(bundle);
    const baseKit = loadPinnedKitV2({ root: absoluteRoot });
    if (!isDeepStrictEqual(bundle.source_manifest, baseKit.bundle.source_manifest)
        || !isDeepStrictEqual(bundle.suites, baseKit.bundle.suites)
        || !isDeepStrictEqual(bundle.totals, baseKit.bundle.totals)) {
        throw new Error('v3 evaluation bundle drifted from the pinned v2 corpus');
    }
    return {
        root: absoluteRoot,
        bundle,
        bundleSha256: sha256V3(bundleBytes),
        sourceManifestSha256: baseKit.sourceManifestSha256,
        sourceManifestClaimSha256: baseKit.sourceManifestClaimSha256,
        authorityExecutionCompanionSha256: baseKit.authorityExecutionCompanionSha256,
        contracts: baseKit.contracts,
        baseKit,
    };
}
export function verifySubmissionManifestV3(manifest, kit) {
    if (!plainObject(manifest)
        || manifest['@version'] !== 'EP-CLEAN-ROOM-SUBMISSION-v3') {
        throw new Error('unsupported clean-room submission version');
    }
    if (manifest.runner?.protocol !== 'EP-CONFORMANCE-FILE-RUNNER-v3') {
        throw new Error('submission runner protocol is not v3');
    }
    if (manifest.kit?.vector_bundle_sha256 !== kit.bundleSha256) {
        throw new Error('submission vector bundle hash does not match the v3 evaluator');
    }
    const projected = structuredClone(manifest);
    projected['@version'] = 'EP-CLEAN-ROOM-SUBMISSION-v2';
    projected.runner.protocol = 'EP-CONFORMANCE-FILE-RUNNER-v2';
    projected.kit.vector_bundle_sha256 = kit.baseKit.bundleSha256;
    verifySubmissionManifestV2(projected, kit.baseKit);
}
function executionInput(vector) {
    const input = structuredClone(vector);
    for (const field of [
        'id',
        'expect',
        'description',
        'failure_class',
        'reason',
        'mutation',
    ]) {
        delete input[field];
    }
    // In this suite `note` is test commentary, not verifier input. Other nested
    // note fields can be signed protocol material and therefore remain intact.
    if (plainObject(input.canonicalization))
        delete input.canonicalization.note;
    return input;
}
function evaluatorCase(contract, vector, expected) {
    const input = executionInput(vector);
    if (contract.path !== 'conformance/vectors/currency.v2.json') {
        return { input, expected };
    }
    const expectedStatus = vector.currency?.expect_status;
    if (typeof expectedStatus !== 'string' || expectedStatus === '') {
        throw new Error(`${contract.path}: currency case is missing its evaluator status`);
    }
    if (!plainObject(input.currency)) {
        throw new Error(`${contract.path}: currency execution input is malformed`);
    }
    delete input.currency.expect_status;
    return {
        input,
        expected: { currency_status: expectedStatus },
    };
}
function suiteMetadata(executionSuite) {
    const metadata = {
        id: executionSuite.suite,
        vectors_version: executionSuite.vectors_version,
    };
    if (Object.hasOwn(executionSuite, 'algorithm')) {
        metadata.algorithm = structuredClone(executionSuite.algorithm);
    }
    if (Object.hasOwn(executionSuite, 'common')) {
        metadata.common = structuredClone(executionSuite.common);
    }
    return metadata;
}
function opaqueToken(prefix, randomBytes) {
    return `${prefix}_${randomBytes(24).toString('base64url')}`;
}
function shuffled(values, randomBytes) {
    return values
        .map((value) => ({ value, order: randomBytes(24) }))
        .sort((left, right) => Buffer.compare(left.order, right.order))
        .map(({ value }) => value);
}
function randomizerContract(domain) {
    return {
        '@version': domain,
        seed_bytes: 32,
        counter_initial: 0,
        block: 'SHA-256(UTF8(domain) || 0x00 || seed || uint64be(counter))',
        request_rule: 'concatenate successive 32-byte blocks, return the requested prefix, and discard any unused suffix',
    };
}
function challengeGeneratorContract() {
    return {
        '@version': CHALLENGE_GENERATOR,
        randomizer: randomizerContract(CHALLENGE_GENERATOR),
        pair_count: CHALLENGE_PAIR_COUNT,
        payload_per_pair: '{"value":base64url(random_bytes(24)),"nested":[true,null,zero_based_pair_index]}',
        input_json: 'JSON.stringify(payload)',
        canonicalization: 'RFC 8785 compatible canonicalizeV3(JSON.parse(input_json))',
        correct_digest: 'lowercase_hex(SHA-256(UTF8(canonicalization)))',
        wrong_digest: 'lowercase_hex(random_bytes(32)), resampled only if equal to the correct digest',
        cases_per_pair: 'one correct-digest case and one wrong-digest case over the exact same input_json',
        handles: 'base64url(random_bytes(24)) prefixed with cr3_',
        run_id: 'base64url(random_bytes(24)) prefixed with run_',
        presentation_order: 'sort cases by independent random_bytes(24) values',
    };
}
function deterministicRandomBytes(seed, domain) {
    if (seed.length !== 32)
        throw new Error('randomizer seed must contain exactly 32 bytes');
    let counter = 0;
    return (size) => {
        const chunks = [];
        let length = 0;
        while (length < size) {
            const encodedCounter = Buffer.alloc(8);
            encodedCounter.writeBigUInt64BE(BigInt(counter));
            counter += 1;
            const chunk = crypto.createHash('sha256')
                .update(domain, 'utf8')
                .update(Buffer.from([0]))
                .update(seed)
                .update(encodedCounter)
                .digest();
            chunks.push(chunk);
            length += chunk.length;
        }
        return Buffer.concat(chunks).subarray(0, size);
    };
}
function buildSession(contract, cases, randomBytes) {
    const parsed = readJsonFromBytes(contract.executionBytes, contract.executionPath);
    const bindings = new Map();
    const entries = cases.map((entry) => {
        let handle;
        do
            handle = opaqueToken('cr3', randomBytes);
        while (bindings.has(handle));
        bindings.set(handle, { sourceId: entry.sourceId, expected: entry.expected });
        return {
            handle,
            input: entry.input,
        };
    });
    const executionSuite = {
        '@version': 'EP-CLEAN-ROOM-EXECUTION-SUITE-v3',
        runner_protocol: 'EP-CONFORMANCE-FILE-RUNNER-v3',
        run_id: opaqueToken('run', randomBytes),
        suite: suiteMetadata(parsed),
        vectors: shuffled(entries, randomBytes),
    };
    for (const forbidden of ['expect', 'expect_status']) {
        if (containsObjectKey(executionSuite, forbidden)) {
            throw new Error(`${contract.path}: v3 runner input contains forbidden expectation field ${forbidden}`);
        }
    }
    const executionBytes = Buffer.from(`${JSON.stringify(executionSuite)}\n`, 'utf8');
    return { executionSuite, executionBytes, bindings };
}
function readJsonFromBytes(bytes, label) {
    try {
        const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
        if (!plainObject(value))
            throw new Error('top level is not an object');
        return value;
    }
    catch (error) {
        throw new Error(`${label} is not valid UTF-8 JSON: ${errorMessage(error)}`);
    }
}
export function buildExecutionSessionV3(contract, { randomBytes = crypto.randomBytes } = {}) {
    const suite = readJsonFromBytes(contract.executionBytes, contract.executionPath);
    if (!Array.isArray(suite.vectors) || suite.vectors.length !== contract.vectors) {
        throw new Error(`${contract.path}: execution suite vector count mismatch`);
    }
    const cases = suite.vectors.map((vector) => {
        if (!plainObject(vector) || typeof vector.id !== 'string') {
            throw new Error(`${contract.path}: malformed execution vector`);
        }
        const expected = contract.expectations.get(vector.id);
        if (!expected)
            throw new Error(`${contract.path}: evaluator expectation is missing`);
        const projected = evaluatorCase(contract, vector, expected);
        return {
            sourceId: vector.id,
            ...projected,
        };
    });
    return buildSession(contract, cases, randomBytes);
}
function canonicalizationCase(value, valid, randomBytes) {
    const inputJson = JSON.stringify(value);
    const digest = sha256V3(Buffer.from(canonicalizeV3(JSON.parse(inputJson)), 'utf8'));
    let submittedDigest = digest;
    if (!valid) {
        do
            submittedDigest = randomBytes(32).toString('hex');
        while (submittedDigest === digest);
    }
    return {
        input: {
            canonicalization: {
                input_json: inputJson,
                expected_digest: submittedDigest,
            },
        },
        expected: { valid },
    };
}
export function buildPostBuildChallengesV3(kit, { seed = crypto.randomBytes(32) } = {}) {
    const contract = kit.contracts.find((entry) => entry.path === 'conformance/vectors/canonicalization.v1.json');
    if (!contract)
        throw new Error('canonicalization suite is missing from the v3 kit');
    const randomBytes = deterministicRandomBytes(seed, CHALLENGE_GENERATOR);
    const values = [];
    for (let index = 0; index < CHALLENGE_PAIR_COUNT; index += 1) {
        const value = {
            value: randomBytes(24).toString('base64url'),
            nested: [true, null, index],
        };
        values.push({
            sourceId: `post-build-canonical-pair-${index}-valid`,
            ...canonicalizationCase(value, true, randomBytes),
        });
        values.push({
            sourceId: `post-build-canonical-pair-${index}-invalid`,
            ...canonicalizationCase(value, false, randomBytes),
        });
    }
    return {
        ...buildSession(contract, values, randomBytes),
        seed,
        generator: CHALLENGE_GENERATOR,
    };
}
function compareTypedResult(expected, actual) {
    if (typeof expected.reason_contains === 'string') {
        const expectedFields = { ...expected };
        const requiredReason = expectedFields.reason_contains;
        delete expectedFields.reason_contains;
        const actualFields = { ...actual };
        const reasons = actualFields.reasons;
        delete actualFields.reasons;
        if (!Array.isArray(reasons) || reasons.some((reason) => typeof reason !== 'string')) {
            return 'typed reasons array is required';
        }
        if (!isDeepStrictEqual(actualFields, expectedFields))
            return 'typed result fields differ';
        return reasons.join(' ').includes(requiredReason)
            ? null
            : `typed reasons omit ${requiredReason}`;
    }
    return isDeepStrictEqual(actual, expected) ? null : 'exact typed result differs';
}
export function validateResultRowsV3(session, rows) {
    if (!Array.isArray(rows) || rows.length !== session.bindings.size) {
        throw new Error('runner returned wrong result count');
    }
    const seen = new Set();
    const normalized = [];
    for (const row of rows) {
        if (!plainObject(row)
            || Object.keys(row).length !== 2
            || typeof row.handle !== 'string'
            || !HANDLE_PATTERN.test(row.handle)
            || !Object.hasOwn(row, 'result')) {
            throw new Error('runner emitted a malformed v3 result row');
        }
        if (seen.has(row.handle))
            throw new Error(`runner duplicated handle ${row.handle}`);
        const binding = session.bindings.get(row.handle);
        if (!binding)
            throw new Error(`runner emitted unknown handle ${row.handle}`);
        if (!plainObject(row.result))
            throw new Error(`${row.handle}: result must be a typed object`);
        const difference = compareTypedResult(binding.expected, row.result);
        if (difference)
            throw new Error(`${binding.sourceId}: ${difference}`);
        seen.add(row.handle);
        normalized.push({ id: binding.sourceId, result: row.result });
    }
    if (seen.size !== session.bindings.size)
        throw new Error('runner omitted a v3 handle');
    return normalized.sort((left, right) => left.id.localeCompare(right.id));
}
function parseRunnerOutput(stdout, label) {
    try {
        return JSON.parse(stdout);
    }
    catch (error) {
        throw new Error(`${label}: runner emitted invalid JSON: ${errorMessage(error)}`);
    }
}
function runnerEnvironment() {
    const executableDirectories = [
        path.dirname(process.execPath),
        '/usr/local/bin',
        '/usr/bin',
        '/bin',
        '/usr/sbin',
        '/sbin',
    ];
    return {
        PATH: [...new Set(executableDirectories)].join(path.delimiter),
        LANG: 'C',
        LC_ALL: 'C',
        TZ: 'UTC',
    };
}
function executeSession(session, runner, runnerManifest, temporary, label) {
    verifyRunnerArtifactV2(runnerManifest, runner.path);
    const target = path.join(temporary, `${crypto.randomBytes(16).toString('hex')}.json`);
    fs.writeFileSync(target, session.executionBytes, { mode: 0o444 });
    fs.chmodSync(target, 0o444);
    let stdout = '';
    let runnerError = null;
    try {
        stdout = execFileSync(runner.path, [...runnerManifest.fixed_arguments, target], {
            cwd: temporary,
            encoding: 'utf8',
            timeout: 180_000,
            maxBuffer: 64 * 1024 * 1024,
            stdio: ['ignore', 'pipe', 'pipe'],
            env: runnerEnvironment(),
        });
    }
    catch (error) {
        runnerError = error;
    }
    if (sha256V3(fs.readFileSync(target)) !== sha256V3(session.executionBytes)) {
        throw new Error(`${label}: runner mutated the execution suite`);
    }
    verifyRunnerArtifactV2(runnerManifest, runner.path);
    if (runnerError) {
        const stderr = runnerError?.stderr;
        throw new Error(`${label}: runner failed: ${String(stderr || errorMessage(runnerError)).trim()}`);
    }
    return validateResultRowsV3(session, parseRunnerOutput(stdout, label));
}
export function verifyCleanRoomSubmissionV3({ manifestPath, runnerPath, attestationPath, trustedAttestorsPath, emitPath, requireAcceptance = false, allowUnsafeLocalExecution = false, root = ROOT, }) {
    const kit = loadPinnedKitV3({ root });
    const { value: manifest } = readJson(path.resolve(manifestPath), 'submission manifest');
    verifySubmissionManifestV3(manifest, kit);
    const runner = verifyRunnerArtifactV2(manifest.runner, runnerPath);
    const attestation = attestationPath
        ? readJson(path.resolve(attestationPath), 'independent attestation').value
        : null;
    const trusted = trustedAttestorsPath
        ? readJson(path.resolve(trustedAttestorsPath), 'trusted attestors').value
        : null;
    const acceptance = verifyIndependentAttestationV2(manifest, attestation, trusted);
    if (requireAcceptance && acceptance.accepted !== true) {
        throw new Error('external clean-room acceptance refused: independent attestation is required');
    }
    if (allowUnsafeLocalExecution !== true) {
        throw new Error('local runner execution refused: explicit unsafe-local-execution acknowledgement is required');
    }
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-clean-room-v3-eval-'));
    const suites = [];
    let vectorCount = 0;
    let challengeReport;
    const sessionRandomizer = randomizerContract(SESSION_RANDOMIZER);
    try {
        // These inputs are created only after the submitted entrypoint file hash
        // and mode are checked. Fresh positive/negative pairs make an unknown=>
        // false table fail this narrow computation challenge. This is not a claim
        // of process isolation or freedom from entrypoint-path TOCTOU races.
        const challenge = buildPostBuildChallengesV3(kit);
        const challengeRows = executeSession(challenge, runner, manifest.runner, temporary, 'post-build canonicalization challenge');
        challengeReport = {
            status: 'pass',
            suite: 'conformance/vectors/canonicalization.v1.json',
            cases: challengeRows.length,
            valid_cases: [...challenge.bindings.values()]
                .filter((entry) => entry.expected.valid === true).length,
            invalid_cases: [...challenge.bindings.values()]
                .filter((entry) => entry.expected.valid === false).length,
            generator: challenge.generator,
            generator_contract: challengeGeneratorContract(),
            generator_contract_sha256: canonicalDigest(challengeGeneratorContract()),
            evaluator_artifact_sha256: sha256V3(fs.readFileSync(fileURLToPath(import.meta.url))),
            seed_base64url: challenge.seed.toString('base64url'),
            execution_input_sha256: sha256V3(challenge.executionBytes),
            execution_input_base64url: challenge.executionBytes.toString('base64url'),
            normalized_results_sha256: canonicalDigest(challengeRows),
            normalized_results: challengeRows,
            scope: 'fresh canonicalization computation only; not proof that other suites are not table-driven',
        };
        for (const contract of kit.contracts) {
            const randomizationSeed = crypto.randomBytes(32);
            const session = buildExecutionSessionV3(contract, {
                randomBytes: deterministicRandomBytes(randomizationSeed, SESSION_RANDOMIZER),
            });
            const rows = executeSession(session, runner, manifest.runner, temporary, contract.path);
            vectorCount += rows.length;
            suites.push({
                path: contract.path,
                sha256: contract.sha256,
                source_execution_path: contract.executionPath,
                source_execution_sha256: contract.executionSha256,
                execution_input_sha256: sha256V3(session.executionBytes),
                randomization_seed_base64url: randomizationSeed.toString('base64url'),
                vectors: rows.length,
                normalized_results_sha256: canonicalDigest(rows),
                status: 'pass',
            });
        }
    }
    finally {
        fs.rmSync(temporary, { recursive: true, force: true });
    }
    if (suites.length !== 21 || vectorCount !== 335) {
        throw new Error('external clean-room evaluation did not complete all 21 suites and 335 vectors');
    }
    const report = {
        '@version': 'EP-CLEAN-ROOM-EVALUATION-v3',
        conformance: {
            status: 'pass',
            bundle: kit.bundle['@version'],
            bundle_sha256: kit.bundleSha256,
            conformance_manifest_sha256: kit.sourceManifestSha256,
            conformance_manifest_claim_sha256: kit.sourceManifestClaimSha256,
            authority_document_execution_companion_sha256: kit.authorityExecutionCompanionSha256,
            suites: suites.length,
            vectors: vectorCount,
        },
        input_separation: {
            expected_results_excluded_from_runner_input: true,
            catalogue_vector_ids_excluded_from_runner_input: true,
            currency_status_assertions_excluded_from_runner_input: true,
            pinned_presentation_fields_removed: true,
            handles: 'opaque_random_per_run',
            vector_order: 'random_per_run',
            session_randomizer: sessionRandomizer,
            session_randomizer_contract_sha256: canonicalDigest(sessionRandomizer),
            process_sandbox: false,
            inherited_environment: false,
            runner_environment_variables: ['PATH', 'LANG', 'LC_ALL', 'TZ'],
        },
        post_build_challenge: challengeReport,
        implementation: manifest.implementation,
        runner: {
            protocol: manifest.runner.protocol,
            artifact_sha256: runner.sha256,
            artifact_scope: 'entrypoint_file_only',
            mode: runner.mode,
            fixed_arguments_sha256: canonicalDigest(manifest.runner.fixed_arguments),
            fixed_argument_target_bytes_hashed: false,
            interpreter_and_dynamic_dependencies_hashed: false,
            entrypoint_path_toctou_excluded: false,
        },
        construction: manifest.construction,
        acceptance,
        submission_sha256: canonicalDigest(manifest),
        suites,
    };
    report.report_sha256 = canonicalDigest(report);
    if (emitPath) {
        const target = path.resolve(emitPath);
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, `${JSON.stringify(report, null, 2)}\n`);
    }
    return report;
}
function cliOptions(argv) {
    const values = new Map();
    let requireAcceptance = false;
    let allowUnsafeLocalExecution = false;
    for (let index = 0; index < argv.length; index += 1) {
        const argument = argv[index];
        if (argument === '--require-acceptance') {
            requireAcceptance = true;
            continue;
        }
        if (argument === '--allow-unsafe-local-execution') {
            allowUnsafeLocalExecution = true;
            continue;
        }
        if (![
            '--manifest',
            '--runner',
            '--attestation',
            '--trusted-attestors',
            '--emit',
        ].includes(argument)) {
            throw new Error(`unknown argument: ${argument}`);
        }
        const value = argv[++index];
        if (!value)
            throw new Error(`${argument} requires a value`);
        values.set(argument, value);
    }
    const manifestPath = values.get('--manifest');
    const runnerPath = values.get('--runner');
    if (!manifestPath || !runnerPath) {
        throw new Error('usage: verify-clean-room-submission-v3 --manifest FILE --runner EXECUTABLE '
            + '--allow-unsafe-local-execution '
            + '[--attestation FILE --trusted-attestors FILE] [--require-acceptance] [--emit FILE]');
    }
    return {
        manifestPath,
        runnerPath,
        attestationPath: values.get('--attestation'),
        trustedAttestorsPath: values.get('--trusted-attestors'),
        emitPath: values.get('--emit'),
        requireAcceptance,
        allowUnsafeLocalExecution,
    };
}
if (process.argv[1]
    && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        const report = verifyCleanRoomSubmissionV3(cliOptions(process.argv.slice(2)));
        console.log(`CLEAN-ROOM V3: PASS (${report.conformance.suites} suites, `
            + `${report.conformance.vectors} vectors, `
            + `${report.post_build_challenge.cases} post-build challenges; `
            + `acceptance=${report.acceptance.accepted}; sha256:${report.report_sha256})`);
    }
    catch (error) {
        console.error(`CLEAN-ROOM V3: FAIL: ${errorMessage(error)}`);
        process.exitCode = 1;
    }
}
