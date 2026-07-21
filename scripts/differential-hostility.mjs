#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from differential-hostility.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Deterministic hostile-input differential runner. The built-in JS/Python/Go
// ports are one-team consistency evidence; accepted external runners can be
// added without changing the corpus or upgrading that claim implicitly.
import crypto from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2);
const option = (name) => {
    const index = argv.indexOf(name);
    return index >= 0 ? argv[index + 1] : null;
};
const emitPath = option('--emit');
if (argv.includes('--emit') && !emitPath)
    throw new Error('--emit requires a path');
const BUNDLE = JSON.parse(fs.readFileSync(path.join(ROOT, 'conformance/clean-room/bundle.v1.json'), 'utf8'));
const PRIMARY_FIELDS = [
    'document', 'signoff', 'quorum', 'revocation', 'time_attestation',
    'trust_receipt', 'provenance_chain', 'evidence_record', 'canonicalization',
    'currency', 'initiator_attestation', 'consumption_proof', 'witness_quorum',
    'timestamp_proof',
];
const destructiveValues = [null, {}, [], '', true, 9007199254740992];
const timestampNames = /^(?:issued_at|expires_at|signed_at|revoked_at|checked_at|valid_from|valid_to|gen_time|now|not_before|not_after)$/i;
const publicKeyNames = /(?:^|_)(?:public_key|approver_public_key|log_public_key|tsa_keys|revoker_keys)$/i;
const graphArrayNames = /^(?:links|nodes|edges|members|contexts|signoffs|chain|delegations)$/i;
function clone(value) {
    return structuredClone(value);
}
function mutateFirstLeaf(value) {
    if (!value || typeof value !== 'object')
        return false;
    for (const key of Object.keys(value).sort()) {
        const child = value[key];
        if (typeof child === 'string') {
            value[key] = `${child}#hostile`;
            return true;
        }
        if (typeof child === 'number') {
            value[key] = child + 1;
            return true;
        }
        if (mutateFirstLeaf(child))
            return true;
    }
    return false;
}
function mutateNamed(value, pattern, replacement) {
    if (!value || typeof value !== 'object')
        return false;
    for (const key of Object.keys(value).sort()) {
        if (pattern.test(key)) {
            value[key] = clone(replacement);
            return true;
        }
        if (mutateNamed(value[key], pattern, replacement))
            return true;
    }
    return false;
}
function mutateAllNamed(value, pattern, replacement) {
    if (!value || typeof value !== 'object')
        return 0;
    let count = 0;
    for (const key of Object.keys(value).sort()) {
        if (pattern.test(key)) {
            value[key] = clone(replacement);
            count += 1;
        }
        else {
            count += mutateAllNamed(value[key], pattern, replacement);
        }
    }
    return count;
}
function duplicateNamedGraphNode(value) {
    if (!value || typeof value !== 'object')
        return false;
    for (const key of Object.keys(value).sort()) {
        if (graphArrayNames.test(key) && Array.isArray(value[key]) && value[key].length > 0) {
            value[key] = [clone(value[key][0]), ...value[key]];
            return true;
        }
        if (duplicateNamedGraphNode(value[key]))
            return true;
    }
    return false;
}
function reverseObjectOrder(value) {
    if (Array.isArray(value))
        return value.map(reverseObjectOrder);
    if (!value || typeof value !== 'object')
        return value;
    const out = {};
    for (const key of Object.keys(value).reverse())
        out[key] = reverseObjectOrder(value[key]);
    return out;
}
const cases = [];
const expectations = new Map();
const caseSuites = new Map();
const categoryCounts = new Map();
function addCase(value, category, expectation, suite) {
    cases.push(value);
    expectations.set(value.id, expectation);
    caseSuites.set(value.id, suite);
    categoryCounts.set(category, (categoryCounts.get(category) || 0) + 1);
}
for (const suiteRef of BUNDLE.suites) {
    const suite = JSON.parse(fs.readFileSync(path.join(ROOT, suiteRef.path), 'utf8'));
    const selected = [];
    const positive = suite.vectors.find((vector) => vector.expect?.valid === true);
    const negative = suite.vectors.find((vector) => vector.expect?.valid === false);
    if (positive)
        selected.push(positive);
    if (negative && negative !== positive)
        selected.push(negative);
    for (const source of selected) {
        const prefix = `${path.basename(suiteRef.path, '.json')}_${source.id}`.replace(/[^a-zA-Z0-9_.-]/g, '_');
        const primary = PRIMARY_FIELDS.find((field) => Object.hasOwn(source, field));
        if (!primary)
            throw new Error(`no polymorphic primary field for ${suiteRef.path}#${source.id}`);
        const inert = clone(source);
        inert.id = `${prefix}__unknown_wrapper`;
        inert._ep_hostility = { ignored: true, unicode: 'replacement-�-astral-🙂' };
        addCase(inert, 'unknown-wrapper', { kind: 'metamorphic', expected: source.expect.valid }, suite.suite);
        const unicode = clone(source);
        unicode.id = `${prefix}__unicode_aliases`;
        unicode._ep_hostility = { 'caf\u00e9': 'caf\u00e9', 'cafe\u0301': 'cafe\u0301', bidi: '\u202ereliance' };
        addCase(unicode, 'unicode', { kind: 'metamorphic', expected: source.expect.valid }, suite.suite);
        const permuted = reverseObjectOrder(source);
        permuted.id = `${prefix}__object_permutation`;
        addCase(permuted, 'action-permutation', { kind: 'metamorphic', expected: source.expect.valid }, suite.suite);
        for (let i = 0; i < destructiveValues.length; i += 1) {
            const hostile = clone(source);
            hostile.id = `${prefix}__type_${i}`;
            hostile[primary] = clone(destructiveValues[i]);
            addCase(hostile, 'hostile-type', { kind: 'reject' }, suite.suite);
        }
        if (source[primary] && typeof source[primary] === 'object') {
            const nested = clone(source);
            nested.id = `${prefix}__nested_leaf`;
            if (mutateFirstLeaf(nested[primary]))
                addCase(nested, 'nested-leaf', { kind: 'consensus' }, suite.suite);
        }
        const timestamp = clone(source);
        timestamp.id = `${prefix}__impossible_timestamp`;
        if (mutateNamed(timestamp[primary], timestampNames, '2026-02-30T25:61:61Z')) {
            addCase(timestamp, 'timestamp', { kind: primary === 'currency' ? 'consensus' : 'reject' }, suite.suite);
        }
        const spki = clone(source);
        spki.id = `${prefix}__invalid_spki`;
        if (mutateAllNamed(spki, publicKeyNames, '***not-base64url-spki***') > 0) {
            addCase(spki, 'spki', { kind: 'reject' }, suite.suite);
        }
        const graph = clone(source);
        graph.id = `${prefix}__duplicate_graph_node`;
        if (duplicateNamedGraphNode(graph[primary]))
            addCase(graph, 'evidence-graph', { kind: 'consensus' }, suite.suite);
    }
}
const corpus = {
    suite: 'EP-DIFFERENTIAL-HOSTILITY-v2',
    seed: 'ep-hostility-v2-fixed',
    vectors: cases,
};
const corpusBytes = Buffer.from(`${JSON.stringify(corpus)}\n`);
const corpusHash = crypto.createHash('sha256').update(corpusBytes).digest('hex');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-hostility-'));
const corpusPath = path.join(dir, 'vectors.json');
fs.writeFileSync(corpusPath, corpusBytes);
const implementations = [
    { name: 'javascript', kind: 'one-team-port', command: 'node', args: ['conformance/runners/run-js.mjs'], cwd: ROOT },
    { name: 'python', kind: 'one-team-port', command: 'python3', args: ['conformance/runners/run_py.py'], cwd: ROOT },
    { name: 'go', kind: 'one-team-port', command: 'go', args: ['run', './cmd/conformance'], cwd: path.join(ROOT, 'packages/go-verify') },
];
const externalPath = option('--external-runners');
if (externalPath) {
    const config = JSON.parse(fs.readFileSync(path.resolve(externalPath), 'utf8'));
    if (!Array.isArray(config.runners))
        throw new Error('external runner config must contain a runners array');
    for (const runner of config.runners) {
        if (typeof runner?.name !== 'string' || typeof runner.command !== 'string' || !Array.isArray(runner.args || [])) {
            throw new Error('external runner config contains a malformed runner');
        }
        if (!path.isAbsolute(runner.command))
            throw new Error(`external runner ${runner.name} command must be absolute`);
        const commandReal = fs.realpathSync(runner.command);
        if (!fs.statSync(commandReal).isFile())
            throw new Error(`external runner ${runner.name} command is not a file`);
        implementations.push({
            name: runner.name,
            kind: 'external-submission',
            dispatch: runner.dispatch || 'mixed',
            command: commandReal,
            args: runner.args || [],
            cwd: path.resolve(ROOT, runner.cwd || '.'),
            artifactSha256: crypto.createHash('sha256').update(fs.readFileSync(commandReal)).digest('hex'),
        });
        const lastImplementation = implementations.at(-1);
        if (!['mixed', 'suite'].includes(lastImplementation?.dispatch)) {
            throw new Error(`external runner ${runner.name} has unsupported dispatch mode`);
        }
    }
}
if (new Set(implementations.map((implementation) => implementation.name)).size !== implementations.length) {
    throw new Error('implementation names must be unique');
}
let deep = { leaf: true };
for (let i = 0; i < 66; i += 1)
    deep = { nested: deep };
const rawParserCases = [
    { id: 'truncated-json', bytes: Buffer.from('{"suite":"EP-RECEIPT-v1","vectors":[') },
    { id: 'duplicate-root-member', bytes: Buffer.from('{"suite":"EP-RECEIPT-v1","vectors":[],"vectors":[]}') },
    { id: 'duplicate-vector-member', bytes: Buffer.from('{"suite":"EP-RECEIPT-v1","vectors":[{"id":"a","id":"b"}]}') },
    { id: 'unpaired-surrogate', bytes: Buffer.from('{"suite":"EP-RECEIPT-v1","vectors":[{"id":"\\ud800"}]}') },
    { id: 'over-depth', bytes: Buffer.from(JSON.stringify({ suite: 'EP-RECEIPT-v1', vectors: [{ id: 'deep', document: deep }] })) },
    { id: 'invalid-utf8', bytes: Buffer.concat([Buffer.from('{"suite":"EP-RECEIPT-v1","vectors":[],"x":"'), Buffer.from([0xc3, 0x28]), Buffer.from('"}')]) },
];
function executeCorpus(implementation, inputPath, expectedCount, label) {
    let stdout;
    try {
        stdout = execFileSync(implementation.command, [...implementation.args, inputPath], {
            cwd: implementation.cwd,
            encoding: 'utf8',
            timeout: 180_000,
            maxBuffer: 64 * 1024 * 1024,
            stdio: ['ignore', 'pipe', 'pipe'],
        });
    }
    catch (error) {
        throw new Error(`${implementation.name} crashed on ${label}: ${error.stderr || error.message}`);
    }
    let parsed;
    try {
        parsed = JSON.parse(stdout);
    }
    catch (error) {
        throw new Error(`${implementation.name} emitted invalid JSON for ${label}: ${error.message}`);
    }
    if (!Array.isArray(parsed) || parsed.length !== expectedCount) {
        throw new Error(`${implementation.name} returned ${parsed?.length} results for ${expectedCount} ${label} cases`);
    }
    return parsed;
}
function writeReport(status, divergences) {
    if (!emitPath)
        return;
    const report = {
        '@version': 'EP-DIFFERENTIAL-HOSTILITY-REPORT-v1',
        status,
        corpus: {
            suite: corpus.suite,
            seed: corpus.seed,
            sha256: corpusHash,
            structured_cases: cases.length,
            raw_parser_cases: rawParserCases.length,
            categories: Object.fromEntries([...categoryCounts.entries()].sort()),
        },
        implementations: implementations.map((implementation) => ({
            name: implementation.name,
            relationship: implementation.kind,
            dispatch: implementation.dispatch || 'mixed',
            ...(implementation.artifactSha256 ? { artifact_sha256: implementation.artifactSha256 } : {}),
        })),
        divergences,
    };
    report.report_sha256 = crypto.createHash('sha256').update(JSON.stringify(report)).digest('hex');
    const target = path.resolve(emitPath);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, `${JSON.stringify(report, null, 2)}\n`);
}
try {
    const divergences = [];
    const executionFailures = new Map(implementations.map((implementation) => [implementation.name, new Set()]));
    for (const rawCase of rawParserCases) {
        const rawPath = path.join(dir, `${rawCase.id}.json`);
        fs.writeFileSync(rawPath, rawCase.bytes);
        for (const implementation of implementations) {
            const result = spawnSync(implementation.command, [...implementation.args, rawPath], {
                cwd: implementation.cwd,
                encoding: 'utf8',
                timeout: 180_000,
                maxBuffer: 64 * 1024 * 1024,
                stdio: ['ignore', 'pipe', 'pipe'],
            });
            if (result.status === 0) {
                divergences.push({ id: rawCase.id, implementation: implementation.name, reason: 'malformed_raw_json_accepted' });
            }
            else if (result.signal || /panicked at/.test(result.stderr || '')) {
                divergences.push({ id: rawCase.id, implementation: implementation.name, reason: 'runner_crash' });
            }
        }
    }
    const outputs = new Map();
    for (const implementation of implementations) {
        let parsed;
        if (implementation.dispatch === 'suite') {
            parsed = [];
            const bySuite = new Map();
            for (const hostile of cases) {
                const suite = caseSuites.get(hostile.id) || '';
                if (!bySuite.has(suite))
                    bySuite.set(suite, []);
                bySuite.get(suite).push(hostile);
            }
            let suiteIndex = 0;
            for (const [suite, suiteCases] of bySuite) {
                const suitePath = path.join(dir, `suite-${suiteIndex}.json`);
                fs.writeFileSync(suitePath, `${JSON.stringify({ suite, seed: corpus.seed, vectors: suiteCases })}\n`);
                try {
                    parsed.push(...executeCorpus(implementation, suitePath, suiteCases.length, `hostile ${suite} corpus`));
                }
                catch {
                    for (let caseIndex = 0; caseIndex < suiteCases.length; caseIndex += 1) {
                        const hostile = suiteCases[caseIndex];
                        const singlePath = path.join(dir, `suite-${suiteIndex}-case-${caseIndex}.json`);
                        fs.writeFileSync(singlePath, `${JSON.stringify({ suite, seed: corpus.seed, vectors: [hostile] })}\n`);
                        try {
                            parsed.push(...executeCorpus(implementation, singlePath, 1, `hostile ${suite} case ${hostile.id}`));
                        }
                        catch (error) {
                            executionFailures.get(implementation.name).add(hostile.id);
                            const detail = String(error.message)
                                .replace(/\(\d+\) panicked at/g, '(process) panicked at')
                                .split('\n').map((line) => line.trim()).filter(Boolean).slice(0, 2).join(' | ');
                            divergences.push({
                                id: hostile.id,
                                implementation: implementation.name,
                                reason: 'runner_crash',
                                detail,
                            });
                        }
                    }
                }
                suiteIndex += 1;
            }
        }
        else {
            parsed = executeCorpus(implementation, corpusPath, cases.length, 'hostile mixed-suite corpus');
        }
        const map = new Map();
        for (const result of parsed) {
            if (map.has(result.id) || typeof result.valid !== 'boolean')
                throw new Error(`${implementation.name} emitted malformed or duplicate result ${result.id}`);
            map.set(result.id, result.valid);
        }
        outputs.set(implementation.name, map);
    }
    for (const hostile of cases) {
        if (implementations.some((implementation) => executionFailures.get(implementation.name).has(hostile.id)))
            continue;
        const values = implementations.map((implementation) => outputs.get(implementation.name).get(hostile.id));
        if (values.some((value) => typeof value !== 'boolean')) {
            divergences.push({ id: hostile.id, reason: 'missing_result', values });
            continue;
        }
        if (!values.every((value) => value === values[0])) {
            divergences.push({ id: hostile.id, reason: 'cross_language_divergence', values });
            continue;
        }
        const expected = expectations.get(hostile.id);
        if (expected.kind === 'metamorphic' && values[0] !== expected.expected) {
            divergences.push({ id: hostile.id, reason: 'metamorphic_verdict_changed', expected: expected.expected, values });
        }
        else if (expected.kind === 'reject' && values[0] !== false) {
            divergences.push({ id: hostile.id, reason: 'hostile_input_accepted', values });
        }
    }
    if (divergences.length) {
        writeReport('fail', divergences);
        console.error(`DIFFERENTIAL HOSTILITY: FAIL (${divergences.length} divergence(s))`);
        for (const divergence of divergences.slice(0, 50))
            console.error(JSON.stringify(divergence));
        process.exitCode = 1;
    }
    else {
        const externalCount = implementations.filter((implementation) => implementation.kind === 'external-submission').length;
        const categories = Object.fromEntries([...categoryCounts.entries()].sort());
        writeReport('pass', []);
        console.log(`DIFFERENTIAL HOSTILITY: PASS (${cases.length} structured cases + ${rawParserCases.length} raw parser refusals; ${implementations.length} implementations; ${externalCount} external; corpus sha256:${corpusHash})`);
        console.log(`  categories ${JSON.stringify(categories)}`);
    }
}
finally {
    fs.rmSync(dir, { recursive: true, force: true });
}
