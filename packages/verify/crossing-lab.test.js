// SPDX-License-Identifier: Apache-2.0
// Generated from crossing-lab.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, symlinkSync, unlinkSync, writeFileSync, } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { CROSSING_LAB_REPORT_VERSION, CROSSING_LAB_SCAN_SEED_VERSION, CROSSING_LAB_STATEMENT, CROSSING_LAB_VERIFY_VERSION, canonicalizeCrossingLab, crossingLabScanProfileContract, digestCrossingLab, initCrossingLab, initCrossingLabFromScanSeed, runCrossingLab, sealCrossingLab, writeCrossingLabReport, } from './dist/crossing-lab.js';
const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(HERE, 'cli.js');
const CROSSING_LAB_RUNTIME_SUPPORTED = process.allowedNodeEnvironmentFlags.has('--allow-net')
    && (process.allowedNodeEnvironmentFlags.has('--permission')
        || process.allowedNodeEnvironmentFlags.has('--experimental-permission'));
const runtimeTest = CROSSING_LAB_RUNTIME_SUPPORTED ? test : test.skip;
function freshWorkspace() {
    const parent = mkdtempSync(join(tmpdir(), 'emilia-crossing-lab-'));
    const target = join(parent, 'workspace');
    initCrossingLab(target);
    return target;
}
function readWorkspace(root) {
    return JSON.parse(readFileSync(join(root, 'workspace.json'), 'utf8'));
}
function writeWorkspace(root, workspace) {
    writeFileSync(join(root, 'workspace.json'), `${JSON.stringify(workspace, null, 2)}\n`);
}
const SCAN_PROFILE = 'ccs-wang-draft08-v13';
function writeScanSeed(parent) {
    const manifestPath = join(parent, 'action-control.manifest.json');
    const selectedAction = {
        id: 'discovered.sendwire',
        selector: { protocol: 'mcp', tool: 'sendWire' },
        action_type: 'payment.release.1',
        assurance_class: 'class_a',
        receipt_required: true,
        material_fields: ['action_type', 'amount_usd', 'currency', 'payee_ref'],
    };
    const manifest = {
        actions: [{
                id: selectedAction.id,
                action_type: selectedAction.action_type,
                assurance_class: selectedAction.assurance_class,
                receipt_required: true,
                match: selectedAction.selector,
                execution_binding: { required_fields: selectedAction.material_fields },
            }],
    };
    const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
    writeFileSync(manifestPath, manifestBytes);
    const seed = {
        '@version': CROSSING_LAB_SCAN_SEED_VERSION,
        verify_version: CROSSING_LAB_VERIFY_VERSION,
        profile_id: SCAN_PROFILE,
        profile_contract: crossingLabScanProfileContract(SCAN_PROFILE),
        profile_compatibility: 'UNVERIFIED_OPERATOR_CONFIRMATION_REQUIRED',
        reviewed_manifest: {
            file: 'action-control.manifest.json',
            sha256: `sha256:${crypto.createHash('sha256').update(manifestBytes).digest('hex')}`,
        },
        generated_scaffold_sha256: `sha256:${'1'.repeat(64)}`,
        local_rr1_results_digest: `sha256:${'2'.repeat(64)}`,
        selected_action: selectedAction,
        selected_action_digest: digestCrossingLab(selectedAction),
        operator_confirmation: {
            status: 'required',
            workspace_state: 'unsealed',
            required_inputs: [
                'native_artifact',
                'adapter_bytes',
                'trust_roots',
                'status_source',
                'relying_party_id',
                'exact_material_fields',
                'profile_compatibility_confirmation',
            ],
        },
    };
    const seedPath = join(parent, 'scan-crossing-seed.json');
    writeFileSync(seedPath, `${JSON.stringify(seed, null, 2)}\n`);
    return { seedPath, manifestPath, seed };
}
test('reviewed Scan seed creates an explicit unsealed three-file workspace', () => {
    const parent = mkdtempSync(join(tmpdir(), 'emilia-crossing-lab-scan-'));
    const { seedPath, seed } = writeScanSeed(parent);
    const target = join(parent, 'crossing-lab');
    const created = initCrossingLabFromScanSeed(seedPath, target);
    assert.deepEqual(created.files, ['adapter.mjs', 'artifact.json', 'workspace.json']);
    assert.deepEqual(readdirSync(target).sort(), created.files);
    assert.equal(created.profile_id, SCAN_PROFILE);
    assert.equal(created.state, 'unsealed');
    const workspace = JSON.parse(readFileSync(join(target, 'workspace.json'), 'utf8'));
    assert.equal(workspace['@version'], 'EP-AEB-CROSSING-LAB-DRAFT-v1');
    assert.equal(workspace.state, 'UNSEALED_OPERATOR_INPUT_REQUIRED');
    assert.equal(workspace.profile_id, SCAN_PROFILE);
    assert.equal(workspace.verify_version, CROSSING_LAB_VERIFY_VERSION);
    assert.deepEqual(workspace.profile_contract, crossingLabScanProfileContract(SCAN_PROFILE));
    assert.equal(workspace.profile_compatibility, 'UNVERIFIED_OPERATOR_CONFIRMATION_REQUIRED');
    assert.deepEqual(workspace.selected_action, seed.selected_action);
    assert.deepEqual(workspace.material_values, {
        action_type: null,
        amount_usd: null,
        currency: null,
        payee_ref: null,
    });
    const rawSeedDigest = `sha256:${crypto.createHash('sha256').update(readFileSync(seedPath)).digest('hex')}`;
    assert.equal(workspace.source_seed.sha256, rawSeedDigest);
    assert.equal(JSON.parse(readFileSync(join(target, 'artifact.json'), 'utf8')).source_seed_sha256, rawSeedDigest);
    assert.match(readFileSync(join(target, 'adapter.mjs'), 'utf8'), /scan_crossing_workspace_unsealed/);
    assert.throws(() => sealCrossingLab(target), /invalid Crossing Lab workspace schema/);
    assert.throws(() => runCrossingLab(target), CROSSING_LAB_RUNTIME_SUPPORTED
        ? /invalid Crossing Lab workspace schema/
        : /requires a Node permission runtime with --allow-net support/);
});
test('Scan seed refuses action, profile, and reviewed-manifest substitution', () => {
    const cases = [
        ({ seedPath }) => {
            const seed = JSON.parse(readFileSync(seedPath, 'utf8'));
            seed.selected_action.action_type = 'account.delete.1';
            writeFileSync(seedPath, `${JSON.stringify(seed, null, 2)}\n`);
        },
        ({ seedPath }) => {
            const seed = JSON.parse(readFileSync(seedPath, 'utf8'));
            seed.profile_id = 'invented-profile';
            writeFileSync(seedPath, `${JSON.stringify(seed, null, 2)}\n`);
        },
        ({ seedPath }) => {
            const seed = JSON.parse(readFileSync(seedPath, 'utf8'));
            seed.verify_version = '3.22.0';
            writeFileSync(seedPath, `${JSON.stringify(seed, null, 2)}\n`);
        },
        ({ seedPath }) => {
            const seed = JSON.parse(readFileSync(seedPath, 'utf8'));
            seed.profile_contract.material_fields = ['action_type'];
            writeFileSync(seedPath, `${JSON.stringify(seed, null, 2)}\n`);
        },
        ({ manifestPath }) => writeFileSync(manifestPath, '{}\n'),
    ];
    for (const [index, mutate] of cases.entries()) {
        const parent = mkdtempSync(join(tmpdir(), `emilia-crossing-lab-scan-hostile-${index}-`));
        const fixture = writeScanSeed(parent);
        mutate(fixture);
        assert.throws(() => initCrossingLabFromScanSeed(fixture.seedPath, join(parent, 'workspace')), /selected action digest|supported crossing profile|Verify version mismatch|profile contract mismatch|reviewed manifest digest/);
        assert.equal(existsSync(join(parent, 'workspace')), false);
    }
});
test('Scan seed refuses duplicate reviewed action ids and selectors', () => {
    const cases = [
        (manifest) => manifest.actions.push({
            ...structuredClone(manifest.actions[0]),
            action_type: 'account.delete.1',
        }),
        (manifest) => manifest.actions.push({
            ...structuredClone(manifest.actions[0]),
            id: 'discovered.second-action',
        }),
    ];
    for (const [index, mutate] of cases.entries()) {
        const parent = mkdtempSync(join(tmpdir(), `emilia-crossing-lab-scan-duplicate-${index}-`));
        const fixture = writeScanSeed(parent);
        const manifest = JSON.parse(readFileSync(fixture.manifestPath, 'utf8'));
        mutate(manifest);
        const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
        writeFileSync(fixture.manifestPath, manifestBytes);
        const seed = JSON.parse(readFileSync(fixture.seedPath, 'utf8'));
        seed.reviewed_manifest.sha256 = `sha256:${crypto.createHash('sha256').update(manifestBytes).digest('hex')}`;
        writeFileSync(fixture.seedPath, `${JSON.stringify(seed, null, 2)}\n`);
        assert.throws(() => initCrossingLabFromScanSeed(fixture.seedPath, join(parent, 'workspace')), /duplicate action id or selector/);
    }
});
test('Scan seed initializer refuses malformed fields, hard links, and overwrite', () => {
    const parent = mkdtempSync(join(tmpdir(), 'emilia-crossing-lab-scan-boundary-'));
    const fixture = writeScanSeed(parent);
    const linked = join(parent, 'linked-seed.json');
    execFileSync(process.execPath, ['-e', `require('node:fs').linkSync(${JSON.stringify(fixture.seedPath)}, ${JSON.stringify(linked)})`]);
    assert.throws(() => initCrossingLabFromScanSeed(linked, join(parent, 'hardlink-workspace')), /hard-linked/);
    unlinkSync(linked);
    const target = join(parent, 'workspace');
    initCrossingLabFromScanSeed(fixture.seedPath, target);
    assert.throws(() => initCrossingLabFromScanSeed(fixture.seedPath, target), /refusing to overwrite/);
    const malformedParent = mkdtempSync(join(tmpdir(), 'emilia-crossing-lab-scan-malformed-'));
    const malformed = writeScanSeed(malformedParent);
    const seed = JSON.parse(readFileSync(malformed.seedPath, 'utf8'));
    seed.selected_action.material_fields = ['action_type', 7];
    writeFileSync(malformed.seedPath, `${JSON.stringify(seed, null, 2)}\n`);
    assert.throws(() => initCrossingLabFromScanSeed(malformed.seedPath, join(malformedParent, 'workspace')), /invalid Scan crossing seed/);
});
runtimeTest('scaffold evaluates every positive, hostile, and boundary row deterministically', () => {
    const root = freshWorkspace();
    const first = runCrossingLab(root);
    const second = runCrossingLab(root);
    assert.deepEqual(first, second);
    assert.equal(first['@version'], CROSSING_LAB_REPORT_VERSION);
    assert.equal(first.summary.adapter_rows, 6);
    assert.equal(first.summary.passed, 6);
    assert.equal(first.summary.failed, 0);
    assert.equal(first.summary.harness_passed, 4);
    assert.equal(first.summary.harness_failed, 0);
    assert.equal(first.lab_passed, true);
    assert.equal(first.assurance.self_attested, true);
    assert.equal(first.assurance.certification, false);
    assert.equal(first.assurance.statement, CROSSING_LAB_STATEMENT);
    assert.equal(first.assurance.evaluator_key_purpose, 'PUBLIC_FIXED_SELF_TEST_KEY_NO_ATTRIBUTION');
    assert.equal(first.non_claims.includes('authorization'), true);
    assert.equal(first.non_claims.includes('execution_evidence'), true);
    assert.equal(first.non_claims.includes('native_specification_correctness'), true);
    const { report_digest: _reportDigest, ...body } = first;
    assert.equal(digestCrossingLab(body), first.report_digest);
});
runtimeTest('report keeps native verification, acceptance, mapping, and satisfaction separate', () => {
    const report = runCrossingLab(freshWorkspace());
    const rows = Object.fromEntries(report.adapter_rows.map((entry) => [entry.id, entry]));
    assert.deepEqual(rows['native-artifact-through'].actual, {
        native_verification: 'VERIFIED',
        acceptance: 'ACCEPTED',
        mapping: 'MATCH',
        freshness: 'FRESH',
        satisfaction: 'SATISFIED',
        evaluation_valid: true,
    });
    assert.equal(rows['native-artifact-through'].evaluation['@type'], 'AEB-EVALUATION-v1');
    assert.equal(rows['native-artifact-through'].evaluation.legs.length, 1);
    assert.equal(rows['exact-action-substitution-refused'].actual.mapping, 'MISMATCH');
    assert.equal(rows['exact-action-substitution-refused'].actual.satisfaction, 'UNSATISFIED');
    assert.equal(rows['stale-status-is-indeterminate'].actual.acceptance, 'ACCEPTED');
    assert.equal(rows['stale-status-is-indeterminate'].actual.freshness, 'STALE');
    assert.equal(rows['stale-status-is-indeterminate'].actual.satisfaction, 'INDETERMINATE');
    assert.equal(rows['unavailable-status-is-indeterminate'].actual.freshness, 'UNAVAILABLE');
    assert.ok(rows['native-artifact-through'].evaluation.legs[0].replay_unit.startsWith('sha256:'));
    assert.equal(rows['replay-identity-is-wrapper-independent'].passed, true);
    assert.equal(rows['replay-identity-is-wrapper-independent'].evaluation.legs[0].replay_unit, rows['native-artifact-through'].evaluation.legs[0].replay_unit);
    const harness = Object.fromEntries(report.harness_self_tests.map((entry) => [entry.id, entry]));
    assert.equal(harness['harness-refuses-unknown-native-output'].passed, true);
    assert.equal(harness['harness-refuses-unknown-mapping-output'].passed, true);
});
runtimeTest('artifact, config, profile, and adapter-byte pin drift fail before adapter evaluation', () => {
    const cases = [
        (root, workspace) => {
            const artifact = JSON.parse(readFileSync(join(root, 'artifact.json'), 'utf8'));
            artifact.native_id = 'approval:tampered';
            writeFileSync(join(root, 'artifact.json'), JSON.stringify(artifact));
        },
        (_root, workspace) => {
            workspace.config.adapters['example:native-approval'].config.mode = 'drifted';
            writeWorkspace(_root, workspace);
        },
        (_root, workspace) => {
            workspace.config.profiles['example:payment-release'].version = '2.0.0';
            writeWorkspace(_root, workspace);
        },
        (root) => {
            writeFileSync(join(root, 'adapter.mjs'), '\n// tampered\n', { flag: 'a' });
        },
    ];
    for (const mutate of cases) {
        const root = freshWorkspace();
        mutate(root, readWorkspace(root));
        assert.throws(() => runCrossingLab(root), /workspace pin verification failed/);
    }
});
runtimeTest('workspace traversal and symlinked artifacts are refused', () => {
    const root = freshWorkspace();
    const workspace = readWorkspace(root);
    workspace.artifact = '../artifact.json';
    writeWorkspace(root, workspace);
    assert.throws(() => runCrossingLab(root), /workspace file|invalid artifact pin/);
    const symlinkRoot = freshWorkspace();
    const target = join(dirname(symlinkRoot), 'outside-artifact.json');
    writeFileSync(target, '{}');
    const symlink = join(symlinkRoot, 'linked.json');
    symlinkSync(target, symlink);
    const linkedWorkspace = readWorkspace(symlinkRoot);
    linkedWorkspace.artifact = 'linked.json';
    linkedWorkspace.artifact_digest = digestCrossingLab({});
    writeWorkspace(symlinkRoot, linkedWorkspace);
    assert.throws(() => runCrossingLab(symlinkRoot), /non-symlink file/);
});
runtimeTest('strict JSON, depth, and adapter-size limits fail before module loading', () => {
    const duplicateRoot = freshWorkspace();
    writeFileSync(join(duplicateRoot, 'workspace.json'), '{"@version":"x","@version":"y"}');
    assert.throws(() => runCrossingLab(duplicateRoot), /strict JSON required.*duplicate/i);
    const deepRoot = freshWorkspace();
    const workspace = readWorkspace(deepRoot);
    let nested = null;
    for (let index = 0; index < 40; index += 1)
        nested = [nested];
    workspace.expected_action = nested;
    writeWorkspace(deepRoot, workspace);
    assert.throws(() => runCrossingLab(deepRoot), /depth limit/);
    const largeRoot = freshWorkspace();
    writeFileSync(join(largeRoot, 'adapter.mjs'), 'x'.repeat(262_145));
    assert.throws(() => runCrossingLab(largeRoot), /file-size limit/);
});
runtimeTest('custom adapter receives no ambient network permission', () => {
    const root = freshWorkspace();
    const malicious = `export default {
    id: 'example:native-approval', version: '1.0.0',
    async verifyNative() { await fetch('https://example.com'); return {}; },
    mapAction() { return {}; },
  };\n`;
    writeFileSync(join(root, 'adapter.mjs'), malicious);
    const workspace = readWorkspace(root);
    workspace.adapter.module_digest = `sha256:${crypto.createHash('sha256').update(malicious).digest('hex')}`;
    writeWorkspace(root, workspace);
    const report = runCrossingLab(root);
    assert.equal(report.lab_passed, false);
    assert.ok(report.adapter_rows[0].reasons.includes('adapter_evaluation_error'), JSON.stringify(report.adapter_rows[0]));
});
runtimeTest('adapter cannot dynamically import an undeclared sibling module', () => {
    const root = freshWorkspace();
    const source = `import './helper.mjs';\nexport default {
    id: 'example:native-approval', version: '1.0.0',
    verifyNative() { return {}; }, mapAction() { return {}; },
  };\n`;
    writeFileSync(join(root, 'adapter.mjs'), source);
    writeFileSync(join(root, 'helper.mjs'), 'throw new Error("sibling module executed");\n');
    const workspace = readWorkspace(root);
    workspace.adapter.module_digest = `sha256:${crypto.createHash('sha256').update(source).digest('hex')}`;
    writeWorkspace(root, workspace);
    const report = runCrossingLab(root);
    assert.equal(report.lab_passed, false);
    assert.ok(report.adapter_rows[0].reasons.includes('adapter_evaluation_error'));
});
runtimeTest('adapter execution uses the one captured byte sequence, not the mutable workspace path', () => {
    const root = freshWorkspace();
    const adapterPath = join(root, 'adapter.mjs');
    const source = readFileSync(adapterPath, 'utf8').replace('function nativeBody(artifact) {', `if (!import.meta.url.startsWith('data:text/javascript;base64,')) {
  throw new Error('adapter imported from mutable workspace path');
}
function nativeBody(artifact) {`);
    writeFileSync(adapterPath, source);
    sealCrossingLab(root);
    const report = runCrossingLab(root);
    const sourceDigest = `sha256:${crypto.createHash('sha256').update(source).digest('hex')}`;
    assert.equal(report.adapter.module_digest, sourceDigest);
    assert.equal(report.lab_passed, true);
});
runtimeTest('init and report output never overwrite existing paths', () => {
    const root = freshWorkspace();
    assert.throws(() => initCrossingLab(root), /refusing to overwrite/);
    const report = runCrossingLab(root);
    const output = join(dirname(root), 'report.json');
    writeCrossingLabReport(output, report);
    assert.throws(() => writeCrossingLabReport(output, report), /EEXIST/);
});
runtimeTest('scaffold uses a real native signature and a CAID derived from the exact action', () => {
    const root = freshWorkspace();
    const workspace = readWorkspace(root);
    const actionBytes = JSON.stringify(workspace.expected_action, Object.keys(workspace.expected_action).sort());
    const expectedCaid = `caid:1:${workspace.expected_action.action_type}:jcs-sha256:${crypto.createHash('sha256').update(actionBytes).digest('base64url')}`;
    assert.equal(workspace.evaluation.caid, expectedCaid);
    const artifact = JSON.parse(readFileSync(join(root, 'artifact.json'), 'utf8'));
    assert.match(artifact.signature, /^[A-Za-z0-9_-]+$/);
    artifact.subject_id = 'human:mallory';
    writeFileSync(join(root, 'artifact.json'), `${JSON.stringify(artifact, null, 2)}\n`);
    sealCrossingLab(root);
    const report = runCrossingLab(root);
    assert.equal(report.lab_passed, false);
    assert.equal(report.adapter_rows[0].actual.native_verification, 'FAILED');
});
runtimeTest('seal updates local pins after deliberate edits without claiming semantic validation', () => {
    const root = freshWorkspace();
    writeFileSync(join(root, 'adapter.mjs'), '\n// author edit\n', { flag: 'a' });
    assert.throws(() => runCrossingLab(root), /workspace pin verification failed/);
    const sealed = sealCrossingLab(root);
    assert.match(sealed.workspace_digest, /^sha256:[0-9a-f]{64}$/);
    assert.equal(runCrossingLab(root).lab_passed, true);
});
runtimeTest('nondeterministic adapter output is refused', () => {
    const root = freshWorkspace();
    const adapterPath = join(root, 'adapter.mjs');
    const source = readFileSync(adapterPath, 'utf8').replace("subject: { id: input.artifact.subject_id, kind: 'human' },", "subject: { id: crypto.randomBytes(8).toString('hex'), kind: 'human' },");
    writeFileSync(adapterPath, source);
    sealCrossingLab(root);
    const report = runCrossingLab(root);
    assert.equal(report.lab_passed, false);
    assert.ok(report.adapter_rows[0].reasons.includes('adapter_evaluation_error'));
});
runtimeTest('module-local state cannot evade the same-process determinism check', () => {
    const root = freshWorkspace();
    const adapterPath = join(root, 'adapter.mjs');
    const source = readFileSync(adapterPath, 'utf8')
        .replace("import crypto from 'node:crypto';", "import crypto from 'node:crypto';\nlet crossingLabCounter = 0;")
        .replace("replay_unit: digest({ protocol: 'example-native', native_id: input.artifact.native_id }),", "replay_unit: digest({ protocol: 'example-native', native_id: input.artifact.native_id, call: ++crossingLabCounter }),");
    writeFileSync(adapterPath, source);
    sealCrossingLab(root);
    const report = runCrossingLab(root);
    assert.equal(report.lab_passed, false);
    assert.ok(report.adapter_rows[0].reasons.includes('adapter_evaluation_error'));
});
runtimeTest('seal normalizes an omitted optional unavailable status field', () => {
    const root = freshWorkspace();
    const workspace = readWorkspace(root);
    delete workspace.evaluation.status.unavailable;
    writeWorkspace(root, workspace);
    sealCrossingLab(root);
    const sealed = readWorkspace(root);
    assert.equal(sealed.evaluation.status.unavailable, false);
    assert.equal(runCrossingLab(root).lab_passed, true);
});
runtimeTest('the sample mapper refuses mistyped CAID material after native verification', () => {
    const root = freshWorkspace();
    const workspace = readWorkspace(root);
    const artifactPath = join(root, 'artifact.json');
    const artifact = JSON.parse(readFileSync(artifactPath, 'utf8'));
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const action = { ...artifact.action, amount: 500 };
    const nativeBody = { ...artifact, action };
    delete nativeBody.signature;
    const signedArtifact = {
        ...nativeBody,
        signature: crypto.sign(null, Buffer.from(canonicalizeCrossingLab(nativeBody), 'utf8'), privateKey).toString('base64url'),
    };
    workspace.config.adapters[workspace.adapter.id].trust_roots[0].public_key = publicKey
        .export({ type: 'spki', format: 'der' }).toString('base64url');
    workspace.expected_action = action;
    workspace.hostile_expected_action = { ...action, amount: 501 };
    writeFileSync(artifactPath, `${JSON.stringify(signedArtifact, null, 2)}\n`);
    writeWorkspace(root, workspace);
    sealCrossingLab(root);
    const report = runCrossingLab(root);
    const positive = report.adapter_rows.find((row) => row.id === 'native-artifact-through');
    assert.equal(positive?.actual.native_verification, 'VERIFIED');
    assert.notEqual(positive?.actual.mapping, 'MATCH');
    assert.ok(positive?.reasons.includes('caid_mapping_failed'));
});
runtimeTest('seal never removes a pre-existing predictable sentinel', () => {
    const root = freshWorkspace();
    const sentinel = join(root, `.workspace.json.seal-${process.pid}`);
    writeFileSync(sentinel, 'user-owned sentinel\n');
    sealCrossingLab(root);
    assert.equal(existsSync(sentinel), true);
    assert.equal(readFileSync(sentinel, 'utf8'), 'user-owned sentinel\n');
});
runtimeTest('CLI init and run work offline and preserve exit semantics', () => {
    const parent = mkdtempSync(join(tmpdir(), 'emilia-crossing-lab-cli-'));
    const target = join(parent, 'workspace');
    const init = execFileSync(process.execPath, [CLI, 'crossing-lab', 'init', target], { encoding: 'utf8' });
    assert.match(init, /workspace created/i);
    writeFileSync(join(target, 'adapter.mjs'), '\n// bundled author edit\n', { flag: 'a' });
    const sealed = execFileSync(process.execPath, [CLI, 'crossing-lab', 'seal', target], { encoding: 'utf8' });
    assert.match(sealed, /local pins updated/i);
    const report = JSON.parse(execFileSync(process.execPath, [CLI, 'crossing-lab', 'run', target], { encoding: 'utf8' }));
    assert.equal(report.lab_passed, true);
    assert.equal(report.summary.passed, 6);
});
runtimeTest('packed package carries the CLI, Crossing Lab library, worker, and declarations', () => {
    const raw = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
        cwd: HERE,
        encoding: 'utf8',
        env: { ...process.env, npm_config_loglevel: 'silent' },
    });
    const packed = JSON.parse(raw)[0];
    const files = new Set(packed.files.map((entry) => entry.path));
    for (const expected of [
        'cli.js',
        'dist/crossing-lab.js',
        'dist/crossing-lab.d.ts',
        'dist/crossing-lab-worker.js',
    ])
        assert.equal(files.has(expected), true, `missing packed ${expected}`);
});
