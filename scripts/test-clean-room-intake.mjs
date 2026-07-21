#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from test-clean-room-intake.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../packages/verify/index.js';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const VERIFY = path.join(ROOT, 'scripts/verify-clean-room-submission.mjs');
const REFERENCE = path.join(ROOT, 'conformance/clean-room/reference-port.manifest.json');
const SPECIFICATION_BUNDLE = path.join(ROOT, 'conformance/clean-room/specification-bundle.v1.json');
const specHash = crypto.createHash('sha256').update(fs.readFileSync(SPECIFICATION_BUNDLE)).digest('hex');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-clean-room-contract-'));
function writeJson(name, value) {
    const target = path.join(dir, name);
    fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`);
    return target;
}
function run(args) {
    return spawnSync(process.execPath, [VERIFY, ...args], {
        cwd: ROOT,
        encoding: 'utf8',
        timeout: 180_000,
    });
}
try {
    // The v1 vector bundle is frozen historical evidence. Current reference
    // ports intentionally implement newer terminal-revocation semantics, so the
    // intake contract must not relitigate that old semantic result. The frozen
    // baseline gate preserves the historical run; live conformance checks the
    // current ports. Here the reference manifest is used only to prove strict
    // external mode rejects a same-team submission before executing it.
    const refusedReference = run([
        '--require-external', '--manifest', REFERENCE, '--', process.execPath, 'conformance/runners/run-js.mjs',
    ]);
    if (refusedReference.status === 0 || !refusedReference.stderr.includes('external clean-room acceptance refused')) {
        throw new Error('strict external mode did not refuse the same-team reference port');
    }
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const wrapperPath = path.join(dir, 'synthetic-runner.mjs');
    fs.writeFileSync(wrapperPath, [
        "import fs from 'node:fs';",
        "const suite = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));",
        "const results = suite.vectors.map((vector) => ({ id: vector.id, valid: vector.expect.valid }));",
        "process.stdout.write(JSON.stringify(results));",
        '',
    ].join('\n'));
    const wrapperHash = crypto.createHash('sha256').update(fs.readFileSync(wrapperPath)).digest('hex');
    const unsigned = {
        '@version': 'EP-CLEAN-ROOM-SUBMISSION-v1',
        implementation: {
            implementation_id: 'synthetic-intake-contract',
            organization: 'Independent Implementer Fixture',
            language: 'fixture',
            version: 'test-only',
            source_repository: 'https://example.invalid/independent/verifier',
            source_commit: 'ab'.repeat(20),
            license_spdx: 'Apache-2.0',
            build_instructions: 'Synthetic fixture used only to exercise the intake contract.',
            dependencies: [],
        },
        runner: {
            protocol: 'EP-CONFORMANCE-FILE-RUNNER-v1',
            artifact_argument_index: 0,
            artifact_sha256: wrapperHash,
            fixed_arguments: [wrapperPath],
        },
        independence: {
            claimed: true,
            authors: ['Synthetic Contract Author'],
            specification_inputs: ['EP-CLEAN-ROOM-SPECIFICATION-BUNDLE-v1'],
            specification_bundle_sha256: specHash,
            reference_source_access: 'none',
            emilia_affiliation: 'none',
            statement: 'Synthetic signed fixture: the signature authenticates this claim but does not prove its truth.',
        },
    };
    const manifest = {
        ...unsigned,
        attestation: {
            algorithm: 'Ed25519',
            key_id: 'synthetic-independent-attestor',
            attestor_relationship: 'independent',
            signature_base64url: crypto.sign(null, Buffer.from(canonicalize(unsigned), 'utf8'), privateKey).toString('base64url'),
        },
    };
    const manifestPath = writeJson('submission.json', manifest);
    const trustPath = writeJson('trusted-attestors.json', {
        keys: [{
                key_id: 'synthetic-independent-attestor',
                organization: 'Independent Attestor Fixture',
                independent: true,
                public_key_spki_base64url: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
            }],
    });
    const resultPath = path.join(dir, 'result.json');
    const accepted = run([
        '--require-external', '--manifest', manifestPath, '--trusted-attestors', trustPath,
        '--emit', resultPath, '--', process.execPath, wrapperPath,
    ]);
    if (accepted.status !== 0)
        throw new Error(`valid strict fixture was refused: ${accepted.stderr}`);
    const result = JSON.parse(fs.readFileSync(resultPath, 'utf8'));
    if (result.independence.status !== 'external_clean_room_attested' || result.conformance.status !== 'pass') {
        throw new Error('strict result omitted its external-attested status');
    }
    const tampered = structuredClone(manifest);
    tampered.implementation.version = 'tampered-after-signature';
    const tamperedPath = writeJson('tampered.json', tampered);
    const refusedTamper = run([
        '--require-external', '--manifest', tamperedPath, '--trusted-attestors', trustPath,
        '--', process.execPath, wrapperPath,
    ]);
    if (refusedTamper.status === 0 || !refusedTamper.stderr.includes('attestation signature is invalid')) {
        throw new Error('strict external mode did not refuse a tampered signed manifest');
    }
    console.log(`CLEAN-ROOM CONTRACT: PASS (reference refused; signed fixture accepted; tamper refused; spec sha256:${specHash})`);
}
finally {
    fs.rmSync(dir, { recursive: true, force: true });
}
