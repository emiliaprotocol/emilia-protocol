// SPDX-License-Identifier: Apache-2.0
// Generated from authority-program.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { canonicalize } from './index.js';
import { AUTHORITY_PROGRAM_DOMAIN, AUTHORITY_PROGRAM_VERSION, AUTHORITY_STAGE_RECEIPT_DOMAIN, AUTHORITY_STAGE_RECEIPT_VERSION, authorityProgramDigest, authorityStageReceiptDigest, deriveAuthorityProgramPredecessors, verifyAuthorityProgram, } from './authority-program.js';
const digest = (label) => `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
const clone = (value) => structuredClone(value);
const programKey = crypto.generateKeyPairSync('ed25519');
const stageKeys = {
    'org:alpha': { 'key:alpha': crypto.generateKeyPairSync('ed25519') },
    'org:beta': { 'key:beta': crypto.generateKeyPairSync('ed25519') },
    'org:gamma': { 'key:gamma': crypto.generateKeyPairSync('ed25519') },
    'org:delta': { 'key:delta': crypto.generateKeyPairSync('ed25519') },
};
function publicKey(keyPair) {
    return keyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
}
function signBody(body, domain, keyPair) {
    return crypto.sign(null, Buffer.from(`${domain}${canonicalize(body)}`, 'utf8'), keyPair.privateKey).toString('base64url');
}
function signProgram(body, signer = {
    organization_id: 'org:governance',
    key_id: 'key:program',
    keyPair: programKey,
}) {
    const unsigned = clone(body);
    delete unsigned.proof;
    return {
        ...unsigned,
        proof: {
            algorithm: 'Ed25519',
            organization_id: signer.organization_id,
            key_id: signer.key_id,
            signature_b64u: signBody(unsigned, AUTHORITY_PROGRAM_DOMAIN, signer.keyPair),
        },
    };
}
function signStage(body, organizationId, keyId) {
    const unsigned = clone(body);
    delete unsigned.proof;
    const keyPair = stageKeys[organizationId][keyId];
    assert.ok(keyPair);
    return {
        ...unsigned,
        proof: {
            algorithm: 'Ed25519',
            key_id: keyId,
            signature_b64u: signBody(unsigned, AUTHORITY_STAGE_RECEIPT_DOMAIN, keyPair),
        },
    };
}
function stage(stage_id, organization_id, key_id) {
    return {
        type: 'stage',
        stage_id,
        authority: { organization_id, key_id },
        aec_requirement_digest: digest(`${stage_id}:aec:requirement`),
        aom_requirement_digest: digest(`${stage_id}:aom:requirement`),
        capability_requirement_digest: digest(`${stage_id}:capability:requirement`),
    };
}
function makeProgram() {
    return signProgram({
        '@version': AUTHORITY_PROGRAM_VERSION,
        program_id: 'authority-program:purchase-release:v1',
        root_caid: `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`,
        root_action_digest: digest('root-action'),
        expression: {
            type: 'sequence',
            children: [
                stage('stage-a', 'org:alpha', 'key:alpha'),
                {
                    type: 'parallel',
                    parallel_id: 'parallel-bc',
                    allocation_requirement_digest: digest('parallel-bc:allocation:requirement'),
                    allocation_proof_digest: digest('parallel-bc:allocation:proof'),
                    branches: [
                        stage('stage-b', 'org:beta', 'key:beta'),
                        stage('stage-c', 'org:gamma', 'key:gamma'),
                    ],
                },
                stage('stage-d', 'org:delta', 'key:delta'),
            ],
        },
    });
}
function makeStageReceipt(program, stageNode, predecessors) {
    const stageId = stageNode.stage_id;
    return signStage({
        '@version': AUTHORITY_STAGE_RECEIPT_VERSION,
        receipt_id: `authority-stage-receipt:${stageId}:v1`,
        program_digest: authorityProgramDigest(program),
        root_caid: program.root_caid,
        root_action_digest: program.root_action_digest,
        stage_id: stageId,
        issuer: clone(stageNode.authority),
        predecessor_receipt_digests: [...predecessors].sort(),
        aec: {
            requirement_digest: stageNode.aec_requirement_digest,
            result_digest: digest(`${stageId}:aec:result`),
        },
        aom: {
            requirement_digest: stageNode.aom_requirement_digest,
            result_digest: digest(`${stageId}:aom:result`),
        },
        capability: {
            requirement_digest: stageNode.capability_requirement_digest,
            input_digest: digest(`${stageId}:capability:input`),
            output_digest: digest(`${stageId}:capability:output`),
        },
    }, stageNode.authority.organization_id, stageNode.authority.key_id);
}
function stagesById(program) {
    const [a, parallel, d] = program.expression.children;
    return new Map([
        [a.stage_id, a],
        [parallel.branches[0].stage_id, parallel.branches[0]],
        [parallel.branches[1].stage_id, parallel.branches[1]],
        [d.stage_id, d],
    ]);
}
function makeBundle() {
    const program = makeProgram();
    const byId = stagesById(program);
    const a = makeStageReceipt(program, byId.get('stage-a'), []);
    const aDigest = authorityStageReceiptDigest(a);
    const b = makeStageReceipt(program, byId.get('stage-b'), [aDigest]);
    const c = makeStageReceipt(program, byId.get('stage-c'), [aDigest]);
    const d = makeStageReceipt(program, byId.get('stage-d'), [
        authorityStageReceiptDigest(b),
        authorityStageReceiptDigest(c),
    ]);
    return { program, receipts: [d, b, a, c] };
}
function optionsFor(bundle) {
    const expected = Object.fromEntries(bundle.receipts.map((receipt) => [receipt.stage_id, clone(receipt)]));
    return {
        programPin: {
            digest: authorityProgramDigest(bundle.program),
            organization_id: 'org:governance',
            key_id: 'key:program',
            public_key: publicKey(programKey),
        },
        stageKeys: Object.fromEntries(Object.entries(stageKeys).map(([organizationId, keys]) => [
            organizationId,
            Object.fromEntries(Object.entries(keys).map(([keyId, keyPair]) => [keyId, publicKey(keyPair)])),
        ])),
        verifyAec: ({ stage_id }) => ({
            valid: true,
            requirement_digest: expected[stage_id].aec.requirement_digest,
            result_digest: expected[stage_id].aec.result_digest,
        }),
        verifyAom: ({ stage_id }) => ({
            valid: true,
            requirement_digest: expected[stage_id].aom.requirement_digest,
            result_digest: expected[stage_id].aom.result_digest,
        }),
        verifyCapabilityNarrowing: ({ stage_id }) => ({
            valid: true,
            narrowed: true,
            requirement_digest: expected[stage_id].capability.requirement_digest,
            input_digest: expected[stage_id].capability.input_digest,
            output_digest: expected[stage_id].capability.output_digest,
        }),
        verifyParallelAllocation: ({ parallel_id }) => ({
            valid: true,
            authoritative: true,
            parallel_id,
            requirement_digest: digest(`${parallel_id}:allocation:requirement`),
            proof_digest: digest(`${parallel_id}:allocation:proof`),
        }),
    };
}
function resignReceipt(receipt) {
    return signStage(receipt, receipt.issuer.organization_id, receipt.issuer.key_id);
}
test('verifies a signed nested sequence/parallel program as immutable digest joins', () => {
    const bundle = makeBundle();
    assert.deepEqual(deriveAuthorityProgramPredecessors(bundle.program.expression), {
        'stage-a': [],
        'stage-b': ['stage-a'],
        'stage-c': ['stage-a'],
        'stage-d': ['stage-b', 'stage-c'],
    });
    const result = verifyAuthorityProgram(bundle.program, bundle.receipts, optionsFor(bundle));
    assert.deepEqual(result, {
        '@version': 'EP-AUTHORITY-PROGRAM-VERIFY-RESULT-v1',
        valid: true,
        program_digest: authorityProgramDigest(bundle.program),
        root_caid: bundle.program.root_caid,
        root_action_digest: bundle.program.root_action_digest,
        stage_receipt_digests: Object.fromEntries(bundle.receipts
            .map((receipt) => [receipt.stage_id, authorityStageReceiptDigest(receipt)])
            .sort(([left], [right]) => left.localeCompare(right))),
        parallel_allocation_status: 'verified',
        execution_proven: false,
        reason: null,
    });
});
test('fails closed for unsigned, wrongly signed, untrusted, or wrongly pinned programs', () => {
    const bundle = makeBundle();
    const options = optionsFor(bundle);
    const unsigned = clone(bundle.program);
    delete unsigned.proof;
    assert.equal(verifyAuthorityProgram(unsigned, bundle.receipts, options).reason, 'invalid_program_envelope');
    const wronglySigned = clone(bundle.program);
    wronglySigned.proof.signature_b64u = wronglySigned.proof.signature_b64u.replace(/^./, (c) => c === 'A' ? 'B' : 'A');
    const wrongSignatureOptions = {
        ...options,
        programPin: { ...options.programPin, digest: authorityProgramDigest(wronglySigned) },
    };
    assert.equal(verifyAuthorityProgram(wronglySigned, bundle.receipts, wrongSignatureOptions).reason, 'invalid_program_signature');
    const wrongSigner = clone(bundle.program);
    wrongSigner.proof.organization_id = 'org:attacker';
    const wrongSignerOptions = {
        ...options,
        programPin: { ...options.programPin, digest: authorityProgramDigest(wrongSigner) },
    };
    assert.equal(verifyAuthorityProgram(wrongSigner, bundle.receipts, wrongSignerOptions).reason, 'program_signer_mismatch');
    const wrongPin = { ...options, programPin: { ...options.programPin, digest: digest('wrong-program') } };
    assert.equal(verifyAuthorityProgram(bundle.program, bundle.receipts, wrongPin).reason, 'program_digest_mismatch');
});
test('rejects arbitrary DAG vocabulary and every unknown signed field', () => {
    const bundle = makeBundle();
    const options = optionsFor(bundle);
    const dag = clone(bundle.program);
    dag.expression = { type: 'dag', nodes: [], edges: [] };
    const signedDag = signProgram(dag);
    const dagOptions = { ...options, programPin: { ...options.programPin, digest: authorityProgramDigest(signedDag) } };
    assert.equal(verifyAuthorityProgram(signedDag, bundle.receipts, dagOptions).reason, 'invalid_program_expression');
    const extraProgramField = signProgram({ ...bundle.program, policy: { threshold: 2 } });
    const extraOptions = { ...options, programPin: { ...options.programPin, digest: authorityProgramDigest(extraProgramField) } };
    assert.equal(verifyAuthorityProgram(extraProgramField, bundle.receipts, extraOptions).reason, 'invalid_program_envelope');
    const extraReceipt = clone(bundle.receipts);
    extraReceipt[0] = resignReceipt({ ...extraReceipt[0], mutable_status: 'advanced' });
    assert.equal(verifyAuthorityProgram(bundle.program, extraReceipt, options).reason, 'invalid_stage_receipt');
});
test('hostile JavaScript objects cannot throw through the pure verifier', () => {
    const hostile = {};
    Object.defineProperty(hostile, 'proof', {
        enumerable: true,
        get() { throw new Error('attacker getter'); },
    });
    const result = verifyAuthorityProgram(hostile, [], {});
    assert.deepEqual(result, {
        '@version': 'EP-AUTHORITY-PROGRAM-VERIFY-RESULT-v1',
        valid: false,
        program_digest: null,
        root_caid: null,
        root_action_digest: null,
        stage_receipt_digests: {},
        parallel_allocation_status: null,
        execution_proven: false,
        reason: 'malformed_input',
    });
    const cyclic = {};
    cyclic.self = cyclic;
    assert.equal(verifyAuthorityProgram(cyclic, [], {}).reason, 'malformed_input');
    const oversized = makeBundle();
    const oversizedOptions = optionsFor(oversized);
    oversizedOptions.programPin.public_key = 'A'.repeat(10_000);
    assert.equal(verifyAuthorityProgram(oversized.program, oversized.receipts, oversizedOptions).reason, 'invalid_program_signature');
});
test('requires the exact canonical predecessor receipt digest set', () => {
    const bundle = makeBundle();
    const options = optionsFor(bundle);
    const mutateD = (predecessors) => bundle.receipts.map((receipt) => (receipt.stage_id === 'stage-d'
        ? resignReceipt({ ...receipt, predecessor_receipt_digests: predecessors })
        : receipt));
    const d = bundle.receipts.find((receipt) => receipt.stage_id === 'stage-d');
    assert.ok(d);
    assert.equal(verifyAuthorityProgram(bundle.program, mutateD(d.predecessor_receipt_digests.slice(0, 1)), options).reason, 'predecessor_receipt_digest_mismatch');
    assert.equal(verifyAuthorityProgram(bundle.program, mutateD([...d.predecessor_receipt_digests, digest('extra')]), options).reason, 'predecessor_receipt_digest_mismatch');
    assert.equal(verifyAuthorityProgram(bundle.program, mutateD([...d.predecessor_receipt_digests].reverse()), options).reason, 'predecessor_receipt_digest_mismatch');
});
test('rejects the wrong stage organization and receipt replay across every binding axis', () => {
    const bundle = makeBundle();
    const options = optionsFor(bundle);
    const wrongOrg = clone(bundle.receipts);
    const bIndex = wrongOrg.findIndex((receipt) => receipt.stage_id === 'stage-b');
    wrongOrg[bIndex] = signStage({ ...wrongOrg[bIndex], issuer: { organization_id: 'org:gamma', key_id: 'key:gamma' } }, 'org:gamma', 'key:gamma');
    assert.equal(verifyAuthorityProgram(bundle.program, wrongOrg, options).reason, 'stage_authority_mismatch');
    const replayedStage = clone(bundle.receipts);
    replayedStage[bIndex] = clone(replayedStage.find((receipt) => receipt.stage_id === 'stage-a'));
    assert.equal(verifyAuthorityProgram(bundle.program, replayedStage, options).reason, 'duplicate_stage_receipt');
    const duplicateReceiptId = clone(bundle.receipts);
    duplicateReceiptId[bIndex].receipt_id = duplicateReceiptId.find((receipt) => receipt.stage_id === 'stage-a').receipt_id;
    duplicateReceiptId[bIndex] = resignReceipt(duplicateReceiptId[bIndex]);
    assert.equal(verifyAuthorityProgram(bundle.program, duplicateReceiptId, options).reason, 'duplicate_stage_receipt');
    const otherProgram = signProgram({ ...bundle.program, program_id: 'authority-program:other:v1' });
    const otherOptions = { ...options, programPin: { ...options.programPin, digest: authorityProgramDigest(otherProgram) } };
    assert.equal(verifyAuthorityProgram(otherProgram, bundle.receipts, otherOptions).reason, 'stage_program_digest_mismatch');
    const otherRoot = signProgram({
        ...bundle.program,
        root_caid: `caid:1:payment.release.1:jcs-sha256:${'B'.repeat(43)}`,
    });
    const otherRootOptions = { ...options, programPin: { ...options.programPin, digest: authorityProgramDigest(otherRoot) } };
    assert.equal(verifyAuthorityProgram(otherRoot, bundle.receipts, otherRootOptions).reason, 'stage_program_digest_mismatch');
    const otherAuthority = clone(bundle.program);
    otherAuthority.expression.children[1].branches[0].authority = {
        organization_id: 'org:gamma',
        key_id: 'key:gamma',
    };
    const signedOtherAuthority = signProgram(otherAuthority);
    const otherAuthorityOptions = {
        ...options,
        programPin: { ...options.programPin, digest: authorityProgramDigest(signedOtherAuthority) },
    };
    assert.equal(verifyAuthorityProgram(signedOtherAuthority, bundle.receipts, otherAuthorityOptions).reason, 'stage_program_digest_mismatch');
});
test('requires exact independently verified AEC and explicit AOM joins', () => {
    const bundle = makeBundle();
    const options = optionsFor(bundle);
    const index = bundle.receipts.findIndex((receipt) => receipt.stage_id === 'stage-b');
    const wrongAec = clone(bundle.receipts);
    wrongAec[index].aec.result_digest = digest('wrong-aec-result');
    wrongAec[index] = resignReceipt(wrongAec[index]);
    assert.equal(verifyAuthorityProgram(bundle.program, wrongAec, options).reason, 'aec_verification_mismatch');
    const wrongAom = clone(bundle.receipts);
    wrongAom[index].aom.requirement_digest = digest('wrong-aom-requirement');
    wrongAom[index] = resignReceipt(wrongAom[index]);
    assert.equal(verifyAuthorityProgram(bundle.program, wrongAom, options).reason, 'aom_requirement_mismatch');
    const resultSmuggling = {
        ...options,
        verifyAec: (context) => ({ ...options.verifyAec(context), operator_override: true }),
    };
    assert.equal(verifyAuthorityProgram(bundle.program, bundle.receipts, resultSmuggling).reason, 'aec_verification_mismatch');
});
test('rejects capability broadening and parallel budget claims without authoritative allocation proof', () => {
    const bundle = makeBundle();
    const options = optionsFor(bundle);
    const broadened = {
        ...options,
        verifyCapabilityNarrowing: (context) => ({
            ...options.verifyCapabilityNarrowing(context),
            narrowed: context.stage_id !== 'stage-b',
        }),
    };
    assert.equal(verifyAuthorityProgram(bundle.program, bundle.receipts, broadened).reason, 'capability_not_narrowed');
    const noAllocationVerifier = { ...options, verifyParallelAllocation: undefined };
    assert.equal(verifyAuthorityProgram(bundle.program, bundle.receipts, noAllocationVerifier).reason, 'parallel_allocation_unproven');
    const selfAsserted = {
        ...options,
        verifyParallelAllocation: ({ parallel_id }) => ({
            valid: true,
            authoritative: false,
            parallel_id,
            requirement_digest: digest(`${parallel_id}:allocation:requirement`),
            proof_digest: digest(`${parallel_id}:allocation:proof`),
        }),
    };
    assert.equal(verifyAuthorityProgram(bundle.program, bundle.receipts, selfAsserted).reason, 'parallel_allocation_unproven');
});
