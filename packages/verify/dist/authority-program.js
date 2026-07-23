// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AUTHORITY-PROGRAM-v1 — pure, offline authority-composition verifier.
 *
 * This module verifies a relying-party-pinned signed program and immutable,
 * organization-signed stage receipts. It deliberately has no store, clock,
 * scheduler, transition API, threshold grammar, execution path, revocation
 * mutation, reconciliation, or policy evaluation.
 *
 * AEC means an EP Authorization Evidence Chain requirement/result. AOM means
 * an EP Action Outcome Manifest requirement/result. AOM is an explicit wire
 * contract here; it is not silently treated as EP-OUTCOME-BINDING or any other
 * existing outcome artifact. Native AEC, AOM, and capability verifiers remain
 * separately owned and are injected by the relying party.
 */
import crypto from 'node:crypto';
import { canonicalize } from './index.js';
export const AUTHORITY_PROGRAM_VERSION = 'EP-AUTHORITY-PROGRAM-v1';
export const AUTHORITY_PROGRAM_DOMAIN = 'EP-AUTHORITY-PROGRAM-v1\0';
export const AUTHORITY_STAGE_RECEIPT_VERSION = 'EP-AUTHORITY-STAGE-RECEIPT-v1';
export const AUTHORITY_STAGE_RECEIPT_DOMAIN = 'EP-AUTHORITY-STAGE-RECEIPT-v1\0';
export const AUTHORITY_PROGRAM_RESULT_VERSION = 'EP-AUTHORITY-PROGRAM-VERIFY-RESULT-v1';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
// Join the deployed CAID v1 wire format; an authority-program-only digest
// label would sever this artifact from the CAID registry and its vectors.
const ROOT_CAID = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z0-9-]+)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const MAX_STAGES = 64;
const MAX_DEPTH = 32;
const MAX_BRANCHES = 32;
const MAX_INPUT_NODES = 4096;
const MAX_INPUT_STRING_BYTES = 1024 * 1024;
const own = (value, key) => (value !== null
    && typeof value === 'object'
    && Object.prototype.hasOwnProperty.call(value, key));
function record(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function exactObject(value, required) {
    if (!record(value))
        return false;
    const keys = Object.keys(value);
    return keys.length === required.length
        && required.every((key) => own(value, key));
}
function boundedPlainJson(value) {
    const stack = [{ value, depth: 0 }];
    const seen = new WeakSet();
    let nodes = 0;
    let stringBytes = 0;
    while (stack.length > 0) {
        const current = stack.pop();
        nodes += 1;
        if (nodes > MAX_INPUT_NODES || current.depth > MAX_DEPTH + 8)
            return false;
        if (current.value === null || typeof current.value === 'boolean')
            continue;
        if (typeof current.value === 'string') {
            stringBytes += Buffer.byteLength(current.value, 'utf8');
            if (stringBytes > MAX_INPUT_STRING_BYTES)
                return false;
            continue;
        }
        if (typeof current.value === 'number') {
            if (!Number.isSafeInteger(current.value))
                return false;
            continue;
        }
        if (!record(current.value) && !Array.isArray(current.value))
            return false;
        if (seen.has(current.value))
            return false;
        seen.add(current.value);
        if (Array.isArray(current.value)) {
            if (current.value.length > MAX_INPUT_NODES)
                return false;
            for (const member of current.value)
                stack.push({ value: member, depth: current.depth + 1 });
            continue;
        }
        const entries = Object.entries(current.value);
        if (entries.length > MAX_INPUT_NODES)
            return false;
        for (const [key, member] of entries) {
            stringBytes += Buffer.byteLength(key, 'utf8');
            if (stringBytes > MAX_INPUT_STRING_BYTES)
                return false;
            stack.push({ value: member, depth: current.depth + 1 });
        }
    }
    return true;
}
function identifier(value) {
    return typeof value === 'string' && IDENTIFIER.test(value);
}
function canonicalBase64url(value, expectedBytes) {
    if (typeof value !== 'string' || value.length === 0
        || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1)
        return null;
    const decoded = Buffer.from(value, 'base64url');
    if (decoded.toString('base64url') !== value)
        return null;
    return expectedBytes === undefined || decoded.length === expectedBytes ? decoded : null;
}
function loadEd25519Key(value) {
    try {
        if (typeof value !== 'string')
            return null;
        const der = canonicalBase64url(value, 44);
        if (!der)
            return null;
        const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
        return key.asymmetricKeyType === 'ed25519' ? key : null;
    }
    catch {
        return null;
    }
}
function digest(value) {
    return `sha256:${crypto.createHash('sha256').update(canonicalize(value), 'utf8').digest('hex')}`;
}
function unsigned(value) {
    const body = {};
    for (const [key, member] of Object.entries(value)) {
        if (key !== 'proof')
            body[key] = member;
    }
    return body;
}
function signingBytes(value, domain) {
    return Buffer.from(`${domain}${canonicalize(unsigned(value))}`, 'utf8');
}
function verifyEd25519(value, domain, publicKey) {
    const key = loadEd25519Key(publicKey);
    const signature = canonicalBase64url(value.proof?.signature_b64u, 64);
    if (!key || !signature)
        return false;
    try {
        return crypto.verify(null, signingBytes(value, domain), key, signature);
    }
    catch {
        return false;
    }
}
function validProof(value, { program = false } = {}) {
    const required = program
        ? ['algorithm', 'organization_id', 'key_id', 'signature_b64u']
        : ['algorithm', 'key_id', 'signature_b64u'];
    return exactObject(value, required)
        && value.algorithm === 'Ed25519'
        && (!program || identifier(value.organization_id))
        && identifier(value.key_id)
        && canonicalBase64url(value.signature_b64u, 64) !== null;
}
function uniqueDigests(value) {
    return Array.isArray(value)
        && value.length <= MAX_STAGES
        && value.every((member) => typeof member === 'string' && DIGEST.test(member))
        && new Set(value).size === value.length;
}
function validStage(value) {
    return exactObject(value, [
        'type',
        'stage_id',
        'authority',
        'aec_requirement_digest',
        'aom_requirement_digest',
        'capability_requirement_digest',
    ])
        && value.type === 'stage'
        && identifier(value.stage_id)
        && exactObject(value.authority, ['organization_id', 'key_id'])
        && identifier(value.authority.organization_id)
        && identifier(value.authority.key_id)
        && typeof value.aec_requirement_digest === 'string'
        && DIGEST.test(value.aec_requirement_digest)
        && typeof value.aom_requirement_digest === 'string'
        && DIGEST.test(value.aom_requirement_digest)
        && typeof value.capability_requirement_digest === 'string'
        && DIGEST.test(value.capability_requirement_digest);
}
function analyzeExpression(expression) {
    const predecessors = {};
    const stages = new Map();
    const parallels = [];
    const parallelIds = new Set();
    const walk = (node, incoming, depth) => {
        if (depth > MAX_DEPTH || !record(node))
            return null;
        if (node.type === 'stage') {
            if (!validStage(node) || stages.has(node.stage_id) || stages.size >= MAX_STAGES)
                return null;
            stages.set(node.stage_id, node);
            predecessors[node.stage_id] = [...new Set(incoming)].sort();
            return [node.stage_id];
        }
        if (node.type === 'sequence') {
            if (!exactObject(node, ['type', 'children'])
                || !Array.isArray(node.children)
                || node.children.length < 2
                || node.children.length > MAX_BRANCHES)
                return null;
            let exits = incoming;
            for (const child of node.children) {
                const next = walk(child, exits, depth + 1);
                if (!next)
                    return null;
                exits = next;
            }
            return exits;
        }
        if (node.type === 'parallel') {
            if (!exactObject(node, [
                'type',
                'parallel_id',
                'allocation_requirement_digest',
                'allocation_proof_digest',
                'branches',
            ])
                || !identifier(node.parallel_id)
                || parallelIds.has(node.parallel_id)
                || typeof node.allocation_requirement_digest !== 'string'
                || !DIGEST.test(node.allocation_requirement_digest)
                || typeof node.allocation_proof_digest !== 'string'
                || !DIGEST.test(node.allocation_proof_digest)
                || !Array.isArray(node.branches)
                || node.branches.length < 2
                || node.branches.length > MAX_BRANCHES)
                return null;
            parallelIds.add(node.parallel_id);
            parallels.push(node);
            const exits = [];
            for (const branch of node.branches) {
                const branchExits = walk(branch, incoming, depth + 1);
                if (!branchExits)
                    return null;
                exits.push(...branchExits);
            }
            return [...new Set(exits)].sort();
        }
        return null;
    };
    const exits = walk(expression, [], 0);
    return exits && stages.size > 0 ? { predecessors, stages, parallels } : null;
}
function validProgramEnvelope(value) {
    return exactObject(value, [
        '@version',
        'program_id',
        'root_caid',
        'root_action_digest',
        'expression',
        'proof',
    ])
        && value['@version'] === AUTHORITY_PROGRAM_VERSION
        && identifier(value.program_id)
        && typeof value.root_caid === 'string'
        && ROOT_CAID.test(value.root_caid)
        && typeof value.root_action_digest === 'string'
        && DIGEST.test(value.root_action_digest)
        && validProof(value.proof, { program: true });
}
function validJoin(value) {
    return exactObject(value, ['requirement_digest', 'result_digest'])
        && typeof value.requirement_digest === 'string'
        && DIGEST.test(value.requirement_digest)
        && typeof value.result_digest === 'string'
        && DIGEST.test(value.result_digest);
}
function validCapabilityJoin(value) {
    return exactObject(value, ['requirement_digest', 'input_digest', 'output_digest'])
        && typeof value.requirement_digest === 'string'
        && DIGEST.test(value.requirement_digest)
        && typeof value.input_digest === 'string'
        && DIGEST.test(value.input_digest)
        && typeof value.output_digest === 'string'
        && DIGEST.test(value.output_digest);
}
function validStageReceipt(value) {
    return exactObject(value, [
        '@version',
        'receipt_id',
        'program_digest',
        'root_caid',
        'root_action_digest',
        'stage_id',
        'issuer',
        'predecessor_receipt_digests',
        'aec',
        'aom',
        'capability',
        'proof',
    ])
        && value['@version'] === AUTHORITY_STAGE_RECEIPT_VERSION
        && identifier(value.receipt_id)
        && typeof value.program_digest === 'string'
        && DIGEST.test(value.program_digest)
        && typeof value.root_caid === 'string'
        && ROOT_CAID.test(value.root_caid)
        && typeof value.root_action_digest === 'string'
        && DIGEST.test(value.root_action_digest)
        && identifier(value.stage_id)
        && exactObject(value.issuer, ['organization_id', 'key_id'])
        && identifier(value.issuer.organization_id)
        && identifier(value.issuer.key_id)
        && uniqueDigests(value.predecessor_receipt_digests)
        && validJoin(value.aec)
        && validJoin(value.aom)
        && validCapabilityJoin(value.capability)
        && validProof(value.proof)
        && value.proof.key_id === value.issuer.key_id;
}
function failure(reason, program = null, programDigest = null) {
    return {
        '@version': AUTHORITY_PROGRAM_RESULT_VERSION,
        valid: false,
        program_digest: programDigest,
        root_caid: record(program) && typeof program.root_caid === 'string' ? program.root_caid : null,
        root_action_digest: record(program) && typeof program.root_action_digest === 'string'
            ? program.root_action_digest
            : null,
        stage_receipt_digests: {},
        parallel_allocation_status: null,
        root_action_binding_status: null,
        freshness_proven: false,
        revocation_checked: false,
        execution_proven: false,
        reason,
    };
}
function safeCallback(callback, context) {
    if (typeof callback !== 'function')
        return null;
    try {
        return callback(Object.freeze(structuredClone(context)));
    }
    catch {
        return null;
    }
}
function validEvidenceResult(value) {
    return exactObject(value, ['valid', 'requirement_digest', 'result_digest'])
        && value.valid === true
        && typeof value.requirement_digest === 'string'
        && DIGEST.test(value.requirement_digest)
        && typeof value.result_digest === 'string'
        && DIGEST.test(value.result_digest);
}
function validCapabilityResult(value) {
    return exactObject(value, [
        'valid',
        'narrowed',
        'requirement_digest',
        'input_digest',
        'output_digest',
    ])
        && value.valid === true
        && typeof value.narrowed === 'boolean'
        && typeof value.requirement_digest === 'string'
        && DIGEST.test(value.requirement_digest)
        && typeof value.input_digest === 'string'
        && DIGEST.test(value.input_digest)
        && typeof value.output_digest === 'string'
        && DIGEST.test(value.output_digest);
}
function validParallelResult(value) {
    return exactObject(value, [
        'valid',
        'authoritative',
        'parallel_id',
        'requirement_digest',
        'proof_digest',
    ])
        && value.valid === true
        && typeof value.authoritative === 'boolean'
        && identifier(value.parallel_id)
        && typeof value.requirement_digest === 'string'
        && DIGEST.test(value.requirement_digest)
        && typeof value.proof_digest === 'string'
        && DIGEST.test(value.proof_digest);
}
function validRootActionBindingResult(value) {
    return exactObject(value, [
        'valid',
        'root_caid',
        'root_action_digest',
    ])
        && value.valid === true
        && typeof value.root_caid === 'string'
        && ROOT_CAID.test(value.root_caid)
        && typeof value.root_action_digest === 'string'
        && DIGEST.test(value.root_action_digest);
}
/** Digest of the exact signed authority-program envelope. */
export function authorityProgramDigest(program) {
    return digest(program);
}
/** Digest of the exact signed immutable stage receipt. */
export function authorityStageReceiptDigest(receipt) {
    return digest(receipt);
}
/**
 * Derive each stage's immediate predecessor stage IDs from a recursive
 * series/parallel expression. Arbitrary DAG edges are never accepted.
 */
export function deriveAuthorityProgramPredecessors(expression) {
    const analysis = analyzeExpression(expression);
    if (!analysis)
        throw new Error('invalid authority-program series/parallel expression');
    return structuredClone(analysis.predecessors);
}
/**
 * Verify a signed authority program and all immutable stage receipts.
 *
 * The callbacks are relying-party-owned pure adapters to native verifiers.
 * Their returned objects are closed and must bind the exact signed digests.
 * No callback result can authorize execution; the result explicitly reports
 * `freshness_proven: false`, `revocation_checked: false`, and
 * `execution_proven: false`.
 */
function verifyAuthorityProgramCore(program, stageReceipts, options = {}) {
    if (!validProgramEnvelope(program))
        return failure('invalid_program_envelope');
    const analysis = analyzeExpression(program.expression);
    if (!analysis)
        return failure('invalid_program_expression', program);
    const programDigest = authorityProgramDigest(program);
    if (!exactObject(options.programPin, [
        'digest',
        'organization_id',
        'key_id',
        'public_key',
    ])
        || typeof options.programPin.digest !== 'string'
        || !DIGEST.test(options.programPin.digest)
        || !identifier(options.programPin.organization_id)
        || !identifier(options.programPin.key_id)
        || typeof options.programPin.public_key !== 'string') {
        return failure('invalid_program_pin', program, programDigest);
    }
    if (options.programPin.digest !== programDigest) {
        return failure('program_digest_mismatch', program, programDigest);
    }
    if (program.proof.organization_id !== options.programPin.organization_id
        || program.proof.key_id !== options.programPin.key_id) {
        return failure('program_signer_mismatch', program, programDigest);
    }
    if (!verifyEd25519(program, AUTHORITY_PROGRAM_DOMAIN, options.programPin.public_key)) {
        return failure('invalid_program_signature', program, programDigest);
    }
    const rootActionBinding = safeCallback(options.verifyRootActionBinding, {
        program_digest: programDigest,
        root_caid: program.root_caid,
        root_action_digest: program.root_action_digest,
    });
    if (!validRootActionBindingResult(rootActionBinding)) {
        return failure('root_action_binding_unproven', program, programDigest);
    }
    if (rootActionBinding.root_caid !== program.root_caid
        || rootActionBinding.root_action_digest !== program.root_action_digest) {
        return failure('root_action_binding_mismatch', program, programDigest);
    }
    if (!Array.isArray(stageReceipts) || stageReceipts.length !== analysis.stages.size) {
        return failure('stage_receipt_set_mismatch', program, programDigest);
    }
    const receipts = new Map();
    const receiptIds = new Set();
    for (const receipt of stageReceipts) {
        if (!validStageReceipt(receipt))
            return failure('invalid_stage_receipt', program, programDigest);
        if (receipts.has(receipt.stage_id) || receiptIds.has(receipt.receipt_id)) {
            return failure('duplicate_stage_receipt', program, programDigest);
        }
        receipts.set(receipt.stage_id, receipt);
        receiptIds.add(receipt.receipt_id);
    }
    for (const stageId of analysis.stages.keys()) {
        if (!receipts.has(stageId))
            return failure('stage_receipt_set_mismatch', program, programDigest);
    }
    const receiptDigests = new Map();
    for (const [stageId, receipt] of receipts) {
        receiptDigests.set(stageId, authorityStageReceiptDigest(receipt));
    }
    for (const [stageId, stage] of analysis.stages) {
        const receipt = receipts.get(stageId);
        if (receipt.program_digest !== programDigest) {
            return failure('stage_program_digest_mismatch', program, programDigest);
        }
        if (receipt.root_caid !== program.root_caid) {
            return failure('stage_root_caid_mismatch', program, programDigest);
        }
        if (receipt.root_action_digest !== program.root_action_digest) {
            return failure('stage_root_action_digest_mismatch', program, programDigest);
        }
        if (receipt.issuer.organization_id !== stage.authority.organization_id
            || receipt.issuer.key_id !== stage.authority.key_id) {
            return failure('stage_authority_mismatch', program, programDigest);
        }
        const organizationKeys = record(options.stageKeys) && record(options.stageKeys[stage.authority.organization_id])
            ? options.stageKeys[stage.authority.organization_id]
            : null;
        const stagePublicKey = organizationKeys?.[stage.authority.key_id];
        if (!verifyEd25519(receipt, AUTHORITY_STAGE_RECEIPT_DOMAIN, stagePublicKey)) {
            return failure('invalid_stage_signature', program, programDigest);
        }
        const expectedPredecessors = analysis.predecessors[stageId]
            .map((predecessorId) => receiptDigests.get(predecessorId))
            .sort();
        if (canonicalize(receipt.predecessor_receipt_digests) !== canonicalize(expectedPredecessors)) {
            return failure('predecessor_receipt_digest_mismatch', program, programDigest);
        }
        if (receipt.aec.requirement_digest !== stage.aec_requirement_digest) {
            return failure('aec_requirement_mismatch', program, programDigest);
        }
        const aec = safeCallback(options.verifyAec, {
            stage_id: stageId,
            program_digest: programDigest,
            root_caid: program.root_caid,
            root_action_digest: program.root_action_digest,
            requirement_digest: receipt.aec.requirement_digest,
            result_digest: receipt.aec.result_digest,
        });
        if (!validEvidenceResult(aec)
            || aec.requirement_digest !== receipt.aec.requirement_digest
            || aec.result_digest !== receipt.aec.result_digest) {
            return failure('aec_verification_mismatch', program, programDigest);
        }
        if (receipt.aom.requirement_digest !== stage.aom_requirement_digest) {
            return failure('aom_requirement_mismatch', program, programDigest);
        }
        const aom = safeCallback(options.verifyAom, {
            stage_id: stageId,
            program_digest: programDigest,
            root_caid: program.root_caid,
            root_action_digest: program.root_action_digest,
            requirement_digest: receipt.aom.requirement_digest,
            result_digest: receipt.aom.result_digest,
        });
        if (!validEvidenceResult(aom)
            || aom.requirement_digest !== receipt.aom.requirement_digest
            || aom.result_digest !== receipt.aom.result_digest) {
            return failure('aom_verification_mismatch', program, programDigest);
        }
        if (receipt.capability.requirement_digest !== stage.capability_requirement_digest) {
            return failure('capability_requirement_mismatch', program, programDigest);
        }
        const capability = safeCallback(options.verifyCapabilityNarrowing, {
            stage_id: stageId,
            program_digest: programDigest,
            root_caid: program.root_caid,
            root_action_digest: program.root_action_digest,
            requirement_digest: receipt.capability.requirement_digest,
            input_digest: receipt.capability.input_digest,
            output_digest: receipt.capability.output_digest,
        });
        if (!validCapabilityResult(capability)) {
            return failure('capability_verification_failed', program, programDigest);
        }
        if (!capability.narrowed)
            return failure('capability_not_narrowed', program, programDigest);
        if (capability.requirement_digest !== receipt.capability.requirement_digest
            || capability.input_digest !== receipt.capability.input_digest
            || capability.output_digest !== receipt.capability.output_digest) {
            return failure('capability_verification_mismatch', program, programDigest);
        }
    }
    for (const parallel of analysis.parallels) {
        const branchBindings = parallel.branches.map((branch) => {
            const stageIds = [];
            const collect = (node) => {
                if (node.type === 'stage') {
                    stageIds.push(node.stage_id);
                    return;
                }
                for (const child of node.type === 'sequence' ? node.children : node.branches)
                    collect(child);
            };
            collect(branch);
            return stageIds.sort().map((stageId) => {
                const receipt = receipts.get(stageId);
                return {
                    stage_id: stageId,
                    receipt_digest: receiptDigests.get(stageId),
                    capability_input_digest: receipt.capability.input_digest,
                    capability_output_digest: receipt.capability.output_digest,
                };
            });
        });
        const allocation = safeCallback(options.verifyParallelAllocation, {
            parallel_id: parallel.parallel_id,
            program_digest: programDigest,
            root_caid: program.root_caid,
            root_action_digest: program.root_action_digest,
            requirement_digest: parallel.allocation_requirement_digest,
            proof_digest: parallel.allocation_proof_digest,
            branches: branchBindings,
        });
        if (!validParallelResult(allocation) || !allocation.authoritative) {
            return failure('parallel_allocation_unproven', program, programDigest);
        }
        if (allocation.parallel_id !== parallel.parallel_id
            || allocation.requirement_digest !== parallel.allocation_requirement_digest
            || allocation.proof_digest !== parallel.allocation_proof_digest) {
            return failure('parallel_allocation_mismatch', program, programDigest);
        }
    }
    const orderedDigests = Object.fromEntries([...receiptDigests.entries()].sort(([left], [right]) => left.localeCompare(right)));
    return {
        '@version': AUTHORITY_PROGRAM_RESULT_VERSION,
        valid: true,
        program_digest: programDigest,
        root_caid: program.root_caid,
        root_action_digest: program.root_action_digest,
        stage_receipt_digests: orderedDigests,
        parallel_allocation_status: analysis.parallels.length > 0 ? 'verified' : 'not_applicable',
        root_action_binding_status: 'verified',
        freshness_proven: false,
        revocation_checked: false,
        execution_proven: false,
        reason: null,
    };
}
export function verifyAuthorityProgram(program, stageReceipts, options = {}) {
    try {
        if (!record(options))
            return failure('malformed_input');
        if (!boundedPlainJson(program)
            || !boundedPlainJson(stageReceipts)
            || (options.programPin !== undefined && !boundedPlainJson(options.programPin))
            || (options.stageKeys !== undefined && !boundedPlainJson(options.stageKeys))) {
            return failure('malformed_input');
        }
        const snapshotOptions = {
            programPin: structuredClone(options.programPin),
            stageKeys: structuredClone(options.stageKeys),
            verifyAec: options.verifyAec,
            verifyAom: options.verifyAom,
            verifyCapabilityNarrowing: options.verifyCapabilityNarrowing,
            verifyParallelAllocation: options.verifyParallelAllocation,
            verifyRootActionBinding: options.verifyRootActionBinding,
        };
        return verifyAuthorityProgramCore(structuredClone(program), structuredClone(stageReceipts), snapshotOptions);
    }
    catch {
        return failure('malformed_input');
    }
}
//# sourceMappingURL=authority-program.js.map