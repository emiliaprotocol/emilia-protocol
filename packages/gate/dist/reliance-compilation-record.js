// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Institution-readable record of one deterministic Reliance Program compile.
 *
 * The record makes the source-to-Gate mapping reviewable and reproducible. It
 * does not sign the source, establish that an institution's policy is true or
 * legally sufficient, authorize an action, or report an execution outcome.
 */
import { canonicalize, hashCanonical, } from './execution-binding.js';
import { RELIANCE_PROGRAM_VERSION, RELIANCE_PROGRAM_V2_VERSION, } from './reliance-program.js';
import { TRUST_PROGRAM_VERSION, TRUST_PROGRAM_V2_VERSION, trustProgramDigest, trustProgramV2Digest, validateTrustProgram, validateTrustProgramV2, } from './trust-program.js';
export const RELIANCE_COMPILATION_RECORD_VERSION = 'EP-RELIANCE-PROGRAM-COMPILATION-RECORD-v1';
export const RELIANCE_COMPILER_PROFILE = 'EP-RELIANCE-PROGRAM-COMPILER-v1';
export const RELIANCE_COMPILATION_LIMITATIONS = Object.freeze([
    'source_signature_does_not_establish_policy_truth_or_legal_effect',
    'compilation_does_not_authorize_or_execute_the_action',
    'native_evidence_and_outcome_require_separate_verification',
]);
export const RELIANCE_COMPILATION_CLAIM_BOUNDARY = 'This record identifies one deterministic mapping from a verified Reliance Program source to a Gate Trust Program. It does not establish policy truth, legal sufficiency, authorization, provider entry, execution, or outcome.';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const RECORD_KEYS = new Set([
    '@version', 'compiler', 'source', 'output', 'trace', 'limitations',
    'claim_boundary', 'record_digest',
]);
const COMPILER_KEYS = new Set([
    'profile', 'compiled_artifact_version', 'target_program_version',
]);
const SOURCE_KEYS = new Set(['digest', 'relying_party_id']);
const OUTPUT_KEYS = new Set([
    'program_digest', 'root_caid', 'action_digest', 'valid_from', 'expires_at',
    'stage_count', 'requirement_count', 'consequence_mode',
]);
const TRACE_KEYS = new Set([
    'stage_id', 'requirement_id', 'profile_id', 'profile_hash',
]);
const COMPILED_KEYS = new Set([
    'version', 'source_digest', 'relying_party_id', 'program', 'program_digest',
    'trace', 'claim_boundary',
]);
export class RelianceCompilationRecordError extends TypeError {
    code;
    constructor(code, message) {
        super(message);
        this.name = 'RelianceCompilationRecordError';
        this.code = code;
    }
}
function refuse(code, message) {
    throw new RelianceCompilationRecordError(code, message);
}
function isRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function isDataRecord(value) {
    return isRecord(value) && Reflect.ownKeys(value).every((key) => {
        if (typeof key !== 'string')
            return false;
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
    });
}
function exact(value, keys) {
    return isDataRecord(value)
        && Reflect.ownKeys(value).length === keys.size
        && Object.keys(value).every((key) => keys.has(key));
}
function canonicalCopy(value) {
    return JSON.parse(canonicalize(value));
}
function deepFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value))
        return value;
    Object.freeze(value);
    for (const child of Object.values(value))
        deepFreeze(child);
    return value;
}
function digest(value) {
    return `sha256:${hashCanonical(value)}`;
}
function unsignedRecord(record) {
    const { record_digest: _recordDigest, ...body } = record;
    return body;
}
function validateCompiled(compiled) {
    if (!exact(compiled, COMPILED_KEYS)
        || ![RELIANCE_PROGRAM_VERSION, RELIANCE_PROGRAM_V2_VERSION].includes(compiled.version)
        || typeof compiled.source_digest !== 'string' || !DIGEST.test(compiled.source_digest)
        || typeof compiled.relying_party_id !== 'string' || compiled.relying_party_id.length === 0
        || typeof compiled.program_digest !== 'string' || !DIGEST.test(compiled.program_digest)
        || typeof compiled.claim_boundary !== 'string' || compiled.claim_boundary.length === 0
        || !Array.isArray(compiled.trace)) {
        refuse('compiled_artifact_invalid', 'compiled Reliance Program has an invalid closed shape');
    }
    const hybrid = compiled.version === RELIANCE_PROGRAM_V2_VERSION;
    const expectedProgramVersion = hybrid ? TRUST_PROGRAM_V2_VERSION : TRUST_PROGRAM_VERSION;
    const validation = hybrid
        ? validateTrustProgramV2(compiled.program)
        : validateTrustProgram(compiled.program);
    if (!validation.valid || compiled.program?.['@version'] !== expectedProgramVersion) {
        refuse('compiled_artifact_invalid', 'compiled Reliance Program target is invalid');
    }
    const expectedDigest = hybrid
        ? trustProgramV2Digest(compiled.program)
        : trustProgramDigest(compiled.program);
    if (compiled.program_digest !== expectedDigest) {
        refuse('compiled_artifact_invalid', 'compiled Reliance Program digest does not match its program');
    }
    const expectedTrace = new Map();
    for (const stage of compiled.program.stages) {
        for (const requirement of stage.requirements) {
            expectedTrace.set(`${stage.stage_id}\0${requirement.requirement_id}`, requirement.policy_digest);
        }
    }
    if (compiled.trace.length !== expectedTrace.size) {
        refuse('compiled_artifact_invalid', 'compiler trace does not cover every requirement exactly once');
    }
    const seen = new Set();
    for (const entry of compiled.trace) {
        if (!exact(entry, TRACE_KEYS)
            || typeof entry.stage_id !== 'string'
            || typeof entry.requirement_id !== 'string'
            || typeof entry.profile_id !== 'string'
            || typeof entry.profile_hash !== 'string' || !DIGEST.test(entry.profile_hash)) {
            refuse('compiled_artifact_invalid', 'compiler trace contains an invalid entry');
        }
        const key = `${entry.stage_id}\0${entry.requirement_id}`;
        if (seen.has(key) || expectedTrace.get(key) !== entry.profile_hash) {
            refuse('compiled_artifact_invalid', 'compiler trace does not match the compiled requirement');
        }
        seen.add(key);
    }
}
function buildRecordBody(compiled) {
    const requirementCount = compiled.program.stages.reduce((total, stage) => total + stage.requirements.length, 0);
    return {
        '@version': RELIANCE_COMPILATION_RECORD_VERSION,
        compiler: {
            profile: RELIANCE_COMPILER_PROFILE,
            compiled_artifact_version: compiled.version,
            target_program_version: compiled.program['@version'],
        },
        source: {
            digest: compiled.source_digest,
            relying_party_id: compiled.relying_party_id,
        },
        output: {
            program_digest: compiled.program_digest,
            root_caid: compiled.program.root_caid,
            action_digest: compiled.program.action_digest,
            valid_from: compiled.program.valid_from,
            expires_at: compiled.program.expires_at,
            stage_count: compiled.program.stages.length,
            requirement_count: requirementCount,
            consequence_mode: compiled.program.execution.consequence_mode,
        },
        trace: canonicalCopy(compiled.trace),
        limitations: [...RELIANCE_COMPILATION_LIMITATIONS],
        claim_boundary: RELIANCE_COMPILATION_CLAIM_BOUNDARY,
    };
}
/**
 * Build an immutable, content-addressed review record from a compiler result.
 * The caller obtains `compiled` from compileRelianceProgram or
 * compileRelianceProgramV2; this function revalidates the complete result.
 */
export function createRelianceProgramCompilationRecord(compiled) {
    validateCompiled(compiled);
    const body = buildRecordBody(compiled);
    return deepFreeze({
        ...body,
        record_digest: digest(body),
    });
}
function validateRecordShape(record) {
    if (!exact(record, RECORD_KEYS)
        || record['@version'] !== RELIANCE_COMPILATION_RECORD_VERSION
        || !exact(record.compiler, COMPILER_KEYS)
        || record.compiler.profile !== RELIANCE_COMPILER_PROFILE
        || ![RELIANCE_PROGRAM_VERSION, RELIANCE_PROGRAM_V2_VERSION]
            .includes(record.compiler.compiled_artifact_version)
        || ![TRUST_PROGRAM_VERSION, TRUST_PROGRAM_V2_VERSION]
            .includes(record.compiler.target_program_version)
        || !exact(record.source, SOURCE_KEYS)
        || typeof record.source.digest !== 'string' || !DIGEST.test(record.source.digest)
        || typeof record.source.relying_party_id !== 'string'
        || record.source.relying_party_id.length === 0
        || !exact(record.output, OUTPUT_KEYS)
        || typeof record.output.program_digest !== 'string' || !DIGEST.test(record.output.program_digest)
        || typeof record.output.root_caid !== 'string'
        || typeof record.output.action_digest !== 'string' || !DIGEST.test(record.output.action_digest)
        || typeof record.output.valid_from !== 'string'
        || typeof record.output.expires_at !== 'string'
        || !Number.isSafeInteger(record.output.stage_count) || record.output.stage_count < 1
        || !Number.isSafeInteger(record.output.requirement_count) || record.output.requirement_count < 1
        || !['receipt-program', 'action-escrow'].includes(record.output.consequence_mode)
        || !Array.isArray(record.trace)
        || record.trace.some((entry) => !exact(entry, TRACE_KEYS)
            || typeof entry.stage_id !== 'string'
            || typeof entry.requirement_id !== 'string'
            || typeof entry.profile_id !== 'string'
            || typeof entry.profile_hash !== 'string' || !DIGEST.test(entry.profile_hash))
        || !Array.isArray(record.limitations)
        || canonicalize(record.limitations) !== canonicalize([...RELIANCE_COMPILATION_LIMITATIONS])
        || record.claim_boundary !== RELIANCE_COMPILATION_CLAIM_BOUNDARY
        || typeof record.record_digest !== 'string' || !DIGEST.test(record.record_digest)) {
        refuse('record_schema_invalid', 'Reliance Program compilation record is malformed');
    }
}
/**
 * Verify a record against an independently obtained compiler result. A caller
 * can recompile the signed source and profile catalog, then pass that fresh
 * result here. The verifier never treats the record itself as authority.
 */
export function verifyRelianceProgramCompilationRecord(record, compiled) {
    try {
        validateRecordShape(record);
        const computedDigest = digest(unsignedRecord(record));
        if (computedDigest !== record.record_digest) {
            return { valid: false, reason: 'record_digest_mismatch', record_digest: computedDigest };
        }
        validateCompiled(compiled);
        const expected = createRelianceProgramCompilationRecord(compiled);
        if (canonicalize(record) !== canonicalize(expected)) {
            return { valid: false, reason: 'record_compilation_mismatch', record_digest: computedDigest };
        }
        return {
            valid: true,
            reason: null,
            record_digest: computedDigest,
            source_digest: record.source.digest,
            program_digest: record.output.program_digest,
        };
    }
    catch (error) {
        return {
            valid: false,
            reason: error instanceof RelianceCompilationRecordError
                ? error.code : 'record_schema_invalid',
            record_digest: null,
        };
    }
}
/** Render the closed record as deterministic, institution-readable Markdown. */
export function renderRelianceProgramCompilationRecord(record) {
    validateRecordShape(record);
    const computedDigest = digest(unsignedRecord(record));
    if (computedDigest !== record.record_digest) {
        refuse('record_digest_mismatch', 'Reliance Program compilation record digest does not match');
    }
    const lines = [
        '# Reliance Program compilation record',
        '',
        `- Record digest: \`${record.record_digest}\``,
        `- Relying party: \`${record.source.relying_party_id}\``,
        `- Source digest: \`${record.source.digest}\``,
        `- Compiler profile: \`${record.compiler.profile}\``,
        `- Target: \`${record.compiler.target_program_version}\``,
        `- Program digest: \`${record.output.program_digest}\``,
        '',
        '## Exact action',
        '',
        `- CAID: \`${record.output.root_caid}\``,
        `- Action digest: \`${record.output.action_digest}\``,
        `- Validity: \`${record.output.valid_from}\` to \`${record.output.expires_at}\``,
        `- Consequence owner: \`${record.output.consequence_mode}\``,
        '',
        '## Compiled requirements',
        '',
    ];
    for (const entry of record.trace) {
        lines.push(`- \`${entry.stage_id}/${entry.requirement_id}\` pins \`${entry.profile_id}\` at \`${entry.profile_hash}\``);
    }
    lines.push('', '## Claim boundary', '', record.claim_boundary, '', '## Limitations', '');
    for (const limitation of record.limitations)
        lines.push(`- \`${limitation}\``);
    lines.push('');
    return lines.join('\n');
}
//# sourceMappingURL=reliance-compilation-record.js.map