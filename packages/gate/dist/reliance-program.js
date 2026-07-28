// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Customer-owned Reliance Program source and deterministic compiler.
 *
 * The signed source is the relying party's policy artifact. Compilation emits
 * the existing Gate Trust Program wire format; it does not create another
 * authorization engine or let a presenter select the acceptance bar.
 */
import crypto from 'node:crypto';
import { canonicalize, hashCanonical } from './execution-binding.js';
import { TRUST_PROGRAM_VERSION, trustProgramDigest, validateTrustProgram, } from './trust-program.js';
import { createPinnedEvidenceAdapter } from './trust-program-adapters.js';
export const RELIANCE_PROGRAM_SOURCE_VERSION = 'EP-RELIANCE-PROGRAM-SOURCE-v1';
export const RELIANCE_PROGRAM_VERSION = 'EP-RELIANCE-PROGRAM-v1';
export const RELIANCE_PROGRAM_SIGNATURE_ALGORITHM = 'Ed25519';
export const RELIANCE_PROGRAM_ADMISSIBILITY_EVIDENCE = 'ep-admissibility-evaluation';
export const RELIANCE_PROGRAM_ADMISSIBILITY_VERIFIER = 'ep-admissibility-profile:v1';
const DOMAIN = `${RELIANCE_PROGRAM_VERSION}\0`;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const TRUST_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CAID = /^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const SOURCE_KEYS = new Set([
    '@version', 'program_id', 'version', 'relying_party', 'root_caid',
    'action_digest', 'valid_from', 'expires_at', 'stages', 'execution',
]);
const RELYING_PARTY_KEYS = new Set(['id', 'key_id']);
const STAGE_KEYS = new Set(['stage_id', 'depends_on', 'rule', 'profiles']);
const PROFILE_REF_KEYS = new Set([
    'profile_id', 'profile_hash', 'evaluation_max_age_sec', 'revocation_required',
]);
const EXECUTION_KEYS = new Set([
    'depends_on', 'consequence_mode', 'capability_template_digest', 'escrow_profile_digest',
]);
const ENVELOPE_KEYS = new Set(['@version', 'source', 'source_digest', 'signature']);
const SIGNATURE_KEYS = new Set(['algorithm', 'key_id', 'value']);
const TRUSTED_SIGNER_KEYS = new Set(['relying_party_id', 'public_key']);
const MAX_STAGES = 64;
const MAX_PROFILES_PER_STAGE = 64;
const MAX_PROFILE_CATALOG = 1024;
const MAX_PROFILE_BYTES = 262_144;
export class RelianceProgramValidationError extends TypeError {
    code;
    constructor(code, message) {
        super(message);
        this.name = 'RelianceProgramValidationError';
        this.code = code;
    }
}
function refuse(code, message) {
    throw new RelianceProgramValidationError(code, message);
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
function strictInstant(value) {
    if (typeof value !== 'string'
        || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value))
        return NaN;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? parsed : NaN;
}
function exactIdentifiers(value, maximum = MAX_STAGES) {
    return Array.isArray(value) && value.length <= maximum
        && value.every((entry) => typeof entry === 'string' && TRUST_ID.test(entry))
        && new Set(value).size === value.length;
}
function validateRule(rule, profileCount) {
    if (!isDataRecord(rule) || !['all', 'any', 'threshold'].includes(rule.mode))
        return false;
    const keys = rule.mode === 'threshold'
        ? new Set(['mode', 'required', 'distinct_subjects', 'distinct_keys'])
        : new Set(['mode', 'distinct_subjects', 'distinct_keys']);
    if (!exact(rule, keys)
        || typeof rule.distinct_subjects !== 'boolean'
        || typeof rule.distinct_keys !== 'boolean')
        return false;
    if (rule.mode !== 'threshold')
        return true;
    return Number.isSafeInteger(rule.required) && rule.required >= 1 && rule.required <= profileCount;
}
function validateSource(value) {
    try {
        canonicalize(value);
    }
    catch {
        refuse('source_not_canonical', 'reliance program source is not canonicalizable JSON');
    }
    if (!exact(value, SOURCE_KEYS) || value['@version'] !== RELIANCE_PROGRAM_SOURCE_VERSION
        || !exact(value.relying_party, RELYING_PARTY_KEYS)) {
        refuse('source_schema_invalid', 'reliance program source is not a closed v1 object');
    }
    if (typeof value.program_id !== 'string' || !TRUST_ID.test(value.program_id)
        || !Number.isSafeInteger(value.version) || value.version < 1
        || typeof value.relying_party.id !== 'string' || !ID.test(value.relying_party.id)
        || typeof value.relying_party.key_id !== 'string' || !TRUST_ID.test(value.relying_party.key_id)
        || typeof value.root_caid !== 'string' || !CAID.test(value.root_caid)
        || typeof value.action_digest !== 'string' || !DIGEST.test(value.action_digest)) {
        refuse('source_binding_invalid', 'relying party, CAID, or action binding is invalid');
    }
    const validFrom = strictInstant(value.valid_from);
    const expiresAt = strictInstant(value.expires_at);
    if (!Number.isFinite(validFrom) || !Number.isFinite(expiresAt) || expiresAt <= validFrom) {
        refuse('source_time_window_invalid', 'reliance program validity window is invalid');
    }
    if (!Array.isArray(value.stages) || value.stages.length < 1 || value.stages.length > MAX_STAGES) {
        refuse('source_stage_count_invalid', 'reliance program stage count is invalid');
    }
    const stageIds = new Set();
    for (const stage of value.stages) {
        if (!exact(stage, STAGE_KEYS) || typeof stage.stage_id !== 'string'
            || !TRUST_ID.test(stage.stage_id) || stageIds.has(stage.stage_id)
            || !exactIdentifiers(stage.depends_on)
            || !Array.isArray(stage.profiles) || stage.profiles.length < 1
            || stage.profiles.length > MAX_PROFILES_PER_STAGE
            || !validateRule(stage.rule, stage.profiles.length)) {
            refuse('source_stage_invalid', 'reliance program stage is invalid');
        }
        stageIds.add(stage.stage_id);
        const profileIds = new Set();
        for (const reference of stage.profiles) {
            if (!exact(reference, PROFILE_REF_KEYS)
                || typeof reference.profile_id !== 'string' || !ID.test(reference.profile_id)
                || profileIds.has(reference.profile_id)
                || typeof reference.profile_hash !== 'string' || !DIGEST.test(reference.profile_hash)
                || !Number.isSafeInteger(reference.evaluation_max_age_sec)
                || reference.evaluation_max_age_sec < 1 || reference.evaluation_max_age_sec > 31_536_000
                || typeof reference.revocation_required !== 'boolean') {
                refuse('source_profile_reference_invalid', 'admissibility profile reference is invalid');
            }
            profileIds.add(reference.profile_id);
        }
    }
    if (!exact(value.execution, EXECUTION_KEYS)
        || !exactIdentifiers(value.execution.depends_on)
        || value.execution.depends_on.length < 1
        || !['receipt-program', 'action-escrow'].includes(value.execution.consequence_mode)
        || (value.execution.consequence_mode === 'receipt-program'
            && (!DIGEST.test(value.execution.capability_template_digest)
                || value.execution.escrow_profile_digest !== null))
        || (value.execution.consequence_mode === 'action-escrow'
            && (!DIGEST.test(value.execution.escrow_profile_digest)
                || value.execution.capability_template_digest !== null))) {
        refuse('source_execution_invalid', 'reliance program consequence owner is invalid');
    }
}
function signingBytes(source) {
    return Buffer.concat([
        Buffer.from(DOMAIN, 'utf8'),
        Buffer.from(canonicalize(source), 'utf8'),
    ]);
}
function publicKey(value) {
    try {
        if (value instanceof crypto.KeyObject) {
            const key = value.type === 'public' ? value : crypto.createPublicKey(value);
            return key.asymmetricKeyType === 'ed25519' ? key : null;
        }
        if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value))
            return null;
        const bytes = Buffer.from(value, 'base64url');
        if (bytes.toString('base64url') !== value)
            return null;
        const key = crypto.createPublicKey({ key: bytes, type: 'spki', format: 'der' });
        return key.asymmetricKeyType === 'ed25519' ? key : null;
    }
    catch {
        return null;
    }
}
export function relianceProgramSourceDigest(source) {
    validateSource(source);
    return digest(source);
}
export function signRelianceProgram(source, privateKey) {
    validateSource(source);
    const key = privateKey instanceof crypto.KeyObject
        ? privateKey : crypto.createPrivateKey(privateKey);
    if (key.asymmetricKeyType !== 'ed25519') {
        refuse('signing_key_invalid', 'reliance program signing key must be Ed25519');
    }
    const frozenSource = canonicalCopy(source);
    const signature = crypto.sign(null, signingBytes(frozenSource), key).toString('base64url');
    return deepFreeze({
        '@version': RELIANCE_PROGRAM_VERSION,
        source: frozenSource,
        source_digest: digest(frozenSource),
        signature: {
            algorithm: RELIANCE_PROGRAM_SIGNATURE_ALGORITHM,
            key_id: frozenSource.relying_party.key_id,
            value: signature,
        },
    });
}
export function verifyRelianceProgram(envelope, { trustedKeys = {} } = {}) {
    if (!exact(envelope, ENVELOPE_KEYS) || envelope['@version'] !== RELIANCE_PROGRAM_VERSION
        || !exact(envelope.signature, SIGNATURE_KEYS)
        || envelope.signature.algorithm !== RELIANCE_PROGRAM_SIGNATURE_ALGORITHM
        || typeof envelope.source_digest !== 'string' || !DIGEST.test(envelope.source_digest)
        || typeof envelope.signature.key_id !== 'string'
        || typeof envelope.signature.value !== 'string'
        || !/^[A-Za-z0-9_-]+$/.test(envelope.signature.value)
        || Buffer.from(envelope.signature.value, 'base64url').length !== 64
        || Buffer.from(envelope.signature.value, 'base64url').toString('base64url') !== envelope.signature.value) {
        return { valid: false, reason: 'envelope_schema_invalid', source_digest: null };
    }
    try {
        validateSource(envelope.source);
    }
    catch (error) {
        return { valid: false, reason: error instanceof RelianceProgramValidationError
                ? error.code : 'source_schema_invalid', source_digest: null };
    }
    if (envelope.signature.key_id !== envelope.source.relying_party.key_id) {
        return { valid: false, reason: 'signature_key_mismatch', source_digest: envelope.source_digest };
    }
    const computed = digest(envelope.source);
    if (computed !== envelope.source_digest) {
        return { valid: false, reason: 'source_digest_mismatch', source_digest: computed };
    }
    if (!isRecord(trustedKeys) || !Object.hasOwn(trustedKeys, envelope.signature.key_id)) {
        return { valid: false, reason: 'relying_party_key_untrusted', source_digest: computed };
    }
    const signer = trustedKeys[envelope.signature.key_id];
    if (!exact(signer, TRUSTED_SIGNER_KEYS)
        || signer.relying_party_id !== envelope.source.relying_party.id) {
        return { valid: false, reason: 'relying_party_identity_mismatch', source_digest: computed };
    }
    const key = publicKey(signer.public_key);
    if (!key) {
        return { valid: false, reason: 'relying_party_key_untrusted', source_digest: computed };
    }
    const valid = crypto.verify(null, signingBytes(envelope.source), key, Buffer.from(envelope.signature.value, 'base64url'));
    if (!valid)
        return { valid: false, reason: 'signature_invalid', source_digest: computed };
    return {
        valid: true,
        reason: null,
        source_digest: computed,
        relying_party_id: envelope.source.relying_party.id,
        key_id: envelope.signature.key_id,
    };
}
function profileMap(profiles) {
    if (!Array.isArray(profiles) || profiles.length > MAX_PROFILE_CATALOG) {
        refuse('profile_catalog_invalid', 'profile catalog must be a bounded array');
    }
    const result = new Map();
    for (const profile of profiles) {
        if (!isDataRecord(profile) || typeof profile.id !== 'string' || !ID.test(profile.id)
            || typeof profile.profile_hash !== 'string' || !DIGEST.test(profile.profile_hash)
            || result.has(profile.id)) {
            refuse('profile_catalog_invalid', 'profile catalog contains an invalid or duplicate entry');
        }
        const { profile_hash: profileHash, ...profileBody } = profile;
        let computed;
        try {
            const canonical = canonicalize(profileBody);
            if (Buffer.byteLength(canonical, 'utf8') > MAX_PROFILE_BYTES) {
                refuse('profile_catalog_invalid', `profile ${profile.id} exceeds the size limit`);
            }
            computed = `sha256:${crypto.createHash('sha256').update(canonical, 'utf8').digest('hex')}`;
        }
        catch (error) {
            if (error instanceof RelianceProgramValidationError)
                throw error;
            refuse('profile_integrity_invalid', `profile ${profile.id} is not canonicalizable`);
        }
        if (computed !== profileHash) {
            refuse('profile_integrity_invalid', `profile ${profile.id} self-hash does not match its content`);
        }
        result.set(profile.id, profile);
    }
    return result;
}
function verifiedProfile(profile) {
    const catalog = profileMap([profile]);
    return catalog.values().next().value;
}
/**
 * Adapt the existing Admissibility Profile evaluator into one constructor-
 * pinned Trust Program verifier. The runtime artifact supplies evidence only;
 * the profile, evaluator, projection, and clock are all relying-party owned.
 */
export function createAdmissibilityProfileTrustAdapter({ profile, evaluate, project, now, }) {
    const pinnedProfile = canonicalCopy(verifiedProfile(profile));
    if (typeof evaluate !== 'function' || typeof project !== 'function') {
        refuse('admissibility_adapter_invalid', 'admissibility evaluator and projection are required');
    }
    const profileHash = pinnedProfile.profile_hash;
    return createPinnedEvidenceAdapter({
        policyDigest: profileHash,
        trustedConfiguration: {
            profile_id: pinnedProfile.id,
            profile_hash: profileHash,
        },
        verify: async (evidence, context) => {
            if (!exact(evidence, new Set(['bundle']))) {
                return { valid: false, reason: 'admissibility_evidence_schema_invalid' };
            }
            const evaluationTime = typeof now === 'function' ? now() : now;
            let evaluation;
            try {
                evaluation = await evaluate(pinnedProfile, evidence.bundle, {
                    ...(evaluationTime === undefined ? {} : { now: evaluationTime }),
                    expectedProfileHash: profileHash,
                });
            }
            catch {
                return { valid: false, reason: 'admissibility_evaluation_failed' };
            }
            if (!isDataRecord(evaluation)
                || evaluation.profile_hash !== profileHash
                || evaluation.verdict !== 'admissible') {
                const verdict = typeof evaluation?.verdict === 'string'
                    && /^[a-z_]{1,64}$/.test(evaluation.verdict)
                    ? evaluation.verdict : 'unverifiable';
                return { valid: false, reason: `admissibility_${verdict}` };
            }
            let projection;
            try {
                projection = await project({
                    evaluation: Object.freeze(canonicalCopy(evaluation)),
                    bundle: evidence.bundle,
                });
            }
            catch {
                return { valid: false, reason: 'admissibility_projection_failed' };
            }
            if (!isDataRecord(projection)) {
                return { valid: false, reason: 'admissibility_projection_invalid' };
            }
            return {
                valid: true,
                binding_digest: context.expectedBindingDigest,
                policy_digest: profileHash,
                subjects: projection.subjects,
                key_fingerprints: projection.key_fingerprints,
                issued_at: projection.issued_at,
                expires_at: projection.expires_at,
                revocation_checked_at: projection.revocation_checked_at ?? null,
            };
        },
    });
}
export function compileRelianceProgram(envelope, { trustedKeys = {}, profiles = [] } = {}) {
    const verified = verifyRelianceProgram(envelope, { trustedKeys });
    if (verified.valid !== true) {
        refuse(verified.reason ?? 'source_unverified', 'reliance program source did not verify');
    }
    const signed = envelope;
    const source = canonicalCopy(signed.source);
    const catalog = profileMap(profiles);
    const trace = [];
    const stages = source.stages.map((stage) => ({
        stage_id: stage.stage_id,
        depends_on: [...stage.depends_on],
        rule: canonicalCopy(stage.rule),
        requirements: stage.profiles.map((reference, index) => {
            const profile = catalog.get(reference.profile_id);
            if (!profile || profile.profile_hash !== reference.profile_hash) {
                refuse('profile_pin_mismatch', `profile ${reference.profile_id} does not match the relying-party pin`);
            }
            const requirementId = `admissibility-${String(index + 1).padStart(2, '0')}`;
            trace.push({
                stage_id: stage.stage_id,
                requirement_id: requirementId,
                profile_id: reference.profile_id,
                profile_hash: reference.profile_hash,
            });
            return {
                requirement_id: requirementId,
                evidence_type: RELIANCE_PROGRAM_ADMISSIBILITY_EVIDENCE,
                verifier_profile: RELIANCE_PROGRAM_ADMISSIBILITY_VERIFIER,
                policy_digest: reference.profile_hash,
                max_age_sec: reference.evaluation_max_age_sec,
                revocation_required: reference.revocation_required,
            };
        }),
    }));
    const program = {
        '@version': TRUST_PROGRAM_VERSION,
        program_id: source.program_id,
        version: source.version,
        root_caid: source.root_caid,
        action_digest: source.action_digest,
        valid_from: source.valid_from,
        expires_at: source.expires_at,
        stages,
        execution: canonicalCopy(source.execution),
    };
    const checked = validateTrustProgram(program);
    if (!checked.valid) {
        refuse('compiled_program_invalid', `compiled Trust Program is invalid: ${checked.reason}`);
    }
    return deepFreeze({
        version: RELIANCE_PROGRAM_VERSION,
        source_digest: verified.source_digest,
        relying_party_id: verified.relying_party_id,
        program,
        program_digest: trustProgramDigest(program),
        trace,
        claim_boundary: 'Compilation proves a pinned RP program maps to the existing Trust Program; it does not prove evidence sufficiency, authorization, or execution.',
    });
}
//# sourceMappingURL=reliance-program.js.map