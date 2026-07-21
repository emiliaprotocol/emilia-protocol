// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Constructor-pinned adapters for the Gate Trust Program profile.
 *
 * These adapters do not create another policy engine. They provide the narrow
 * joins needed to consume existing Quorum, AEC, Receipt Program, and Action
 * Escrow verification results without allowing a presenter to choose verifier
 * functions, trust roots, policies, mappings, or expected values at runtime.
 */
import crypto from 'node:crypto';
// The compatibility entry point resolves to dist both from src during native
// TypeScript tests and from the compiled dist module.
// @ts-ignore -- declarations live behind the compatibility entry point.
import { canonicalize } from '../execution-binding.js';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const TRUST_BINDING_KEYS = new Set([
    'instance_id',
    'program_digest',
    'program_version',
    'root_caid',
    'action_digest',
    'stage_id',
    'requirement_id',
    'policy_digest',
    'predecessor_receipt_digests',
]);
const ARTIFACT_KEYS = new Set(['evidence_id', 'binding', 'evidence']);
const QUORUM_EVIDENCE_KEYS = new Set(['members']);
const QUORUM_MEMBER_KEYS = new Set(['role', 'signoff']);
const RECEIPT_EVIDENCE_KEYS = new Set(['certificate']);
const ACTION_ESCROW_EVIDENCE_KEYS = new Set([
    'package', 'document_bytes', 'project_record_bytes',
]);
const ACTION_ESCROW_COMPONENT_VERIFIERS = Object.freeze([
    'verifyBinding',
    'verifyProjectRecord',
    'verifyProfile',
    'verifyDocumentExecution',
    'verifyAgreementAcceptance',
    'verifyReleaseApproval',
    'verifyFunding',
    'verifyMilestone',
    'verifyRelease',
    'verifyAmendment',
    'verifyState',
]);
const FORBIDDEN_RUNTIME_TRUST_KEYS = new Set([
    'approverKeys',
    'componentVerifiers',
    'expectedAction',
    'expectedActionDigest',
    'expectedAgreementId',
    'expectedContext',
    'expectedProgramDigest',
    'keys',
    'keysByType',
    'mappings',
    'policies',
    'policiesByType',
    'resolveCaid',
    'trustedCertificateKeys',
    'trustedConfiguration',
    'trustedKeys',
    'trustRoots',
    'verificationOptions',
    'verifierFunctions',
    'verifiers',
]);
const VERIFY_PACKAGE = '@emilia-protocol/verify';
const AEC_PACKAGE = '@emilia-protocol/verify/evidence-chain';
const LOCAL_VERIFY_PACKAGE = '../../verify/index.js';
const LOCAL_AEC_PACKAGE = '../../verify/evidence-chain.js';
const RECEIPT_PROGRAM_MODULE = '../receipt-program.js';
const ACTION_ESCROW_EVIDENCE_MODULE = '../action-escrow-evidence.js';
async function verifyQuorumDefault(quorum, options) {
    try {
        const verifier = await import(VERIFY_PACKAGE);
        return verifier.verifyQuorum(quorum, options);
    }
    catch (error) {
        if (error?.code !== 'ERR_MODULE_NOT_FOUND')
            throw error;
        const verifier = await import(LOCAL_VERIFY_PACKAGE);
        return verifier.verifyQuorum(quorum, options);
    }
}
async function verifyAuthorizationChainDefault(chain, options) {
    try {
        const verifier = await import(AEC_PACKAGE);
        return verifier.verifyAuthorizationChain(chain, options);
    }
    catch (error) {
        if (error?.code !== 'ERR_MODULE_NOT_FOUND')
            throw error;
        const verifier = await import(LOCAL_AEC_PACKAGE);
        return verifier.verifyAuthorizationChain(chain, options);
    }
}
async function verifyReceiptProgramCertificateDefault(certificate, options) {
    const verifier = await import(RECEIPT_PROGRAM_MODULE);
    return verifier.verifyReceiptProgramCertificate(certificate, options);
}
async function verifyActionEscrowEvidencePackageDefault(pkg, options) {
    const verifier = await import(ACTION_ESCROW_EVIDENCE_MODULE);
    return verifier.verifyActionEscrowEvidencePackage(pkg, options);
}
function refusal(reason) {
    return Object.freeze({ valid: false, reason });
}
function terminalRefusal(reason) {
    return Object.freeze({
        valid: false,
        reason,
        outcome: null,
        evidence_digest: null,
    });
}
function isRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
/** Only enumerable data properties are accepted from a presenter. */
function isDataRecord(value) {
    if (!isRecord(value))
        return false;
    return Reflect.ownKeys(value).every((key) => {
        if (typeof key !== 'string')
            return false;
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
    });
}
function exactKeys(value, allowed, required = allowed) {
    return isDataRecord(value)
        && Object.keys(value).every((key) => allowed.has(key))
        && [...required].every((key) => Object.hasOwn(value, key));
}
function canonicalCopy(value) {
    return JSON.parse(canonicalize(value));
}
function canonicalDigest(value) {
    return `sha256:${crypto.createHash('sha256')
        .update(Buffer.from(canonicalize(value), 'utf8')).digest('hex')}`;
}
function deepFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value))
        return value;
    Object.freeze(value);
    for (const child of Object.values(value))
        deepFreeze(child);
    return value;
}
/**
 * Snapshot constructor-owned configuration while preserving injected verifier
 * function identity. Host objects such as KeyObject are immutable references;
 * canonical data and byte arrays are copied.
 */
function snapshotPinned(value, seen = new WeakMap()) {
    if (value === null || typeof value !== 'object')
        return value;
    if (value instanceof Uint8Array)
        return Uint8Array.from(value);
    if (value instanceof ArrayBuffer)
        return value.slice(0);
    if (value instanceof Date)
        return new Date(value.getTime());
    if (value instanceof crypto.KeyObject)
        return value;
    if (seen.has(value))
        return seen.get(value);
    if (Array.isArray(value)) {
        const result = [];
        seen.set(value, result);
        for (const entry of value)
            result.push(snapshotPinned(entry, seen));
        return Object.freeze(result);
    }
    if (!isDataRecord(value)) {
        throw new TypeError('pinned adapter configuration must use data properties');
    }
    const result = {};
    seen.set(value, result);
    for (const [key, entry] of Object.entries(value))
        result[key] = snapshotPinned(entry, seen);
    return Object.freeze(result);
}
function canonicalInstant(value) {
    if (typeof value !== 'string'
        || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) {
        return null;
    }
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
}
function normalizedStrings(value) {
    if (!Array.isArray(value) || value.length === 0 || value.length > 256)
        return null;
    const normalized = [];
    for (const entry of value) {
        if (typeof entry !== 'string' || entry.length === 0 || entry.length > 512
            || /[\u0000-\u001f\u007f]/.test(entry))
            return null;
        normalized.push(entry);
    }
    return [...new Set(normalized)].sort();
}
function normalizedFingerprints(value) {
    if (!Array.isArray(value) || value.length === 0 || value.length > 256
        || value.some((entry) => typeof entry !== 'string' || !DIGEST.test(entry)))
        return null;
    return [...new Set(value)].sort();
}
function containsRuntimeTrustConfiguration(value) {
    const stack = [value];
    const seen = new WeakSet();
    while (stack.length) {
        const current = stack.pop();
        if (!current || typeof current !== 'object')
            continue;
        if (seen.has(current))
            return true;
        seen.add(current);
        if (Array.isArray(current)) {
            stack.push(...current);
            continue;
        }
        if (!isDataRecord(current))
            return true;
        for (const [key, entry] of Object.entries(current)) {
            if (FORBIDDEN_RUNTIME_TRUST_KEYS.has(key))
                return true;
            if (entry && typeof entry === 'object')
                stack.push(entry);
        }
    }
    return false;
}
function normalizeVerifiedClaims(result) {
    const subjects = normalizedStrings(result.subjects);
    const keyFingerprints = normalizedFingerprints(result.key_fingerprints);
    const issuedAt = canonicalInstant(result.issued_at);
    const expiresAt = canonicalInstant(result.expires_at);
    const revocationCheckedAt = result.revocation_checked_at === null
        || result.revocation_checked_at === undefined
        ? null : canonicalInstant(result.revocation_checked_at);
    if (!subjects || !keyFingerprints)
        return refusal('evidence_principal_set_invalid');
    if (!issuedAt || !expiresAt || Date.parse(expiresAt) <= Date.parse(issuedAt)) {
        return refusal('evidence_time_invalid');
    }
    if (result.revocation_checked_at !== null && result.revocation_checked_at !== undefined
        && revocationCheckedAt === null)
        return refusal('evidence_revocation_time_invalid');
    return Object.freeze({
        valid: true,
        reason: null,
        binding_digest: result.binding_digest,
        policy_digest: result.policy_digest,
        subjects,
        key_fingerprints: keyFingerprints,
        issued_at: issuedAt,
        expires_at: expiresAt,
        revocation_checked_at: revocationCheckedAt,
    });
}
function exactTrustBinding(value, requirement, program) {
    if (!exactKeys(value, TRUST_BINDING_KEYS)
        || typeof value.instance_id !== 'string' || value.instance_id.length === 0
        || typeof value.stage_id !== 'string' || value.stage_id.length === 0
        || value.requirement_id !== requirement.requirement_id
        || value.policy_digest !== requirement.policy_digest
        || value.program_version !== program.version
        || value.root_caid !== program.root_caid
        || value.action_digest !== program.action_digest
        || !DIGEST.test(value.program_digest)
        || !Array.isArray(value.predecessor_receipt_digests)
        || value.predecessor_receipt_digests.some((entry) => typeof entry !== 'string' || !DIGEST.test(entry))
        || new Set(value.predecessor_receipt_digests).size
            !== value.predecessor_receipt_digests.length
        || value.predecessor_receipt_digests.some((entry, index) => index > 0
            && entry < value.predecessor_receipt_digests[index - 1]))
        return null;
    let digest;
    try {
        if (value.program_digest !== canonicalDigest(program))
            return null;
        digest = canonicalDigest(value);
    }
    catch {
        return null;
    }
    return { binding: deepFreeze(canonicalCopy(value)), digest };
}
function resolvePinnedInstant(value) {
    return typeof value === 'function' ? value() : value;
}
/**
 * Wrap any evidence verifier in the Trust Program stage-verifier contract.
 * Runtime artifacts have a closed three-field envelope, so trust configuration
 * cannot ride beside the evidence and influence verification.
 */
export function createPinnedEvidenceAdapter({ policyDigest, verify, trustedConfiguration = {}, metadata, }) {
    if (!DIGEST.test(policyDigest) || typeof verify !== 'function'
        || (metadata !== undefined && typeof metadata !== 'function')) {
        throw new TypeError('pinned evidence adapter configuration invalid');
    }
    const pinnedConfiguration = snapshotPinned(trustedConfiguration);
    return async function pinnedEvidenceAdapter({ artifact, requirement, program }) {
        if (!exactKeys(artifact, ARTIFACT_KEYS))
            return refusal('artifact_schema_invalid');
        if (!isDataRecord(requirement) || !isDataRecord(program))
            return refusal('verification_context_invalid');
        if (requirement.policy_digest !== policyDigest)
            return refusal('requirement_policy_mismatch');
        const expected = exactTrustBinding(artifact.binding, requirement, program);
        if (!expected)
            return refusal('trust_binding_invalid');
        let evidence;
        try {
            evidence = deepFreeze(canonicalCopy(artifact.evidence));
        }
        catch {
            return refusal('evidence_not_canonical');
        }
        if (containsRuntimeTrustConfiguration(evidence)) {
            return refusal('artifact_trust_configuration_forbidden');
        }
        const context = Object.freeze({
            trustedConfiguration: pinnedConfiguration,
            expectedBinding: expected.binding,
            expectedBindingDigest: expected.digest,
            expectedPolicyDigest: policyDigest,
            requirement: deepFreeze(canonicalCopy(requirement)),
            program: deepFreeze(canonicalCopy(program)),
        });
        let verified;
        try {
            verified = await verify(evidence, context);
        }
        catch {
            return refusal('evidence_verification_failed');
        }
        if (!isDataRecord(verified) || verified.valid !== true) {
            return refusal(typeof verified?.reason === 'string'
                ? verified.reason : 'evidence_verification_failed');
        }
        let claims = verified;
        if (metadata) {
            try {
                const resolved = await metadata(verified, Object.freeze({ ...context, evidence }));
                if (!isDataRecord(resolved))
                    return refusal('evidence_metadata_invalid');
                claims = { ...verified, ...resolved };
            }
            catch {
                return refusal('evidence_metadata_invalid');
            }
        }
        if (claims.binding_digest !== expected.digest)
            return refusal('evidence_binding_mismatch');
        if (claims.policy_digest !== policyDigest)
            return refusal('evidence_policy_mismatch');
        return normalizeVerifiedClaims(claims);
    };
}
/** Canonical SHA-256 fingerprint of an SPKI public key. */
export function canonicalKeyFingerprint(value) {
    try {
        let key;
        if (value instanceof crypto.KeyObject) {
            key = value.type === 'public' ? value : crypto.createPublicKey(value);
        }
        else {
            if (typeof value !== 'string' || !BASE64URL.test(value))
                return null;
            const bytes = Buffer.from(value, 'base64url');
            if (bytes.toString('base64url') !== value)
                return null;
            key = crypto.createPublicKey({ key: bytes, type: 'spki', format: 'der' });
        }
        const spki = key.export({ type: 'spki', format: 'der' });
        return `sha256:${crypto.createHash('sha256').update(spki).digest('hex')}`;
    }
    catch {
        return null;
    }
}
function publicKeyValue(value) {
    try {
        if (typeof value === 'string')
            return canonicalKeyFingerprint(value) ? value : null;
        if (!(value instanceof crypto.KeyObject))
            return null;
        const key = value.type === 'public' ? value : crypto.createPublicKey(value);
        return key.export({ type: 'spki', format: 'der' }).toString('base64url');
    }
    catch {
        return null;
    }
}
function validQuorumPolicy(policy) {
    if (!isDataRecord(policy)
        || !['threshold', 'ordered'].includes(policy.mode)
        || !Number.isSafeInteger(policy.required) || policy.required < 1
        || !Array.isArray(policy.approvers) || policy.approvers.length === 0
        || policy.required > policy.approvers.length)
        return false;
    const slots = new Set();
    for (const slot of policy.approvers) {
        if (!isDataRecord(slot) || typeof slot.role !== 'string' || slot.role.length === 0
            || typeof slot.approver !== 'string' || slot.approver.length === 0)
            return false;
        const key = `${slot.role}\u0000${slot.approver}`;
        if (slots.has(key))
            return false;
        slots.add(key);
    }
    return true;
}
/** Compose Trust Program with the repository's Quorum verifier. */
export function createQuorumTrustProgramAdapter(options) {
    const policy = snapshotPinned(options.policy);
    const approverKeys = snapshotPinned(options.approverKeys);
    const verificationOptions = snapshotPinned(options.verificationOptions ?? {});
    const verifyQuorum = options.verifyQuorum ?? verifyQuorumDefault;
    const policyValid = validQuorumPolicy(policy);
    const pinnedKeysValid = policyValid && policy.approvers.every((slot) => publicKeyValue(approverKeys[slot.approver]) !== null);
    return createPinnedEvidenceAdapter({
        policyDigest: options.policyDigest,
        verify: async (evidence, context) => {
            if (!policyValid || !pinnedKeysValid)
                return refusal('quorum_policy_invalid');
            if (!exactKeys(evidence, QUORUM_EVIDENCE_KEYS)
                || !Array.isArray(evidence.members) || evidence.members.length === 0
                || evidence.members.length > policy.approvers.length) {
                return refusal('quorum_evidence_schema_invalid');
            }
            const members = [];
            for (const member of evidence.members) {
                if (!exactKeys(member, QUORUM_MEMBER_KEYS)
                    || typeof member.role !== 'string' || !isDataRecord(member.signoff)
                    || !isDataRecord(member.signoff.context)
                    || typeof member.signoff.context.approver !== 'string') {
                    return refusal('quorum_evidence_schema_invalid');
                }
                const approver = member.signoff.context.approver;
                const admitted = policy.approvers.some((slot) => slot.role === member.role && slot.approver === approver);
                const publicKey = publicKeyValue(approverKeys[approver]);
                if (!admitted || !publicKey)
                    return refusal('quorum_member_not_pinned');
                members.push({
                    role: member.role,
                    approver_public_key: publicKey,
                    signoff: member.signoff,
                });
            }
            let result;
            try {
                result = await verifyQuorum({
                    '@type': 'ep.quorum',
                    action_hash: context.expectedBindingDigest,
                    policy,
                    members,
                }, verificationOptions);
            }
            catch {
                return refusal('quorum_verification_failed');
            }
            if (!isDataRecord(result) || result.valid !== true)
                return refusal('quorum_verification_failed');
            const issued = members.map((member) => canonicalInstant(member.signoff.context.issued_at));
            const expires = members.map((member) => canonicalInstant(member.signoff.context.expires_at));
            if (issued.some((entry) => entry === null) || expires.some((entry) => entry === null)) {
                return refusal('evidence_time_invalid');
            }
            const subjects = members.map((member) => member.signoff.context.approver);
            const fingerprints = members.map((member) => canonicalKeyFingerprint(member.approver_public_key));
            if (fingerprints.some((entry) => entry === null))
                return refusal('evidence_principal_set_invalid');
            return {
                valid: true,
                binding_digest: context.expectedBindingDigest,
                policy_digest: options.policyDigest,
                subjects,
                key_fingerprints: fingerprints,
                issued_at: issued.sort()[0],
                expires_at: expires.sort()[0],
                revocation_checked_at: resolvePinnedInstant(options.revocationCheckedAt),
            };
        },
    });
}
/** Compose Trust Program with AEC under RP-owned policy, action, and trust roots. */
export function createAecTrustProgramAdapter(options) {
    if (typeof options.requirement !== 'string' || !options.requirement.trim()) {
        throw new TypeError('AEC relying-party requirement required');
    }
    const keysByType = snapshotPinned(options.keysByType);
    const policiesByType = snapshotPinned(options.policiesByType);
    const verifiers = snapshotPinned(options.verifiers ?? {});
    const verifyAuthorizationChain = options.verifyAuthorizationChain
        ?? verifyAuthorizationChainDefault;
    return createPinnedEvidenceAdapter({
        policyDigest: options.policyDigest,
        metadata: options.metadata,
        verify: async (chain, context) => {
            let result;
            try {
                result = await verifyAuthorizationChain(chain, {
                    keysByType,
                    policiesByType,
                    verifiers,
                    requirement: options.requirement,
                    expectedAction: context.expectedBinding,
                    expectedActionDigest: context.expectedBindingDigest,
                    verificationTime: resolvePinnedInstant(options.verificationTime),
                });
            }
            catch {
                return refusal('aec_verification_failed');
            }
            const actionDigest = typeof result?.action_digest === 'string'
                ? result.action_digest.replace(/^sha256:/, '') : null;
            if (!isDataRecord(result) || result.satisfied !== true
                || result.expected_action_bound !== true
                || actionDigest !== context.expectedBindingDigest.slice('sha256:'.length)) {
                return refusal('aec_verification_failed');
            }
            return {
                ...result,
                valid: true,
                binding_digest: context.expectedBindingDigest,
                policy_digest: options.policyDigest,
            };
        },
    });
}
function receiptProgramOwnership(binding) {
    return isDataRecord(binding)
        && binding.consequence_mode === 'receipt-program'
        && typeof binding.capability_template_digest === 'string'
        && DIGEST.test(binding.capability_template_digest)
        && binding.escrow_profile_digest === null;
}
function actionEscrowOwnership(binding, profileDigest) {
    return isDataRecord(binding)
        && binding.consequence_mode === 'action-escrow'
        && binding.capability_template_digest === null
        && binding.escrow_profile_digest === profileDigest
        && DIGEST.test(binding.escrow_profile_digest);
}
/** Explicitly detect and refuse Action Escrow nested under Receipt Program. */
export function containsActionEscrowConsequence(value) {
    const stack = [value];
    const seen = new WeakSet();
    while (stack.length) {
        const current = stack.pop();
        if (!current || typeof current !== 'object')
            continue;
        if (seen.has(current))
            return true;
        seen.add(current);
        if (Array.isArray(current)) {
            stack.push(...current);
            continue;
        }
        if (!isDataRecord(current))
            return true;
        for (const [key, entry] of Object.entries(current)) {
            if (key.startsWith('action_escrow')
                || (key === 'consequence_mode' && entry === 'action-escrow')
                || (typeof entry === 'string'
                    && (entry.startsWith('EP-ACTION-ESCROW-')
                        || entry.toLowerCase().includes('action-escrow'))))
                return true;
            if (entry && typeof entry === 'object')
                stack.push(entry);
        }
    }
    return false;
}
function withOptions(fn, options) {
    Object.defineProperty(fn, 'options', {
        configurable: false,
        enumerable: false,
        writable: false,
        value: options,
    });
    return Object.freeze(fn);
}
/** Verify and normalize one Receipt Program terminal certificate. */
export function createReceiptProgramTerminalOutcomeVerifier(options) {
    if (typeof options.programId !== 'string' || options.programId.length === 0
        || (options.programDigest !== undefined && !DIGEST.test(options.programDigest))
        || typeof options.resolveCaid !== 'function') {
        throw new TypeError('Receipt Program adapter configuration invalid');
    }
    const pinned = snapshotPinned({
        programId: options.programId,
        programDigest: options.programDigest,
        trustedCertificateKeys: options.trustedCertificateKeys,
        expectedContext: options.expectedContext,
        resolveCaid: options.resolveCaid,
    });
    const verifyCertificate = options.verifyReceiptProgramCertificate
        ?? verifyReceiptProgramCertificateDefault;
    const verifier = async ({ evidence, authorizationBinding }) => {
        if (!receiptProgramOwnership(authorizationBinding)) {
            return terminalRefusal('consequence_ownership_invalid');
        }
        if (!exactKeys(evidence, RECEIPT_EVIDENCE_KEYS)) {
            return terminalRefusal('receipt_program_evidence_schema_invalid');
        }
        let certificate;
        try {
            certificate = deepFreeze(canonicalCopy(evidence.certificate));
        }
        catch {
            return terminalRefusal('receipt_program_evidence_invalid');
        }
        if (containsActionEscrowConsequence(certificate?.program)) {
            return terminalRefusal('action_escrow_receipt_program_nesting_refused');
        }
        let result;
        try {
            result = await verifyCertificate(certificate, {
                trustedCertificateKeys: pinned.trustedCertificateKeys,
                expectedContext: pinned.expectedContext,
                resolveCaid: pinned.resolveCaid,
            });
        }
        catch {
            return terminalRefusal('receipt_program_verification_failed');
        }
        const certificateProgram = certificate.program;
        if (!isDataRecord(result) || result.ok !== true
            || !isDataRecord(certificateProgram)
            || !['executed', 'refused', 'indeterminate'].includes(result.outcome)
            || certificate.outcome !== result.outcome
            || certificateProgram.program_id !== pinned.programId
            || certificateProgram.operation_id !== authorizationBinding.operation_id
            || certificateProgram.action_digest !== authorizationBinding.action_digest
            || certificateProgram.caid !== authorizationBinding.root_caid
            || (pinned.programDigest !== undefined && result.program_digest !== pinned.programDigest)) {
            return terminalRefusal('receipt_program_binding_mismatch');
        }
        return Object.freeze({
            valid: true,
            reason: null,
            outcome: result.outcome,
            evidence_digest: canonicalDigest(certificate),
        });
    };
    return withOptions(verifier, pinned);
}
/** Trust Program executionOutcomeVerifier wrapper for Receipt Program. */
export function createReceiptProgramExecutionOutcomeVerifier(options) {
    const terminal = createReceiptProgramTerminalOutcomeVerifier(options);
    return async function receiptProgramExecutionOutcomeVerifier(input) {
        const result = await terminal(input);
        return result.valid === true
            && result.outcome === input.outcome
            && result.evidence_digest === input.evidenceDigest;
    };
}
function actionEscrowOutcome(stage) {
    if (stage === 'released' || stage === 'completed')
        return 'executed';
    if (stage === 'cancelled')
        return 'refused';
    if (stage === 'release_indeterminate')
        return 'indeterminate';
    return null;
}
/** Verify and normalize one Action Escrow authenticated terminal package. */
export function createActionEscrowTerminalOutcomeVerifier(options) {
    if (typeof options.agreementId !== 'string' || options.agreementId.length === 0
        || !DIGEST.test(options.releaseActionDigest) || !DIGEST.test(options.profileDigest)
        || !isDataRecord(options.componentVerifiers)) {
        throw new TypeError('Action Escrow adapter configuration invalid');
    }
    const componentVerifiers = snapshotPinned(options.componentVerifiers);
    const pinned = snapshotPinned({
        agreementId: options.agreementId,
        releaseActionDigest: options.releaseActionDigest,
        profileDigest: options.profileDigest,
        componentVerifiers,
        now: options.now,
        maxDocumentBytes: options.maxDocumentBytes,
        maxProjectRecordBytes: options.maxProjectRecordBytes,
    });
    const verifyPackage = options.verifyActionEscrowEvidencePackage
        ?? verifyActionEscrowEvidencePackageDefault;
    const verifier = async ({ evidence, authorizationBinding }) => {
        if (!actionEscrowOwnership(authorizationBinding, pinned.profileDigest)) {
            return terminalRefusal('consequence_ownership_invalid');
        }
        if (!exactKeys(evidence, ACTION_ESCROW_EVIDENCE_KEYS, new Set(['package', 'document_bytes'])))
            return terminalRefusal('action_escrow_evidence_schema_invalid');
        let pkg;
        try {
            pkg = deepFreeze(canonicalCopy(evidence.package));
        }
        catch {
            return terminalRefusal('action_escrow_evidence_invalid');
        }
        const outcome = actionEscrowOutcome(pkg.stage);
        if (!outcome)
            return terminalRefusal('action_escrow_state_not_terminal');
        if (pkg.agreement_id !== pinned.agreementId || pkg.package_digest === undefined
            || !DIGEST.test(pkg.package_digest)) {
            return terminalRefusal('action_escrow_binding_mismatch');
        }
        if (!(evidence.document_bytes instanceof Uint8Array)
            || (evidence.project_record_bytes !== undefined
                && !(evidence.project_record_bytes instanceof Uint8Array))) {
            return terminalRefusal('action_escrow_evidence_invalid');
        }
        const verificationOptions = {
            documentBytes: Uint8Array.from(evidence.document_bytes),
            expectedAgreementId: pinned.agreementId,
        };
        if (evidence.project_record_bytes !== undefined) {
            verificationOptions.projectRecordBytes = Uint8Array.from(evidence.project_record_bytes);
        }
        for (const name of ACTION_ESCROW_COMPONENT_VERIFIERS) {
            const candidate = componentVerifiers[name];
            if (candidate !== undefined) {
                if (typeof candidate !== 'function')
                    return terminalRefusal('action_escrow_verifier_invalid');
                verificationOptions[name] = candidate;
            }
        }
        if (pinned.now !== undefined)
            verificationOptions.now = resolvePinnedInstant(pinned.now);
        if (pinned.maxDocumentBytes !== undefined) {
            verificationOptions.maxDocumentBytes = pinned.maxDocumentBytes;
        }
        if (pinned.maxProjectRecordBytes !== undefined) {
            verificationOptions.maxProjectRecordBytes = pinned.maxProjectRecordBytes;
        }
        let result;
        try {
            result = await verifyPackage(pkg, verificationOptions);
        }
        catch {
            return terminalRefusal('action_escrow_verification_failed');
        }
        if (!isDataRecord(result) || result.valid !== true
            || result.package_digest !== pkg.package_digest
            || result.agreement_id !== pinned.agreementId
            || result.action_digest !== pinned.releaseActionDigest
            || result.profile_digest !== pinned.profileDigest
            || authorizationBinding.action_digest !== pinned.releaseActionDigest) {
            return terminalRefusal('action_escrow_binding_mismatch');
        }
        return Object.freeze({
            valid: true,
            reason: null,
            outcome,
            evidence_digest: result.package_digest,
        });
    };
    return withOptions(verifier, pinned);
}
/** Trust Program executionOutcomeVerifier wrapper for Action Escrow. */
export function createActionEscrowExecutionOutcomeVerifier(options) {
    const terminal = createActionEscrowTerminalOutcomeVerifier(options);
    return async function actionEscrowExecutionOutcomeVerifier(input) {
        const result = await terminal(input);
        return result.valid === true
            && result.outcome === input.outcome
            && result.evidence_digest === input.evidenceDigest;
    };
}
export default {
    canonicalKeyFingerprint,
    containsActionEscrowConsequence,
    createPinnedEvidenceAdapter,
    createQuorumTrustProgramAdapter,
    createAecTrustProgramAdapter,
    createReceiptProgramTerminalOutcomeVerifier,
    createReceiptProgramExecutionOutcomeVerifier,
    createActionEscrowTerminalOutcomeVerifier,
    createActionEscrowExecutionOutcomeVerifier,
};
//# sourceMappingURL=trust-program-adapters.js.map