// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AEB-CROSSING-RECORD-v1
 *
 * A carrier-neutral, offline-verifiable record that one relying-party boundary
 * evaluated one exact action under one native authority instance. The record
 * is evidence only: verification never authorizes a later crossing.
 *
 * Native authority is an open set behind one closed projection contract. The
 * two reference mappings below demonstrate an authorization-server grant and
 * a bounded-capability receipt without claiming that the native systems are
 * equivalent. They share the record schema and verifier, not record bytes.
 */
import { AEB_EVALUATION_VERSION, AEB_EVALUATION_V2_VERSION, canonicalizeAeb, digestAeb, digestAebTyped, } from "./aeb-adapter-contract.js";
import { actionDigest as aecActionDigest } from "./evidence-chain.js";
import { SIGNATURE_AGILITY_VERSION, signAgileSet, verifyAgileSignatureSet, } from "./pq-signature-agility.js";
export const AEB_CROSSING_RECORD_VERSION = "EP-AEB-CROSSING-RECORD-v1";
export const AEB_CROSSING_RECORD_DOMAIN = `${AEB_CROSSING_RECORD_VERSION}\0`;
export const AEB_CROSSING_RECORD_V2_VERSION = "EP-AEB-CROSSING-RECORD-v2";
export const AEB_CROSSING_RECORD_V2_DOMAIN = `${AEB_CROSSING_RECORD_V2_VERSION}\0`;
/**
 * A separate, derived lifecycle index.  This MUST NOT be confused with or
 * relabeled as the already shipped EP-AEB-CROSSING-RECORD-v2 profile above.
 */
export const AEB_CROSSING_LIFECYCLE_INDEX_V2_VERSION = "EP-AEB-CROSSING-LIFECYCLE-INDEX-v2";
export const AEB_CROSSING_LIFECYCLE_INDEX_V2_DOMAIN = `${AEB_CROSSING_LIFECYCLE_INDEX_V2_VERSION}\0`;
export const AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS = Object.freeze([
    "Ed25519",
    "ML-DSA-65",
]);
export const WIMSE_OAUTH_CROSSING_MAPPING_PROFILE = "EP-AEB-CROSSING-WIMSE-OAUTH-v1";
export const BCR_CROSSING_MAPPING_PROFILE = "EP-AEB-CROSSING-BCR-v1";
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/#-]{0,511}$/;
const CAID = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const REASON_CODE = /^[a-z][a-z0-9_]{0,127}$/;
const NATIVE_VERIFICATIONS = new Set([
    "VERIFIED",
    "FAILED",
    "INDETERMINATE",
]);
const RP_ACCEPTANCES = new Set([
    "ACCEPTED",
    "REJECTED",
    "INDETERMINATE",
]);
const ACTION_RELATIONS = new Set([
    "EXACT_MATCH",
    "MISMATCH",
    "INDETERMINATE",
]);
const STATUSES = new Set([
    "CURRENT",
    "STALE",
    "UNAVAILABLE",
    "REVOKED",
    "INDETERMINATE",
]);
const REPLAYS = new Set(["FRESH", "REPLAY", "INDETERMINATE"]);
const ADMISSIONS = new Set([
    "ADMIT",
    "REFUSE",
    "INDETERMINATE",
    "NOT_APPLICABLE",
]);
const CUSTODIES = new Set([
    "UNRESERVED",
    "RESERVED",
    "INVOKING",
    "INDETERMINATE",
    "TERMINAL",
]);
const COMMITMENTS = new Set([
    "NOT_INVOKED",
    "COMMITTED",
    "PROVEN_NOT_COMMITTED",
    "INDETERMINATE",
]);
const EFFECTS = new Set([
    "NOT_OBSERVED",
    "OBSERVED_AS_REQUESTED",
    "DIVERGED",
    "INDETERMINATE",
]);
const RETRIES = new Set([
    "NOT_APPLICABLE",
    "REFUSE",
    "REQUIRES_NEW_ADMISSION",
]);
const RECONCILIATIONS = new Set([
    "NOT_APPLICABLE",
    "REQUIRED",
    "REFUSED",
    "APPLIED",
]);
const ADMISSION_REFERENCE_STATES = new Set([
    "PRESENT",
    "MISSING",
    "NOT_APPLICABLE",
    "INDETERMINATE",
]);
const REASON_CODES = new Set([
    "action_mismatch",
    "effect_diverged",
    "material_field_loss",
    "native_replay_detected",
    "native_verification_failed",
    "native_verification_indeterminate",
    "provider_crash",
    "provider_timeout",
    "reconciliation_binding_mismatch",
    "reconciliation_not_authenticated",
    "rp_acceptance_indeterminate",
    "rp_acceptance_rejected",
    "status_revoked",
    "status_stale",
    "status_unavailable",
    "wrong_trust_root",
]);
const DOCUMENT_KEYS = new Set(["@version", "body", "signatures"]);
const BODY_KEYS = new Set([
    "record_id",
    "operation_id",
    "issued_at",
    "signature_profile",
    "native_authority",
    "action",
    "boundary",
    "requirements",
    "contract_digest",
    "admission_reference",
    "lifecycle_records",
    "evaluated_evidence_digests",
    "configuration_digests",
    "referee",
]);
const V2_BODY_KEYS = new Set([...BODY_KEYS, "admission_domain_digest"]);
const LIFECYCLE_INDEX_V2_BODY_KEYS = new Set([
    "record_id",
    "operation_id",
    "issued_at",
    "signature_profile",
    "action",
    "admission_domain_digest",
    "lifecycle",
    "source_crossing_record",
    "conversion",
    "contract_digest",
    "execution_authorizing",
]);
const LIFECYCLE_INDEX_KEYS = new Set([
    "evaluation",
    "local_admission_digest",
    "authority_custody",
    "provider_entry_digest",
    "effect_observation_digest",
    "provider_outcome_digest",
    "reconciliation_digest",
]);
const LIFECYCLE_EVALUATION_KEYS = new Set(["profile", "digest"]);
/** Conversion reason code that marks the evaluation profile label unchecked. */
const UNVERIFIED_EVALUATION_REFERENCE = "evaluation_reference_unverified";
const LIFECYCLE_CUSTODY_KEYS = new Set(["phase", "digest"]);
const LIFECYCLE_SOURCE_KEYS = new Set(["version", "digest"]);
const LIFECYCLE_CONVERSION_KEYS = new Set(["status", "reason_codes"]);
const SIGNATURE_PROFILE_KEYS = new Set(["id", "required_algorithms"]);
const AUTHORITY_KEYS = new Set([
    "adapter_id",
    "adapter_version",
    "mapping_profile_id",
    "mapping_profile_digest",
    "native_profile",
    "issuer",
    "subject",
    "authority_instance_digest",
    "evidence_digest",
    "replay_unit",
    "native_verification",
    "rp_acceptance",
    "status",
    "constraints_digest",
    "validity",
]);
const STATUS_KEYS = new Set(["value", "checked_at", "source_head_digest"]);
const VALIDITY_KEYS = new Set(["not_before", "not_after"]);
const ACTION_KEYS = new Set(["caid", "action_digest"]);
const BOUNDARY_KEYS = new Set([
    "relying_party_id",
    "audience",
    "executor_id",
    "state_domain_id",
]);
const REQUIREMENT_KEYS = new Set(["admission_digest", "review_digest"]);
const ADMISSION_REFERENCE_KEYS = new Set(["state", "digest"]);
const LIFECYCLE_KEYS = new Set([
    "evaluation_digest",
    "consumption_digest",
    "provider_entry_digest",
]);
const REFEREE_KEYS = new Set([
    "native_verification",
    "rp_acceptance",
    "action_relation",
    "status",
    "replay",
    "admission",
    "custody",
    "provider_commitment",
    "observed_effect",
    "retry",
    "reconciliation",
    "reason_codes",
]);
const SIGNATURE_KEYS = new Set(["alg", "sig", "key_id"]);
class CrossingRecordError extends TypeError {
    code;
    constructor(code) {
        super(code);
        this.code = code;
        this.name = "CrossingRecordError";
    }
}
function isRecord(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function exactKeys(value, expected) {
    const keys = Reflect.ownKeys(value);
    return (keys.length === expected.size &&
        keys.every((key) => typeof key === "string" && expected.has(key)));
}
function identifier(value) {
    return (typeof value === "string" &&
        IDENTIFIER.test(value) &&
        !/[\u0000-\u001f\u007f]/.test(value));
}
function digest(value) {
    return typeof value === "string" && DIGEST.test(value);
}
function instant(value) {
    if (typeof value !== "string" ||
        !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value))
        return false;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed);
}
function validStatus(value) {
    return (isRecord(value) &&
        exactKeys(value, STATUS_KEYS) &&
        STATUSES.has(value.value) &&
        instant(value.checked_at) &&
        digest(value.source_head_digest));
}
function validValidity(value) {
    return (isRecord(value) &&
        exactKeys(value, VALIDITY_KEYS) &&
        instant(value.not_before) &&
        instant(value.not_after) &&
        Date.parse(value.not_before) < Date.parse(value.not_after));
}
function validAuthority(value) {
    return (isRecord(value) &&
        exactKeys(value, AUTHORITY_KEYS) &&
        identifier(value.adapter_id) &&
        identifier(value.adapter_version) &&
        identifier(value.mapping_profile_id) &&
        digest(value.mapping_profile_digest) &&
        identifier(value.native_profile) &&
        identifier(value.issuer) &&
        identifier(value.subject) &&
        digest(value.authority_instance_digest) &&
        digest(value.evidence_digest) &&
        digest(value.replay_unit) &&
        NATIVE_VERIFICATIONS.has(value.native_verification) &&
        RP_ACCEPTANCES.has(value.rp_acceptance) &&
        validStatus(value.status) &&
        digest(value.constraints_digest) &&
        validValidity(value.validity));
}
function validDigestList(value) {
    return (Array.isArray(value) &&
        value.length > 0 &&
        value.length <= 128 &&
        value.every(digest) &&
        new Set(value).size === value.length);
}
function validReferee(value) {
    return (isRecord(value) &&
        exactKeys(value, REFEREE_KEYS) &&
        NATIVE_VERIFICATIONS.has(value.native_verification) &&
        RP_ACCEPTANCES.has(value.rp_acceptance) &&
        ACTION_RELATIONS.has(value.action_relation) &&
        STATUSES.has(value.status) &&
        REPLAYS.has(value.replay) &&
        ADMISSIONS.has(value.admission) &&
        CUSTODIES.has(value.custody) &&
        COMMITMENTS.has(value.provider_commitment) &&
        EFFECTS.has(value.observed_effect) &&
        RETRIES.has(value.retry) &&
        RECONCILIATIONS.has(value.reconciliation) &&
        Array.isArray(value.reason_codes) &&
        value.reason_codes.length <= 16 &&
        value.reason_codes.every((code) => typeof code === "string" &&
            REASON_CODE.test(code) &&
            REASON_CODES.has(code)) &&
        new Set(value.reason_codes).size === value.reason_codes.length);
}
function algorithmSetMatches(value) {
    return (Array.isArray(value) &&
        value.length === AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS.length &&
        value.every((algorithm, index) => algorithm === AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS[index]));
}
function signatureArray(value) {
    return (Array.isArray(value) &&
        value.length === AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS.length &&
        value.every((signature, index) => isRecord(signature) &&
            (exactKeys(signature, SIGNATURE_KEYS) ||
                exactKeys(signature, new Set(["alg", "sig"]))) &&
            signature.alg === AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS[index] &&
            typeof signature.sig === "string" &&
            (signature.key_id === undefined || identifier(signature.key_id))));
}
export function crossingRecordContractDigest(body) {
    return digestAebTyped({
        action: body.action,
        native_authority: {
            native_profile: body.native_authority.native_profile,
            issuer: body.native_authority.issuer,
            subject: body.native_authority.subject,
            authority_instance_digest: body.native_authority.authority_instance_digest,
            replay_unit: body.native_authority.replay_unit,
            mapping_profile_id: body.native_authority.mapping_profile_id,
            mapping_profile_digest: body.native_authority.mapping_profile_digest,
            constraints_digest: body.native_authority.constraints_digest,
            validity: body.native_authority.validity,
        },
        requirement_profile: body.requirements.admission_digest,
        audience: body.boundary.audience,
        executor: body.boundary.executor_id,
        state_domain: body.boundary.state_domain_id,
    }, `${AEB_CROSSING_RECORD_VERSION}:contract`);
}
export function crossingRecordV2AdmissionDomainDigest(boundary) {
    return digestAebTyped({
        relying_party_id: boundary.relying_party_id,
        audience: boundary.audience,
        executor_id: boundary.executor_id,
        state_domain_id: boundary.state_domain_id,
    }, `${AEB_CROSSING_RECORD_V2_VERSION}:admission-domain`);
}
export function crossingRecordV2ContractDigest(body) {
    return digestAebTyped({
        action: body.action,
        native_authority: {
            native_profile: body.native_authority.native_profile,
            issuer: body.native_authority.issuer,
            subject: body.native_authority.subject,
            authority_instance_digest: body.native_authority.authority_instance_digest,
            replay_unit: body.native_authority.replay_unit,
            mapping_profile_id: body.native_authority.mapping_profile_id,
            mapping_profile_digest: body.native_authority.mapping_profile_digest,
            constraints_digest: body.native_authority.constraints_digest,
            validity: body.native_authority.validity,
        },
        requirement_profile: body.requirements.admission_digest,
        admission_domain_digest: body.admission_domain_digest,
    }, `${AEB_CROSSING_RECORD_V2_VERSION}:contract`);
}
export function crossingRecordSignedBytes(body) {
    return Buffer.from(`${AEB_CROSSING_RECORD_DOMAIN}${canonicalizeAeb(body)}`, "utf8");
}
export function crossingRecordDigest(body) {
    return digestAebTyped(body, `${AEB_CROSSING_RECORD_VERSION}:record`);
}
export function crossingRecordV2SignedBytes(body) {
    return Buffer.from(`${AEB_CROSSING_RECORD_V2_DOMAIN}${canonicalizeAeb(body)}`, "utf8");
}
export function crossingRecordV2Digest(body) {
    return digestAebTyped(body, `${AEB_CROSSING_RECORD_V2_VERSION}:record`);
}
export function crossingLifecycleIndexV2AdmissionDomainDigest(boundary) {
    return digestAebTyped({
        relying_party_id: boundary.relying_party_id,
        audience: boundary.audience,
        executor_id: boundary.executor_id,
        state_domain_id: boundary.state_domain_id,
    }, `${AEB_CROSSING_LIFECYCLE_INDEX_V2_VERSION}:admission-domain`);
}
export function crossingLifecycleIndexV2ContractDigest(body) {
    return digestAebTyped({
        operation_id: body.operation_id,
        action: body.action,
        admission_domain_digest: body.admission_domain_digest,
        evaluation: body.lifecycle.evaluation,
    }, `${AEB_CROSSING_LIFECYCLE_INDEX_V2_VERSION}:contract`);
}
export function crossingLifecycleIndexV2SignedBytes(body) {
    return Buffer.from(`${AEB_CROSSING_LIFECYCLE_INDEX_V2_DOMAIN}${canonicalizeAeb(body)}`, "utf8");
}
export function crossingLifecycleIndexV2Digest(body) {
    return digestAebTyped(body, `${AEB_CROSSING_LIFECYCLE_INDEX_V2_VERSION}:record`);
}
function validateBody(body) {
    if (!isRecord(body) || !exactKeys(body, BODY_KEYS))
        return "malformed_record";
    if (!identifier(body.record_id) ||
        !identifier(body.operation_id) ||
        !instant(body.issued_at)) {
        return "malformed_record";
    }
    if (!isRecord(body.signature_profile) ||
        !exactKeys(body.signature_profile, SIGNATURE_PROFILE_KEYS) ||
        body.signature_profile.id !== SIGNATURE_AGILITY_VERSION)
        return "malformed_record";
    if (!algorithmSetMatches(body.signature_profile.required_algorithms))
        return "algorithm_set_mismatch";
    if (!validAuthority(body.native_authority))
        return "native_authority_invalid";
    if (!isRecord(body.action) ||
        !exactKeys(body.action, ACTION_KEYS) ||
        typeof body.action.caid !== "string" ||
        !CAID.test(body.action.caid) ||
        !digest(body.action.action_digest))
        return "malformed_record";
    if (!isRecord(body.boundary) ||
        !exactKeys(body.boundary, BOUNDARY_KEYS) ||
        !Object.values(body.boundary).every(identifier))
        return "malformed_record";
    if (!isRecord(body.requirements) ||
        !exactKeys(body.requirements, REQUIREMENT_KEYS) ||
        !digest(body.requirements.admission_digest) ||
        !digest(body.requirements.review_digest)) {
        return "malformed_record";
    }
    if (!digest(body.contract_digest))
        return "malformed_record";
    if (crossingRecordContractDigest(body) !==
        body.contract_digest) {
        return "contract_digest_mismatch";
    }
    if (!isRecord(body.admission_reference) ||
        !exactKeys(body.admission_reference, ADMISSION_REFERENCE_KEYS) ||
        !ADMISSION_REFERENCE_STATES.has(body.admission_reference.state)) {
        return "admission_reference_invalid";
    }
    if (body.admission_reference.state === "PRESENT") {
        if (!digest(body.admission_reference.digest))
            return "admission_reference_invalid";
    }
    else if (body.admission_reference.digest !== null)
        return "admission_reference_invalid";
    if (!isRecord(body.lifecycle_records) ||
        !exactKeys(body.lifecycle_records, LIFECYCLE_KEYS) ||
        !digest(body.lifecycle_records.evaluation_digest) ||
        !(body.lifecycle_records.consumption_digest === null ||
            digest(body.lifecycle_records.consumption_digest)) ||
        !(body.lifecycle_records.provider_entry_digest === null ||
            digest(body.lifecycle_records.provider_entry_digest))) {
        return "malformed_record";
    }
    if (!validDigestList(body.evaluated_evidence_digests) ||
        !validDigestList(body.configuration_digests) ||
        !validReferee(body.referee))
        return "malformed_record";
    const authority = body.native_authority;
    const referee = body.referee;
    if (referee.status !== authority.status.value)
        return "status_inconsistent";
    if (referee.admission === "ADMIT" &&
        (authority.native_verification !== "VERIFIED" ||
            authority.rp_acceptance !== "ACCEPTED" ||
            referee.native_verification !== "VERIFIED" ||
            referee.rp_acceptance !== "ACCEPTED" ||
            referee.action_relation !== "EXACT_MATCH" ||
            referee.status !== "CURRENT" ||
            referee.replay !== "FRESH"))
        return "authority_broadened";
    if (referee.native_verification !== authority.native_verification ||
        referee.rp_acceptance !== authority.rp_acceptance)
        return "authority_axis_mismatch";
    if (referee.admission === "ADMIT") {
        if (body.admission_reference.state !== "PRESENT")
            return "admission_reference_invalid";
        if (!digest(body.lifecycle_records.consumption_digest))
            return "consumption_record_required";
        if (!["RESERVED", "INVOKING", "TERMINAL"].includes(referee.custody))
            return "custody_inconsistent";
    }
    if (body.admission_reference.state === "MISSING" &&
        !["INDETERMINATE", "NOT_APPLICABLE"].includes(referee.admission)) {
        return "admission_reference_invalid";
    }
    if (body.admission_reference.state === "NOT_APPLICABLE" &&
        !["REFUSE", "NOT_APPLICABLE"].includes(referee.admission)) {
        return "admission_reference_invalid";
    }
    if (referee.status !== "CURRENT" && referee.admission === "ADMIT")
        return "status_inconsistent";
    return null;
}
function validateV2Body(body) {
    if (!isRecord(body) || !exactKeys(body, V2_BODY_KEYS))
        return "malformed_record";
    const { admission_domain_digest: admissionDomainDigest, ...v1Shape } = body;
    if (!digest(admissionDomainDigest))
        return "malformed_record";
    const v1Reason = validateBody({
        ...v1Shape,
        contract_digest: crossingRecordContractDigest(v1Shape),
    });
    if (v1Reason)
        return v1Reason;
    const typed = body;
    if (crossingRecordV2AdmissionDomainDigest(typed.boundary) !==
        typed.admission_domain_digest)
        return "admission_domain_mismatch";
    if (crossingRecordV2ContractDigest(typed) !== typed.contract_digest)
        return "contract_digest_mismatch";
    return null;
}
function nullableDigest(value) {
    return value === null || digest(value);
}
const EVALUATION_VERDICTS = new Set(["SATISFIED", "UNSATISFIED", "INDETERMINATE"]);
/**
 * Reads only the members the join needs from a pinned (plain JSON) copy of
 * an AEB-EVALUATION-v1 or -v2 record. Anything else is malformed.
 */
function evaluationFacts(value) {
    if (!isRecord(value))
        return null;
    let profile;
    let caid;
    let verdict;
    let commitment;
    if (value["@type"] === AEB_EVALUATION_VERSION) {
        if (!isRecord(value.composition))
            return null;
        profile = AEB_EVALUATION_VERSION;
        caid = value.caid;
        verdict = value.verdict;
        commitment = value.composition.action_digest;
    }
    else if (value["@type"] === AEB_EVALUATION_V2_VERSION) {
        if (!isRecord(value.action) || !isRecord(value.satisfaction))
            return null;
        profile = AEB_EVALUATION_V2_VERSION;
        caid = value.action.caid;
        verdict = value.satisfaction.verdict;
        commitment = value.action.normalized_action_digest;
    }
    else {
        return null;
    }
    if (typeof value.operation_id !== "string" ||
        value.operation_id.length === 0 ||
        typeof caid !== "string" ||
        typeof verdict !== "string" ||
        !EVALUATION_VERDICTS.has(verdict) ||
        !digest(commitment) ||
        !Array.isArray(value.legs))
        return null;
    const legs = [];
    for (const leg of value.legs) {
        if (!isRecord(leg) || !digest(leg.evidence_digest))
            return null;
        legs.push({
            evidence_digest: leg.evidence_digest,
            verdict: leg.verdict,
            native_verification: leg.native_verification,
            acceptance: leg.acceptance,
            mapping: leg.mapping,
            caid: leg.caid,
            action_digest: leg.action_digest,
        });
    }
    return {
        profile,
        operation_id: value.operation_id,
        caid,
        verdict,
        action_commitment: commitment,
        legs,
    };
}
/** Same AEC action commitment AEB-EVALUATION-v1 composition computes. */
function evaluationActionCommitment(caid, normalizedActionDigest) {
    const raw = aecActionDigest({
        caid,
        normalized_action_digest: normalizedActionDigest,
    });
    return raw.startsWith("sha256:") ? raw : `sha256:${raw}`;
}
/**
 * Joins a caller-supplied evaluation record to the crossing that cites it.
 * Returns null when bound, otherwise a refusal reason. Never throws.
 *
 * The join key between native_authority and an evaluated leg is
 * evidence_digest: the digest of the exact native artifact. The crossing's
 * replay_unit and adapter_id are derived under the crossing mapping profile
 * and are not expected to equal the leg's adapter-derived values.
 */
function evaluationJoinReason(evaluation, target) {
    let pinned;
    let evaluationDigest;
    try {
        // The strict canonicalizer reads members through property descriptors, so
        // getters never run, and refuses accessors, symbols, and sparse arrays. A
        // Proxy's traps can run during that read; the join then uses only the
        // plain snapshot, and any throw is reported as evaluation_malformed.
        pinned = JSON.parse(canonicalizeAeb(evaluation));
        evaluationDigest = digestAeb(pinned);
    }
    catch {
        return "evaluation_malformed";
    }
    const facts = evaluationFacts(pinned);
    if (!facts)
        return "evaluation_malformed";
    if (evaluationDigest !== target.digest)
        return "evaluation_digest_mismatch";
    if (target.profile !== undefined &&
        target.profile !== null &&
        facts.profile !== target.profile)
        return "evaluation_profile_mismatch";
    if (facts.operation_id !== target.operation_id)
        return "evaluation_operation_mismatch";
    if (facts.caid !== target.action.caid)
        return "evaluation_action_mismatch";
    // An evaluation that committed to a normalized action, or that is
    // SATISFIED, must have committed to exactly this action.
    const committedToAction = facts.action_commitment !==
        evaluationActionCommitment(facts.caid, null);
    if ((committedToAction || facts.verdict === "SATISFIED") &&
        facts.action_commitment !==
            evaluationActionCommitment(facts.caid, target.action.action_digest))
        return "evaluation_action_mismatch";
    if (target.referee?.admission === "ADMIT" && facts.verdict !== "SATISFIED")
        return "evaluation_verdict_inconsistent";
    const authority = target.native_authority;
    if (authority) {
        const candidates = facts.legs.filter((leg) => leg.evidence_digest === authority.evidence_digest);
        if (candidates.length === 0)
            return "evaluation_authority_unmatched";
        const exactMatch = target.referee?.action_relation === "EXACT_MATCH";
        const admitted = target.referee?.admission === "ADMIT";
        const consistent = candidates.some((leg) => (!admitted || leg.verdict === "SATISFIED") &&
            (authority.native_verification !== "VERIFIED" ||
                leg.native_verification === "VERIFIED") &&
            (authority.rp_acceptance !== "ACCEPTED" ||
                leg.acceptance === "ACCEPTED") &&
            (!exactMatch ||
                (leg.mapping === "MATCH" &&
                    leg.caid === target.action.caid &&
                    leg.action_digest === target.action.action_digest)));
        if (!consistent)
            return "evaluation_authority_inconsistent";
    }
    return null;
}
/**
 * Returns the evaluation reference a crossing record or lifecycle index
 * commits to for `evaluation`: its "@type" as the profile label and the
 * untyped digestAeb over the complete signed record. Issuers SHOULD use this
 * instead of computing a digest themselves. Throws on a malformed record.
 */
export function aebCrossingEvaluationReference(evaluation) {
    let pinned;
    try {
        pinned = JSON.parse(canonicalizeAeb(evaluation));
    }
    catch {
        throw new CrossingRecordError("evaluation_malformed");
    }
    const facts = evaluationFacts(pinned);
    if (!facts)
        throw new CrossingRecordError("evaluation_malformed");
    return { profile: facts.profile, digest: digestAeb(pinned) };
}
function validateLifecycleIndexV2Body(body) {
    if (!isRecord(body) || !exactKeys(body, LIFECYCLE_INDEX_V2_BODY_KEYS))
        return "malformed_lifecycle_index";
    if (!identifier(body.record_id) ||
        !identifier(body.operation_id) ||
        !instant(body.issued_at) ||
        body.execution_authorizing !== false)
        return "malformed_lifecycle_index";
    if (!isRecord(body.signature_profile) ||
        !exactKeys(body.signature_profile, SIGNATURE_PROFILE_KEYS) ||
        body.signature_profile.id !== SIGNATURE_AGILITY_VERSION)
        return "malformed_lifecycle_index";
    if (!algorithmSetMatches(body.signature_profile.required_algorithms))
        return "algorithm_set_mismatch";
    if (!isRecord(body.action) ||
        !exactKeys(body.action, ACTION_KEYS) ||
        typeof body.action.caid !== "string" ||
        !CAID.test(body.action.caid) ||
        !digest(body.action.action_digest) ||
        !digest(body.admission_domain_digest))
        return "malformed_lifecycle_index";
    if (!isRecord(body.lifecycle) || !exactKeys(body.lifecycle, LIFECYCLE_INDEX_KEYS))
        return "malformed_lifecycle_index";
    const lifecycle = body.lifecycle;
    if (!isRecord(lifecycle.evaluation) ||
        !exactKeys(lifecycle.evaluation, LIFECYCLE_EVALUATION_KEYS) ||
        ![AEB_EVALUATION_VERSION, AEB_EVALUATION_V2_VERSION].includes(lifecycle.evaluation.profile) ||
        !digest(lifecycle.evaluation.digest) ||
        !nullableDigest(lifecycle.local_admission_digest) ||
        !nullableDigest(lifecycle.provider_entry_digest) ||
        !nullableDigest(lifecycle.effect_observation_digest) ||
        !nullableDigest(lifecycle.provider_outcome_digest) ||
        !nullableDigest(lifecycle.reconciliation_digest))
        return "malformed_lifecycle_index";
    if (!isRecord(lifecycle.authority_custody) ||
        !exactKeys(lifecycle.authority_custody, LIFECYCLE_CUSTODY_KEYS) ||
        ![
            "NOT_APPLICABLE",
            "RESERVATION",
            "CONSUMPTION",
            "INDETERMINATE",
        ].includes(lifecycle.authority_custody.phase) ||
        !nullableDigest(lifecycle.authority_custody.digest))
        return "malformed_lifecycle_index";
    if (lifecycle.authority_custody.phase === "NOT_APPLICABLE" &&
        lifecycle.authority_custody.digest !== null)
        return "custody_reference_inconsistent";
    if (["RESERVATION", "CONSUMPTION"].includes(lifecycle.authority_custody.phase) &&
        !digest(lifecycle.authority_custody.digest))
        return "custody_reference_inconsistent";
    if (!isRecord(body.source_crossing_record) ||
        !exactKeys(body.source_crossing_record, LIFECYCLE_SOURCE_KEYS) ||
        ![
            AEB_CROSSING_RECORD_VERSION,
            AEB_CROSSING_RECORD_V2_VERSION,
            null,
        ].includes(body.source_crossing_record.version) ||
        !nullableDigest(body.source_crossing_record.digest) ||
        ((body.source_crossing_record.version === null) !==
            (body.source_crossing_record.digest === null)))
        return "source_crossing_record_invalid";
    if (!isRecord(body.conversion) ||
        !exactKeys(body.conversion, LIFECYCLE_CONVERSION_KEYS) ||
        !["NATIVE", "COMPLETE", "INDETERMINATE"].includes(body.conversion.status) ||
        !Array.isArray(body.conversion.reason_codes) ||
        body.conversion.reason_codes.length > 32 ||
        !body.conversion.reason_codes.every((reason) => typeof reason === "string" && REASON_CODE.test(reason)) ||
        new Set(body.conversion.reason_codes).size !==
            body.conversion.reason_codes.length)
        return "conversion_report_invalid";
    if (body.conversion.status === "NATIVE" &&
        body.source_crossing_record.version !== null)
        return "conversion_report_invalid";
    if (body.conversion.status !== "NATIVE" &&
        body.source_crossing_record.version === null)
        return "conversion_report_invalid";
    if (body.conversion.status === "COMPLETE" &&
        body.conversion.reason_codes.length !== 0)
        return "conversion_report_invalid";
    if (body.conversion.status === "INDETERMINATE" &&
        body.conversion.reason_codes.length === 0)
        return "conversion_report_invalid";
    // An unverified evaluation label exists only as the honest output of a
    // legacy conversion that could not bind the source evaluation, and it is
    // always the AEB-EVALUATION-v1 label that 4.1.0 wrote.
    if (body.conversion.reason_codes.includes(UNVERIFIED_EVALUATION_REFERENCE) &&
        (body.conversion.status !== "INDETERMINATE" ||
            lifecycle.evaluation.profile !== AEB_EVALUATION_VERSION))
        return "conversion_report_invalid";
    // A conversion that could not resolve custody is not COMPLETE.
    if (body.conversion.status === "COMPLETE" &&
        lifecycle.authority_custody.phase === "INDETERMINATE")
        return "conversion_report_invalid";
    if (!digest(body.contract_digest))
        return "malformed_lifecycle_index";
    const typed = body;
    if (crossingLifecycleIndexV2ContractDigest(typed) !== typed.contract_digest)
        return "contract_digest_mismatch";
    if (lifecycle.local_admission_digest === null) {
        if (!["NOT_APPLICABLE", "INDETERMINATE"].includes(lifecycle.authority_custody.phase) ||
            lifecycle.authority_custody.digest !== null ||
            lifecycle.provider_entry_digest !== null ||
            lifecycle.effect_observation_digest !== null ||
            lifecycle.provider_outcome_digest !== null ||
            lifecycle.reconciliation_digest !== null)
            return "lifecycle_order_invalid";
    }
    if (lifecycle.provider_entry_digest === null &&
        (lifecycle.effect_observation_digest !== null ||
            lifecycle.provider_outcome_digest !== null ||
            lifecycle.reconciliation_digest !== null))
        return "lifecycle_order_invalid";
    // Provider entry (and therefore any outcome, observation, or
    // reconciliation) requires a referenced authority reservation or
    // consumption. Only a conversion that reports INDETERMINATE may carry a
    // legacy provider entry whose custody record it could not resolve.
    if (lifecycle.provider_entry_digest !== null) {
        const phase = lifecycle.authority_custody.phase;
        if (phase === "NOT_APPLICABLE")
            return "lifecycle_order_invalid";
        if (phase === "INDETERMINATE" && body.conversion.status !== "INDETERMINATE")
            return "lifecycle_order_invalid";
    }
    return null;
}
function mappingCommonValid(input) {
    return (NATIVE_VERIFICATIONS.has(input.native_verification) &&
        RP_ACCEPTANCES.has(input.rp_acceptance) &&
        digest(input.mapping_profile_digest) &&
        digest(input.constraints_digest) &&
        validStatus(input.status) &&
        validValidity(input.validity));
}
export function mapWimseOAuthCrossingAuthority(input) {
    if (!isRecord(input) ||
        !mappingCommonValid(input) ||
        !identifier(input.authorization_server) ||
        !identifier(input.subject) ||
        !identifier(input.token_id) ||
        !digest(input.token_digest)) {
        return { ok: false, reason: "mapping_input_invalid" };
    }
    const authority = {
        adapter_id: "native:wimse-oauth-authorization-server",
        adapter_version: "1",
        mapping_profile_id: WIMSE_OAUTH_CROSSING_MAPPING_PROFILE,
        mapping_profile_digest: input.mapping_profile_digest,
        native_profile: "WIMSE-OAUTH-AUTHORIZATION-SERVER",
        issuer: input.authorization_server,
        subject: input.subject,
        authority_instance_digest: digestAebTyped({
            native_profile: "WIMSE-OAUTH-AUTHORIZATION-SERVER",
            authorization_server: input.authorization_server,
            subject: input.subject,
            token_id: input.token_id,
            token_digest: input.token_digest,
        }, `${WIMSE_OAUTH_CROSSING_MAPPING_PROFILE}:authority-instance`),
        evidence_digest: input.token_digest,
        replay_unit: digestAebTyped({
            authorization_server: input.authorization_server,
            token_id: input.token_id,
        }, `${WIMSE_OAUTH_CROSSING_MAPPING_PROFILE}:replay-unit`),
        native_verification: input.native_verification,
        rp_acceptance: input.rp_acceptance,
        status: structuredClone(input.status),
        constraints_digest: input.constraints_digest,
        validity: structuredClone(input.validity),
    };
    return { ok: true, authority };
}
export function mapBcrCrossingAuthority(input) {
    if (!isRecord(input) ||
        !mappingCommonValid(input) ||
        !identifier(input.issuer) ||
        !identifier(input.subject) ||
        !identifier(input.capability_id) ||
        !Number.isSafeInteger(input.generation) ||
        input.generation < 0 ||
        !digest(input.receipt_digest)) {
        return { ok: false, reason: "mapping_input_invalid" };
    }
    const authority = {
        adapter_id: "native:ep-bounded-capability-receipt",
        adapter_version: "1",
        mapping_profile_id: BCR_CROSSING_MAPPING_PROFILE,
        mapping_profile_digest: input.mapping_profile_digest,
        native_profile: "EP-BOUNDED-CAPABILITY-RECEIPT",
        issuer: input.issuer,
        subject: input.subject,
        authority_instance_digest: digestAebTyped({
            native_profile: "EP-BOUNDED-CAPABILITY-RECEIPT",
            issuer: input.issuer,
            subject: input.subject,
            capability_id: input.capability_id,
            generation: input.generation,
            receipt_digest: input.receipt_digest,
        }, `${BCR_CROSSING_MAPPING_PROFILE}:authority-instance`),
        evidence_digest: input.receipt_digest,
        replay_unit: digestAebTyped({
            issuer: input.issuer,
            capability_id: input.capability_id,
            generation: input.generation,
        }, `${BCR_CROSSING_MAPPING_PROFILE}:replay-unit`),
        native_verification: input.native_verification,
        rp_acceptance: input.rp_acceptance,
        status: structuredClone(input.status),
        constraints_digest: input.constraints_digest,
        validity: structuredClone(input.validity),
    };
    return { ok: true, authority };
}
export const WIMSE_OAUTH_CROSSING_ADAPTER = Object.freeze({
    id: "native:wimse-oauth-authorization-server",
    version: "1",
    mapping_profile_id: WIMSE_OAUTH_CROSSING_MAPPING_PROFILE,
    map: mapWimseOAuthCrossingAuthority,
});
export const BCR_CROSSING_ADAPTER = Object.freeze({
    id: "native:ep-bounded-capability-receipt",
    version: "1",
    mapping_profile_id: BCR_CROSSING_MAPPING_PROFILE,
    map: mapBcrCrossingAuthority,
});
export async function issueAebCrossingRecord(draft, options) {
    const partial = structuredClone(draft);
    const body = {
        ...partial,
        signature_profile: {
            id: SIGNATURE_AGILITY_VERSION,
            required_algorithms: [...AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS],
        },
        contract_digest: crossingRecordContractDigest(partial),
    };
    const reason = validateBody(body);
    if (reason)
        throw new CrossingRecordError(reason);
    if (!Array.isArray(options?.signing_keys) ||
        options.signing_keys.length !==
            AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS.length ||
        options.signing_keys.some((key, index) => key.alg !== AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS[index])) {
        throw new CrossingRecordError("algorithm_set_mismatch");
    }
    const signatures = await signAgileSet(crossingRecordSignedBytes(body), options.signing_keys, options);
    return {
        "@version": AEB_CROSSING_RECORD_VERSION,
        body,
        signatures,
    };
}
export async function issueAebCrossingRecordV2(draft, context, options) {
    // Pin caller-owned expectations before inspecting an untrusted draft. The
    // strict canonicalizer rejects accessors instead of executing them, unlike
    // structuredClone. Neither draft getters nor proxy inspection may rewrite
    // the expected action/domain and turn a mismatch into a signature.
    const pinnedContext = JSON.parse(canonicalizeAeb(context));
    const pinnedOptions = {
        ...options,
        signing_keys: options?.signing_keys?.map((key) => ({
            ...key,
            private_key: key.private_key instanceof Uint8Array
                ? new Uint8Array(key.private_key) : key.private_key,
        })),
    };
    const partial = JSON.parse(canonicalizeAeb(draft));
    if (!isRecord(pinnedContext) ||
        !isRecord(pinnedContext.action) ||
        !exactKeys(pinnedContext.action, ACTION_KEYS) ||
        canonicalizeAeb(pinnedContext.action) !== canonicalizeAeb(partial.action))
        throw new CrossingRecordError("action_mismatch");
    if (!isRecord(pinnedContext.admission_domain) ||
        !exactKeys(pinnedContext.admission_domain, BOUNDARY_KEYS) ||
        !Object.values(pinnedContext.admission_domain).every(identifier) ||
        canonicalizeAeb(pinnedContext.admission_domain) !==
            canonicalizeAeb(partial.boundary))
        throw new CrossingRecordError("admission_domain_mismatch");
    const admissionDomainDigest = crossingRecordV2AdmissionDomainDigest(partial.boundary);
    const bodyWithoutContract = {
        ...partial,
        signature_profile: {
            id: SIGNATURE_AGILITY_VERSION,
            required_algorithms: [...AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS],
        },
        admission_domain_digest: admissionDomainDigest,
    };
    const body = {
        ...bodyWithoutContract,
        contract_digest: crossingRecordV2ContractDigest(bodyWithoutContract),
    };
    const reason = validateV2Body(body);
    if (reason)
        throw new CrossingRecordError(reason);
    if (!Array.isArray(pinnedOptions.signing_keys) ||
        pinnedOptions.signing_keys.length !==
            AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS.length ||
        pinnedOptions.signing_keys.some((key, index) => key.alg !== AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS[index]))
        throw new CrossingRecordError("algorithm_set_mismatch");
    const signatures = await signAgileSet(crossingRecordV2SignedBytes(body), pinnedOptions.signing_keys, pinnedOptions);
    return { "@version": AEB_CROSSING_RECORD_V2_VERSION, body, signatures };
}
/**
 * Issues the derived lifecycle index.  It references the native/local
 * admission and provider records by digest; it does not flatten or reproduce
 * their decisions.
 */
export async function issueAebCrossingLifecycleIndexV2(draft, context, options) {
    const pinnedContext = JSON.parse(canonicalizeAeb(context));
    const pinnedOptions = {
        ...options,
        signing_keys: options?.signing_keys?.map((key) => ({
            ...key,
            private_key: key.private_key instanceof Uint8Array
                ? new Uint8Array(key.private_key)
                : key.private_key,
        })),
    };
    const partial = JSON.parse(canonicalizeAeb(draft));
    if (!isRecord(pinnedContext) ||
        !isRecord(pinnedContext.action) ||
        !exactKeys(pinnedContext.action, ACTION_KEYS) ||
        canonicalizeAeb(pinnedContext.action) !== canonicalizeAeb(partial.action))
        throw new CrossingRecordError("action_mismatch");
    if (!isRecord(pinnedContext.admission_domain) ||
        !exactKeys(pinnedContext.admission_domain, BOUNDARY_KEYS) ||
        !Object.values(pinnedContext.admission_domain).every(identifier))
        throw new CrossingRecordError("admission_domain_mismatch");
    if (!isRecord(pinnedContext.evaluation) ||
        !exactKeys(pinnedContext.evaluation, LIFECYCLE_EVALUATION_KEYS) ||
        canonicalizeAeb(pinnedContext.evaluation) !==
            canonicalizeAeb(partial.lifecycle?.evaluation))
        throw new CrossingRecordError("evaluation_reference_mismatch");
    const bodyWithoutContract = {
        ...partial,
        signature_profile: {
            id: SIGNATURE_AGILITY_VERSION,
            required_algorithms: [...AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS],
        },
        admission_domain_digest: crossingLifecycleIndexV2AdmissionDomainDigest(pinnedContext.admission_domain),
    };
    const body = {
        ...bodyWithoutContract,
        contract_digest: crossingLifecycleIndexV2ContractDigest(bodyWithoutContract),
    };
    const reason = validateLifecycleIndexV2Body(body);
    if (reason)
        throw new CrossingRecordError(reason);
    if (!Array.isArray(pinnedOptions.signing_keys) ||
        pinnedOptions.signing_keys.length !==
            AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS.length ||
        pinnedOptions.signing_keys.some((key, index) => key.alg !== AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS[index]))
        throw new CrossingRecordError("algorithm_set_mismatch");
    const signatures = await signAgileSet(crossingLifecycleIndexV2SignedBytes(body), pinnedOptions.signing_keys, pinnedOptions);
    return {
        "@version": AEB_CROSSING_LIFECYCLE_INDEX_V2_VERSION,
        body,
        signatures,
    };
}
/**
 * Deterministically converts a structurally valid v1 crossing record into the
 * new lifecycle index.  Any v1 axis that asserted later lifecycle state
 * without a corresponding record digest is reported as INDETERMINATE rather
 * than copied as if it were independently verifiable.
 *
 * v1 carries an unlabeled evaluation digest. Unless the caller supplies the
 * source evaluation and it binds to the source record, the index carries that
 * digest under the unchecked `AEB-EVALUATION-v1` label that 4.1.0 wrote, and
 * the conversion is INDETERMINATE with `evaluation_reference_unverified`,
 * which marks the label unchecked. A supplied evaluation that does not
 * bind is refused with `source_evaluation_mismatch`; nothing is signed.
 * References that v1 recorded out of lifecycle order (custody or provider
 * entry without a local admission reference, or provider entry without a
 * custody reference) are reported INDETERMINATE instead of being signed as
 * an ordered lifecycle.
 */
export async function upgradeAebCrossingRecordV1ToLifecycleIndexV2(source, options) {
    const pinnedSource = JSON.parse(canonicalizeAeb(source));
    let pinnedEvaluation;
    if (options?.source_evaluation !== undefined) {
        try {
            pinnedEvaluation = JSON.parse(canonicalizeAeb(options.source_evaluation));
        }
        catch {
            throw new CrossingRecordError("source_evaluation_mismatch");
        }
    }
    if (!isRecord(pinnedSource) ||
        !exactKeys(pinnedSource, DOCUMENT_KEYS) ||
        pinnedSource["@version"] !== AEB_CROSSING_RECORD_VERSION ||
        !isRecord(pinnedSource.body) ||
        validateBody(pinnedSource.body) !== null ||
        !signatureArray(pinnedSource.signatures))
        throw new CrossingRecordError("source_crossing_record_invalid");
    const sourceVerification = await verifyAebCrossingRecord(pinnedSource, {
        verification_keys: options.source_verification_keys,
        mldsaBackend: options.mldsaBackend,
        mldsaBackendLoader: options.mldsaBackendLoader,
        ...(pinnedEvaluation === undefined ? {} : { evaluation: pinnedEvaluation }),
    });
    if (!sourceVerification.verified) {
        if (sourceVerification.checks.evaluation_binding === false)
            throw new CrossingRecordError("source_evaluation_mismatch");
        throw new CrossingRecordError("source_crossing_record_unverified");
    }
    const evaluationBound = sourceVerification.evaluation_binding === "BOUND";
    const sourceBody = pinnedSource.body;
    const reasonCodes = [];
    const localAdmissionDigest = sourceBody.admission_reference.state === "PRESENT"
        ? sourceBody.admission_reference.digest
        : null;
    if (["MISSING", "INDETERMINATE"].includes(sourceBody.admission_reference.state))
        reasonCodes.push("local_admission_reference_indeterminate");
    let custody = {
        phase: "NOT_APPLICABLE",
        digest: null,
    };
    if (sourceBody.lifecycle_records.consumption_digest !== null) {
        if (["RESERVED", "INVOKING"].includes(sourceBody.referee.custody)) {
            custody = {
                phase: "RESERVATION",
                digest: sourceBody.lifecycle_records.consumption_digest,
            };
        }
        else if (sourceBody.referee.custody === "TERMINAL") {
            custody = {
                phase: "CONSUMPTION",
                digest: sourceBody.lifecycle_records.consumption_digest,
            };
        }
        else {
            custody = {
                phase: "INDETERMINATE",
                digest: sourceBody.lifecycle_records.consumption_digest,
            };
            reasonCodes.push("custody_phase_indeterminate");
        }
    }
    else if (!["UNRESERVED"].includes(sourceBody.referee.custody)) {
        custody = { phase: "INDETERMINATE", digest: null };
        reasonCodes.push("custody_reference_unavailable");
    }
    // v1 never enforced lifecycle order. Nothing may follow a missing local
    // admission reference, and provider entry requires a custody reference.
    let providerEntryDigest = sourceBody.lifecycle_records.provider_entry_digest;
    if (localAdmissionDigest === null) {
        if (custody.digest !== null) {
            custody = { phase: "INDETERMINATE", digest: null };
            reasonCodes.push("custody_reference_without_admission");
        }
        if (providerEntryDigest !== null) {
            providerEntryDigest = null;
            reasonCodes.push("provider_entry_reference_without_admission");
        }
    }
    else if (providerEntryDigest !== null && custody.phase === "NOT_APPLICABLE") {
        custody = { phase: "INDETERMINATE", digest: null };
        reasonCodes.push("provider_entry_without_custody_reference");
    }
    if (sourceBody.lifecycle_records.provider_entry_digest !== null &&
        sourceBody.referee.admission !== "ADMIT")
        reasonCodes.push("provider_entry_without_admit");
    if (!evaluationBound)
        reasonCodes.push(UNVERIFIED_EVALUATION_REFERENCE);
    if (sourceBody.referee.provider_commitment !== "NOT_INVOKED")
        reasonCodes.push("provider_outcome_reference_unavailable");
    if (sourceBody.referee.observed_effect !== "NOT_OBSERVED")
        reasonCodes.push("effect_observation_reference_unavailable");
    if (sourceBody.referee.reconciliation !== "NOT_APPLICABLE")
        reasonCodes.push("reconciliation_reference_unavailable");
    const reasons = [...new Set(reasonCodes)].sort();
    const conversionStatus = reasons.length === 0 ? "COMPLETE" : "INDETERMINATE";
    // Only a bound evaluation supplies the profile label; v1 never carried one.
    // Otherwise the label is the AEB-EVALUATION-v1 value 4.1.0 always wrote,
    // marked unchecked by the evaluation_reference_unverified reason code.
    const boundProfile = evaluationBound
        ? evaluationFacts(pinnedEvaluation)?.profile
        : undefined;
    if (evaluationBound && boundProfile === undefined)
        throw new CrossingRecordError("source_evaluation_mismatch");
    const evaluation = {
        profile: boundProfile ?? AEB_EVALUATION_VERSION,
        digest: sourceBody.lifecycle_records.evaluation_digest,
    };
    return issueAebCrossingLifecycleIndexV2({
        record_id: `${sourceBody.record_id}:lifecycle-index-v2`,
        operation_id: sourceBody.operation_id,
        issued_at: sourceBody.issued_at,
        action: sourceBody.action,
        lifecycle: {
            evaluation,
            local_admission_digest: localAdmissionDigest,
            authority_custody: custody,
            provider_entry_digest: providerEntryDigest,
            effect_observation_digest: null,
            provider_outcome_digest: null,
            reconciliation_digest: null,
        },
        source_crossing_record: {
            version: AEB_CROSSING_RECORD_VERSION,
            digest: crossingRecordDigest(sourceBody),
        },
        conversion: { status: conversionStatus, reason_codes: reasons },
        execution_authorizing: false,
    }, {
        action: sourceBody.action,
        admission_domain: sourceBody.boundary,
        evaluation,
    }, options);
}
function refusal(reason, checks, recordDigest = null, evaluationBinding = "INDETERMINATE") {
    return {
        verified: false,
        reason,
        execution_authorizing: false,
        record_digest: recordDigest,
        evaluation_binding: evaluationBinding,
        checks,
    };
}
function crossingEvaluationTarget(body) {
    return {
        digest: body.lifecycle_records.evaluation_digest,
        operation_id: body.operation_id,
        action: body.action,
        native_authority: body.native_authority,
        referee: body.referee,
    };
}
export async function verifyAebCrossingRecord(value, options) {
    const checks = {
        schema: false,
        algorithm_set: null,
        authority: null,
        contract_digest: null,
        admission_reference: null,
        semantics: null,
        evaluation_binding: null,
        signature_set: null,
    };
    let evaluationBinding = "INDETERMINATE";
    try {
        const suppliedEvaluation = options?.evaluation;
        if (!isRecord(value) ||
            !exactKeys(value, DOCUMENT_KEYS) ||
            value["@version"] !== AEB_CROSSING_RECORD_VERSION ||
            !isRecord(value.body))
            return refusal("malformed_record", checks);
        checks.schema = true;
        if (!isRecord(value.body.signature_profile) ||
            !algorithmSetMatches(value.body.signature_profile.required_algorithms)) {
            checks.algorithm_set = false;
            return refusal("algorithm_set_mismatch", checks);
        }
        checks.algorithm_set = true;
        const structural = validateBody(value.body);
        if (structural) {
            if (structural === "native_authority_invalid" ||
                structural === "authority_axis_mismatch")
                checks.authority = false;
            if (structural === "contract_digest_mismatch")
                checks.contract_digest = false;
            if (structural === "admission_reference_invalid")
                checks.admission_reference = false;
            if ([
                "authority_broadened",
                "status_inconsistent",
                "custody_inconsistent",
                "consumption_record_required",
            ].includes(structural)) {
                checks.semantics = false;
            }
            return refusal(structural, checks);
        }
        checks.authority = true;
        checks.contract_digest = true;
        checks.admission_reference = true;
        checks.semantics = true;
        const body = value.body;
        const bodyDigest = crossingRecordDigest(body);
        if (suppliedEvaluation !== undefined) {
            const joinReason = evaluationJoinReason(suppliedEvaluation, crossingEvaluationTarget(body));
            checks.evaluation_binding = joinReason === null;
            if (joinReason)
                return refusal(joinReason, checks, bodyDigest, "MISMATCH");
            evaluationBinding = "BOUND";
        }
        if (!signatureArray(value.signatures)) {
            checks.signature_set = false;
            const algorithms = Array.isArray(value.signatures)
                ? value.signatures.map((signature) => signature?.alg)
                : [];
            const reason = algorithms.length < AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS.length
                ? "hybrid_leg_missing"
                : "signature_invalid";
            return refusal(reason, checks, bodyDigest);
        }
        const result = await verifyAgileSignatureSet(crossingRecordSignedBytes(body), value.signatures, options?.verification_keys, {
            ...options,
            policy: "hybrid_all",
            requiredAlgorithms: [...AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS],
        });
        if (result.verified !== true) {
            checks.signature_set = false;
            return refusal(result.reason === "missing_required_algorithm"
                ? "hybrid_leg_missing"
                : "signature_invalid", checks, bodyDigest);
        }
        checks.signature_set = true;
        return {
            verified: true,
            reason: null,
            execution_authorizing: false,
            record_digest: bodyDigest,
            evaluation_binding: evaluationBinding,
            checks,
        };
    }
    catch {
        return refusal("malformed_record", checks);
    }
}
export async function verifyAebCrossingRecordV2(value, options) {
    const checks = {
        schema: false,
        algorithm_set: null,
        authority: null,
        contract_digest: null,
        admission_domain: null,
        admission_reference: null,
        semantics: null,
        evaluation_binding: null,
        signature_set: null,
    };
    let evaluationBinding = "INDETERMINATE";
    const refuse = (reason, recordDigest = null, binding = "INDETERMINATE") => ({
        verified: false,
        reason,
        execution_authorizing: false,
        record_digest: recordDigest,
        evaluation_binding: binding,
        checks,
    });
    try {
        const suppliedEvaluation = options?.evaluation;
        if (!isRecord(value) ||
            !exactKeys(value, DOCUMENT_KEYS) ||
            value["@version"] !== AEB_CROSSING_RECORD_V2_VERSION ||
            !isRecord(value.body))
            return refuse("malformed_record");
        checks.schema = true;
        if (!isRecord(value.body.signature_profile) ||
            !algorithmSetMatches(value.body.signature_profile.required_algorithms)) {
            checks.algorithm_set = false;
            return refuse("algorithm_set_mismatch");
        }
        checks.algorithm_set = true;
        const structural = validateV2Body(value.body);
        if (structural) {
            if (["native_authority_invalid", "authority_axis_mismatch"].includes(structural))
                checks.authority = false;
            if (structural === "contract_digest_mismatch")
                checks.contract_digest = false;
            if (structural === "admission_domain_mismatch")
                checks.admission_domain = false;
            if (structural === "admission_reference_invalid")
                checks.admission_reference = false;
            if ([
                "authority_broadened",
                "status_inconsistent",
                "custody_inconsistent",
                "consumption_record_required",
            ].includes(structural))
                checks.semantics = false;
            return refuse(structural);
        }
        checks.authority = true;
        checks.contract_digest = true;
        checks.admission_domain = true;
        checks.admission_reference = true;
        checks.semantics = true;
        const body = value.body;
        const bodyDigest = crossingRecordV2Digest(body);
        if (suppliedEvaluation !== undefined) {
            const joinReason = evaluationJoinReason(suppliedEvaluation, crossingEvaluationTarget(body));
            checks.evaluation_binding = joinReason === null;
            if (joinReason)
                return refuse(joinReason, bodyDigest, "MISMATCH");
            evaluationBinding = "BOUND";
        }
        if (!signatureArray(value.signatures)) {
            checks.signature_set = false;
            const algorithms = Array.isArray(value.signatures)
                ? value.signatures.map((signature) => signature?.alg)
                : [];
            return refuse(algorithms.length < AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS.length
                ? "hybrid_leg_missing"
                : "signature_invalid", bodyDigest);
        }
        const result = await verifyAgileSignatureSet(crossingRecordV2SignedBytes(body), value.signatures, options?.verification_keys, {
            ...options,
            policy: "hybrid_all",
            requiredAlgorithms: [...AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS],
        });
        if (result.verified !== true) {
            checks.signature_set = false;
            return refuse(result.reason === "missing_required_algorithm"
                ? "hybrid_leg_missing"
                : "signature_invalid", bodyDigest);
        }
        checks.signature_set = true;
        return {
            verified: true,
            reason: null,
            execution_authorizing: false,
            record_digest: bodyDigest,
            evaluation_binding: evaluationBinding,
            checks,
        };
    }
    catch {
        return refuse("malformed_record");
    }
}
export async function verifyAebCrossingLifecycleIndexV2(value, options) {
    const checks = {
        schema: false,
        algorithm_set: null,
        action: null,
        admission_domain: null,
        evaluation: null,
        evaluation_binding: null,
        contract_digest: null,
        lifecycle_order: null,
        signature_set: null,
    };
    let conversionStatus = null;
    let evaluationBinding = "INDETERMINATE";
    const refuse = (reason, recordDigest = null, binding = "INDETERMINATE") => ({
        verified: false,
        reason,
        execution_authorizing: false,
        record_digest: recordDigest,
        conversion_status: conversionStatus,
        evaluation_binding: binding,
        checks,
    });
    try {
        const expectedEvaluation = options?.expected_evaluation;
        const suppliedEvaluation = options?.evaluation;
        if (!isRecord(value) ||
            !exactKeys(value, DOCUMENT_KEYS) ||
            value["@version"] !== AEB_CROSSING_LIFECYCLE_INDEX_V2_VERSION ||
            !isRecord(value.body))
            return refuse("malformed_lifecycle_index");
        checks.schema = true;
        if (!isRecord(value.body.signature_profile) ||
            !algorithmSetMatches(value.body.signature_profile.required_algorithms)) {
            checks.algorithm_set = false;
            return refuse("algorithm_set_mismatch");
        }
        checks.algorithm_set = true;
        const structural = validateLifecycleIndexV2Body(value.body);
        if (structural) {
            if (structural === "contract_digest_mismatch")
                checks.contract_digest = false;
            if (["lifecycle_order_invalid", "custody_reference_inconsistent"].includes(structural))
                checks.lifecycle_order = false;
            return refuse(structural);
        }
        const body = value.body;
        conversionStatus = body.conversion.status;
        checks.contract_digest = true;
        checks.lifecycle_order = true;
        checks.action = canonicalizeAeb(options?.expected_action)
            === canonicalizeAeb(body.action);
        if (!checks.action)
            return refuse("action_mismatch");
        checks.admission_domain =
            crossingLifecycleIndexV2AdmissionDomainDigest(options?.admission_domain) === body.admission_domain_digest;
        if (!checks.admission_domain)
            return refuse("admission_domain_mismatch");
        if (expectedEvaluation === undefined && suppliedEvaluation === undefined) {
            checks.evaluation = false;
            return refuse("evaluation_reference_required");
        }
        if (expectedEvaluation !== undefined) {
            checks.evaluation = canonicalizeAeb(expectedEvaluation)
                === canonicalizeAeb(body.lifecycle.evaluation);
            if (!checks.evaluation)
                return refuse("evaluation_reference_mismatch");
        }
        if (suppliedEvaluation !== undefined) {
            const joinReason = evaluationJoinReason(suppliedEvaluation, {
                digest: body.lifecycle.evaluation.digest,
                // An unverified conversion label is not compared.
                profile: body.conversion.reason_codes.includes(UNVERIFIED_EVALUATION_REFERENCE)
                    ? null
                    : body.lifecycle.evaluation.profile,
                operation_id: body.operation_id,
                action: body.action,
            });
            checks.evaluation_binding = joinReason === null;
            if (joinReason)
                return refuse(joinReason, null, "MISMATCH");
            if (expectedEvaluation === undefined)
                checks.evaluation = true;
            evaluationBinding = "BOUND";
        }
        const bodyDigest = crossingLifecycleIndexV2Digest(body);
        if (!signatureArray(value.signatures)) {
            checks.signature_set = false;
            const algorithms = Array.isArray(value.signatures)
                ? value.signatures.map((signature) => signature?.alg)
                : [];
            return refuse(algorithms.length < AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS.length
                ? "hybrid_leg_missing"
                : "signature_invalid", bodyDigest);
        }
        const result = await verifyAgileSignatureSet(crossingLifecycleIndexV2SignedBytes(body), value.signatures, options?.verification_keys, {
            ...options,
            policy: "hybrid_all",
            requiredAlgorithms: [...AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS],
        });
        if (result.verified !== true) {
            checks.signature_set = false;
            return refuse(result.reason === "missing_required_algorithm"
                ? "hybrid_leg_missing"
                : "signature_invalid", bodyDigest);
        }
        checks.signature_set = true;
        return {
            verified: true,
            reason: null,
            execution_authorizing: false,
            record_digest: bodyDigest,
            conversion_status: conversionStatus,
            evaluation_binding: evaluationBinding,
            checks,
        };
    }
    catch {
        return refuse("malformed_lifecycle_index");
    }
}
//# sourceMappingURL=aeb-crossing-record.js.map