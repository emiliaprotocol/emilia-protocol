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
import { canonicalizeAeb, digestAebTyped, } from "./aeb-adapter-contract.js";
import { SIGNATURE_AGILITY_VERSION, signAgileSet, verifyAgileSignatureSet, } from "./pq-signature-agility.js";
export const AEB_CROSSING_RECORD_VERSION = "EP-AEB-CROSSING-RECORD-v1";
export const AEB_CROSSING_RECORD_DOMAIN = `${AEB_CROSSING_RECORD_VERSION}\0`;
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
        relying_party: body.boundary.relying_party_id,
        audience: body.boundary.audience,
        executor: body.boundary.executor_id,
        state_domain: body.boundary.state_domain_id,
    }, `${AEB_CROSSING_RECORD_VERSION}:contract`);
}
export function crossingRecordSignedBytes(body) {
    return Buffer.from(`${AEB_CROSSING_RECORD_DOMAIN}${canonicalizeAeb(body)}`, "utf8");
}
export function crossingRecordDigest(body) {
    return digestAebTyped(body, `${AEB_CROSSING_RECORD_VERSION}:record`);
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
function refusal(reason, checks, recordDigest = null) {
    return {
        verified: false,
        reason,
        execution_authorizing: false,
        record_digest: recordDigest,
        checks,
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
        signature_set: null,
    };
    try {
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
            checks,
        };
    }
    catch {
        return refusal("malformed_record", checks);
    }
}
//# sourceMappingURL=aeb-crossing-record.js.map