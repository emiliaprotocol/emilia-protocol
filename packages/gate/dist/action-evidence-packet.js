// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Action Evidence Packet v1.
 *
 * This is a content-addressed join of native artifacts for one exact Gate
 * action. This module orchestrates relying-party-supplied native verifier
 * adapters; it does not itself implement or certify those native verifiers.
 * The packet never decides coverage, causation, liability, a claim, or payment.
 */
import { RISK_DIGEST, riskClone, riskDigest, riskExact, riskFreeze, riskIdentifier, riskInstant, riskRecord, } from './reliance-risk-crypto.js';
import { PROVIDER_OUTCOME_CONTEXT_VERSION, providerOutcomeContextDigest, verifyProviderOutcomeBinding, } from './provider-outcome-binding.js';
export const ACTION_EVIDENCE_PACKET_VERSION = 'EP-ACTION-EVIDENCE-PACKET-v1';
export const ACTION_EVIDENCE_MANIFEST_VERSION = 'EP-ACTION-EVIDENCE-MANIFEST-v1';
export const ACTION_EVIDENCE_PACKET_RESULT_VERSION = 'EP-ACTION-EVIDENCE-PACKET-RESULT-v1';
export const ACTION_EVIDENCE_PACKET_CLAIM_BOUNDARY = 'technical_evidence_join_for_one_exact_action_not_insurance_coverage_not_claim_adjudication_not_causation_not_liability_not_payment';
export const ACTION_EVIDENCE_PACKET_RESULTS = Object.freeze([
    'TECHNICALLY_COMPLETE',
    'INCOMPLETE',
    'CONFLICTED',
    'INDETERMINATE',
]);
export const ACTION_EVIDENCE_COMPONENT_ROLES = Object.freeze([
    'aeb',
    'admission_snapshot',
    'admission_decision',
    'qualification_statement',
    'qualification_status_head',
    'open_exposure_ceiling',
    'open_exposure_record',
    'open_exposure_history',
    'observed_effect_relation',
    'coverage_surface',
    'refusal_probe',
    'supplied_population_report',
    'loss_report',
    'recourse',
    'loss_allocation',
]);
const REQUIRED_COMPONENT_ROLES = Object.freeze([
    'aeb',
    'admission_snapshot',
    'admission_decision',
    'qualification_statement',
    'qualification_status_head',
    'open_exposure_ceiling',
    'open_exposure_record',
    'open_exposure_history',
    'observed_effect_relation',
    'coverage_surface',
    'refusal_probe',
    'supplied_population_report',
]);
const OPTIONAL_COMPONENT_ROLES = Object.freeze([
    'loss_report',
    'recourse',
    'loss_allocation',
]);
// 16 source pairs + one schedule + all 15 component roles = 48. Leave bounded
// headroom without making the advertised 16-source limit impossible.
const MAX_ATTACHMENTS = 64;
const MAX_PACKET_BYTES = 16 * 1024 * 1024;
const MANIFEST_KEYS = [
    '@version',
    'packet_id',
    'assembled_at',
    'subject',
    'subject_digest',
    'schedule',
    'components',
    'provider_outcomes',
    'claim_boundary',
];
const PACKET_KEYS = ['@version', 'manifest', 'manifest_digest', 'attachments'];
const ARTIFACT_REFERENCE_KEYS = ['artifact_digest', 'expected_state'];
const SCHEDULE_REFERENCE_KEYS = ['artifact_digest', 'evaluation'];
const PROVIDER_REFERENCE_KEYS = [
    'binding_artifact_digest',
    'outcome_observation_artifact_digest',
    'expected_source',
];
const NATIVE_VERIFICATION_KEYS = [
    'verification',
    'currentness',
    'artifact_digest',
    'subject_digest',
    'state',
    'reason',
];
const SCHEDULE_VERIFICATION_KEYS = [
    'verification',
    'currentness',
    'artifact_digest',
    'subject_digest',
    'evaluation',
    'outcome_requirements',
    'reason',
];
const OUTCOME_REQUIREMENTS_KEYS = [
    'required_sources',
    'quorum',
    'observation_window',
    'require_control_domain_independence',
];
const OUTCOME_SOURCE_REQUIREMENT_KEYS = ['role', 'source_class'];
const OBSERVATION_WINDOW_KEYS = [
    'opens_before_provider_entry_sec',
    'closes_after_provider_entry_sec',
    'max_observation_age_sec',
];
const OEL_TERMINAL_STATES = new Set([
    'CLOSED_COMMITTED',
    'CLOSED_PROVEN_NOT_COMMITTED',
    'INDETERMINATE',
]);
const EFFECT_RELATIONS = new Set([
    'OBSERVED_AS_REQUESTED',
    'DIVERGED',
    'INDETERMINATE',
]);
const COVERAGE_STATES = new Set([
    'gated',
    'witness_only',
    'ungated',
    'stale',
    'unknown',
]);
const PROBE_RESULTS = new Set([
    'blocked_without_receipt',
    'executed_without_receipt',
    'indeterminate',
]);
function canonicalUtcInstant(value) {
    if (typeof value !== 'string' || !Number.isFinite(riskInstant(value)))
        return false;
    try {
        return new Date(Date.parse(value)).toISOString() === value;
    }
    catch {
        return false;
    }
}
function denseArray(value, minimum, maximum) {
    if (!Array.isArray(value) || value.length < minimum || value.length > maximum)
        return false;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 || !keys.includes('length'))
        return false;
    for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) {
            return false;
        }
    }
    return keys.every((key) => key === 'length'
        || (typeof key === 'string' && /^(0|[1-9][0-9]*)$/.test(key)));
}
function validDigest(value) {
    return typeof value === 'string' && RISK_DIGEST.test(value);
}
function validExpectedState(value) {
    return riskIdentifier(value);
}
function validReference(value) {
    return riskExact(value, ARTIFACT_REFERENCE_KEYS)
        && validDigest(value.artifact_digest)
        && validExpectedState(value.expected_state);
}
function validScheduleReference(value) {
    return riskExact(value, SCHEDULE_REFERENCE_KEYS)
        && validDigest(value.artifact_digest)
        && ['ELIGIBLE', 'NOT_ELIGIBLE', 'INDETERMINATE'].includes(value.evaluation);
}
function validSourceIdentity(value) {
    if (!riskRecord(value))
        return false;
    const keys = Object.hasOwn(value, 'facility_id')
        ? ['role', 'source_id', 'source_class', 'facility_id']
        : ['role', 'source_id', 'source_class'];
    return riskExact(value, keys)
        && ['executor', 'system_of_record', 'independent_observer'].includes(value.role)
        && riskIdentifier(value.source_id)
        && riskIdentifier(value.source_class)
        && (!Object.hasOwn(value, 'facility_id') || riskIdentifier(value.facility_id));
}
function validProviderReference(value) {
    return riskExact(value, PROVIDER_REFERENCE_KEYS)
        && validDigest(value.binding_artifact_digest)
        && validDigest(value.outcome_observation_artifact_digest)
        && value.binding_artifact_digest !== value.outcome_observation_artifact_digest
        && validSourceIdentity(value.expected_source);
}
function validProviderReferences(value) {
    if (!denseArray(value, 2, 16))
        return false;
    const identities = new Set();
    for (const reference of value) {
        if (!validProviderReference(reference))
            return false;
        const identity = reference.expected_source.source_id;
        if (identities.has(identity))
            return false;
        identities.add(identity);
    }
    return true;
}
function boundedScheduleSeconds(value, minimum) {
    return Number.isSafeInteger(value)
        && Number(value) >= minimum
        && Number(value) <= 31_536_000;
}
function validObservationWindow(value) {
    return riskExact(value, OBSERVATION_WINDOW_KEYS)
        && boundedScheduleSeconds(value.opens_before_provider_entry_sec, 0)
        && boundedScheduleSeconds(value.closes_after_provider_entry_sec, 0)
        && boundedScheduleSeconds(value.max_observation_age_sec, 1);
}
function validOutcomeRequirements(value) {
    if (!riskExact(value, OUTCOME_REQUIREMENTS_KEYS)
        || !denseArray(value.required_sources, 2, 16)
        || !Number.isSafeInteger(value.quorum)
        || value.quorum < 2
        || value.quorum > value.required_sources.length
        || !validObservationWindow(value.observation_window)
        || value.require_control_domain_independence !== true)
        return false;
    const identities = new Set();
    let previous = null;
    for (const source of value.required_sources) {
        if (!riskExact(source, OUTCOME_SOURCE_REQUIREMENT_KEYS)
            || !['executor', 'system_of_record', 'independent_observer'].includes(source.role)
            || !riskIdentifier(source.source_class))
            return false;
        const identity = `${source.role}\0${source.source_class}`;
        if (identities.has(identity) || (previous !== null && previous > identity))
            return false;
        identities.add(identity);
        previous = identity;
    }
    return true;
}
function validSubject(value) {
    if (!riskRecord(value) || value['@version'] !== PROVIDER_OUTCOME_CONTEXT_VERSION)
        return false;
    try {
        providerOutcomeContextDigest(value);
        return true;
    }
    catch {
        return false;
    }
}
function validComponents(value) {
    if (!riskRecord(value)
        || !riskExact(value, ACTION_EVIDENCE_COMPONENT_ROLES))
        return false;
    for (const role of REQUIRED_COMPONENT_ROLES) {
        if (!validReference(value[role]))
            return false;
    }
    for (const role of OPTIONAL_COMPONENT_ROLES) {
        if (value[role] !== null && !validReference(value[role]))
            return false;
    }
    return value.aeb.expected_state === 'SATISFIED'
        && value.admission_snapshot.expected_state === 'IMMUTABLE'
        && value.admission_decision.expected_state === 'ALLOW'
        && value.qualification_statement.expected_state === 'QUALIFIED'
        && value.qualification_status_head.expected_state === 'CURRENT'
        && value.open_exposure_ceiling.expected_state === 'ACTIVE'
        && OEL_TERMINAL_STATES.has(value.open_exposure_record.expected_state)
        && OEL_TERMINAL_STATES.has(value.open_exposure_history.expected_state)
        && EFFECT_RELATIONS.has(value.observed_effect_relation.expected_state)
        && COVERAGE_STATES.has(value.coverage_surface.expected_state)
        && PROBE_RESULTS.has(value.refusal_probe.expected_state)
        && value.supplied_population_report.expected_state === 'VERIFIED_SUPPLIED_POPULATION';
}
function validManifest(value) {
    if (!riskExact(value, MANIFEST_KEYS)
        || value['@version'] !== ACTION_EVIDENCE_MANIFEST_VERSION
        || !riskIdentifier(value.packet_id)
        || !canonicalUtcInstant(value.assembled_at)
        || !validSubject(value.subject)
        || !validDigest(value.subject_digest)
        || !validScheduleReference(value.schedule)
        || !validComponents(value.components)
        || !validProviderReferences(value.provider_outcomes)
        || value.claim_boundary !== ACTION_EVIDENCE_PACKET_CLAIM_BOUNDARY)
        return false;
    return value.subject_digest === providerOutcomeContextDigest(value.subject)
        && Date.parse(value.subject.observed_at) <= Date.parse(value.assembled_at);
}
function referencedArtifacts(manifest) {
    const refs = [
        { role: 'schedule', digest: manifest.schedule.artifact_digest },
    ];
    manifest.provider_outcomes.forEach((reference, index) => {
        refs.push({
            role: `provider_outcome_binding:${index}`,
            digest: reference.binding_artifact_digest,
        });
        refs.push({
            role: `outcome_observation:${index}`,
            digest: reference.outcome_observation_artifact_digest,
        });
    });
    for (const role of ACTION_EVIDENCE_COMPONENT_ROLES) {
        const ref = manifest.components[role];
        if (ref !== null)
            refs.push({ role, digest: ref.artifact_digest });
    }
    return refs;
}
function attachmentMap(attachments) {
    if (!denseArray(attachments, 0, MAX_ATTACHMENTS)) {
        throw new TypeError('action evidence attachments are invalid');
    }
    const mapped = Object.create(null);
    for (const artifact of attachments) {
        const digest = actionEvidenceArtifactDigest(artifact);
        if (Object.hasOwn(mapped, digest)) {
            throw new TypeError('action evidence attachments contain duplicate content');
        }
        mapped[digest] = riskClone(artifact);
    }
    return mapped;
}
/** Canonical digest for every JSON attachment. */
export function actionEvidenceArtifactDigest(artifact) {
    return riskDigest(artifact);
}
/** Canonical digest for the closed manifest. */
export function actionEvidenceManifestDigest(manifest) {
    if (!validManifest(manifest))
        throw new TypeError('action evidence manifest is invalid');
    return riskDigest(manifest);
}
/**
 * Build a complete content-addressed container. This function checks shape and
 * attachment addressing only. Native acceptance remains the responsibility of
 * the explicitly supplied verifier adapters.
 */
export function buildActionEvidencePacket(input) {
    if (!validManifest(input?.manifest)) {
        throw new TypeError('action evidence manifest is invalid');
    }
    const manifest = riskClone(input.manifest);
    const attachments = attachmentMap(input.attachments);
    const refs = referencedArtifacts(manifest);
    if (new Set(refs.map((entry) => entry.digest)).size !== refs.length) {
        throw new TypeError('action evidence manifest reuses an artifact across roles');
    }
    if (refs.some((entry) => !Object.hasOwn(attachments, entry.digest))) {
        throw new TypeError('action evidence manifest references a missing attachment');
    }
    if (Object.keys(attachments).some((digest) => !refs.some((entry) => entry.digest === digest)))
        throw new TypeError('action evidence packet contains an unreferenced attachment');
    const packet = {
        '@version': ACTION_EVIDENCE_PACKET_VERSION,
        manifest,
        manifest_digest: actionEvidenceManifestDigest(manifest),
        attachments,
    };
    if (Buffer.byteLength(JSON.stringify(packet), 'utf8') > MAX_PACKET_BYTES) {
        throw new TypeError('action evidence packet exceeds the size limit');
    }
    return riskFreeze(packet);
}
function validNativeVerification(value) {
    return riskExact(value, NATIVE_VERIFICATION_KEYS)
        && ['VERIFIED', 'NOT_VERIFIED', 'INDETERMINATE'].includes(value.verification)
        && ['CURRENT', 'STALE', 'INDETERMINATE'].includes(value.currentness)
        && validDigest(value.artifact_digest)
        && validDigest(value.subject_digest)
        && validExpectedState(value.state)
        && (value.reason === null || riskIdentifier(value.reason));
}
function validScheduleVerification(value) {
    return riskExact(value, SCHEDULE_VERIFICATION_KEYS)
        && ['VERIFIED', 'NOT_VERIFIED', 'INDETERMINATE'].includes(value.verification)
        && ['CURRENT', 'STALE', 'INDETERMINATE'].includes(value.currentness)
        && validDigest(value.artifact_digest)
        && validDigest(value.subject_digest)
        && ['ELIGIBLE', 'NOT_ELIGIBLE', 'INDETERMINATE'].includes(value.evaluation)
        && validOutcomeRequirements(value.outcome_requirements)
        && (value.reason === null || riskIdentifier(value.reason));
}
class Classification {
    reasons = [];
    verified = [];
    incomplete = [];
    conflicted = [];
    indeterminate = [];
    add(kind, component, reason) {
        if (!this[kind].includes(component))
            this[kind].push(component);
        if (!this.reasons.includes(reason))
            this.reasons.push(reason);
    }
    result() {
        if (this.conflicted.length > 0)
            return 'CONFLICTED';
        if (this.indeterminate.length > 0)
            return 'INDETERMINATE';
        if (this.incomplete.length > 0)
            return 'INCOMPLETE';
        return 'TECHNICALLY_COMPLETE';
    }
}
function verificationResult(classification, manifestDigest, subjectDigest) {
    return riskFreeze({
        '@version': ACTION_EVIDENCE_PACKET_RESULT_VERSION,
        result: classification.result(),
        reasons: [...classification.reasons],
        manifest_digest: manifestDigest,
        subject_digest: subjectDigest,
        verified_components: [...classification.verified],
        incomplete_components: [...classification.incomplete],
        conflicted_components: [...classification.conflicted],
        indeterminate_components: [...classification.indeterminate],
        claim_boundary: ACTION_EVIDENCE_PACKET_CLAIM_BOUNDARY,
    });
}
function classifyNative(classification, component, ref, verification, subjectDigest) {
    if (verification.artifact_digest !== ref.artifact_digest
        || verification.subject_digest !== subjectDigest
        || verification.state !== ref.expected_state) {
        classification.add('conflicted', component, `${component}_binding_conflict`);
        return;
    }
    if (verification.verification === 'INDETERMINATE'
        || verification.currentness === 'INDETERMINATE') {
        classification.add('indeterminate', component, `${component}_verification_indeterminate`);
        return;
    }
    if (verification.verification !== 'VERIFIED') {
        classification.add('incomplete', component, `${component}_not_verified`);
        return;
    }
    if (verification.currentness !== 'CURRENT') {
        classification.add('incomplete', component, `${component}_not_current`);
        return;
    }
    classification.verified.push(component);
}
function classifyTerminalSemantics(classification, manifest) {
    const recordState = manifest.components.open_exposure_record.expected_state;
    const historyState = manifest.components.open_exposure_history.expected_state;
    if (recordState !== historyState) {
        classification.add('conflicted', 'open_exposure', 'open_exposure_terminal_state_conflict');
    }
    const outcomeToOel = {
        COMMITTED: 'CLOSED_COMMITTED',
        PROVEN_NOT_COMMITTED: 'CLOSED_PROVEN_NOT_COMMITTED',
        INDETERMINATE: 'INDETERMINATE',
    };
    if (recordState !== outcomeToOel[manifest.subject.outcome]) {
        classification.add('conflicted', 'open_exposure', 'provider_and_exposure_outcome_conflict');
    }
    if (manifest.subject.outcome === 'INDETERMINATE') {
        classification.add('indeterminate', 'provider_outcome', 'provider_outcome_indeterminate');
    }
    const relation = manifest.components.observed_effect_relation.expected_state;
    if (relation === 'DIVERGED') {
        classification.add('conflicted', 'observed_effect_relation', 'observed_effect_diverged');
    }
    else if (relation === 'INDETERMINATE') {
        classification.add('indeterminate', 'observed_effect_relation', 'observed_effect_indeterminate');
    }
    const coverage = manifest.components.coverage_surface.expected_state;
    const probe = manifest.components.refusal_probe.expected_state;
    if (coverage === 'ungated') {
        classification.add('conflicted', 'coverage', 'coverage_surface_ungated');
    }
    else if (coverage === 'witness_only') {
        classification.add('incomplete', 'coverage', 'coverage_surface_witness_only');
    }
    else if (coverage === 'stale' || coverage === 'unknown') {
        classification.add('indeterminate', 'coverage', 'coverage_evidence_indeterminate');
    }
    if (probe === 'executed_without_receipt') {
        classification.add('conflicted', 'coverage', 'refusal_probe_observed_bypass');
    }
    else if (probe === 'indeterminate') {
        classification.add('indeterminate', 'coverage', 'coverage_evidence_indeterminate');
    }
    if (manifest.schedule.evaluation === 'INDETERMINATE') {
        classification.add('indeterminate', 'schedule', 'schedule_evaluation_indeterminate');
    }
    else if (manifest.schedule.evaluation === 'NOT_ELIGIBLE') {
        classification.add('conflicted', 'schedule', 'action_executed_while_schedule_not_eligible');
    }
}
/**
 * Fail-closed orchestration of the packet and every native verifier adapter.
 * No packet field can introduce a trust key or currentness rule.
 */
export async function verifyActionEvidencePacket(packet, options) {
    const classification = new Classification();
    let manifestDigest = null;
    let subjectDigest = null;
    try {
        if (!riskExact(packet, PACKET_KEYS)
            || packet['@version'] !== ACTION_EVIDENCE_PACKET_VERSION
            || !validDigest(packet.manifest_digest)
            || !riskRecord(packet.attachments)
            || Object.keys(packet.attachments).length > MAX_ATTACHMENTS) {
            classification.add('conflicted', 'packet', 'packet_structure_invalid');
            return verificationResult(classification, null, null);
        }
        if (Buffer.byteLength(JSON.stringify(packet), 'utf8') > MAX_PACKET_BYTES) {
            classification.add('conflicted', 'packet', 'packet_size_limit_exceeded');
            return verificationResult(classification, null, null);
        }
        if (!validManifest(packet.manifest)) {
            classification.add('conflicted', 'manifest', 'manifest_structure_invalid');
            return verificationResult(classification, null, null);
        }
        manifestDigest = actionEvidenceManifestDigest(packet.manifest);
        subjectDigest = providerOutcomeContextDigest(packet.manifest.subject);
        if (manifestDigest !== packet.manifest_digest) {
            classification.add('conflicted', 'manifest', 'manifest_digest_mismatch');
            return verificationResult(classification, manifestDigest, subjectDigest);
        }
        if (!validSubject(options?.expected_context)) {
            classification.add('incomplete', 'relying_party', 'expected_context_missing_or_invalid');
        }
        else if (providerOutcomeContextDigest(options.expected_context) !== subjectDigest) {
            classification.add('conflicted', 'subject', 'expected_context_mismatch');
        }
        // assembled_at is content-addressed but not authenticated. It is useful for
        // internal chronology only and is never accepted as a security-freshness
        // signal. Currentness comes from the verified schedule and native adapters.
        if (!canonicalUtcInstant(options?.now)) {
            classification.add('incomplete', 'currentness', 'verification_time_invalid');
        }
        const refs = referencedArtifacts(packet.manifest);
        if (new Set(refs.map((entry) => entry.digest)).size !== refs.length) {
            classification.add('conflicted', 'manifest', 'artifact_role_reuse');
        }
        const referenced = new Set(refs.map((entry) => entry.digest));
        for (const [digest, artifact] of Object.entries(packet.attachments)) {
            if (!validDigest(digest)) {
                classification.add('conflicted', 'attachments', 'attachment_key_invalid');
                continue;
            }
            let recomputed;
            try {
                recomputed = actionEvidenceArtifactDigest(artifact);
            }
            catch {
                classification.add('conflicted', 'attachments', 'attachment_not_canonical_json');
                continue;
            }
            if (recomputed !== digest) {
                classification.add('conflicted', 'attachments', 'attachment_digest_mismatch');
            }
            if (!referenced.has(digest)) {
                classification.add('conflicted', 'attachments', 'unreferenced_attachment');
            }
        }
        let outcomeRequirements = null;
        const scheduleArtifact = packet.attachments[packet.manifest.schedule.artifact_digest];
        if (scheduleArtifact === undefined) {
            classification.add('incomplete', 'schedule', 'schedule_attachment_missing');
        }
        else if (typeof options?.verify_schedule !== 'function') {
            classification.add('incomplete', 'schedule', 'schedule_verifier_missing');
        }
        else if (canonicalUtcInstant(options?.now)) {
            try {
                const verified = await options.verify_schedule({
                    artifact: scheduleArtifact,
                    artifact_digest: packet.manifest.schedule.artifact_digest,
                    subject: packet.manifest.subject,
                    subject_digest: subjectDigest,
                    expected_evaluation: packet.manifest.schedule.evaluation,
                    now: options.now,
                });
                if (!validScheduleVerification(verified)) {
                    classification.add('incomplete', 'schedule', 'schedule_verification_result_invalid');
                }
                else if (verified.artifact_digest !== packet.manifest.schedule.artifact_digest
                    || verified.subject_digest !== subjectDigest
                    || verified.evaluation !== packet.manifest.schedule.evaluation) {
                    classification.add('conflicted', 'schedule', 'schedule_binding_conflict');
                }
                else if (verified.verification === 'INDETERMINATE'
                    || verified.currentness === 'INDETERMINATE') {
                    classification.add('indeterminate', 'schedule', 'schedule_verification_indeterminate');
                }
                else if (verified.verification !== 'VERIFIED') {
                    classification.add('incomplete', 'schedule', 'schedule_not_verified');
                }
                else if (verified.currentness !== 'CURRENT') {
                    classification.add('incomplete', 'schedule', 'schedule_not_current');
                }
                else {
                    outcomeRequirements = riskFreeze(riskClone(verified.outcome_requirements));
                }
            }
            catch {
                classification.add('incomplete', 'schedule', 'schedule_verifier_failed');
            }
        }
        for (const role of ACTION_EVIDENCE_COMPONENT_ROLES) {
            const ref = packet.manifest.components[role];
            if (ref === null)
                continue;
            const artifact = packet.attachments[ref.artifact_digest];
            if (artifact === undefined) {
                classification.add('incomplete', role, `${role}_attachment_missing`);
                continue;
            }
            const verifier = options?.component_verifiers?.[role];
            if (typeof verifier !== 'function') {
                classification.add('incomplete', role, `${role}_verifier_missing`);
                continue;
            }
            if (!canonicalUtcInstant(options?.now))
                continue;
            try {
                const verified = await verifier({
                    role,
                    artifact,
                    artifact_digest: ref.artifact_digest,
                    subject: packet.manifest.subject,
                    subject_digest: subjectDigest,
                    expected_state: ref.expected_state,
                    now: options.now,
                });
                if (!validNativeVerification(verified)) {
                    classification.add('incomplete', role, `${role}_verification_result_invalid`);
                    continue;
                }
                classifyNative(classification, role, ref, verified, subjectDigest);
            }
            catch {
                classification.add('incomplete', role, `${role}_verifier_failed`);
            }
        }
        const verifiedProviderSources = [];
        if (!riskRecord(options?.provider_outcome)
            || !riskRecord(options.provider_outcome.source_keys)
            || !validSubject(options?.expected_context)
            || !canonicalUtcInstant(options?.now)) {
            classification.add('incomplete', 'provider_outcomes', 'provider_outcome_trust_inputs_missing');
        }
        else if (outcomeRequirements === null) {
            classification.add('incomplete', 'provider_outcomes', 'verified_schedule_outcome_requirements_missing');
        }
        else if (!canonicalUtcInstant(options.provider_outcome.provider_entry_at)) {
            classification.add('incomplete', 'provider_outcomes', 'provider_entry_time_missing_or_invalid');
        }
        else if (options.provider_outcome.maximum_observation_age_ms !== undefined
            && (!Number.isSafeInteger(options.provider_outcome.maximum_observation_age_ms)
                || options.provider_outcome.maximum_observation_age_ms < 0
                || options.provider_outcome.maximum_observation_age_ms > 31_536_000_000)) {
            classification.add('incomplete', 'provider_outcomes', 'observation_age_tightening_invalid');
        }
        else {
            const providerOutcomeOptions = options.provider_outcome;
            const expectedContext = options.expected_context;
            const callerMaximumAgeMs = providerOutcomeOptions.maximum_observation_age_ms;
            const signedWindow = outcomeRequirements.observation_window;
            const signedMaximumAgeMs = signedWindow.max_observation_age_sec * 1_000;
            const effectiveMaximumAgeMs = callerMaximumAgeMs === undefined
                ? signedMaximumAgeMs
                : Math.min(signedMaximumAgeMs, callerMaximumAgeMs);
            const providerEntryMs = Date.parse(providerOutcomeOptions.provider_entry_at);
            const windowStartMs = providerEntryMs
                - (signedWindow.opens_before_provider_entry_sec * 1_000);
            const windowEndMs = providerEntryMs
                + (signedWindow.closes_after_provider_entry_sec * 1_000);
            const sharedProviderEventMs = Date.parse(expectedContext.observed_at);
            const assembledAtMs = Date.parse(packet.manifest.assembled_at);
            const nowMs = Date.parse(options.now);
            if (sharedProviderEventMs < providerEntryMs
                || sharedProviderEventMs > windowEndMs
                || sharedProviderEventMs > nowMs) {
                classification.add('conflicted', 'provider_outcomes', 'provider_event_outside_schedule_window');
            }
            if (assembledAtMs > nowMs) {
                classification.add('conflicted', 'manifest', 'packet_assembled_after_verification_time');
            }
            for (let index = 0; index < packet.manifest.provider_outcomes.length; index += 1) {
                const reference = packet.manifest.provider_outcomes[index];
                const component = `provider_outcome:${index}`;
                const providerBinding = packet.attachments[reference.binding_artifact_digest];
                const outcomeObservation = packet.attachments[reference.outcome_observation_artifact_digest];
                if (providerBinding === undefined || outcomeObservation === undefined) {
                    classification.add('incomplete', component, 'provider_outcome_attachment_missing');
                    continue;
                }
                const verified = await verifyProviderOutcomeBinding(providerBinding, outcomeObservation, {
                    source_keys: providerOutcomeOptions.source_keys,
                    expected_source: reference.expected_source,
                    expected_context: expectedContext,
                    now: options.now,
                    maximum_observation_age_ms: effectiveMaximumAgeMs,
                    agility: options.provider_outcome.agility,
                });
                if (verified.status === 'CONFLICTED') {
                    classification.add('conflicted', component, `provider_outcome_${verified.reason ?? 'conflicted'}`);
                    continue;
                }
                if (verified.status !== 'VERIFIED') {
                    classification.add('incomplete', component, `provider_outcome_${verified.reason ?? 'incomplete'}`);
                    continue;
                }
                const interval = verified.observation_interval;
                if (interval === null) {
                    classification.add('incomplete', component, 'provider_observation_interval_missing');
                    continue;
                }
                const observedFromMs = Date.parse(interval.observed_from);
                const observedUntilMs = Date.parse(interval.observed_until);
                const attestedAtMs = Date.parse(interval.attested_at);
                if (observedFromMs < windowStartMs
                    || observedFromMs > sharedProviderEventMs
                    || sharedProviderEventMs > observedUntilMs
                    || sharedProviderEventMs > attestedAtMs
                    || observedUntilMs > windowEndMs) {
                    classification.add('conflicted', component, 'provider_observation_outside_schedule_window');
                    continue;
                }
                if (attestedAtMs > assembledAtMs || attestedAtMs > nowMs) {
                    classification.add('conflicted', component, 'provider_observation_attested_after_assembly');
                    continue;
                }
                const pin = providerOutcomeOptions.source_keys[reference.expected_source.source_id];
                if (!riskRecord(pin) || !riskIdentifier(pin.control_domain_id)) {
                    classification.add('incomplete', component, 'provider_outcome_control_domain_missing');
                    continue;
                }
                verifiedProviderSources.push({
                    source_id: reference.expected_source.source_id,
                    role: reference.expected_source.role,
                    source_class: reference.expected_source.source_class,
                    control_domain_id: pin.control_domain_id,
                });
            }
        }
        if (outcomeRequirements === null) {
            classification.add('incomplete', 'provider_quorum', 'verified_schedule_outcome_requirements_missing');
        }
        else {
            const required = new Set(outcomeRequirements.required_sources.map((source) => `${source.role}\0${source.source_class}`));
            const matchedSlots = new Set();
            const matchedDomains = new Set();
            for (const source of verifiedProviderSources) {
                const slot = `${source.role}\0${source.source_class}`;
                if (!required.has(slot)) {
                    classification.add('conflicted', 'provider_quorum', 'provider_source_not_required_by_schedule');
                    continue;
                }
                matchedSlots.add(slot);
                matchedDomains.add(source.control_domain_id);
            }
            if (matchedSlots.size < outcomeRequirements.quorum) {
                classification.add('incomplete', 'provider_quorum', 'provider_outcome_quorum_not_met');
            }
            if (outcomeRequirements.require_control_domain_independence
                && matchedDomains.size < outcomeRequirements.quorum) {
                classification.add('incomplete', 'provider_quorum', 'provider_control_domain_independence_not_met');
            }
        }
        for (const ref of refs) {
            if (!Object.hasOwn(packet.attachments, ref.digest)) {
                classification.add('incomplete', ref.role, `${ref.role}_attachment_missing`);
            }
        }
        classifyTerminalSemantics(classification, packet.manifest);
        return verificationResult(classification, manifestDigest, subjectDigest);
    }
    catch {
        classification.add('conflicted', 'packet', 'packet_verification_failed');
        return verificationResult(classification, manifestDigest, subjectDigest);
    }
}
//# sourceMappingURL=action-evidence-packet.js.map