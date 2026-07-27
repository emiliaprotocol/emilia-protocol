// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate Qualification v2 pure verification profile.
 *
 * This is intentionally a strict, closed, profile-shaped subset of in-toto
 * Statements and DSSE envelopes. It is not a general in-toto parser. Every
 * signed payload must be canonical JSON, every reference is SHA-256 over the
 * decoded Statement payload (never over its mutable signature envelope), and
 * every decision is storage-independent and fail closed.
 */
import crypto from 'node:crypto';
export const CANDIDATE_MANIFEST_VERSION = 'EP-CANDIDATE-MANIFEST-v1';
export const EVALUATION_CAMPAIGN_PREDICATE = 'https://emiliaprotocol.ai/attestation/evaluation-campaign/v1';
export const TEST_RESULT_PREDICATE = 'https://in-toto.io/attestation/test-result/v0.1';
export const AGENT_EVALUATION_EVIDENCE_PREDICATE = 'https://emiliaprotocol.ai/attestation/agent-evaluation-evidence/v1';
export const QUALIFICATION_STATEMENT_PREDICATE = 'https://in-toto.io/attestation/svr/v0.2';
export const QUALIFICATION_STATUS_VERSION = 'EP-QUALIFICATION-STATUS-v1';
export const RUNTIME_CANDIDATE_MEASUREMENT_VERSION = 'EP-RUNTIME-CANDIDATE-MEASUREMENT-v1';
export const IN_TOTO_STATEMENT_V1 = 'https://in-toto.io/Statement/v1';
export const IN_TOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json';
export const QUALIFICATION_STATUS_PAYLOAD_TYPE = 'application/vnd.emilia.qualification-status+json';
export const RUNTIME_MEASUREMENT_PAYLOAD_TYPE = 'application/vnd.emilia.runtime-candidate-measurement+json';
export const QUALIFICATION_PROPERTY = 'EMILIA_GATE_QUALIFICATION_V2';
export const TERMINAL_OUTCOMES = Object.freeze(['PASS', 'FAIL', 'ABORTED', 'EXPIRED']);
export const QUALIFICATION_DECISIONS = Object.freeze(['QUALIFIED', 'NOT_QUALIFIED', 'INDETERMINATE']);
export const MODEL_PINNING_STRENGTHS = Object.freeze([
    'UNPINNABLE', 'MUTABLE_ALIAS', 'VERSION_PINNED', 'IMMUTABLE_DIGEST',
]);
export const GATE_QUALIFICATION_LIMITS = Object.freeze({
    max_payload_bytes: 1_048_576,
    max_string_bytes: 4096,
    max_signatures: 8,
    max_campaigns: 32,
    max_status_entries: 256,
    max_test_results: 4096,
    max_agent_evidence: 32,
    max_terminal_outcomes: 4096,
    max_challenges: 512,
    max_batches: 128,
    max_attempts_per_challenge: 16,
    max_measurements: 256,
    max_test_names: 4096,
    max_configuration_refs: 32,
    max_properties: 128,
    max_object_depth: 32,
    max_object_nodes: 65_536,
});
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const HEX256 = /^[0-9a-f]{64}$/;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const FATAL_UTF8 = new TextDecoder('utf-8', { fatal: true });
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
function record(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function exactObject(value, required, optional = []) {
    if (!record(value))
        return false;
    const allowed = new Set([...required, ...optional]);
    const keys = Object.keys(value);
    return required.every((key) => own(value, key)) && keys.every((key) => allowed.has(key));
}
function validUnicode(value) {
    for (let index = 0; index < value.length; index += 1) {
        const code = value.charCodeAt(index);
        if (code >= 0xd800 && code <= 0xdbff) {
            const next = value.charCodeAt(index + 1);
            if (!(next >= 0xdc00 && next <= 0xdfff))
                return false;
            index += 1;
        }
        else if (code >= 0xdc00 && code <= 0xdfff)
            return false;
    }
    return true;
}
function nonEmptyString(value, maxBytes = GATE_QUALIFICATION_LIMITS.max_string_bytes) {
    return typeof value === 'string' && value.length > 0 && validUnicode(value)
        && Buffer.byteLength(value, 'utf8') <= maxBytes && !/[\u0000-\u001f\u007f]/.test(value);
}
function digest(value) {
    return typeof value === 'string' && SHA256.test(value);
}
function safeNonNegativeInteger(value) {
    return Number.isSafeInteger(value) && value >= 0;
}
function instantMs(value) {
    if (typeof value !== 'string')
        return NaN;
    const match = RFC3339.exec(value);
    if (!match)
        return NaN;
    const [, year, month, day, hour, minute, second, , , offsetHour, offsetMinute] = match;
    if (offsetHour !== undefined && (Number(offsetHour) > 23 || Number(offsetMinute) > 59))
        return NaN;
    const calendar = new Date(0);
    calendar.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
    calendar.setUTCHours(Number(hour), Number(minute), Number(second), 0);
    if (calendar.toISOString().slice(0, 19) !== `${year}-${month}-${day}T${hour}:${minute}:${second}`)
        return NaN;
    return Date.parse(value);
}
function uri(value) {
    if (!nonEmptyString(value))
        return false;
    try {
        return Boolean(new URL(value).protocol);
    }
    catch {
        return false;
    }
}
function sortedUniqueStrings(value, min, max, predicate) {
    if (!Array.isArray(value) || value.length < min || value.length > max || !value.every(predicate))
        return false;
    for (let index = 1; index < value.length; index += 1) {
        if (Buffer.compare(Buffer.from(value[index - 1]), Buffer.from(value[index])) >= 0)
            return false;
    }
    return true;
}
function canonicalJsonInternal(value, state, depth) {
    state.nodes += 1;
    if (state.nodes > GATE_QUALIFICATION_LIMITS.max_object_nodes || depth > GATE_QUALIFICATION_LIMITS.max_object_depth) {
        throw new TypeError('canonical_value_too_large');
    }
    if (value === null)
        return 'null';
    if (typeof value === 'boolean')
        return value ? 'true' : 'false';
    if (typeof value === 'string') {
        if (!validUnicode(value))
            throw new TypeError('invalid_unicode');
        return JSON.stringify(value);
    }
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value))
            throw new TypeError('non_canonical_number');
        return JSON.stringify(value);
    }
    if (Array.isArray(value))
        return `[${value.map((entry) => canonicalJsonInternal(entry, state, depth + 1)).join(',')}]`;
    if (!record(value))
        throw new TypeError('non_canonical_value');
    return `{${Object.keys(value).sort().map((key) => {
        if (!validUnicode(key) || value[key] === undefined)
            throw new TypeError('non_canonical_member');
        return `${JSON.stringify(key)}:${canonicalJsonInternal(value[key], state, depth + 1)}`;
    }).join(',')}}`;
}
export function canonicalizeQualification(value) {
    return canonicalJsonInternal(value, { nodes: 0 }, 0);
}
export function qualificationPayloadDigest(value) {
    return `sha256:${crypto.createHash('sha256').update(canonicalizeQualification(value), 'utf8').digest('hex')}`;
}
function bytesDigest(value) {
    return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}
function canonicalBase64(value, maxBytes = GATE_QUALIFICATION_LIMITS.max_payload_bytes) {
    if (typeof value !== 'string' || value.length === 0 || value.length > Math.ceil(maxBytes / 3) * 4 + 4
        || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))
        return null;
    const decoded = Buffer.from(value, 'base64');
    return decoded.length <= maxBytes && decoded.toString('base64') === value ? decoded : null;
}
function canonicalBase64url(value) {
    if (typeof value !== 'string' || value.length === 0 || value.length % 4 === 1 || !/^[A-Za-z0-9_-]+$/.test(value))
        return null;
    const decoded = Buffer.from(value, 'base64url');
    return decoded.toString('base64url') === value ? decoded : null;
}
export function dsseSigningBytes(payloadType, payload) {
    const type = Buffer.from(payloadType, 'utf8');
    const body = Buffer.from(payload);
    return Buffer.concat([
        Buffer.from(`DSSEv1 ${type.length} `, 'ascii'), type,
        Buffer.from(` ${body.length} `, 'ascii'), body,
    ]);
}
function decodeCanonicalEnvelope(envelope, expectedPayloadType) {
    if (!exactObject(envelope, ['payloadType', 'payload', 'signatures']) || envelope.payloadType !== expectedPayloadType) {
        return { valid: false, reason: 'invalid_envelope' };
    }
    if (!Array.isArray(envelope.signatures) || envelope.signatures.length === 0
        || envelope.signatures.length > GATE_QUALIFICATION_LIMITS.max_signatures)
        return { valid: false, reason: 'invalid_envelope_signatures' };
    const keyids = new Set();
    for (const signature of envelope.signatures) {
        if (!exactObject(signature, ['keyid', 'sig']) || !nonEmptyString(signature.keyid, 512)
            || !canonicalBase64(signature.sig, 512) || keyids.has(signature.keyid))
            return { valid: false, reason: 'invalid_envelope_signatures' };
        keyids.add(signature.keyid);
    }
    const bytes = canonicalBase64(envelope.payload);
    if (!bytes)
        return { valid: false, reason: 'invalid_envelope_payload' };
    let text;
    let payload;
    try {
        text = FATAL_UTF8.decode(bytes);
        payload = JSON.parse(text);
        if (canonicalizeQualification(payload) !== text)
            return { valid: false, reason: 'non_canonical_payload' };
    }
    catch {
        return { valid: false, reason: 'invalid_envelope_payload' };
    }
    if (!record(payload))
        return { valid: false, reason: 'invalid_envelope_payload' };
    return { valid: true, value: { envelope: envelope, payload, bytes, payload_digest: bytesDigest(bytes) } };
}
function loadEd25519Key(value) {
    try {
        let key;
        if (value.includes('-----BEGIN'))
            key = crypto.createPublicKey(value);
        else {
            const der = canonicalBase64url(value);
            if (!der)
                return null;
            key = crypto.createPublicKey({ key: der, type: 'spki', format: 'der' });
        }
        return key.asymmetricKeyType === 'ed25519' ? key : null;
    }
    catch {
        return null;
    }
}
function publicKeyFingerprint(key) {
    const bytes = key.export({ type: 'spki', format: 'der' });
    return crypto.createHash('sha256').update(bytes).digest('hex');
}
function validTrustPolicy(policy) {
    if (!exactObject(policy, ['keys', 'accepted_keyids', 'threshold']) || !record(policy.keys)
        || !Array.isArray(policy.accepted_keyids) || !safeNonNegativeInteger(policy.threshold)
        || policy.threshold < 1 || policy.threshold > GATE_QUALIFICATION_LIMITS.max_signatures)
        return false;
    const keyids = Object.keys(policy.keys);
    if (keyids.length === 0 || keyids.length > 256
        || !keyids.every((keyid) => nonEmptyString(keyid, 512)
            && typeof policy.keys[keyid] === 'string'
            && policy.keys[keyid].length > 0
            && validUnicode(policy.keys[keyid])
            && Buffer.byteLength(policy.keys[keyid], 'utf8') <= 8192))
        return false;
    if (policy.accepted_keyids.length < policy.threshold
        || new Set(policy.accepted_keyids).size !== policy.accepted_keyids.length
        || !policy.accepted_keyids.every((keyid) => typeof keyid === 'string' && own(policy.keys, keyid)))
        return false;
    const fingerprints = new Set();
    for (const keyid of keyids) {
        const key = loadEd25519Key(policy.keys[keyid]);
        if (!key)
            return false;
        const fingerprint = publicKeyFingerprint(key);
        if (fingerprints.has(fingerprint))
            return false;
        fingerprints.add(fingerprint);
    }
    const acceptedFingerprints = new Set(policy.accepted_keyids.map((keyid) => publicKeyFingerprint(loadEd25519Key(policy.keys[keyid]))));
    return acceptedFingerprints.size >= policy.threshold;
}
function verifyEnvelope(envelope, expectedPayloadType, trust, schema) {
    const decoded = decodeCanonicalEnvelope(envelope, expectedPayloadType);
    if (!decoded.valid || !decoded.value)
        return { payload: null, payload_digest: null, verified: false, accepted: false, reason: decoded.reason ?? 'invalid_envelope' };
    const checked = schema(decoded.value.payload);
    if (!checked.valid || !checked.value)
        return { payload: null, payload_digest: decoded.value.payload_digest, verified: false, accepted: false, reason: checked.reason ?? 'invalid_payload_schema' };
    if (!validTrustPolicy(trust))
        return { payload: checked.value, payload_digest: decoded.value.payload_digest, verified: false, accepted: false, reason: 'invalid_trust_policy' };
    const pae = dsseSigningBytes(decoded.value.envelope.payloadType, decoded.value.bytes);
    const acceptedKeyFingerprints = new Set();
    for (const signature of decoded.value.envelope.signatures) {
        if (!own(trust.keys, signature.keyid))
            return { payload: checked.value, payload_digest: decoded.value.payload_digest, verified: false, accepted: false, reason: 'untrusted_verification_key' };
        const key = loadEd25519Key(trust.keys[signature.keyid]);
        const sig = canonicalBase64(signature.sig, 512);
        if (!key || !sig || !crypto.verify(null, pae, key, sig))
            return { payload: checked.value, payload_digest: decoded.value.payload_digest, verified: false, accepted: false, reason: 'invalid_artifact_signature' };
        if (trust.accepted_keyids.includes(signature.keyid)) {
            acceptedKeyFingerprints.add(publicKeyFingerprint(key));
        }
    }
    const accepted = acceptedKeyFingerprints.size;
    return {
        payload: checked.value,
        payload_digest: decoded.value.payload_digest,
        verified: true,
        accepted: accepted >= trust.threshold,
        reason: accepted >= trust.threshold ? 'accepted' : 'artifact_not_accepted',
    };
}
function resourceDescriptor(value) {
    return exactObject(value, ['name', 'digest']) && nonEmptyString(value.name)
        && exactObject(value.digest, ['sha256']) && typeof value.digest.sha256 === 'string' && HEX256.test(value.digest.sha256);
}
function resourceMatches(value, name, expected) {
    return resourceDescriptor(value) && value.name === name && expected === `sha256:${value.digest.sha256}`;
}
function statement(value, predicateType) {
    return exactObject(value, ['_type', 'subject', 'predicateType', 'predicate'])
        && value._type === IN_TOTO_STATEMENT_V1 && value.predicateType === predicateType
        && Array.isArray(value.subject) && value.subject.length > 0 && value.subject.length <= 16
        && value.subject.every(resourceDescriptor) && record(value.predicate);
}
function validModel(value) {
    if (!exactObject(value, ['provider', 'identity', 'version', 'artifact_digest', 'pinning_strength'])
        || !nonEmptyString(value.provider) || !nonEmptyString(value.identity) || !nonEmptyString(value.version)
        || !MODEL_PINNING_STRENGTHS.includes(value.pinning_strength))
        return false;
    if (value.artifact_digest !== null && !digest(value.artifact_digest))
        return false;
    return value.pinning_strength !== 'IMMUTABLE_DIGEST' || digest(value.artifact_digest);
}
function validStaticCandidate(value) {
    return exactObject(value, [
        'code_digests', 'dependency_digests', 'prompt_template_digests', 'tool_definition_digests',
        'effective_permissions_digest', 'model', 'retrieval_configuration_digest', 'builder_orchestrator_digest',
    ])
        && sortedUniqueStrings(value.code_digests, 1, 256, digest)
        && sortedUniqueStrings(value.dependency_digests, 0, 1024, digest)
        && sortedUniqueStrings(value.prompt_template_digests, 1, 256, digest)
        && sortedUniqueStrings(value.tool_definition_digests, 1, 512, digest)
        && digest(value.effective_permissions_digest) && validModel(value.model)
        && digest(value.retrieval_configuration_digest) && digest(value.builder_orchestrator_digest);
}
export function validateCandidateManifest(value) {
    try {
        if (!exactObject(value, ['profile', 'candidate_id', 'static'])
            || value.profile !== CANDIDATE_MANIFEST_VERSION || !nonEmptyString(value.candidate_id)
            || !validStaticCandidate(value.static))
            return { valid: false, reason: 'invalid_candidate_manifest' };
        canonicalizeQualification(value);
        return { valid: true, value };
    }
    catch {
        return { valid: false, reason: 'invalid_candidate_manifest' };
    }
}
function validHiddenChallenges(value) {
    if (!record(value) || !own(value, 'scheme'))
        return false;
    if (value.scheme === 'SALTED_SHA256_SET') {
        return exactObject(value, ['scheme', 'commitments'])
            && sortedUniqueStrings(value.commitments, 1, GATE_QUALIFICATION_LIMITS.max_challenges, digest);
    }
    return value.scheme === 'MERKLE_SHA256' && exactObject(value, ['scheme', 'root_digest', 'challenge_count'])
        && digest(value.root_digest) && safeNonNegativeInteger(value.challenge_count)
        && value.challenge_count >= 1 && value.challenge_count <= GATE_QUALIFICATION_LIMITS.max_challenges;
}
export function validateEvaluationCampaign(value) {
    try {
        if (!statement(value, EVALUATION_CAMPAIGN_PREDICATE) || value.subject.length !== 1)
            return { valid: false, reason: 'invalid_evaluation_campaign' };
        const p = value.predicate;
        if (!exactObject(p, [
            'campaign_id', 'candidate_manifest_digest', 'assignment_digest', 'qualification_policy_digest',
            'harness_digest', 'evaluator_configuration_digest', 'environment_digest', 'hidden_challenges',
            'scenario_selection_commitment_digest', 'planned_batches', 'maximum_batches', 'attempt_ceiling',
            'not_before', 'not_after', 'predecessor_campaign_payload_digest',
        ]) || !nonEmptyString(p.campaign_id) || !digest(p.candidate_manifest_digest) || !digest(p.assignment_digest)
            || !digest(p.qualification_policy_digest) || !digest(p.harness_digest) || !digest(p.evaluator_configuration_digest)
            || !digest(p.environment_digest) || !validHiddenChallenges(p.hidden_challenges)
            || !digest(p.scenario_selection_commitment_digest) || !safeNonNegativeInteger(p.planned_batches)
            || !safeNonNegativeInteger(p.maximum_batches) || p.planned_batches < 1 || p.maximum_batches < p.planned_batches
            || p.maximum_batches > GATE_QUALIFICATION_LIMITS.max_batches || !safeNonNegativeInteger(p.attempt_ceiling)
            || p.attempt_ceiling < 1 || p.attempt_ceiling > GATE_QUALIFICATION_LIMITS.max_attempts_per_challenge
            || !Number.isFinite(instantMs(p.not_before)) || !Number.isFinite(instantMs(p.not_after))
            || instantMs(p.not_before) >= instantMs(p.not_after)
            || (p.predecessor_campaign_payload_digest !== null && !digest(p.predecessor_campaign_payload_digest))
            || !resourceMatches(value.subject[0], 'candidate-manifest', p.candidate_manifest_digest)) {
            return { valid: false, reason: 'invalid_evaluation_campaign' };
        }
        return { valid: true, value };
    }
    catch {
        return { valid: false, reason: 'invalid_evaluation_campaign' };
    }
}
function validStringList(value) {
    return sortedUniqueStrings(value, 0, GATE_QUALIFICATION_LIMITS.max_test_names, (entry) => nonEmptyString(entry));
}
export function validateTestResultReference(value) {
    try {
        if (!statement(value, TEST_RESULT_PREDICATE) || value.subject.length !== 1)
            return { valid: false, reason: 'invalid_test_result' };
        const p = value.predicate;
        if (!exactObject(p, ['result', 'configuration'], ['url', 'passedTests', 'warnedTests', 'failedTests'])
            || !['PASSED', 'WARNED', 'FAILED'].includes(p.result) || !Array.isArray(p.configuration)
            || p.configuration.length < 1 || p.configuration.length > GATE_QUALIFICATION_LIMITS.max_configuration_refs
            || !p.configuration.every(resourceDescriptor)
            || (own(p, 'url') && !uri(p.url))
            || (own(p, 'passedTests') && !validStringList(p.passedTests))
            || (own(p, 'warnedTests') && !validStringList(p.warnedTests))
            || (own(p, 'failedTests') && !validStringList(p.failedTests)))
            return { valid: false, reason: 'invalid_test_result' };
        return { valid: true, value };
    }
    catch {
        return { valid: false, reason: 'invalid_test_result' };
    }
}
function validMerkleProof(value) {
    return Array.isArray(value) && value.length <= 16 && value.every((entry) => exactObject(entry, ['side', 'digest'])
        && ['LEFT', 'RIGHT'].includes(entry.side) && digest(entry.digest));
}
function validTerminalReference(value) {
    if (!exactObject(value, [
        'batch', 'challenge_index', 'attempt', 'challenge_commitment', 'challenge_proof',
        'scenario_selection_commitment_digest', 'outcome', 'test_result_payload_digest',
        'terminal_evidence_payload_digest', 'started_at', 'finished_at',
    ]) || !safeNonNegativeInteger(value.batch) || value.batch < 1 || !safeNonNegativeInteger(value.challenge_index)
        || !safeNonNegativeInteger(value.attempt) || value.attempt < 1 || !digest(value.challenge_commitment)
        || !validMerkleProof(value.challenge_proof) || !digest(value.scenario_selection_commitment_digest)
        || !TERMINAL_OUTCOMES.includes(value.outcome) || !digest(value.terminal_evidence_payload_digest)
        || !Number.isFinite(instantMs(value.started_at)) || !Number.isFinite(instantMs(value.finished_at))
        || instantMs(value.started_at) > instantMs(value.finished_at))
        return false;
    if (value.outcome === 'PASS' || value.outcome === 'FAIL')
        return digest(value.test_result_payload_digest);
    return value.test_result_payload_digest === null;
}
function validOutcomeCounts(value) {
    return exactObject(value, ['PASS', 'FAIL', 'ABORTED', 'EXPIRED'])
        && TERMINAL_OUTCOMES.every((outcome) => safeNonNegativeInteger(value[outcome]));
}
function terminalReferenceKey(value) {
    return `${String(value.batch).padStart(3, '0')}:${String(value.challenge_index).padStart(4, '0')}:${String(value.attempt).padStart(3, '0')}`;
}
function validMeasurements(value) {
    if (!Array.isArray(value) || value.length > GATE_QUALIFICATION_LIMITS.max_measurements)
        return false;
    let prior = '';
    for (const measurement of value) {
        if (!exactObject(measurement, ['name', 'value', 'unit']) || !nonEmptyString(measurement.name)
            || !nonEmptyString(measurement.value) || (measurement.unit !== null && !nonEmptyString(measurement.unit)))
            return false;
        if (prior && Buffer.compare(Buffer.from(prior), Buffer.from(measurement.name)) >= 0)
            return false;
        prior = measurement.name;
    }
    return true;
}
export function validateAgentEvaluationEvidence(value) {
    try {
        if (!statement(value, AGENT_EVALUATION_EVIDENCE_PREDICATE) || value.subject.length !== 1)
            return { valid: false, reason: 'invalid_agent_evaluation_evidence' };
        const p = value.predicate;
        if (!exactObject(p, [
            'campaign_payload_digest', 'candidate_manifest_digest', 'assignment_digest', 'qualification_policy_digest',
            'completed_batches', 'issued_challenges', 'terminal_outcomes', 'outcome_counts',
            'terminal_outcomes_root', 'measurements', 'started_at', 'completed_at',
        ]) || !digest(p.campaign_payload_digest) || !digest(p.candidate_manifest_digest) || !digest(p.assignment_digest)
            || !digest(p.qualification_policy_digest) || !safeNonNegativeInteger(p.completed_batches) || p.completed_batches < 1
            || !safeNonNegativeInteger(p.issued_challenges) || !Array.isArray(p.terminal_outcomes)
            || p.terminal_outcomes.length < 1 || p.terminal_outcomes.length > GATE_QUALIFICATION_LIMITS.max_terminal_outcomes
            || !p.terminal_outcomes.every(validTerminalReference) || !validOutcomeCounts(p.outcome_counts)
            || !digest(p.terminal_outcomes_root) || !validMeasurements(p.measurements)
            || !Number.isFinite(instantMs(p.started_at)) || !Number.isFinite(instantMs(p.completed_at))
            || instantMs(p.started_at) > instantMs(p.completed_at)
            || !resourceMatches(value.subject[0], 'candidate-manifest', p.candidate_manifest_digest)) {
            return { valid: false, reason: 'invalid_agent_evaluation_evidence' };
        }
        for (let index = 1; index < p.terminal_outcomes.length; index += 1) {
            if (terminalReferenceKey(p.terminal_outcomes[index - 1]) >= terminalReferenceKey(p.terminal_outcomes[index])) {
                return { valid: false, reason: 'terminal_outcomes_not_canonical' };
            }
        }
        return { valid: true, value };
    }
    catch {
        return { valid: false, reason: 'invalid_agent_evaluation_evidence' };
    }
}
export function validateQualificationStatement(value) {
    try {
        if (!statement(value, QUALIFICATION_STATEMENT_PREDICATE) || value.subject.length !== 3)
            return { valid: false, reason: 'invalid_qualification_statement' };
        const p = value.predicate;
        if (!exactObject(p, ['verifier', 'timeCreated', 'properties'])
            || !exactObject(p.verifier, ['id', 'policies']) || !uri(p.verifier.id)
            || !Array.isArray(p.verifier.policies) || p.verifier.policies.length !== 2
            || !p.verifier.policies.every(resourceDescriptor) || !Number.isFinite(instantMs(p.timeCreated))
            || !sortedUniqueStrings(p.properties, 1, GATE_QUALIFICATION_LIMITS.max_properties, (entry) => nonEmptyString(entry))) {
            return { valid: false, reason: 'invalid_qualification_statement' };
        }
        return { valid: true, value };
    }
    catch {
        return { valid: false, reason: 'invalid_qualification_statement' };
    }
}
export function validateQualificationStatus(value) {
    try {
        if (!exactObject(value, [
            'profile', 'authority_id', 'qualification_statement_payload_digest', 'candidate_manifest_digest',
            'assignment_digest', 'qualification_policy_digest', 'status', 'sequence',
            'previous_status_payload_digest', 'issued_at', 'next_update', 'valid_until',
        ]) || value.profile !== QUALIFICATION_STATUS_VERSION || !nonEmptyString(value.authority_id)
            || !digest(value.qualification_statement_payload_digest) || !digest(value.candidate_manifest_digest)
            || !digest(value.assignment_digest) || !digest(value.qualification_policy_digest)
            || !['QUALIFIED', 'SUSPENDED', 'REVOKED', 'EXPIRED'].includes(value.status)
            || !safeNonNegativeInteger(value.sequence)
            || (value.previous_status_payload_digest !== null && !digest(value.previous_status_payload_digest))
            || !Number.isFinite(instantMs(value.issued_at)) || !Number.isFinite(instantMs(value.next_update))
            || !Number.isFinite(instantMs(value.valid_until)) || instantMs(value.issued_at) >= instantMs(value.next_update)
            || instantMs(value.issued_at) >= instantMs(value.valid_until))
            return { valid: false, reason: 'invalid_qualification_status' };
        return { valid: true, value };
    }
    catch {
        return { valid: false, reason: 'invalid_qualification_status' };
    }
}
export function validateRuntimeCandidateMeasurement(value) {
    try {
        if (!exactObject(value, [
            'profile', 'measurement_id', 'authority_id', 'measurement_mechanism_digest',
            'candidate_manifest_digest', 'assignment_digest', 'measured_at',
            'candidate_influence_cutoff', 'remains_in_execution_path', 'static', 'dynamic_retrieval_root',
            'memory_state_snapshot_digest', 'user_input_digest', 'protected_request_digest',
        ]) || value.profile !== RUNTIME_CANDIDATE_MEASUREMENT_VERSION || !nonEmptyString(value.measurement_id)
            || !nonEmptyString(value.authority_id) || !digest(value.measurement_mechanism_digest)
            || !digest(value.candidate_manifest_digest) || !digest(value.assignment_digest)
            || !Number.isFinite(instantMs(value.measured_at)) || !Number.isFinite(instantMs(value.candidate_influence_cutoff))
            || instantMs(value.measured_at) > instantMs(value.candidate_influence_cutoff)
            || typeof value.remains_in_execution_path !== 'boolean' || !validStaticCandidate(value.static)
            || !digest(value.dynamic_retrieval_root) || !digest(value.memory_state_snapshot_digest)
            || !digest(value.user_input_digest) || !digest(value.protected_request_digest))
            return { valid: false, reason: 'invalid_runtime_measurement' };
        return { valid: true, value };
    }
    catch {
        return { valid: false, reason: 'invalid_runtime_measurement' };
    }
}
function validateStatusObservation(value) {
    return exactObject(value, ['authority_id', 'head_payload_digest', 'sequence', 'observed_at'])
        && nonEmptyString(value.authority_id) && digest(value.head_payload_digest)
        && safeNonNegativeInteger(value.sequence) && Number.isFinite(instantMs(value.observed_at));
}
export function terminalOutcomesRoot(outcomes) {
    return qualificationPayloadDigest({ profile: 'EP-TERMINAL-OUTCOMES-v1', outcomes });
}
export function qualificationGraphDigest(graph) {
    return qualificationPayloadDigest({ profile: 'EP-QUALIFICATION-GRAPH-v1', ...graph });
}
export function qualificationMerkleParent(left, right) {
    if (!digest(left) || !digest(right))
        throw new TypeError('invalid_merkle_digest');
    return qualificationPayloadDigest({ left, right });
}
function verifiesChallengeCommitment(challenges, reference) {
    if (challenges.scheme === 'SALTED_SHA256_SET') {
        return reference.challenge_proof.length === 0 && challenges.commitments[reference.challenge_index] === reference.challenge_commitment;
    }
    if (!safeNonNegativeInteger(reference.challenge_index)
        || reference.challenge_index >= challenges.challenge_count)
        return false;
    const expectedDepth = Math.ceil(Math.log2(challenges.challenge_count));
    if (reference.challenge_proof.length !== expectedDepth)
        return false;
    let current = reference.challenge_commitment;
    let position = reference.challenge_index;
    for (const step of reference.challenge_proof) {
        const expectedSide = position % 2 === 0 ? 'RIGHT' : 'LEFT';
        if (step.side !== expectedSide)
            return false;
        current = expectedSide === 'LEFT'
            ? qualificationMerkleParent(step.digest, current)
            : qualificationMerkleParent(current, step.digest);
        position = Math.floor(position / 2);
    }
    return current === challenges.root_digest;
}
function baseDecision(reason = 'verification_not_run') {
    return {
        decision: 'INDETERMINATE',
        reason,
        verification: 'NOT_VERIFIED',
        acceptance: 'NOT_ACCEPTED',
        candidate_match: 'UNKNOWN',
        assignment_scope: 'UNKNOWN',
        currentness: 'UNKNOWN',
        campaign_graph: 'INVALID',
        remeasure_at_begin_invocation: false,
        checks: {
            schemas: false,
            payload_signatures: false,
            trust_accepted: false,
            campaign_lineage: false,
            terminal_outcomes_complete: false,
            hidden_challenge_commitments: false,
            qualification_statement_binding: false,
            status_chain: false,
            status_current_as_observed: false,
            runtime_candidate_exact_match: false,
            assignment_in_scope: false,
            protected_request_bound: false,
        },
        payload_digests: {
            candidate_manifest: null,
            campaign_head: null,
            qualification_graph: null,
            qualification_statement: null,
            qualification_status_head: null,
            runtime_measurement: null,
            protected_request_digest: null,
        },
    };
}
function refuse(result, reason, decision = 'INDETERMINATE') {
    result.reason = reason;
    result.decision = decision;
    return result;
}
function validContext(context) {
    if (!exactObject(context, [
        'now', 'expected_candidate_manifest_digest', 'expected_assignment_digest',
        'expected_qualification_policy_digest', 'expected_protected_request_digest',
        'expected_runtime_measurement_authority_id', 'expected_runtime_measurement_mechanism_digest',
        'expected_status_authority_id', 'minimum_status_sequence', 'max_status_observation_age_seconds',
        'max_runtime_measurement_age_seconds', 'minimum_model_pinning_strength', 'trust',
    ]) || !Number.isFinite(instantMs(context.now)) || !digest(context.expected_candidate_manifest_digest)
        || !digest(context.expected_assignment_digest) || !digest(context.expected_qualification_policy_digest)
        || !digest(context.expected_protected_request_digest)
        || !nonEmptyString(context.expected_runtime_measurement_authority_id)
        || !digest(context.expected_runtime_measurement_mechanism_digest)
        || !nonEmptyString(context.expected_status_authority_id)
        || !safeNonNegativeInteger(context.minimum_status_sequence)
        || !safeNonNegativeInteger(context.max_status_observation_age_seconds)
        || !safeNonNegativeInteger(context.max_runtime_measurement_age_seconds)
        || !MODEL_PINNING_STRENGTHS.includes(context.minimum_model_pinning_strength)
        || !exactObject(context.trust, [
            'campaign', 'test_result', 'agent_evidence', 'qualification_statement',
            'qualification_status', 'runtime_measurement',
        ]))
        return false;
    return Object.values(context.trust).every(validTrustPolicy);
}
function validBundleShape(bundle) {
    return exactObject(bundle, [
        'candidate_manifest', 'campaigns', 'test_results', 'agent_evaluation_evidence',
        'qualification_statement', 'qualification_status_chain',
        'qualification_status_observation', 'runtime_measurement',
    ]) && Array.isArray(bundle.campaigns) && bundle.campaigns.length >= 1
        && bundle.campaigns.length <= GATE_QUALIFICATION_LIMITS.max_campaigns
        && Array.isArray(bundle.test_results) && bundle.test_results.length <= GATE_QUALIFICATION_LIMITS.max_test_results
        && Array.isArray(bundle.agent_evaluation_evidence) && bundle.agent_evaluation_evidence.length >= 1
        && bundle.agent_evaluation_evidence.length <= GATE_QUALIFICATION_LIMITS.max_agent_evidence
        && Array.isArray(bundle.qualification_status_chain) && bundle.qualification_status_chain.length >= 1
        && bundle.qualification_status_chain.length <= GATE_QUALIFICATION_LIMITS.max_status_entries;
}
function sameCanonical(left, right) {
    return canonicalizeQualification(left) === canonicalizeQualification(right);
}
function verifyConfigurations(testResult, campaign) {
    const configuration = testResult.predicate.configuration;
    if (configuration.length !== 3)
        return false;
    return resourceMatches(configuration[0], 'environment', campaign.environment_digest)
        && resourceMatches(configuration[1], 'evaluator-configuration', campaign.evaluator_configuration_digest)
        && resourceMatches(configuration[2], 'harness', campaign.harness_digest);
}
function expectedCounts(references) {
    const counts = { PASS: 0, FAIL: 0, ABORTED: 0, EXPIRED: 0 };
    for (const reference of references)
        counts[reference.outcome] += 1;
    return counts;
}
function pinningRank(value) {
    return MODEL_PINNING_STRENGTHS.indexOf(value);
}
function verifyArtifactArray(envelopes, payloadType, trust, schema) {
    const values = [];
    const digests = new Set();
    for (const envelope of envelopes) {
        const verified = verifyEnvelope(envelope, payloadType, trust, schema);
        if (!verified.verified)
            return { ok: false, reason: verified.reason, verified: false, accepted: false };
        if (!verified.accepted)
            return { ok: false, reason: verified.reason, verified: true, accepted: false };
        if (digests.has(verified.payload_digest))
            return { ok: false, reason: 'duplicate_payload_digest', verified: true, accepted: true };
        digests.add(verified.payload_digest);
        values.push(verified);
    }
    return { ok: true, values };
}
function markArtifactFailure(result, failure) {
    if (failure.verified)
        result.verification = 'VERIFIED';
    if (failure.accepted)
        result.acceptance = 'ACCEPTED';
    return refuse(result, failure.reason, failure.verified && !failure.accepted ? 'NOT_QUALIFIED' : 'INDETERMINATE');
}
function evaluateInternal(bundle, context) {
    const result = baseDecision();
    if (!validContext(context))
        return refuse(result, 'invalid_evaluation_context');
    if (!validBundleShape(bundle))
        return refuse(result, 'invalid_qualification_bundle');
    const now = instantMs(context.now);
    const manifestValidation = validateCandidateManifest(bundle.candidate_manifest);
    if (!manifestValidation.valid || !manifestValidation.value)
        return refuse(result, manifestValidation.reason ?? 'invalid_candidate_manifest');
    const runtimeVerification = verifyEnvelope(bundle.runtime_measurement, RUNTIME_MEASUREMENT_PAYLOAD_TYPE, context.trust.runtime_measurement, validateRuntimeCandidateMeasurement);
    if (!runtimeVerification.verified)
        return markArtifactFailure(result, runtimeVerification);
    if (!runtimeVerification.accepted)
        return markArtifactFailure(result, runtimeVerification);
    result.checks.schemas = true;
    const manifest = manifestValidation.value;
    const runtime = runtimeVerification.payload;
    const manifestDigest = qualificationPayloadDigest(manifest);
    result.payload_digests.candidate_manifest = manifestDigest;
    result.payload_digests.runtime_measurement = runtimeVerification.payload_digest;
    result.payload_digests.protected_request_digest = runtime.protected_request_digest;
    if (runtime.authority_id !== context.expected_runtime_measurement_authority_id) {
        return refuse(result, 'runtime_measurement_authority_mismatch', 'NOT_QUALIFIED');
    }
    if (runtime.measurement_mechanism_digest
        !== context.expected_runtime_measurement_mechanism_digest) {
        return refuse(result, 'runtime_measurement_mechanism_mismatch', 'NOT_QUALIFIED');
    }
    if (manifestDigest !== context.expected_candidate_manifest_digest
        || runtime.candidate_manifest_digest !== manifestDigest) {
        result.candidate_match = 'MISMATCH';
        return refuse(result, 'candidate_manifest_digest_mismatch', 'NOT_QUALIFIED');
    }
    if (runtime.assignment_digest !== context.expected_assignment_digest) {
        result.assignment_scope = 'OUT_OF_SCOPE';
        return refuse(result, 'runtime_assignment_out_of_scope', 'NOT_QUALIFIED');
    }
    result.assignment_scope = 'IN_SCOPE';
    result.checks.assignment_in_scope = true;
    if (runtime.protected_request_digest !== context.expected_protected_request_digest) {
        return refuse(result, 'protected_request_digest_mismatch', 'NOT_QUALIFIED');
    }
    result.checks.protected_request_bound = true;
    if (!sameCanonical(runtime.static, manifest.static)) {
        result.candidate_match = 'MISMATCH';
        return refuse(result, 'runtime_candidate_mismatch', 'NOT_QUALIFIED');
    }
    if (pinningRank(runtime.static.model.pinning_strength) < pinningRank(context.minimum_model_pinning_strength)) {
        result.candidate_match = 'UNPINNABLE';
        return refuse(result, 'model_pinning_strength_insufficient', 'NOT_QUALIFIED');
    }
    const measuredAt = instantMs(runtime.measured_at);
    const cutoff = instantMs(runtime.candidate_influence_cutoff);
    if (measuredAt > now || cutoff > now || now - measuredAt > context.max_runtime_measurement_age_seconds * 1000) {
        result.candidate_match = 'STALE';
        return refuse(result, 'runtime_measurement_stale');
    }
    result.candidate_match = 'EXACT_MATCH';
    result.checks.runtime_candidate_exact_match = true;
    result.remeasure_at_begin_invocation = runtime.remains_in_execution_path;
    const campaigns = verifyArtifactArray(bundle.campaigns, IN_TOTO_PAYLOAD_TYPE, context.trust.campaign, validateEvaluationCampaign);
    if (campaigns.ok === false)
        return markArtifactFailure(result, campaigns);
    const testResults = verifyArtifactArray(bundle.test_results, IN_TOTO_PAYLOAD_TYPE, context.trust.test_result, validateTestResultReference);
    if (testResults.ok === false)
        return markArtifactFailure(result, testResults);
    const evidence = verifyArtifactArray(bundle.agent_evaluation_evidence, IN_TOTO_PAYLOAD_TYPE, context.trust.agent_evidence, validateAgentEvaluationEvidence);
    if (evidence.ok === false)
        return markArtifactFailure(result, evidence);
    const qualification = verifyEnvelope(bundle.qualification_statement, IN_TOTO_PAYLOAD_TYPE, context.trust.qualification_statement, validateQualificationStatement);
    if (!qualification.verified)
        return markArtifactFailure(result, qualification);
    if (!qualification.accepted)
        return markArtifactFailure(result, qualification);
    const statuses = verifyArtifactArray(bundle.qualification_status_chain, QUALIFICATION_STATUS_PAYLOAD_TYPE, context.trust.qualification_status, validateQualificationStatus);
    if (statuses.ok === false)
        return markArtifactFailure(result, statuses);
    result.verification = 'VERIFIED';
    result.acceptance = 'ACCEPTED';
    result.checks.payload_signatures = true;
    result.checks.trust_accepted = true;
    const campaignDigests = campaigns.values.map((entry) => entry.payload_digest);
    const campaignPayloads = campaigns.values.map((entry) => entry.payload);
    for (let index = 0; index < campaignPayloads.length; index += 1) {
        const campaign = campaignPayloads[index].predicate;
        const predecessor = index === 0 ? null : campaignDigests[index - 1];
        if (campaign.predecessor_campaign_payload_digest !== predecessor)
            return refuse(result, 'campaign_predecessor_mismatch');
        if (campaign.candidate_manifest_digest !== manifestDigest
            || campaign.assignment_digest !== context.expected_assignment_digest
            || campaign.qualification_policy_digest !== context.expected_qualification_policy_digest) {
            result.assignment_scope = campaign.assignment_digest === context.expected_assignment_digest ? 'IN_SCOPE' : 'OUT_OF_SCOPE';
            return refuse(result, 'campaign_binding_mismatch', 'NOT_QUALIFIED');
        }
    }
    result.checks.campaign_lineage = true;
    const campaignHeadDigest = campaignDigests[campaignDigests.length - 1];
    result.payload_digests.campaign_head = campaignHeadDigest;
    const evidenceByCampaign = new Map();
    for (const entry of evidence.values) {
        const key = entry.payload.predicate.campaign_payload_digest;
        if (evidenceByCampaign.has(key))
            return refuse(result, 'duplicate_campaign_evidence');
        evidenceByCampaign.set(key, entry);
    }
    if (evidenceByCampaign.size !== campaigns.values.length)
        return refuse(result, 'incomplete_campaign_evidence');
    const testResultByDigest = new Map();
    for (const entry of testResults.values)
        testResultByDigest.set(entry.payload_digest, entry);
    const referencedTestResults = new Set();
    for (let campaignIndex = 0; campaignIndex < campaigns.values.length; campaignIndex += 1) {
        const campaignEntry = campaigns.values[campaignIndex];
        const campaign = campaignEntry.payload.predicate;
        const evidenceEntry = evidenceByCampaign.get(campaignEntry.payload_digest);
        if (!evidenceEntry)
            return refuse(result, 'missing_campaign_evidence');
        const ep = evidenceEntry.payload.predicate;
        if (ep.candidate_manifest_digest !== manifestDigest
            || ep.assignment_digest !== context.expected_assignment_digest
            || ep.qualification_policy_digest !== context.expected_qualification_policy_digest) {
            return refuse(result, 'agent_evidence_binding_mismatch', 'NOT_QUALIFIED');
        }
        if (ep.completed_batches < campaign.planned_batches || ep.completed_batches > campaign.maximum_batches
            || ep.issued_challenges !== ep.terminal_outcomes.length
            || !sameCanonical(ep.outcome_counts, expectedCounts(ep.terminal_outcomes))
            || ep.terminal_outcomes_root !== terminalOutcomesRoot(ep.terminal_outcomes)
            || instantMs(ep.started_at) < instantMs(campaign.not_before)
            || instantMs(ep.completed_at) > instantMs(campaign.not_after))
            return refuse(result, 'invalid_campaign_closure');
        const slots = new Map();
        const merkleLeafIndexes = new Map();
        const merkleProofIndexes = new Map();
        for (const reference of ep.terminal_outcomes) {
            if (reference.batch > ep.completed_batches || reference.challenge_index >= (campaign.hidden_challenges.scheme === 'SALTED_SHA256_SET'
                ? campaign.hidden_challenges.commitments.length
                : campaign.hidden_challenges.challenge_count) || reference.attempt > campaign.attempt_ceiling
                || reference.scenario_selection_commitment_digest !== campaign.scenario_selection_commitment_digest
                || instantMs(reference.started_at) < instantMs(ep.started_at)
                || instantMs(reference.finished_at) > instantMs(ep.completed_at))
                return refuse(result, 'hidden_challenge_commitment_mismatch');
            if (campaign.hidden_challenges.scheme === 'MERKLE_SHA256') {
                const priorLeafIndex = merkleLeafIndexes.get(reference.challenge_commitment);
                const proofKey = canonicalizeQualification(reference.challenge_proof);
                const priorProofIndex = merkleProofIndexes.get(proofKey);
                if ((priorLeafIndex !== undefined && priorLeafIndex !== reference.challenge_index)
                    || (priorProofIndex !== undefined && priorProofIndex !== reference.challenge_index)) {
                    return refuse(result, 'duplicate_challenge_leaf_or_proof');
                }
                merkleLeafIndexes.set(reference.challenge_commitment, reference.challenge_index);
                merkleProofIndexes.set(proofKey, reference.challenge_index);
            }
            if (!verifiesChallengeCommitment(campaign.hidden_challenges, reference)) {
                return refuse(result, 'hidden_challenge_commitment_mismatch');
            }
            const slot = `${reference.batch}:${reference.challenge_index}`;
            const attempts = slots.get(slot) ?? [];
            attempts.push(reference.attempt);
            slots.set(slot, attempts);
            if (reference.test_result_payload_digest !== null) {
                const native = testResultByDigest.get(reference.test_result_payload_digest);
                if (!native || referencedTestResults.has(reference.test_result_payload_digest))
                    return refuse(result, 'test_result_reference_mismatch');
                referencedTestResults.add(reference.test_result_payload_digest);
                if (!resourceMatches(native.payload.subject[0], 'candidate-manifest', manifestDigest)
                    || !verifyConfigurations(native.payload, campaign)
                    || (reference.outcome === 'PASS' && native.payload.predicate.result !== 'PASSED')
                    || (reference.outcome === 'FAIL' && native.payload.predicate.result !== 'FAILED')) {
                    return refuse(result, 'test_result_binding_mismatch');
                }
            }
        }
        const challengeCount = campaign.hidden_challenges.scheme === 'SALTED_SHA256_SET'
            ? campaign.hidden_challenges.commitments.length : campaign.hidden_challenges.challenge_count;
        if (slots.size !== ep.completed_batches * challengeCount)
            return refuse(result, 'omitted_terminal_outcome');
        for (const attempts of slots.values()) {
            attempts.sort((left, right) => left - right);
            if (attempts.some((attempt, index) => attempt !== index + 1))
                return refuse(result, 'non_contiguous_challenge_attempts');
        }
    }
    if (referencedTestResults.size !== testResultByDigest.size)
        return refuse(result, 'unreferenced_test_result');
    result.checks.terminal_outcomes_complete = true;
    result.checks.hidden_challenge_commitments = true;
    const graphDigest = qualificationGraphDigest({
        campaign_payload_digests: campaignDigests,
        test_result_payload_digests: [...testResultByDigest.keys()].sort(),
        agent_evaluation_evidence_payload_digests: campaignDigests.map((campaignDigest) => evidenceByCampaign.get(campaignDigest).payload_digest),
    });
    result.payload_digests.qualification_graph = graphDigest;
    const qp = qualification.payload;
    result.payload_digests.qualification_statement = qualification.payload_digest;
    if (!resourceMatches(qp.subject[0], 'candidate-manifest', manifestDigest)
        || !resourceMatches(qp.subject[1], 'evaluation-campaign', campaignHeadDigest)
        || !resourceMatches(qp.subject[2], 'qualification-graph', graphDigest)
        || !resourceMatches(qp.predicate.verifier.policies[0], 'assignment', context.expected_assignment_digest)
        || !resourceMatches(qp.predicate.verifier.policies[1], 'qualification-policy', context.expected_qualification_policy_digest)
        || !qp.predicate.properties.includes(QUALIFICATION_PROPERTY)
        || instantMs(qp.predicate.timeCreated) < Math.max(...evidence.values.map((entry) => instantMs(entry.payload.predicate.completed_at)))
        || instantMs(qp.predicate.timeCreated) > now)
        return refuse(result, 'qualification_statement_binding_mismatch', 'NOT_QUALIFIED');
    result.checks.qualification_statement_binding = true;
    if (!validateStatusObservation(bundle.qualification_status_observation))
        return refuse(result, 'invalid_status_observation');
    const observation = bundle.qualification_status_observation;
    const sequenceDigests = new Map();
    let priorDigest = null;
    let priorIssuedAt = -Infinity;
    for (let index = 0; index < statuses.values.length; index += 1) {
        const entry = statuses.values[index];
        const status = entry.payload;
        const existing = sequenceDigests.get(status.sequence);
        if (existing && existing !== entry.payload_digest) {
            result.currentness = 'EQUIVOCATED';
            return refuse(result, 'qualification_status_equivocation', 'NOT_QUALIFIED');
        }
        sequenceDigests.set(status.sequence, entry.payload_digest);
        if (status.sequence !== index || status.previous_status_payload_digest !== priorDigest
            || instantMs(status.issued_at) < priorIssuedAt || status.authority_id !== context.expected_status_authority_id
            || status.qualification_statement_payload_digest !== qualification.payload_digest
            || status.candidate_manifest_digest !== manifestDigest
            || status.assignment_digest !== context.expected_assignment_digest
            || status.qualification_policy_digest !== context.expected_qualification_policy_digest) {
            return refuse(result, 'qualification_status_chain_mismatch');
        }
        priorDigest = entry.payload_digest;
        priorIssuedAt = instantMs(status.issued_at);
    }
    const headEntry = statuses.values[statuses.values.length - 1];
    const head = headEntry.payload;
    result.payload_digests.qualification_status_head = headEntry.payload_digest;
    if (observation.authority_id !== context.expected_status_authority_id
        || observation.head_payload_digest !== headEntry.payload_digest || observation.sequence !== head.sequence
        || head.sequence < context.minimum_status_sequence)
        return refuse(result, 'qualification_status_observation_mismatch');
    result.checks.status_chain = true;
    const observedAt = instantMs(observation.observed_at);
    if (observedAt < instantMs(head.issued_at) || observedAt > now
        || now - observedAt > context.max_status_observation_age_seconds * 1000
        || now >= instantMs(head.next_update)) {
        result.currentness = 'STALE';
        return refuse(result, 'qualification_status_stale');
    }
    if (head.status === 'REVOKED') {
        result.currentness = 'REVOKED';
        return refuse(result, 'qualification_revoked', 'NOT_QUALIFIED');
    }
    if (head.status === 'SUSPENDED') {
        result.currentness = 'SUSPENDED';
        return refuse(result, 'qualification_suspended', 'NOT_QUALIFIED');
    }
    if (head.status === 'EXPIRED' || now >= instantMs(head.valid_until)) {
        result.currentness = 'EXPIRED';
        return refuse(result, 'qualification_expired', 'NOT_QUALIFIED');
    }
    result.currentness = 'CURRENT_AS_OBSERVED';
    result.checks.status_current_as_observed = true;
    result.campaign_graph = 'COMPLETE';
    result.decision = 'QUALIFIED';
    result.reason = 'qualified';
    return result;
}
/** Verify and evaluate qualification without reserving, consuming, or mutating storage. */
export function evaluateQualification(bundle, context) {
    try {
        return evaluateInternal(bundle, context);
    }
    catch {
        return baseDecision('unexpected_verification_error');
    }
}
/** Alias emphasizing complete campaign-graph verification. */
export function verifyQualificationGraph(bundle, context) {
    return evaluateQualification(bundle, context);
}
export const CandidateManifestSchema = Object.freeze({ validate: validateCandidateManifest });
export const EvaluationCampaignSchema = Object.freeze({ validate: validateEvaluationCampaign });
export const TestResultReferenceSchema = Object.freeze({ validate: validateTestResultReference });
export const AgentEvaluationEvidenceSchema = Object.freeze({ validate: validateAgentEvaluationEvidence });
export const QualificationStatementSchema = Object.freeze({ validate: validateQualificationStatement });
export const QualificationStatusSchema = Object.freeze({ validate: validateQualificationStatus });
export const RuntimeCandidateMeasurementSchema = Object.freeze({ validate: validateRuntimeCandidateMeasurement });
//# sourceMappingURL=gate-qualification.js.map