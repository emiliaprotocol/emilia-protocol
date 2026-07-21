// SPDX-License-Identifier: Apache-2.0
// Generated from acrobat-sign.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { createHash } from 'node:crypto';
import { parseJsonObject, requestBounded, responseHeader, validatePinnedOrigin, validateResponseLimit, validateTimeout, } from './bounded-fetch.js';
import { deepFreezeJson } from './licensed-custodian.js';
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_METADATA_BYTES = 256 * 1024;
const DEFAULT_MAX_DOCUMENT_BYTES = 25 * 1024 * 1024;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/;
const ACROBAT_SIGN_API_HOST = /^api(?:\.[a-z]{2}[0-9]+)?\.(?:adobesign\.(?:com|us)|echosign\.com)$/;
const REQUIRED_PARTICIPANT_ROLE = 'SIGNER';
const REQUIRED_MEMBER_STATUS = 'COMPLETED';
const PARTICIPANT_ROLES = new Set([
    'SIGNER',
    'APPROVER',
    'ACCEPTOR',
    'CERTIFIED_RECIPIENT',
    'FORM_FILLER',
    'DELEGATE_TO_SIGNER',
    'DELEGATE_TO_APPROVER',
    'DELEGATE_TO_ACCEPTOR',
    'DELEGATE_TO_CERTIFIED_RECIPIENT',
    'DELEGATE_TO_FORM_FILLER',
    'NOTARY_SIGNER',
    'ELECTRONIC_SEALER',
    'SHARE',
]);
function isRecord(value) {
    return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}
function validString(value, maxLength) {
    return typeof value === 'string'
        && value.length > 0
        && value.length <= maxLength
        && !CONTROL_CHARACTER.test(value);
}
function validEmail(value) {
    return validString(value, 254) && /^[^@\s]+@[^@\s]+$/.test(value);
}
function validateAcrobatSignOrigin(value) {
    const origin = validatePinnedOrigin(value, { fieldName: 'apiOrigin' });
    const hostname = new URL(origin).hostname.toLowerCase();
    if (!ACROBAT_SIGN_API_HOST.test(hostname)) {
        throw new TypeError('apiOrigin must be an Acrobat Sign API access point');
    }
    return origin;
}
function normalizeVersionToken(value) {
    return validString(value, 2048) && !/\s/.test(value) ? value : null;
}
function normalizeStrongEtag(value) {
    if (typeof value !== 'string' || /^W\//i.test(value))
        return null;
    const startsQuoted = value.startsWith('"');
    const endsQuoted = value.endsWith('"');
    if (startsQuoted !== endsQuoted)
        return null;
    const token = startsQuoted ? value.slice(1, -1) : value;
    if (token.includes('"'))
        return null;
    return normalizeVersionToken(token);
}
function metadataEtag(response) {
    const rawEtag = responseHeader(response, 'etag');
    if (rawEtag === null)
        return { valid: true, value: null };
    const normalized = normalizeStrongEtag(rawEtag);
    return normalized === null
        ? { valid: false, value: null }
        : { valid: true, value: normalized };
}
function normalizeOrder(value) {
    if (Number.isSafeInteger(value) && value >= 0)
        return value;
    if (typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value)) {
        const parsed = Number(value);
        return Number.isSafeInteger(parsed) ? parsed : null;
    }
    return null;
}
function mediaType(headers) {
    const value = responseHeader({ headers }, 'content-type');
    return typeof value === 'string'
        ? value.split(';', 1)[0].trim().toLowerCase()
        : null;
}
function closedResult(kind, fields = {}) {
    return deepFreezeJson({
        kind,
        provider: 'acrobat_sign',
        ...fields,
    });
}
function transportReason(reason) {
    return {
        timeout: 'PROVIDER_TIMEOUT',
        network: 'PROVIDER_UNAVAILABLE',
        response_too_large: 'PROVIDER_RESPONSE_TOO_LARGE',
        invalid_response: 'PROVIDER_RESPONSE_INVALID',
    }[reason] || 'PROVIDER_RESPONSE_INVALID';
}
/**
 * @param {string} operation
 * @param {AcrobatSignProviderFailureInput} response
 * @returns {AcrobatSignEvidenceResult}
 */
function providerFailure(operation, response) {
    if (response.kind === 'failure') {
        return closedResult('provider_error', {
            operation,
            reason_code: transportReason(response.reason),
            http_status: null,
        });
    }
    return closedResult('provider_error', {
        operation,
        reason_code: response.kind === 'invalid'
            ? 'PROVIDER_RESPONSE_INVALID'
            : 'PROVIDER_HTTP_ERROR',
        http_status: response.status ?? null,
    });
}
function notificationAgreementId(notification) {
    return isRecord(notification)
        && isRecord(notification.agreement)
        && typeof notification.agreement.id === 'string'
        ? notification.agreement.id
        : null;
}
function normalizeExpected(expected) {
    if (!isRecord(expected)
        || !validString(expected.agreementId, 512)
        || expected.status !== 'SIGNED'
        || !Array.isArray(expected.participantSets)
        || expected.participantSets.length === 0
        || expected.participantSets.length > 100) {
        return null;
    }
    const participantSets = [];
    const setIds = new Set();
    for (const set of expected.participantSets) {
        const role = typeof set?.role === 'string'
            ? set.role.toUpperCase()
            : '';
        const order = normalizeOrder(set?.order);
        const members = Array.isArray(set?.members) ? set.members : null;
        if (!isRecord(set)
            || !validString(set.id, 512)
            || role !== REQUIRED_PARTICIPANT_ROLE
            || order === null
            || !members
            || members.length !== 1
            || setIds.has(set.id)) {
            return null;
        }
        const member = members[0];
        const memberStatus = member?.status === undefined
            ? REQUIRED_MEMBER_STATUS
            : (typeof member.status === 'string' ? member.status.toUpperCase() : null);
        if (!isRecord(member)
            || !validEmail(member.email)
            || memberStatus !== REQUIRED_MEMBER_STATUS) {
            return null;
        }
        setIds.add(set.id);
        participantSets.push({
            set_id: set.id,
            role,
            order,
            members: [{
                    email: member.email.toLowerCase(),
                    member_status: memberStatus,
                }],
            completion_status: REQUIRED_MEMBER_STATUS,
        });
    }
    participantSets.sort((left, right) => (left.order - right.order || left.set_id.localeCompare(right.set_id)));
    return {
        agreementId: expected.agreementId,
        status: expected.status,
        participantSets,
    };
}
function participantSets(value) {
    if (Array.isArray(value))
        return value;
    if (isRecord(value) && Array.isArray(value.participantSets))
        return value.participantSets;
    return null;
}
/**
 * @returns {AcrobatSignParticipantSet[]|null}
 */
function normalizeParticipantSets(value) {
    const sets = participantSets(value);
    if (!sets || sets.length === 0 || sets.length > 100)
        return null;
    const normalizedSets = [];
    const setIds = new Set();
    for (const set of sets) {
        const role = typeof set?.role === 'string' ? set.role.toUpperCase() : '';
        const order = normalizeOrder(set?.order);
        const members = Array.isArray(set?.memberInfos) ? set.memberInfos : null;
        if (!isRecord(set)
            || !validString(set.id, 512)
            || !PARTICIPANT_ROLES.has(role)
            || order === null
            || !members
            || members.length !== 1
            || setIds.has(set.id)) {
            return null;
        }
        const member = members[0];
        if (!isRecord(member)
            || !validEmail(member.email)
            || (member.status !== undefined && !validString(member.status, 64))
            || (member.extendedStatus !== undefined
                && !validString(member.extendedStatus, 64))) {
            return null;
        }
        const memberStatus = member.extendedStatus ?? member.status;
        if (typeof memberStatus !== 'string')
            return null;
        const normalizedStatus = memberStatus.toUpperCase();
        setIds.add(set.id);
        normalizedSets.push({
            set_id: set.id,
            role,
            order,
            members: [{
                    email: member.email.toLowerCase(),
                    member_status: normalizedStatus,
                }],
            completion_status: normalizedStatus === REQUIRED_MEMBER_STATUS
                ? REQUIRED_MEMBER_STATUS
                : 'INCOMPLETE',
        });
    }
    normalizedSets.sort((left, right) => (left.order - right.order || left.set_id.localeCompare(right.set_id)));
    return normalizedSets;
}
/**
 * @returns {AcrobatSignAgreement|null}
 */
function normalizeAgreement(value, response) {
    if (!isRecord(value)
        || !validString(value.id, 512)
        || !validString(value.status, 64))
        return null;
    const etag = metadataEtag(response);
    const sets = normalizeParticipantSets(value.participantSetsInfo);
    if (!etag.valid || !sets)
        return null;
    return {
        agreement_id: value.id,
        agreement_status: value.status.toUpperCase(),
        metadata_etag: etag.value,
        participant_sets: sets,
    };
}
function participantSetsMatch(actual, expected) {
    if (actual.length !== expected.length)
        return false;
    return actual.every((set, index) => {
        const wanted = expected[index];
        return set.set_id === wanted.set_id
            && set.role === wanted.role
            && set.order === wanted.order
            && set.completion_status === wanted.completion_status
            && set.members.length === wanted.members.length
            && set.members.every((member, memberIndex) => {
                const expectedMember = wanted.members[memberIndex];
                return member.email === expectedMember.email
                    && member.member_status === expectedMember.member_status;
            });
    });
}
function agreementSnapshotsMatch(left, right) {
    return left.agreement_id === right.agreement_id
        && left.agreement_status === right.agreement_status
        && left.metadata_etag === right.metadata_etag
        && participantSetsMatch(left.participant_sets, right.participant_sets);
}
function normalizeEventInstant(value) {
    if (!validString(value, 64))
        return null;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? parsed : null;
}
/**
 * @returns {AcrobatSignEventSnapshot|null}
 */
function normalizeAgreementEvents(value) {
    if (!isRecord(value)
        || !Array.isArray(value.events)
        || value.events.length === 0
        || value.events.length > 10_000) {
        return null;
    }
    const events = [];
    const ids = new Set();
    for (const event of value.events) {
        const at = normalizeEventInstant(event?.date);
        const versionId = normalizeVersionToken(event?.versionId);
        if (!isRecord(event)
            || !validString(event.id, 512)
            || !validString(event.type, 128)
            || at === null
            || versionId === null
            || ids.has(event.id)) {
            return null;
        }
        ids.add(event.id);
        events.push({
            event_id: event.id,
            event_type: event.type,
            event_at: new Date(at).toISOString(),
            event_at_epoch_ms: at,
            version_id: versionId,
        });
    }
    events.sort((left, right) => (left.event_at_epoch_ms - right.event_at_epoch_ms
        || left.event_id.localeCompare(right.event_id)));
    // events is non-empty here: value.events.length > 0 was checked above and
    // the loop pushes exactly one entry per source event (or returns null).
    const latestAt = events.at(-1).event_at_epoch_ms;
    const latestVersions = new Set(events
        .filter((event) => event.event_at_epoch_ms === latestAt)
        .map((event) => event.version_id));
    if (latestVersions.size !== 1)
        return null;
    const snapshot = events.map((event) => ({
        event_id: event.event_id,
        event_type: event.event_type,
        event_at: event.event_at,
        version_id: event.version_id,
    }));
    return {
        version_id: events.at(-1).version_id,
        snapshot_digest: `sha256:${createHash('sha256')
            .update(JSON.stringify(snapshot))
            .digest('hex')}`,
    };
}
function eventSnapshotsMatch(left, right) {
    return left.version_id === right.version_id
        && left.snapshot_digest === right.snapshot_digest;
}
function validObservedAt(value) {
    return typeof value === 'string'
        && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
        && Number.isFinite(Date.parse(value));
}
function pdfSignatureMatches(bytes) {
    return bytes.byteLength >= 5
        && bytes[0] === 0x25
        && bytes[1] === 0x50
        && bytes[2] === 0x44
        && bytes[3] === 0x46
        && bytes[4] === 0x2d;
}
/**
 * Acrobat Sign notifications are correlation hints only. This adapter uses the
 * caller-pinned API origin and OAuth token to re-fetch agreement metadata and
 * the final combined PDF. It hashes those bytes but does not verify a DAB.
 */
/**
 * @param {{
 *   apiOrigin?: string,
 *   oauthAccessToken?: string,
 *   fetch?: Function,
 *   timeoutMs?: number,
 *   maxMetadataBytes?: number,
 *   maxDocumentBytes?: number,
 *   clock?: () => string
 * }} [options]
 */
export function createAcrobatSignAdapter({ apiOrigin, oauthAccessToken, fetch: fetchImpl, timeoutMs = DEFAULT_TIMEOUT_MS, maxMetadataBytes = DEFAULT_MAX_METADATA_BYTES, maxDocumentBytes = DEFAULT_MAX_DOCUMENT_BYTES, clock = () => new Date().toISOString(), } = {}) {
    const origin = validateAcrobatSignOrigin(apiOrigin);
    if (!validString(oauthAccessToken, 8192) || /\s/.test(oauthAccessToken)) {
        throw new TypeError('oauthAccessToken is invalid');
    }
    if (typeof fetchImpl !== 'function')
        throw new TypeError('fetch must be injected');
    if (typeof clock !== 'function')
        throw new TypeError('clock must be a function');
    const totalTimeoutMs = validateTimeout(timeoutMs);
    const metadataLimit = validateResponseLimit(maxMetadataBytes, 'maxMetadataBytes');
    const documentLimit = validateResponseLimit(maxDocumentBytes, 'maxDocumentBytes');
    const authorization = `Bearer ${oauthAccessToken}`;
    async function call(path, accept, maxBytes, deadline) {
        const remaining = deadline - Date.now();
        if (remaining < 1)
            return { kind: 'failure', reason: 'timeout' };
        return requestBounded(
        // `typeof fetchImpl !== 'function'` above already throws otherwise; this
        // hoisted nested function doesn't inherit that narrowing from TS.
        fetchImpl, `${origin}${path}`, {
            method: 'GET',
            headers: {
                Accept: accept,
                Authorization: authorization,
            },
        }, {
            expectedOrigin: origin,
            maxBytes,
            timeoutMs: Math.max(1, Math.min(totalTimeoutMs, remaining)),
        });
    }
    async function fetchAgreementSnapshot(encodedAgreementId, deadline, operation) {
        const response = await call(`/api/rest/v6/agreements/${encodedAgreementId}`, 'application/json', metadataLimit, deadline);
        if (response.kind === 'failure') {
            return { ok: false, result: providerFailure(operation, response) };
        }
        if (response.status < 200 || response.status >= 300) {
            return {
                ok: false,
                result: providerFailure(operation, {
                    kind: 'http_error',
                    status: response.status,
                }),
            };
        }
        const parsed = parseJsonObject(response.bytes, responseHeader(response, 'content-type'));
        if (!parsed.ok) {
            return {
                ok: false,
                result: providerFailure(operation, {
                    kind: 'invalid',
                    status: response.status,
                }),
            };
        }
        const agreement = normalizeAgreement(parsed.value, response);
        if (!agreement) {
            return {
                ok: false,
                result: providerFailure(operation, {
                    kind: 'invalid',
                    status: response.status,
                }),
            };
        }
        return { ok: true, agreement };
    }
    async function fetchEventSnapshot(encodedAgreementId, deadline, operation) {
        const response = await call(`/api/rest/v6/agreements/${encodedAgreementId}/events`, 'application/json', metadataLimit, deadline);
        if (response.kind === 'failure') {
            return { ok: false, result: providerFailure(operation, response) };
        }
        if (response.status < 200 || response.status >= 300) {
            return {
                ok: false,
                result: providerFailure(operation, {
                    kind: 'http_error',
                    status: response.status,
                }),
            };
        }
        const parsed = parseJsonObject(response.bytes, responseHeader(response, 'content-type'));
        const events = parsed.ok ? normalizeAgreementEvents(parsed.value) : null;
        if (!events) {
            return {
                ok: false,
                result: providerFailure(operation, {
                    kind: 'invalid',
                    status: response.status,
                }),
            };
        }
        return { ok: true, events };
    }
    async function fetchFinalEvidence({ notification, expected, } = {}) {
        const normalizedExpected = normalizeExpected(expected);
        if (!normalizedExpected) {
            return closedResult('refused', {
                operation: 'fetch_final_evidence',
                reason_code: 'INVALID_EXPECTATION',
            });
        }
        const hintedAgreementId = notificationAgreementId(notification);
        if (!hintedAgreementId) {
            return closedResult('refused', {
                operation: 'fetch_final_evidence',
                reason_code: 'MISSING_NOTIFICATION_AGREEMENT_ID',
            });
        }
        if (hintedAgreementId !== normalizedExpected.agreementId) {
            return closedResult('mismatch', {
                operation: 'fetch_final_evidence',
                reason_code: 'NOTIFICATION_AGREEMENT_ID_MISMATCH',
                expected_agreement_id: normalizedExpected.agreementId,
            });
        }
        const deadline = Date.now() + totalTimeoutMs;
        const encodedAgreementId = encodeURIComponent(normalizedExpected.agreementId);
        const initialSnapshot = await fetchAgreementSnapshot(encodedAgreementId, deadline, 'fetch_agreement');
        if (!initialSnapshot.ok)
            return initialSnapshot.result;
        const agreement = initialSnapshot.agreement;
        if (agreement.agreement_id !== normalizedExpected.agreementId) {
            return closedResult('mismatch', {
                operation: 'fetch_final_evidence',
                reason_code: 'PROVIDER_AGREEMENT_ID_MISMATCH',
                expected_agreement_id: normalizedExpected.agreementId,
            });
        }
        if (agreement.agreement_status !== normalizedExpected.status) {
            return closedResult('not_final', {
                operation: 'fetch_final_evidence',
                reason_code: 'AGREEMENT_NOT_FINAL',
                agreement_id: normalizedExpected.agreementId,
                expected_status: normalizedExpected.status,
                provider_status: agreement.agreement_status,
            });
        }
        if (!participantSetsMatch(agreement.participant_sets, normalizedExpected.participantSets)) {
            return closedResult('mismatch', {
                operation: 'fetch_final_evidence',
                reason_code: 'PARTICIPANT_MISMATCH',
                agreement_id: normalizedExpected.agreementId,
            });
        }
        const initialEvents = await fetchEventSnapshot(encodedAgreementId, deadline, 'fetch_agreement_events');
        if (!initialEvents.ok)
            return initialEvents.result;
        const documentResponse = await call(`/api/rest/v6/agreements/${encodedAgreementId}/combinedDocument`
            + `?versionId=${encodeURIComponent(initialEvents.events.version_id)}`, 'application/pdf', documentLimit, deadline);
        if (documentResponse.kind === 'failure') {
            return providerFailure('fetch_final_document', documentResponse);
        }
        if (documentResponse.status < 200 || documentResponse.status >= 300) {
            return providerFailure('fetch_final_document', {
                kind: 'http_error',
                status: documentResponse.status,
            });
        }
        if (mediaType(documentResponse.headers) !== 'application/pdf'
            || !pdfSignatureMatches(documentResponse.bytes)) {
            return closedResult('mismatch', {
                operation: 'fetch_final_evidence',
                reason_code: 'FINAL_DOCUMENT_NOT_PDF',
                agreement_id: normalizedExpected.agreementId,
            });
        }
        const finalSnapshot = await fetchAgreementSnapshot(encodedAgreementId, deadline, 'refetch_agreement');
        if (!finalSnapshot.ok)
            return finalSnapshot.result;
        const finalEvents = await fetchEventSnapshot(encodedAgreementId, deadline, 'refetch_agreement_events');
        if (!finalEvents.ok)
            return finalEvents.result;
        if (!agreementSnapshotsMatch(agreement, finalSnapshot.agreement)
            || !eventSnapshotsMatch(initialEvents.events, finalEvents.events)) {
            return closedResult('mismatch', {
                operation: 'fetch_final_evidence',
                reason_code: 'AGREEMENT_CHANGED_DURING_FETCH',
                agreement_id: normalizedExpected.agreementId,
            });
        }
        let observedAt;
        try {
            observedAt = clock();
        }
        catch {
            observedAt = null;
        }
        if (!validObservedAt(observedAt)) {
            return closedResult('refused', {
                operation: 'fetch_final_evidence',
                reason_code: 'INVALID_CLOCK',
            });
        }
        const documentBytes = new Uint8Array(documentResponse.bytes);
        const documentSha256 = createHash('sha256').update(documentBytes).digest('hex');
        const evidence = deepFreezeJson({
            '@version': 'EMILIA-EXTERNAL-ESIGN-EVIDENCE-v1',
            provider: 'acrobat_sign',
            retrieval_method: 'authenticated_provider_refetch',
            api_origin: origin,
            agreement_id: agreement.agreement_id,
            agreement_status: agreement.agreement_status,
            agreement_version: initialEvents.events.version_id,
            agreement_events_digest: initialEvents.events.snapshot_digest,
            participant_sets: agreement.participant_sets,
            document: {
                media_type: 'application/pdf',
                byte_length: documentBytes.byteLength,
                sha256: `sha256:${documentSha256}`,
            },
            observed_at: observedAt,
        });
        // Uint8Array is intentionally returned separately from the normalized row.
        // The caller owns DAB digest verification over these exact bytes.
        return Object.freeze({
            kind: 'evidence_ready',
            provider: 'acrobat_sign',
            evidence,
            document_bytes: documentBytes,
        });
    }
    return Object.freeze({
        kind: 'external_esign_adapter',
        provider: 'acrobat_sign',
        api_origin: origin,
        fetchFinalEvidence,
    });
}
