// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import {
  parseJsonObject,
  requestBounded,
  responseHeader,
  validatePinnedOrigin,
  validateResponseLimit,
  validateTimeout,
} from './bounded-fetch.js';
import { deepFreezeJson } from './licensed-custodian.js';

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_METADATA_BYTES = 256 * 1024;
const DEFAULT_MAX_DOCUMENT_BYTES = 25 * 1024 * 1024;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/;
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
  'SHARE',
]);

/**
 * @typedef {{
 *   kind: 'evidence_ready',
 *   provider: 'acrobat_sign',
 *   evidence: Readonly<Record<string, unknown>>,
 *   document_bytes: Uint8Array
 * } | {
 *   kind: 'refused'|'mismatch'|'not_final'|'provider_error',
 *   provider: 'acrobat_sign',
 *   operation: string,
 *   reason_code: string
 * }} AcrobatSignEvidenceResult
 */

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

function normalizeOrder(value) {
  if (Number.isSafeInteger(value) && value >= 0) return value;
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
      || !Array.isArray(expected.participants)
      || expected.participants.length === 0
      || expected.participants.length > 100) {
    return null;
  }
  const participants = [];
  const identities = new Set();
  for (const participant of expected.participants) {
    const role = typeof participant?.role === 'string'
      ? participant.role.toUpperCase()
      : '';
    if (!isRecord(participant)
        || !validEmail(participant.email)
        || !PARTICIPANT_ROLES.has(role)
        || (participant.status !== undefined
          && !validString(participant.status, 64))) {
      return null;
    }
    const normalized = {
      email: participant.email.toLowerCase(),
      role,
      ...(participant.status === undefined
        ? {}
        : { member_status: participant.status.toUpperCase() }),
    };
    const identity = `${normalized.role}\u0000${normalized.email}`;
    if (identities.has(identity)) return null;
    identities.add(identity);
    participants.push(normalized);
  }
  participants.sort((left, right) => (
    left.role.localeCompare(right.role) || left.email.localeCompare(right.email)
  ));
  return {
    agreementId: expected.agreementId,
    status: expected.status,
    participants,
  };
}

function participantSets(value) {
  if (Array.isArray(value)) return value;
  if (isRecord(value) && Array.isArray(value.participantSets)) return value.participantSets;
  return null;
}

function normalizeAgreement(value) {
  if (!isRecord(value)
      || !validString(value.id, 512)
      || !validString(value.status, 64)) return null;
  const sets = participantSets(value.participantSetsInfo);
  if (!sets || sets.length === 0 || sets.length > 100) return null;
  const participants = [];
  const identities = new Set();
  for (const set of sets) {
    const role = typeof set?.role === 'string' ? set.role.toUpperCase() : '';
    const members = Array.isArray(set?.memberInfos) ? set.memberInfos : null;
    if (!isRecord(set)
        || !PARTICIPANT_ROLES.has(role)
        || !members
        || members.length === 0
        || members.length > 100) return null;
    const order = normalizeOrder(set.order);
    for (const member of members) {
      if (!isRecord(member)
          || !validEmail(member.email)
          || (member.status !== undefined && !validString(member.status, 64))) {
        return null;
      }
      const normalized = {
        email: member.email.toLowerCase(),
        role,
        order,
        member_status: member.status !== undefined
          ? member.status.toUpperCase()
          : null,
      };
      const identity = `${normalized.role}\u0000${normalized.email}`;
      if (identities.has(identity)) return null;
      identities.add(identity);
      participants.push(normalized);
    }
  }
  participants.sort((left, right) => (
    left.role.localeCompare(right.role) || left.email.localeCompare(right.email)
  ));
  return {
    agreement_id: value.id,
    agreement_status: value.status.toUpperCase(),
    participants,
  };
}

function participantsMatch(actual, expected) {
  if (actual.length !== expected.length) return false;
  return actual.every((participant, index) => {
    const wanted = expected[index];
    return participant.email === wanted.email
      && participant.role === wanted.role
      && (wanted.member_status === undefined
        || participant.member_status === wanted.member_status);
  });
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
export function createAcrobatSignAdapter({
  apiOrigin,
  oauthAccessToken,
  fetch: fetchImpl,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxMetadataBytes = DEFAULT_MAX_METADATA_BYTES,
  maxDocumentBytes = DEFAULT_MAX_DOCUMENT_BYTES,
  clock = () => new Date().toISOString(),
} = {}) {
  const origin = validatePinnedOrigin(apiOrigin, { fieldName: 'apiOrigin' });
  if (!validString(oauthAccessToken, 8192) || /\s/.test(oauthAccessToken)) {
    throw new TypeError('oauthAccessToken is invalid');
  }
  if (typeof fetchImpl !== 'function') throw new TypeError('fetch must be injected');
  if (typeof clock !== 'function') throw new TypeError('clock must be a function');
  const totalTimeoutMs = validateTimeout(timeoutMs);
  const metadataLimit = validateResponseLimit(maxMetadataBytes, 'maxMetadataBytes');
  const documentLimit = validateResponseLimit(maxDocumentBytes, 'maxDocumentBytes');
  const authorization = `Bearer ${oauthAccessToken}`;

  async function call(path, accept, maxBytes, deadline) {
    const remaining = deadline - Date.now();
    if (remaining < 1) return { kind: 'failure', reason: 'timeout' };
    return requestBounded(
      fetchImpl,
      `${origin}${path}`,
      {
        method: 'GET',
        headers: {
          Accept: accept,
          Authorization: authorization,
        },
      },
      {
        expectedOrigin: origin,
        maxBytes,
        timeoutMs: Math.max(1, Math.min(totalTimeoutMs, remaining)),
      },
    );
  }

  /**
   * @returns {Promise<AcrobatSignEvidenceResult>}
   */
  async function fetchFinalEvidence({ notification, expected } = {}) {
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
    const metadataResponse = await call(
      `/api/rest/v6/agreements/${encodedAgreementId}`,
      'application/json',
      metadataLimit,
      deadline,
    );
    if (metadataResponse.kind === 'failure') {
      return providerFailure('fetch_agreement', metadataResponse);
    }
    if (metadataResponse.status < 200 || metadataResponse.status >= 300) {
      return providerFailure('fetch_agreement', {
        kind: 'http_error',
        status: metadataResponse.status,
      });
    }
    const parsed = parseJsonObject(
      metadataResponse.bytes,
      responseHeader(metadataResponse, 'content-type'),
    );
    if (!parsed.ok) {
      return providerFailure('fetch_agreement', {
        kind: 'invalid',
        status: metadataResponse.status,
      });
    }
    const agreement = normalizeAgreement(parsed.value);
    if (!agreement) {
      return providerFailure('fetch_agreement', {
        kind: 'invalid',
        status: metadataResponse.status,
      });
    }
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
    if (!participantsMatch(agreement.participants, normalizedExpected.participants)) {
      return closedResult('mismatch', {
        operation: 'fetch_final_evidence',
        reason_code: 'PARTICIPANT_MISMATCH',
        agreement_id: normalizedExpected.agreementId,
      });
    }

    const documentResponse = await call(
      `/api/rest/v6/agreements/${encodedAgreementId}/combinedDocument`,
      'application/pdf',
      documentLimit,
      deadline,
    );
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

    let observedAt;
    try {
      observedAt = clock();
    } catch {
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
      participants: agreement.participants,
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
