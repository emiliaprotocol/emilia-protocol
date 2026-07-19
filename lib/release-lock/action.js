// SPDX-License-Identifier: Apache-2.0

import { canonicalize, isCanonicalizable } from '../../packages/verify/index.js';
import {
  RELEASE_LOCK_CO_ACTION_VERSION,
  RELEASE_LOCK_DIGEST_PATTERN,
  RELEASE_LOCK_DRAW_ACTION_VERSION,
  RELEASE_LOCK_MAX_ACTION_BYTES,
} from './constants.js';
import { canonicalDigest } from './crypto.js';
import { releaseLockRefusal } from './errors.js';
import { releaseLockValidationInternals } from './validation.js';

const { assertNoSensitiveKeys } = releaseLockValidationInternals;

function canonicalCopy(value) {
  return JSON.parse(canonicalize(value));
}

function validText(value, max = 512) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= max
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function validateDocumentEvidence(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || value.provider !== expected.provider
      || value.reference !== expected.reference
      || !RELEASE_LOCK_DIGEST_PATTERN.test(value.document_digest)
      || !validText(value.media_type, 128)
      || !Number.isSafeInteger(value.byte_length)
      || value.byte_length <= 0
      || value.byte_length > 100 * 1024 * 1024
      || !validText(value.observed_at, 64)
      || !Number.isFinite(Date.parse(value.observed_at))
      || !isCanonicalizable(value.evidence)) {
    throw releaseLockRefusal(
      422,
      'document_verification_refused',
      'The document provider did not return a bound final-document digest and reference.',
    );
  }
  assertNoSensitiveKeys(value.evidence, 'document provider evidence');
  const safeEvidence = canonicalCopy(value.evidence);
  if (Buffer.byteLength(canonicalize(safeEvidence), 'utf8') > 32 * 1024) {
    throw releaseLockRefusal(413, 'document_evidence_too_large', 'Document provider evidence is too large.');
  }
  return {
    provider: value.provider,
    reference: value.reference,
    digest: value.document_digest,
    media_type: value.media_type,
    byte_length: value.byte_length,
    observed_at: new Date(value.observed_at).toISOString(),
    evidence_digest: canonicalDigest(safeEvidence),
    evidence: safeEvidence,
  };
}

function finalizedAction(materialScope, {
  lockId,
  version,
  createdAt,
  effectReference = null,
}) {
  const materialHash = canonicalDigest(materialScope);
  const action = canonicalCopy({
    ...materialScope,
    lock_id: lockId,
    version,
    ...(effectReference
      ? {
          custodian: {
            ...materialScope.custodian,
            effect_reference: effectReference,
          },
        }
      : {}),
    created_at: createdAt,
  });
  if (Buffer.byteLength(canonicalize(action), 'utf8') > RELEASE_LOCK_MAX_ACTION_BYTES) {
    throw releaseLockRefusal(413, 'payload_too_large', 'Release Lock action is too large.');
  }
  return Object.freeze({
    action,
    actionHash: canonicalDigest(action),
    materialHash,
    effectReference,
  });
}

function actionContext(lockId, version, createdAt) {
  if (!validText(lockId, 64)
      || !Number.isSafeInteger(version)
      || version < 1
      || !validText(createdAt, 64)
      || new Date(createdAt).toISOString() !== createdAt) {
    throw releaseLockRefusal(400, 'invalid_request', 'Release Lock action context is malformed.');
  }
}

/**
 * @param {object} [opts]
 * @param {string} [opts.lockId]
 * @param {number} [opts.version]
 * @param {object} [opts.normalizedInput]
 * @param {object} [opts.documentEvidence]
 * @param {string} [opts.createdAt]
 */
export function buildChangeOrderAction({
  lockId,
  version,
  normalizedInput,
  documentEvidence,
  createdAt,
} = {}) {
  actionContext(lockId, version, createdAt);
  const document = validateDocumentEvidence(
    documentEvidence,
    normalizedInput.change_order.document,
  );
  const materialScope = {
    '@version': RELEASE_LOCK_CO_ACTION_VERSION,
    round: 'CO_ACCEPTED',
    retained_change_order: {
      document,
      scope: normalizedInput.change_order.scope,
      price_delta: normalizedInput.change_order.price_delta,
      currency: normalizedInput.change_order.currency,
      progress_schedule_effect: normalizedInput.change_order.progress_schedule_effect,
    },
    parties: normalizedInput.parties,
    expires_at: normalizedInput.change_order.expires_at,
    payment_authorization: false,
  };
  return Object.freeze({
    ...finalizedAction(materialScope, { lockId, version, createdAt }),
    document,
  });
}

/**
 * @param {object} [opts]
 * @param {string} [opts.lockId]
 * @param {number} [opts.version]
 * @param {object} [opts.normalizedInput]
 * @param {object} [opts.acceptedChangeOrder]
 * @param {object} [opts.completionEvidence]
 * @param {object[]} [opts.lienWaiverEvidence]
 * @param {object[]} [opts.drawDocumentEvidence]
 * @param {string} [opts.createdAt]
 */
export function buildDrawReleaseAction({
  lockId,
  version,
  normalizedInput,
  acceptedChangeOrder,
  completionEvidence,
  lienWaiverEvidence,
  drawDocumentEvidence,
  createdAt,
} = {}) {
  actionContext(lockId, version, createdAt);
  if (!acceptedChangeOrder
      || acceptedChangeOrder.version !== version
      || !RELEASE_LOCK_DIGEST_PATTERN.test(acceptedChangeOrder.action_hash || '')
      || !RELEASE_LOCK_DIGEST_PATTERN.test(acceptedChangeOrder.acceptance_digest || '')
      || !Array.isArray(acceptedChangeOrder.parties)
      || acceptedChangeOrder.parties.length !== 2) {
    throw releaseLockRefusal(
      409,
      'change_order_not_accepted',
      'DRAW_RELEASE requires the current version to have a complete CO_ACCEPTED round.',
    );
  }
  const draw = normalizedInput.draw;
  const completion = validateDocumentEvidence(completionEvidence, draw.completion_evidence);
  if (!Array.isArray(lienWaiverEvidence)
      || lienWaiverEvidence.length !== draw.lien_waivers.length
      || !Array.isArray(drawDocumentEvidence)
      || drawDocumentEvidence.length !== draw.draw_documents.length) {
    throw releaseLockRefusal(422, 'document_verification_refused', 'Required draw documents were not verified.');
  }
  const lienWaivers = lienWaiverEvidence.map((entry, index) => {
    const expected = draw.lien_waivers[index];
    if (!entry
        || entry.payee_party_id !== expected.payee_party_id
        || !entry.evidence) {
      throw releaseLockRefusal(
        422,
        'document_verification_refused',
        'Lien-waiver evidence is not bound to its exact payee.',
      );
    }
    return {
      payee_party_id: expected.payee_party_id,
      document: validateDocumentEvidence(entry.evidence, expected.document),
    };
  });
  const drawDocuments = drawDocumentEvidence.map(
    (evidence, index) => validateDocumentEvidence(evidence, draw.draw_documents[index]),
  );
  const evidenceHashes = {
    completion_evidence_hash: completion.digest,
    lien_waiver_hashes: lienWaivers.map((waiver) => ({
      payee_party_id: waiver.payee_party_id,
      document_hash: waiver.document.digest,
    })),
    draw_document_hashes: drawDocuments.map((document) => document.digest),
  };
  const materialScope = {
    '@version': RELEASE_LOCK_DRAW_ACTION_VERSION,
    round: 'DRAW_RELEASE',
    accepted_change_order: {
      version: acceptedChangeOrder.version,
      action_hash: acceptedChangeOrder.action_hash,
      acceptance_digest: acceptedChangeOrder.acceptance_digest,
    },
    parties: acceptedChangeOrder.parties,
    draw_id: draw.draw_id,
    amount: draw.amount,
    currency: draw.currency,
    payees: draw.payees,
    milestone: draw.milestone,
    completion_evidence: completion,
    lien_waivers: lienWaivers,
    draw_documents: drawDocuments,
    evidence_hashes: evidenceHashes,
    custodian: draw.custodian,
    expires_at: draw.expires_at,
    custodian_eligibility: 'after_complete_draw_release_round',
  };
  const materialHash = canonicalDigest(materialScope);
  const effectReference = `rl:${lockId}:v${version}:draw:${materialHash.slice(-20)}`;
  return Object.freeze({
    ...finalizedAction(materialScope, {
      lockId,
      version,
      createdAt,
      effectReference,
    }),
    completionEvidence: completion,
    lienWaivers,
    drawDocuments,
  });
}
