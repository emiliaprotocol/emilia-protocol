// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

import { canonicalize } from '../../caid/impl/js/caid.mjs';
import {
  MOBILE_ACTION_CAID_TYPE,
  _internals as actionIdentityInternals,
  buildMobileActionIdentity as computeMobileActionIdentity,
  mobileActionFingerprint,
} from '../../packages/mobile/action-identity.js';

export { MOBILE_ACTION_CAID_TYPE, mobileActionFingerprint };
export const MOBILE_DECISION_PASSPORT_VERSION = 'EP-MOBILE-DECISION-PASSPORT-v1';
export const MOBILE_PROVIDER_OUTCOME_VERSION = 'EP-MOBILE-PROVIDER-OUTCOME-v1';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const CAID = /^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const ALIGNMENT_VERDICTS = new Set([
  'EQUIVALENT_UNDER_PROFILE',
  'NOT_EQUIVALENT',
  'INDETERMINATE',
]);
const EFFECT_STATES = new Set([
  'not_consumed',
  'consumed',
  'indeterminate',
  'executed',
  'refused',
]);
const ACTION_REFERENCE = /^[A-Za-z0-9:_.@-]{8,256}$/;

function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function canonicalDigest(value) {
  const result = canonicalize(value);
  if (!result.ok) {
    throw new TypeError(`value is not canonicalizable: ${result.refusals.join(', ')}`);
  }
  return `sha256:${crypto.createHash('sha256').update(result.canonical, 'utf8').digest('hex')}`;
}

function boundedString(value, maximum = 256) {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum;
}

/**
 * Compute a CAID over an exact-action wrapper. The wrapper contains the full
 * authoritative action digest; no caller-selected CAID is accepted. The local
 * action reference is validated for lookup but excluded from the CAID so two
 * approvers and two native systems can correlate the same exact action.
 * @param {{actionReference?: string, action?: Record<string, unknown>}} [input]
 */
export function buildMobileActionIdentity({ actionReference, action } = {}) {
  return computeMobileActionIdentity({ actionReference, action });
}

/** Return a complete, deterministic diff over display-safe material fields. */
export function materialFieldDiff(current = {}, previous = {}) {
  const after = record(current) ? current : {};
  const before = record(previous) ? previous : {};
  const fields = [...new Set([...Object.keys(after), ...Object.keys(before)])].sort();
  const changes = [];
  for (const field of fields) {
    const had = Object.hasOwn(before, field);
    const has = Object.hasOwn(after, field);
    if (had && has && before[field] === after[field]) continue;
    changes.push({
      field,
      change: had ? (has ? 'changed' : 'removed') : 'added',
      before: had ? String(before[field]) : null,
      after: has ? String(after[field]) : null,
    });
  }
  return changes;
}

/**
 * Cross-system equivalence is never inferred. A positive verdict survives
 * normalization only when the native source verified and the exact mapping
 * profile hash is pinned.
 */
export function normalizeSystemAlignments(input = []) {
  if (!Array.isArray(input)) return [];
  return input.slice(0, 32).flatMap((item) => {
    if (!record(item) || !boundedString(item.system, 128)) return [];
    const profilePinned = boundedString(item.profile_id, 256) && SHA256.test(item.profile_hash || '');
    const nativeVerified = item.native_verified === true;
    const requested = ALIGNMENT_VERDICTS.has(item.verdict) ? item.verdict : 'INDETERMINATE';
    const verdict = requested === 'EQUIVALENT_UNDER_PROFILE'
      && (!profilePinned || !nativeVerified)
      ? 'INDETERMINATE'
      : requested;
    return [{
      system: item.system,
      verdict,
      profile_id: boundedString(item.profile_id, 256) ? item.profile_id : null,
      profile_hash: SHA256.test(item.profile_hash || '') ? item.profile_hash : null,
      native_verified: nativeVerified,
      evidence_digest: SHA256.test(item.evidence_digest || '') ? item.evidence_digest : null,
      reason: boundedString(item.reason, 256) ? item.reason : (
        verdict === 'INDETERMINATE' && requested === 'EQUIVALENT_UNDER_PROFILE'
          ? 'native verification and a pinned mapping profile are required'
          : null
      ),
    }];
  });
}

export function deriveMobileActionContinuity(input = {}) {
  const required = Number.isSafeInteger(input.required_approvals) && input.required_approvals > 0
    ? input.required_approvals : 1;
  const approved = Number.isSafeInteger(input.approved_count) && input.approved_count >= 0
    ? input.approved_count : 0;
  const denied = Number.isSafeInteger(input.denied_count) && input.denied_count >= 0
    ? input.denied_count : 0;
  const withdrawn = Number.isSafeInteger(input.withdrawn_count) && input.withdrawn_count >= 0
    ? input.withdrawn_count : 0;
  const effect = EFFECT_STATES.has(input.effect_status) ? input.effect_status : 'not_consumed';
  const quorum = { approved, required, denied, withdrawn };

  if (effect === 'executed') {
    if (input.outcome_verified !== true) {
      throw new TypeError('EXECUTED requires authenticated provider evidence');
    }
    return { state: 'EXECUTED', retry_safe: false, quorum };
  }
  if (effect === 'refused') return { state: 'REFUSED', retry_safe: false, quorum };
  if (effect === 'indeterminate') return { state: 'INDETERMINATE', retry_safe: false, quorum };
  if (effect === 'consumed') return { state: 'CONSUMED', retry_safe: false, quorum };
  // Threshold authorization is the executable state. A non-veto denial or a
  // withdrawn seat must not make the UI/passport contradict a quorum that the
  // database can still consume.
  if (approved >= required) return { state: 'AUTHORIZED', retry_safe: true, quorum };
  if (input.status === 'denied' || denied > 0) return { state: 'DENIED', retry_safe: true, quorum };
  if (input.status === 'withdrawn' || withdrawn > 0) return { state: 'WITHDRAWN', retry_safe: true, quorum };
  if (approved > 0) return { state: 'QUORUM_PENDING', retry_safe: true, quorum };
  if (input.status === 'expired') return { state: 'EXPIRED', retry_safe: true, quorum };
  if (input.status === 'cancelled') return { state: 'CANCELLED', retry_safe: true, quorum };
  return { state: 'AWAITING_DECISION', retry_safe: true, quorum };
}

function safeEvidenceDigest(value) {
  return record(value) ? canonicalDigest(value) : null;
}

/** Portable summary. Raw WebAuthn/provider evidence remains server-side. */
export function buildDecisionPassport(row = {}, continuity = {}) {
  if (!record(row) || !ACTION_REFERENCE.test(row.action_reference || '')
      || !CAID.test(row.action_caid || '') || !SHA256.test(row.action_digest || '')) {
    throw new TypeError('a CAID-bound mobile action row is required');
  }
  const passport = {
    '@version': MOBILE_DECISION_PASSPORT_VERSION,
    action: {
      action_reference: row.action_reference,
      action_caid: row.action_caid,
      action_digest: row.action_digest,
    },
    decision: {
      challenge_id: boundedString(row.decision_challenge_id) ? row.decision_challenge_id : null,
      verdict: boundedString(row.decision_verdict, 64) ? row.decision_verdict : null,
      decided_at: boundedString(row.decided_at, 64) ? row.decided_at : null,
      evidence_digest: safeEvidenceDigest(row.decision_evidence),
    },
    lifecycle: {
      state: boundedString(continuity.state, 64) ? continuity.state : 'AWAITING_DECISION',
      retry_safe: continuity.retry_safe === true,
      quorum: record(continuity.quorum) ? continuity.quorum : null,
      consumption_nonce: boundedString(row.consumption_nonce) ? row.consumption_nonce : null,
      outcome_digest: SHA256.test(row.outcome_digest || '') ? row.outcome_digest : null,
    },
    created_at: boundedString(row.created_at, 64) ? row.created_at : null,
  };
  return Object.freeze({ ...passport, passport_digest: canonicalDigest(passport) });
}

const PROVIDER_OUTCOME_DOMAIN = `${MOBILE_PROVIDER_OUTCOME_VERSION}\0`;
const PROVIDER_OUTCOME_KEYS = new Set([
  '@version', 'operation_id', 'action_caid', 'action_digest', 'consumption_nonce',
  'executor_id', 'outcome', 'observed_at', 'provider_reference', 'proof',
]);
const PROVIDER_PROOF_KEYS = new Set(['algorithm', 'key_id', 'public_key', 'signature_b64u']);

function exactMembers(value, members) {
  return record(value)
    && Object.keys(value).length === members.size
    && Object.keys(value).every((key) => members.has(key));
}

export function mobileExecutorKeyId(publicKey) {
  return `ep:executor-key:sha256:${crypto.createHash('sha256')
    .update(Buffer.from(publicKey, 'base64url')).digest('hex')}`;
}

function providerOutcomeBody(input) {
  return {
    '@version': MOBILE_PROVIDER_OUTCOME_VERSION,
    operation_id: input.operationId,
    action_caid: input.actionCaid,
    action_digest: input.actionDigest,
    consumption_nonce: input.consumptionNonce,
    executor_id: input.executorId,
    outcome: input.outcome,
    observed_at: input.observedAt,
    provider_reference: input.providerReference,
  };
}

function providerSigningBytes(body) {
  const canonical = canonicalize(body);
  if (!canonical.ok) throw new TypeError('provider outcome is not canonicalizable');
  return Buffer.from(`${PROVIDER_OUTCOME_DOMAIN}${canonical.canonical}`, 'utf8');
}

export function buildMobileProviderOutcome(input = {}) {
  if (!boundedString(input.operationId) || !CAID.test(input.actionCaid || '')
      || !SHA256.test(input.actionDigest || '') || !boundedString(input.consumptionNonce)
      || !boundedString(input.executorId) || !['executed', 'refused'].includes(input.outcome)
      || !boundedString(input.observedAt, 64)
      || !Number.isFinite(Date.parse(input.observedAt))
      || !boundedString(input.providerReference)
      || !input.privateKey) {
    throw new TypeError('a complete, CAID-bound provider outcome is required');
  }
  const body = providerOutcomeBody(input);
  const publicKey = crypto.createPublicKey(input.privateKey)
    .export({ type: 'spki', format: 'der' }).toString('base64url');
  return {
    ...body,
    proof: {
      algorithm: 'Ed25519',
      key_id: mobileExecutorKeyId(publicKey),
      public_key: publicKey,
      signature_b64u: crypto.sign(null, providerSigningBytes(body), input.privateKey).toString('base64url'),
    },
  };
}

/**
 * @param {Record<string, any>} evidence
 * @param {{
 *   expected?: {
 *     operation_id?: string,
 *     action_caid?: string,
 *     action_digest?: string,
 *     consumption_nonce?: string,
 *     executor_id?: string,
 *     executor_key_id?: string
 *   },
 *   executorKeys?: Record<string, any>,
 *   notBefore?: string | null,
 *   now?: string
 * }} [options]
 */
export function verifyMobileProviderOutcome(evidence, {
  expected = {},
  executorKeys = {},
  notBefore = null,
  now = new Date().toISOString(),
} = {}) {
  const refused = (reason) => ({ valid: false, reason, outcome: null, evidence_digest: null });
  if (!exactMembers(evidence, PROVIDER_OUTCOME_KEYS)
      || evidence['@version'] !== MOBILE_PROVIDER_OUTCOME_VERSION
      || !boundedString(evidence.operation_id) || !CAID.test(evidence.action_caid || '')
      || !SHA256.test(evidence.action_digest || '') || !boundedString(evidence.consumption_nonce)
      || !boundedString(evidence.executor_id)
      || !['executed', 'refused'].includes(evidence.outcome)
      || !boundedString(evidence.observed_at, 64)
      || !boundedString(evidence.provider_reference)
      || !exactMembers(evidence.proof, PROVIDER_PROOF_KEYS)
      || evidence.proof.algorithm !== 'Ed25519'
      || !/^ep:executor-key:sha256:[0-9a-f]{64}$/.test(evidence.proof.key_id || '')
      || !B64URL.test(evidence.proof.public_key || '')
      || !B64URL.test(evidence.proof.signature_b64u || '')) {
    return refused('malformed_provider_outcome');
  }
  if (evidence.operation_id !== expected.operation_id
      || evidence.action_caid !== expected.action_caid
      || evidence.action_digest !== expected.action_digest
      || evidence.consumption_nonce !== expected.consumption_nonce
      || evidence.executor_id !== expected.executor_id
      || evidence.proof.key_id !== expected.executor_key_id) {
    return refused('provider_outcome_binding_mismatch');
  }
  const observedAt = Date.parse(evidence.observed_at);
  const earliestAt = notBefore === null ? null : Date.parse(notBefore);
  const nowAt = Date.parse(now);
  if (!Number.isFinite(observedAt) || !Number.isFinite(nowAt)
      || (notBefore !== null && !Number.isFinite(earliestAt))
      || (earliestAt !== null && observedAt < earliestAt)
      || observedAt > nowAt) {
    return refused('provider_outcome_time_invalid');
  }
  const pin = record(executorKeys) ? executorKeys[evidence.executor_id] : null;
  const derivedKeyId = mobileExecutorKeyId(evidence.proof.public_key);
  if (!record(pin) || pin.public_key !== evidence.proof.public_key
      || derivedKeyId !== evidence.proof.key_id
      || (pin.key_id !== undefined && pin.key_id !== derivedKeyId)) {
    return refused('executor_key_not_pinned');
  }
  try {
    const key = crypto.createPublicKey({
      key: Buffer.from(pin.public_key, 'base64url'),
      type: 'spki',
      format: 'der',
    });
    const { proof: _proof, ...body } = evidence;
    if (key.asymmetricKeyType !== 'ed25519'
        || !crypto.verify(
          null,
          providerSigningBytes(body),
          key,
          Buffer.from(evidence.proof.signature_b64u, 'base64url'),
        )) {
      return refused('provider_outcome_signature_invalid');
    }
  } catch {
    return refused('provider_outcome_signature_invalid');
  }
  return {
    valid: true,
    reason: null,
    outcome: evidence.outcome,
    evidence_digest: canonicalDigest(evidence),
  };
}

export const _internals = Object.freeze({
  MOBILE_ACTION_CAID_DEFINITION: actionIdentityInternals.DEFINITION,
  canonicalDigest,
  publicKeyId: mobileExecutorKeyId,
});
