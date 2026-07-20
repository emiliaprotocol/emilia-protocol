// SPDX-License-Identifier: Apache-2.0
/**
 * EP-RESOLUTION-v1 -- a durable, four-outcome record of a human resolution.
 *
 * This profile composes with draft-morrison-binding-moment-envelope without
 * changing either artifact's job. The Morrison envelope defines the transient
 * question and answer space. This record proves, under a relying-party-pinned
 * principal key, how that exact envelope was resolved for an exact action.
 *
 * The signed context carries every security-relevant field. The surrounding
 * object carries no presenter-supplied key. Verification fails closed unless
 * the relying party supplies the original binding_moment value, its expected
 * action digest, a role-pinned principal key, the expected WebAuthn RP ID, and
 * an exact WebAuthn origin allowlist.
 */

import crypto from 'node:crypto';
import { canonicalize, isCanonicalizable, verifyWebAuthnSignoff } from '../index.js';
import { strictJsonGate } from './strict-json.js';

type Obj = Record<string, any>;

interface ResolutionOptions {
  bindingMoment?: Obj;
  expectedActionHash?: string;
  principalKeys?: Record<string, Obj>;
  rpId?: string;
  allowedOrigins?: string[];
  expectedSelectedOption?: number;
  expectedNonce?: string;
  expectedInitiator?: string;
  evaluationTime?: number | string | Date;
}

export const RESOLUTION_VERSION = 'EP-RESOLUTION-v1';
export const RESOLUTION_CONTEXT_TYPE = 'ep.resolution.v1';
export const RESOLUTION_OUTCOMES = Object.freeze([
  'approved',
  'declined',
  'amended',
  'rejected',
]);

const HASH = /^sha256:[0-9a-f]{64}$/;
const RFC3339_OFFSET = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const RECEIPT_KEYS = new Set(['profile', 'signoff']);
const SIGNOFF_KEYS = new Set(['@type', 'context', 'webauthn']);
const CONTEXT_KEYS = new Set([
  'ep_version',
  'context_type',
  'envelope_hash',
  'action_hash',
  'principal',
  'principal_key_id',
  'initiator',
  'nonce',
  'issued_at',
  'expires_at',
  'resolution',
]);
const WEBAUTHN_KEYS = new Set(['authenticator_data', 'client_data_json', 'signature']);

function isRecord(value: unknown): value is Obj {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: unknown, allowed: Set<string>, required: Set<string> = allowed): value is Obj {
  if (!isRecord(value)) return false;
  const keys = Object.keys(value);
  return keys.every((key) => allowed.has(key))
    && [...required].every((key) => Object.hasOwn(value, key));
}

function isHash(value: unknown): value is string {
  return typeof value === 'string' && HASH.test(value);
}

function parseInstant(value: unknown): number {
  if (typeof value !== 'string') return NaN;
  const match = value.match(RFC3339_OFFSET);
  if (!match) return NaN;
  const [, year, month, day, hour, minute, second, , offsetHour, offsetMinute] = match;
  const calendar = new Date(0);
  calendar.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
  calendar.setUTCHours(Number(hour), Number(minute), Number(second), 0);
  if (calendar.toISOString().slice(0, 19) !== `${year}-${month}-${day}T${hour}:${minute}:${second}`) return NaN;
  if (offsetHour !== undefined && (Number(offsetHour) > 23 || Number(offsetMinute) > 59)) return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : NaN;
}

function sha256Canonical(value: unknown): string | null {
  try {
    if (!isCanonicalizable(value)) return null;
    return `sha256:${crypto.createHash('sha256').update(canonicalize(value), 'utf8').digest('hex')}`;
  } catch {
    return null;
  }
}

/** Hash the exact value of the draft's `binding_moment` field. */
export function computeBindingMomentHash(bindingMoment: unknown): string | null {
  return isRecord(bindingMoment) ? sha256Canonical(bindingMoment) : null;
}

/** Hash a principal-authored amendment or objection without forcing disclosure. */
export function computeResolutionResponseHash(response: unknown): string | null {
  return sha256Canonical(response);
}

/** Return the WebAuthn challenge for an already-built resolution context. */
export function computeResolutionChallenge(context: unknown): string | null {
  if (!isRecord(context) || !isCanonicalizable(context)) return null;
  try {
    return crypto.createHash('sha256').update(canonicalize(context), 'utf8').digest('base64url');
  } catch {
    return null;
  }
}

function bindingMomentShapeValid(bindingMoment: Obj | undefined): boolean {
  const outerAllowed = new Set(['synopsis', 'findings', 'recommendations', 'offer', 'question', 'meta']);
  const outerRequired = new Set(['synopsis', 'findings', 'recommendations', 'offer', 'question']);
  if (!hasExactKeys(bindingMoment, outerAllowed, outerRequired)) return false;
  if (typeof bindingMoment.synopsis !== 'string'
    || !Array.isArray(bindingMoment.findings) || !bindingMoment.findings.every((x) => typeof x === 'string')
    || !Array.isArray(bindingMoment.recommendations) || !bindingMoment.recommendations.every((x) => typeof x === 'string')
    || typeof bindingMoment.offer !== 'string') return false;

  const question = bindingMoment.question;
  const questionKeys = new Set(['stem', 'options', 'recommended_idx', 'hatches']);
  if (!hasExactKeys(question, questionKeys) || typeof question.stem !== 'string') return false;
  if (!Array.isArray(question.options) || question.options.length < 2 || question.options.length > 4) return false;
  const optionKeys = new Set(['label', 'reasoning']);
  if (!question.options.every((option) => hasExactKeys(option, optionKeys)
    && typeof option.label === 'string' && typeof option.reasoning === 'string')) return false;
  if (!Number.isSafeInteger(question.recommended_idx)
    || question.recommended_idx < 0 || question.recommended_idx >= question.options.length) return false;
  const hatchKeys = new Set(['free_text', 'dialogue']);
  if (!hasExactKeys(question.hatches, hatchKeys)
    || typeof question.hatches.free_text !== 'boolean'
    || typeof question.hatches.dialogue !== 'boolean') return false;

  if (Object.hasOwn(bindingMoment, 'meta')) {
    const metaKeys = new Set(['decision_class', 'calibration_note']);
    if (!hasExactKeys(bindingMoment.meta, metaKeys, new Set())) return false;
    if (Object.values(bindingMoment.meta).some((value) => typeof value !== 'string')) return false;
  }
  return true;
}

function signedClientOrigin(signoff: Obj): string | null {
  try {
    const encoded = signoff?.webauthn?.client_data_json;
    if (typeof encoded !== 'string' || encoded.length === 0 || !/^[A-Za-z0-9_-]+$/.test(encoded)) return null;
    const bytes = Buffer.from(encoded, 'base64url');
    if (bytes.toString('base64url') !== encoded) return null;
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (!strictJsonGate(text).ok) return null;
    const client = JSON.parse(text);
    return isRecord(client) && typeof client.origin === 'string' && client.origin.length > 0
      ? client.origin
      : null;
  } catch {
    return null;
  }
}

function allowedResolutionKeys(outcome: unknown): Set<string> | null {
  if (outcome === 'approved') return new Set(['outcome', 'selected_option']);
  if (outcome === 'declined') return new Set(['outcome']);
  if (outcome === 'amended') return new Set(['outcome', 'response_hash', 'successor_envelope_hash']);
  if (outcome === 'rejected') return new Set(['outcome', 'objection_hash', 'successor_envelope_hash']);
  return null;
}

function resolutionShapeValid(resolution: Obj, bindingMoment: Obj, currentEnvelopeHash: string): boolean {
  if (!isRecord(resolution) || !RESOLUTION_OUTCOMES.includes(resolution.outcome)) return false;
  const allowed = allowedResolutionKeys(resolution.outcome);
  if (!allowed || !Object.keys(resolution).every((key) => allowed.has(key))) return false;

  if (resolution.outcome === 'approved') {
    if (!Number.isInteger(resolution.selected_option) || resolution.selected_option < 0) return false;
    const options = bindingMoment?.question?.options;
    return Array.isArray(options) && resolution.selected_option < options.length;
  }

  if (resolution.outcome === 'declined') return Object.keys(resolution).length === 1;

  if (resolution.outcome === 'amended' && !isHash(resolution.response_hash)) return false;
  if (resolution.outcome === 'rejected'
    && Object.hasOwn(resolution, 'objection_hash')
    && !isHash(resolution.objection_hash)) return false;

  if (Object.hasOwn(resolution, 'successor_envelope_hash')) {
    if (!isHash(resolution.successor_envelope_hash)) return false;
    if (resolution.successor_envelope_hash === currentEnvelopeHash) return false;
  }
  return true;
}

function structureValid(receipt: Obj): boolean {
  if (!hasExactKeys(receipt, RECEIPT_KEYS)) return false;
  if (receipt.profile !== RESOLUTION_VERSION) return false;
  const signoff = receipt.signoff;
  if (!hasExactKeys(signoff, SIGNOFF_KEYS) || signoff['@type'] !== 'ep.signoff') return false;
  if (!hasExactKeys(signoff.context, CONTEXT_KEYS)) return false;
  if (!hasExactKeys(signoff.webauthn, WEBAUTHN_KEYS)) return false;
  const context = signoff.context;
  return context.ep_version === '1.0'
    && context.context_type === RESOLUTION_CONTEXT_TYPE
    && isHash(context.envelope_hash)
    && isHash(context.action_hash)
    && typeof context.principal === 'string' && context.principal.length > 0
    && typeof context.principal_key_id === 'string' && context.principal_key_id.length > 0
    && typeof context.initiator === 'string' && context.initiator.length > 0
    && typeof context.nonce === 'string' && context.nonce.length > 0;
}

function refuse(reason: string, checks: Record<string, boolean>, outcome: string | null = null) {
  return {
    valid: false,
    authorizes_action: false,
    outcome,
    requires_successor: false,
    checks,
    reason,
  };
}

/**
 * Verify a four-outcome resolution receipt fully offline.
 *
 * Required relying-party inputs:
 *   - bindingMoment: the exact value of the Morrison `binding_moment` field;
 *   - expectedActionHash: the digest of the action the executor may perform;
 *   - principalKeys: { key_id: { principal, public_key } } role-scoped pins;
 *   - rpId: the WebAuthn relying-party identifier expected by the verifier.
 *   - allowedOrigins: exact WebAuthn client origins accepted by the verifier.
 *
 * expectedSelectedOption, expectedNonce, expectedInitiator, and evaluationTime
 * are optional for authentic-evidence verification but all are mandatory before
 * the result can set authorizes_action:true.
 */
export function verifyResolutionReceipt(receipt: Obj, opts: ResolutionOptions = {}) {
  const checks: Record<string, boolean> = {
    structure: false,
    canonical_profile: false,
    binding_moment_shape: false,
    outcome_shape: false,
    envelope_binding: false,
    action_binding: false,
    principal_pin: false,
    selected_option_binding: false,
    authorization_context: false,
    initiator_binding: false,
    nonce_binding: false,
    time_window: false,
    evaluation_time: false,
    rp_id: false,
    origin: false,
    webauthn: false,
  };

  try {
    checks.structure = structureValid(receipt);
    if (!checks.structure) return refuse('malformed_resolution_receipt', checks);

    const { context } = receipt.signoff;
    const outcome = context.resolution?.outcome ?? null;

    checks.canonical_profile = isCanonicalizable(context) && isCanonicalizable(opts.bindingMoment);
    if (!checks.canonical_profile) return refuse('resolution_outside_canonicalization_profile', checks, outcome);

    checks.binding_moment_shape = bindingMomentShapeValid(opts.bindingMoment);
    if (!checks.binding_moment_shape) return refuse('malformed_binding_moment', checks, outcome);

    const bindingMoment = opts.bindingMoment as Obj;
    const envelopeHash = computeBindingMomentHash(opts.bindingMoment);
    checks.outcome_shape = resolutionShapeValid(context.resolution, bindingMoment, context.envelope_hash);
    if (!checks.outcome_shape) return refuse('invalid_outcome_shape', checks, outcome);

    checks.envelope_binding = envelopeHash !== null && context.envelope_hash === envelopeHash;
    if (!checks.envelope_binding) return refuse('envelope_binding_mismatch', checks, outcome);

    checks.action_binding = isHash(opts.expectedActionHash)
      && context.action_hash === opts.expectedActionHash;
    if (!checks.action_binding) return refuse('action_binding_mismatch', checks, outcome);

    // Receipt validity and execution authority are deliberately separate. The
    // source envelope has human-facing labels but no normative option-to-action
    // mapping. An approved receipt therefore authorizes only when the relying
    // party independently pins which option denotes the exact expected action.
    const expectedSelectedOption = opts.expectedSelectedOption;
    checks.selected_option_binding = outcome !== 'approved'
      || (typeof expectedSelectedOption === 'number' && Number.isInteger(expectedSelectedOption)
        && expectedSelectedOption >= 0
        && context.resolution.selected_option === expectedSelectedOption);

    const hasPinnedKey = isRecord(opts.principalKeys)
      && Object.hasOwn(opts.principalKeys, context.principal_key_id);
    const pin = hasPinnedKey && opts.principalKeys ? opts.principalKeys[context.principal_key_id] : null;
    const pinnedPublicKey = isRecord(pin) && typeof pin.public_key === 'string' && pin.public_key.length > 0
      ? pin.public_key
      : null;
    checks.principal_pin = pinnedPublicKey !== null
      && isRecord(pin)
      && pin.principal === context.principal;
    if (!checks.principal_pin) return refuse('principal_key_not_pinned_for_role', checks, outcome);

    const initiatorPinned = typeof opts.expectedInitiator === 'string' && opts.expectedInitiator.length > 0;
    checks.initiator_binding = opts.expectedInitiator === undefined
      ? true
      : initiatorPinned && context.initiator === opts.expectedInitiator;
    if (!checks.initiator_binding) return refuse('initiator_binding_mismatch', checks, outcome);

    const noncePinned = typeof opts.expectedNonce === 'string' && opts.expectedNonce.length > 0;
    checks.nonce_binding = opts.expectedNonce === undefined
      ? true
      : noncePinned && context.nonce === opts.expectedNonce;
    if (!checks.nonce_binding) return refuse('nonce_binding_mismatch', checks, outcome);

    const issued = parseInstant(context.issued_at);
    const expires = parseInstant(context.expires_at);
    checks.time_window = Number.isFinite(issued) && Number.isFinite(expires) && issued < expires;
    if (checks.time_window && opts.evaluationTime !== undefined) {
      const evaluation = typeof opts.evaluationTime === 'number'
        ? opts.evaluationTime
        : parseInstant(opts.evaluationTime instanceof Date
          ? opts.evaluationTime.toISOString()
          : opts.evaluationTime);
      checks.evaluation_time = Number.isFinite(evaluation) && evaluation >= issued && evaluation <= expires;
      if (!checks.evaluation_time) return refuse('resolution_outside_validity_window', checks, outcome);
    }
    if (!checks.time_window) return refuse('resolution_outside_validity_window', checks, outcome);

    checks.rp_id = typeof opts.rpId === 'string' && opts.rpId.length > 0;
    if (!checks.rp_id) return refuse('rp_id_required', checks, outcome);

    const origin = signedClientOrigin(receipt.signoff);
    checks.origin = Array.isArray(opts.allowedOrigins)
      && opts.allowedOrigins.length > 0
      && opts.allowedOrigins.every((item) => typeof item === 'string' && item.length > 0)
      && origin !== null
      && opts.allowedOrigins.includes(origin);
    if (!checks.origin) return refuse('webauthn_origin_not_allowed', checks, outcome);

    const signoff = verifyWebAuthnSignoff(receipt.signoff, pinnedPublicKey as string, {
      rpId: opts.rpId,
      allowedOrigins: opts.allowedOrigins,
    });
    checks.webauthn = signoff.valid === true;
    if (!checks.webauthn) return refuse('webauthn_verification_failed', checks, outcome);

    checks.authorization_context = checks.selected_option_binding
      && initiatorPinned
      && noncePinned
      && checks.evaluation_time;

    return {
      valid: true,
      authorizes_action: outcome === 'approved' && checks.authorization_context,
      outcome,
      requires_successor: outcome === 'amended' || outcome === 'rejected',
      checks,
    };
  } catch {
    return refuse('malformed_resolution_receipt', checks);
  }
}

export default {
  RESOLUTION_VERSION,
  RESOLUTION_CONTEXT_TYPE,
  RESOLUTION_OUTCOMES,
  computeBindingMomentHash,
  computeResolutionResponseHash,
  computeResolutionChallenge,
  verifyResolutionReceipt,
};
