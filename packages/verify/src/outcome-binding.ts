// SPDX-License-Identifier: Apache-2.0
/**
 * EP-OUTCOME-ATTESTATION-v1 + EP-OUTCOME-BINDING-v1.
 *
 * The executor signs observations only. Human-approved predictions are read
 * from the cryptographically verified Trust Receipt action. Relying-party
 * policy may add constraints; it can never replace or loosen signed intent.
 */
import crypto from 'node:crypto';
import { canonicalizeStrictJson } from './strict-json.js';
import {
  DIVERGENCE_OUTCOMES,
  MAX_EFFECT_STRING_LENGTH,
  MAX_OBSERVED_EFFECTS,
  OUTCOME_SOURCE_ROLES,
  evaluatePredictedEffects,
  predictedEffectsDigest,
  validatePredictedEffects,
} from './effect-predicates.js';
import {
  signAgileSet,
  verifyAgileSignatureSet,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  type AgileSignature,
  type AgilityOptions,
} from './pq-signature-agility.js';

type Obj = Record<string, any>;

interface OutcomeOptions {
  executorKeys?: Record<string, Obj>;
  now?: string;
  receiptOptions?: Obj;
  policyPredictedEffects?: any[];
}

interface OutcomeSetOptions extends OutcomeOptions {
  sourceKeys?: Record<string, Obj>;
  sourceRequirements?: Obj[];
  observationWindows?: Obj[];
  expectedReceiptId?: string;
  expectedReceiptDigest?: string;
  expectedActionHash?: string;
  expectedConsumptionNonce?: string;
  expectedActionCaid?: string;
  expectedOperationId?: string;
  expectedFacilityId?: string;
}

export const OUTCOME_ATTESTATION_VERSION = 'EP-OUTCOME-ATTESTATION-v1';
export const OUTCOME_ATTESTATION_DOMAIN = 'EP-OUTCOME-ATTESTATION-v1\0';
export const OUTCOME_BINDING_VERSION = 'EP-OUTCOME-BINDING-v1';
export const OUTCOME_BINDING_RESULT_VERSION = 'EP-OUTCOME-BINDING-RESULT-v1';
export const OUTCOME_OBSERVATION_VERSION = 'EP-OUTCOME-OBSERVATION-v1';
export const OUTCOME_OBSERVATION_DOMAIN = 'EP-OUTCOME-OBSERVATION-v1\0';
export const OUTCOME_BINDING_SET_VERSION = 'EP-OUTCOME-BINDING-SET-v1';
export const OUTCOME_BINDING_SET_RESULT_VERSION = 'EP-OUTCOME-BINDING-SET-RESULT-v1';

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const KEY_ID_RE = /^ep:executor-key:sha256:[0-9a-f]{64}$/;
const SOURCE_KEY_ID_RE = /^ep:outcome-source-key:sha256:[0-9a-f]{64}$/;
const RFC3339_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const TOP_KEYS = new Set([
  '@version', 'receipt_id', 'receipt_digest', 'action_hash', 'consumption_nonce', 'execution_id',
  'executor_id', 'executed_at', 'observed_effects', 'observed_effects_digest', 'proof',
]);
const PROOF_KEYS = new Set(['algorithm', 'key_id', 'public_key', 'signature_b64u']);
const OBSERVED_KEYS = new Set(['effect_type', 'target', 'value', 'values']);
const OBSERVATION_KEYS = new Set([
  '@version', 'receipt_id', 'receipt_digest', 'action_hash', 'action_caid',
  'consumption_nonce', 'operation_id', 'source', 'observed_from', 'observed_until',
  'attested_at', 'observed_effects', 'observed_effects_digest', 'proof',
]);
const SOURCE_KEYS = new Set(['role', 'source_id', 'source_class', 'facility_id']);

function canonicalize(value: unknown): string {
  return canonicalizeStrictJson(value);
}
const sha256hex = (bytes: Uint8Array): string => crypto.createHash('sha256').update(bytes).digest('hex');
const digest = (value: unknown): string => `sha256:${sha256hex(Buffer.from(canonicalize(value), 'utf8'))}`;
const safeDigest = (value: unknown): string | null => {
  try { return digest(value); } catch { return null; }
};
const normalizeDigest = (value: unknown): string | null => (
  typeof value === 'string' && /^sha256:[0-9a-f]{64}$/i.test(value)
    ? value.toLowerCase() : null
);

function exactKeys(value: unknown, allowed: Set<string>): value is Obj {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).every((key) => allowed.has(key)));
}

function strictInstantMs(value: unknown): number {
  if (typeof value !== 'string') return NaN;
  const match = value.match(RFC3339_INSTANT);
  if (!match) return NaN;
  const [, y, mo, d, h, mi, s, , oh, om] = match;
  const calendar = new Date(0);
  calendar.setUTCFullYear(Number(y), Number(mo) - 1, Number(d));
  calendar.setUTCHours(Number(h), Number(mi), Number(s), 0);
  if (calendar.toISOString().slice(0, 19) !== `${y}-${mo}-${d}T${h}:${mi}:${s}`) return NaN;
  if (oh !== undefined && (Number(oh) > 23 || Number(om) > 59)) return NaN;
  return Date.parse(value);
}

function publicKeyB64u(key: any): string {
  return crypto.createPublicKey(key).export({ type: 'spki', format: 'der' }).toString('base64url');
}

function canonicalOutcomeSourceKey(publicKey: unknown): { public_key: string; key_id: string } | null {
  if (typeof publicKey !== 'string' || !publicKey) return null;
  try {
    const key = crypto.createPublicKey({
      key: Buffer.from(publicKey, 'base64url'), format: 'der', type: 'spki',
    });
    if (key.asymmetricKeyType !== 'ed25519') return null;
    const canonical = key.export({ type: 'spki', format: 'der' }).toString('base64url');
    return {
      public_key: canonical,
      key_id: `ep:outcome-source-key:sha256:${sha256hex(Buffer.from(canonical, 'base64url'))}`,
    };
  } catch {
    return null;
  }
}

function executorKeyId(publicKey: string): string {
  return `ep:executor-key:sha256:${sha256hex(Buffer.from(publicKey, 'base64url'))}`;
}

function outcomeSourceKeyId(publicKey: string): string {
  const canonical = canonicalOutcomeSourceKey(publicKey);
  if (!canonical) throw new Error('outcome source public key must be canonical Ed25519 SPKI');
  return canonical.key_id;
}

function unsigned(attestation: Obj): Obj {
  const { proof: _proof, ...body } = attestation;
  return body;
}

function signingBytes(attestation: Obj): Buffer {
  return Buffer.from(`${OUTCOME_ATTESTATION_DOMAIN}${canonicalize(unsigned(attestation))}`, 'utf8');
}

function observationSigningBytes(observation: Obj): Buffer {
  return Buffer.from(`${OUTCOME_OBSERVATION_DOMAIN}${canonicalize(unsigned(observation))}`, 'utf8');
}

/** Digest over the exact observed_effects array carried by the attestation. */
export function observedEffectsDigest(observedEffects: unknown): string {
  return digest(observedEffects);
}

/** Digest of the exact Trust Receipt object the attestation references. */
export function trustReceiptDigest(receipt: unknown): string {
  return digest(receipt);
}

/**
 * Canonical digest preimage for an Outcome Binding verifier result.
 *
 * The core commits the exact inputs by digest, every independent binding
 * check, all refusal reasons and evaluations, the acceptance bit, and the
 * reported verdict. It deliberately excludes result_digest itself.
 */
export function outcomeBindingResultCore(result: unknown): Obj {
  const value = result && typeof result === 'object' && !Array.isArray(result)
    ? result as Obj
    : {};
  return {
    '@version': OUTCOME_BINDING_RESULT_VERSION,
    input_commitments: Object.hasOwn(value, 'input_commitments')
      ? value.input_commitments
      : null,
    exact_commitments: Object.hasOwn(value, 'commitments')
      ? value.commitments
      : Object.hasOwn(value, 'exact_commitments') ? value.exact_commitments : null,
    valid: typeof value.valid === 'boolean' ? value.valid : null,
    verdict: Object.hasOwn(value, 'verdict')
      ? value.verdict
      : typeof value.outcome_binding?.outcome === 'string'
        ? value.outcome_binding.outcome
        : null,
    checks: Object.hasOwn(value, 'checks') ? value.checks : null,
    errors: Object.hasOwn(value, 'errors') ? value.errors : null,
    outcome_binding: Object.hasOwn(value, 'outcome_binding') ? value.outcome_binding : null,
  };
}

/** sha256:<hex> over the canonical Outcome Binding result core. */
export function outcomeBindingResultDigest(result: unknown): string {
  return digest(outcomeBindingResultCore(result));
}

/**
 * Recompute and constant-time compare an Outcome Binding result digest.
 *
 * This verifies result integrity only. Call verifyOutcomeBinding to verify the
 * receipt, attestation, policy composition, and exact receipt/action/nonce
 * bindings that produced the result.
 */
export function verifyOutcomeBindingResultDigest(
  result: unknown,
  claimedDigest?: unknown,
): boolean {
  const value = result && typeof result === 'object' && !Array.isArray(result)
    ? result as Obj
    : null;
  const claimed = claimedDigest === undefined ? value?.result_digest : claimedDigest;
  if (!value || typeof claimed !== 'string' || !DIGEST_RE.test(claimed)) return false;
  try {
    const recomputed = outcomeBindingResultDigest(value);
    return crypto.timingSafeEqual(
      Buffer.from(claimed.slice('sha256:'.length), 'hex'),
      Buffer.from(recomputed.slice('sha256:'.length), 'hex'),
    );
  } catch {
    return false;
  }
}

function validateObservedEffects(observed: unknown): { ok: boolean; errors: string[] } {
  const errors: string[] = [];
  if (!Array.isArray(observed)) return { ok: false, errors: ['observed_effects must be an array'] };
  if (observed.length > MAX_OBSERVED_EFFECTS) {
    return { ok: false, errors: [`observed_effects exceeds the ${MAX_OBSERVED_EFFECTS}-entry limit`] };
  }
  observed.forEach((entry, index) => {
    const at = `observed_effects[${index}]`;
    if (!exactKeys(entry, OBSERVED_KEYS)) {
      errors.push(`${at} is not an exact observed-effect object`);
      return;
    }
    if (typeof entry.effect_type !== 'string' || !entry.effect_type
        || [...entry.effect_type].length > MAX_EFFECT_STRING_LENGTH) {
      errors.push(`${at}.effect_type is invalid`);
    }
    if (typeof entry.target !== 'string' || !entry.target
        || [...entry.target].length > MAX_EFFECT_STRING_LENGTH || entry.target.includes('*')) {
      errors.push(`${at}.target must be a bounded literal identifier`);
    }
    const hasValue = Object.hasOwn(entry, 'value');
    const hasValues = Object.hasOwn(entry, 'values');
    if (hasValue === hasValues) errors.push(`${at} must carry exactly one of value or values`);
    if (hasValue && (typeof entry.value !== 'string'
        || [...entry.value].length > MAX_EFFECT_STRING_LENGTH)) {
      errors.push(`${at}.value must be a bounded string`);
    }
    if (hasValues && (!Array.isArray(entry.values)
        || entry.values.length > MAX_OBSERVED_EFFECTS
        || !entry.values.every((v) => typeof v === 'string'
          && [...v].length <= MAX_EFFECT_STRING_LENGTH))) {
      errors.push(`${at}.values must be a bounded array of bounded strings`);
    }
  });
  return { ok: errors.length === 0, errors };
}

/**
 * Build an executor-signed observed-effects attestation.
 *
 * @param {{
 *   receipt_id?: string,
 *   receipt_digest?: string,
 *   action_hash?: string,
 *   consumption_nonce?: string,
 *   execution_id?: string,
 *   executor_id?: string,
 *   executed_at?: string,
 *   observed_effects?: Array<object>,
 *   signer?: {
 *     privateKey?: import('node:crypto').KeyObject,
 *     publicKey?: string,
 *     key_id?: string
 *   }
 * }} [args]
 */
export function buildOutcomeAttestation({
  receipt_id,
  receipt_digest,
  action_hash,
  consumption_nonce,
  execution_id,
  executor_id,
  executed_at,
  observed_effects,
  signer,
}: Obj = {}): Obj {
  const observedValidation = validateObservedEffects(observed_effects);
  if (!observedValidation.ok) throw new Error(observedValidation.errors.join('; '));
  if (typeof receipt_id !== 'string' || !receipt_id) throw new Error('receipt_id is required');
  if (!normalizeDigest(receipt_digest)) throw new Error('receipt_digest must be sha256:<64-hex>');
  if (!normalizeDigest(action_hash)) throw new Error('action_hash must be sha256:<64-hex>');
  if (typeof consumption_nonce !== 'string' || !consumption_nonce) throw new Error('consumption_nonce is required');
  if (typeof execution_id !== 'string' || !execution_id) throw new Error('execution_id is required');
  if (typeof executor_id !== 'string' || !executor_id) throw new Error('executor_id is required');
  if (!Number.isFinite(strictInstantMs(executed_at))) throw new Error('executed_at must be a strict RFC 3339 instant');
  if (!signer?.privateKey) throw new Error('signer.privateKey is required');
  const publicKey = signer.publicKey || publicKeyB64u(signer.privateKey);
  const keyId = executorKeyId(publicKey);
  if (signer.key_id !== undefined && signer.key_id !== keyId) {
    throw new Error('signer.key_id does not match signer public key');
  }
  const body = {
    '@version': OUTCOME_ATTESTATION_VERSION,
    receipt_id,
    receipt_digest: normalizeDigest(receipt_digest),
    action_hash: normalizeDigest(action_hash),
    consumption_nonce,
    execution_id,
    executor_id,
    executed_at,
    observed_effects,
    observed_effects_digest: observedEffectsDigest(observed_effects),
  };
  return {
    ...body,
    proof: {
      algorithm: 'Ed25519',
      key_id: keyId,
      public_key: publicKey,
      signature_b64u: crypto.sign(null, signingBytes(body), signer.privateKey).toString('base64url'),
    },
  };
}

/**
 * Verify the executor attestation under a relying-party-pinned executor key.
 *
 * @param {object} attestation
 * @param {{
 *   executorKeys?: Record<string, {public_key?: string, key_id?: string}>,
 *   now?: string
 * }} [opts]
 */
export function verifyOutcomeAttestation(attestation: Obj, opts: OutcomeOptions = {}) {
  opts = opts && typeof opts === 'object' ? opts : {};
  const executorKeys = opts.executorKeys && typeof opts.executorKeys === 'object'
    ? opts.executorKeys
    : {};
  const { now } = opts;
  const checks: Record<string, boolean> = {
    structure: false,
    observation_digest: false,
    executor_key_pinned: false,
    signature: false,
    execution_time: false,
  };
  const errors: string[] = [];
  const out = () => ({ valid: Object.values(checks).every(Boolean), checks, errors });
  try {
    canonicalize(attestation);
  } catch {
    errors.push('malformed_outcome_attestation: outside canonical JSON domain');
    return out();
  }
  if (!exactKeys(attestation, TOP_KEYS)
      || attestation?.['@version'] !== OUTCOME_ATTESTATION_VERSION
      || typeof attestation.receipt_id !== 'string' || !attestation.receipt_id
      || !normalizeDigest(attestation.receipt_digest)
      || !normalizeDigest(attestation.action_hash)
      || typeof attestation.consumption_nonce !== 'string' || !attestation.consumption_nonce
      || typeof attestation.execution_id !== 'string' || !attestation.execution_id
      || typeof attestation.executor_id !== 'string' || !attestation.executor_id
      || !DIGEST_RE.test(attestation.observed_effects_digest || '')
      || !exactKeys(attestation.proof, PROOF_KEYS)
      || attestation.proof.algorithm !== 'Ed25519'
      || !KEY_ID_RE.test(attestation.proof.key_id || '')
      || typeof attestation.proof.public_key !== 'string'
      || typeof attestation.proof.signature_b64u !== 'string') {
    errors.push('malformed_outcome_attestation');
    return out();
  }
  const observedValidation = validateObservedEffects(attestation.observed_effects);
  if (!observedValidation.ok) {
    errors.push(...observedValidation.errors);
    return out();
  }
  checks.structure = true;

  checks.observation_digest = observedEffectsDigest(attestation.observed_effects)
    === attestation.observed_effects_digest;
  if (!checks.observation_digest) errors.push('observed_effects_digest_mismatch');

  const derivedKeyId = executorKeyId(attestation.proof.public_key);
  const pin = executorKeys[attestation.executor_id];
  checks.executor_key_pinned = derivedKeyId === attestation.proof.key_id
    && pin?.public_key === attestation.proof.public_key
    && (pin.key_id === undefined || pin.key_id === derivedKeyId);
  if (!checks.executor_key_pinned) errors.push('executor_key_not_pinned');

  if (checks.executor_key_pinned) {
    try {
      const key = crypto.createPublicKey({
        key: Buffer.from(/** @type {string} */ (pin.public_key), 'base64url'), format: 'der', type: 'spki',
      });
      checks.signature = key.asymmetricKeyType === 'ed25519'
        && crypto.verify(
          null,
          signingBytes(attestation),
          key,
          Buffer.from(attestation.proof.signature_b64u, 'base64url'),
        );
    } catch {
      checks.signature = false;
    }
  }
  if (!checks.signature) errors.push('executor_signature_invalid');

  const executedAt = strictInstantMs(attestation.executed_at);
  const nowMs = now === undefined ? Date.now() : strictInstantMs(now);
  checks.execution_time = Number.isFinite(executedAt)
    && Number.isFinite(nowMs)
    && executedAt <= nowMs;
  if (!checks.execution_time) errors.push('execution_time_invalid_or_future');
  return out();
}

/** Build a signed observation from an executor, system of record, or independent observer. */
export function buildOutcomeObservation({
  receipt_id,
  receipt_digest,
  action_hash,
  action_caid,
  consumption_nonce,
  operation_id,
  source,
  observed_from,
  observed_until,
  attested_at,
  observed_effects,
  signer,
}: Obj = {}): Obj {
  const observedValidation = validateObservedEffects(observed_effects);
  if (!observedValidation.ok) throw new Error(observedValidation.errors.join('; '));
  if (typeof receipt_id !== 'string' || !receipt_id) throw new Error('receipt_id is required');
  if (!normalizeDigest(receipt_digest)) throw new Error('receipt_digest must be sha256:<64-hex>');
  if (!normalizeDigest(action_hash)) throw new Error('action_hash must be sha256:<64-hex>');
  if (action_caid !== undefined && (typeof action_caid !== 'string' || !action_caid)) {
    throw new Error('action_caid must be a non-empty string when present');
  }
  if (typeof consumption_nonce !== 'string' || !consumption_nonce) throw new Error('consumption_nonce is required');
  if (typeof operation_id !== 'string' || !operation_id) throw new Error('operation_id is required');
  if (!exactKeys(source, SOURCE_KEYS)
      || !OUTCOME_SOURCE_ROLES.includes(source.role)
      || typeof source.source_id !== 'string' || !source.source_id
      || typeof source.source_class !== 'string' || !source.source_class
      || (source.facility_id !== undefined
        && (typeof source.facility_id !== 'string' || !source.facility_id))) {
    throw new Error('source must carry a closed role, source_id, source_class, and optional facility_id');
  }
  const fromMs = strictInstantMs(observed_from);
  const untilMs = strictInstantMs(observed_until);
  const attestedMs = strictInstantMs(attested_at);
  if (![fromMs, untilMs, attestedMs].every(Number.isFinite)
      || fromMs > untilMs || untilMs > attestedMs) {
    throw new Error('observation timestamps must be strict RFC 3339 instants ordered observed_from <= observed_until <= attested_at');
  }
  if (!signer?.privateKey) throw new Error('signer.privateKey is required');
  const publicKey = signer.publicKey || publicKeyB64u(signer.privateKey);
  const keyId = outcomeSourceKeyId(publicKey);
  if (signer.key_id !== undefined && signer.key_id !== keyId) {
    throw new Error('signer.key_id does not match signer public key');
  }
  const body: Obj = {
    '@version': OUTCOME_OBSERVATION_VERSION,
    receipt_id,
    receipt_digest: normalizeDigest(receipt_digest),
    action_hash: normalizeDigest(action_hash),
    ...(action_caid === undefined ? {} : { action_caid }),
    consumption_nonce,
    operation_id,
    source,
    observed_from,
    observed_until,
    attested_at,
    observed_effects,
    observed_effects_digest: observedEffectsDigest(observed_effects),
  };
  return {
    ...body,
    proof: {
      algorithm: 'Ed25519',
      key_id: keyId,
      public_key: publicKey,
      signature_b64u: crypto.sign(null, observationSigningBytes(body), signer.privateKey).toString('base64url'),
    },
  };
}

/** Verify one signed outcome observation under a relying-party-pinned source identity. */
export function verifyOutcomeObservation(observation: Obj, opts: OutcomeSetOptions = {}) {
  const sourceKeys = opts.sourceKeys && typeof opts.sourceKeys === 'object' ? opts.sourceKeys : {};
  const checks: Record<string, boolean> = {
    structure: false,
    observation_digest: false,
    source_key_pinned: false,
    source_metadata_pinned: false,
    source_key_current: false,
    signature: false,
    observation_time: false,
  };
  const errors: string[] = [];
  const out = () => ({ valid: Object.values(checks).every(Boolean), checks, errors });
  try {
    canonicalize(observation);
  } catch {
    errors.push('malformed_outcome_observation: outside canonical JSON domain');
    return out();
  }
  if (!exactKeys(observation, OBSERVATION_KEYS)
      || observation?.['@version'] !== OUTCOME_OBSERVATION_VERSION
      || typeof observation.receipt_id !== 'string' || !observation.receipt_id
      || !normalizeDigest(observation.receipt_digest)
      || !normalizeDigest(observation.action_hash)
      || (observation.action_caid !== undefined
        && (typeof observation.action_caid !== 'string' || !observation.action_caid))
      || typeof observation.consumption_nonce !== 'string' || !observation.consumption_nonce
      || typeof observation.operation_id !== 'string' || !observation.operation_id
      || !exactKeys(observation.source, SOURCE_KEYS)
      || !OUTCOME_SOURCE_ROLES.includes(observation.source?.role)
      || typeof observation.source?.source_id !== 'string' || !observation.source.source_id
      || typeof observation.source?.source_class !== 'string' || !observation.source.source_class
      || (observation.source?.facility_id !== undefined
        && (typeof observation.source.facility_id !== 'string' || !observation.source.facility_id))
      || !DIGEST_RE.test(observation.observed_effects_digest || '')
      || !exactKeys(observation.proof, PROOF_KEYS)
      || observation.proof.algorithm !== 'Ed25519'
      || !SOURCE_KEY_ID_RE.test(observation.proof.key_id || '')
      || typeof observation.proof.public_key !== 'string'
      || typeof observation.proof.signature_b64u !== 'string') {
    errors.push('malformed_outcome_observation');
    return out();
  }
  const observedValidation = validateObservedEffects(observation.observed_effects);
  if (!observedValidation.ok) {
    errors.push(...observedValidation.errors);
    return out();
  }
  checks.structure = true;
  checks.observation_digest = observedEffectsDigest(observation.observed_effects)
    === observation.observed_effects_digest;
  if (!checks.observation_digest) errors.push('observed_effects_digest_mismatch');

  const observationKey = canonicalOutcomeSourceKey(observation.proof.public_key);
  const pin = sourceKeys[observation.source.source_id];
  const pinnedKey = canonicalOutcomeSourceKey(pin?.public_key);
  checks.source_key_pinned = observationKey !== null
    && pinnedKey !== null
    && observationKey.key_id === observation.proof.key_id
    && pinnedKey.key_id === observationKey.key_id
    && (pin.key_id === undefined || pin.key_id === observationKey.key_id);
  if (!checks.source_key_pinned) errors.push('outcome_source_key_not_pinned');
  checks.source_metadata_pinned = pin?.role === observation.source.role
    && pin?.source_class === observation.source.source_class
    && (pin.facility_id === undefined || pin.facility_id === observation.source.facility_id);
  if (!checks.source_metadata_pinned) errors.push('outcome_source_metadata_not_pinned');

  if (checks.source_key_pinned && checks.source_metadata_pinned) {
    try {
      const key = crypto.createPublicKey({
        key: Buffer.from(pinnedKey!.public_key, 'base64url'), format: 'der', type: 'spki',
      });
      checks.signature = key.asymmetricKeyType === 'ed25519'
        && crypto.verify(
          null,
          observationSigningBytes(observation),
          key,
          Buffer.from(observation.proof.signature_b64u, 'base64url'),
        );
    } catch {
      checks.signature = false;
    }
  }
  if (!checks.signature) errors.push('outcome_source_signature_invalid');

  const fromMs = strictInstantMs(observation.observed_from);
  const untilMs = strictInstantMs(observation.observed_until);
  const attestedMs = strictInstantMs(observation.attested_at);
  const nowMs = opts.now === undefined ? Date.now() : strictInstantMs(opts.now);
  checks.observation_time = [fromMs, untilMs, attestedMs, nowMs].every(Number.isFinite)
    && fromMs <= untilMs && untilMs <= attestedMs && attestedMs <= nowMs;
  if (!checks.observation_time) errors.push('observation_time_invalid_or_future');

  const validFromMs = strictInstantMs(pin?.valid_from);
  const validToMs = strictInstantMs(pin?.valid_to);
  const status = pin?.status;
  const compromisedAtMs = pin?.compromised_at === undefined
    ? NaN : strictInstantMs(pin.compromised_at);
  const statusShapeValid = status === 'active' || status === 'retired' || status === 'compromised';
  const compromiseShapeValid = status === 'compromised'
    ? Number.isFinite(compromisedAtMs)
    : pin?.compromised_at === undefined;
  checks.source_key_current = statusShapeValid
    && compromiseShapeValid
    && [validFromMs, validToMs, attestedMs].every(Number.isFinite)
    && validFromMs <= attestedMs
    && attestedMs <= validToMs
    && (status !== 'compromised' || attestedMs < compromisedAtMs);
  if (!checks.source_key_current) errors.push('outcome_source_key_not_current');
  return out();
}

function sourceSelector(prediction: Obj): { role: string; source_class: string | null } {
  return {
    role: prediction.required_source_role || 'executor',
    source_class: prediction.required_source_class || null,
  };
}

function selectorKey(selector: { role: string; source_class: string | null }): string {
  return `${selector.role}\0${selector.source_class || ''}`;
}

export function outcomeBindingSetResultDigest(result: unknown): string {
  const value = result && typeof result === 'object' && !Array.isArray(result) ? result as Obj : {};
  const { result_digest: _resultDigest, ...core } = value;
  return digest({ '@version': OUTCOME_BINDING_SET_RESULT_VERSION, ...core });
}

/**
 * Verify, route, and reconcile a set of signed source observations against
 * signed predictions. This function is authorization-format neutral; callers
 * must separately verify and bind the authorization artifact itself.
 */
export function verifyOutcomeObservationSet(
  predictedEffects: any[],
  observations: Obj[],
  opts: OutcomeSetOptions = {},
): Obj {
  const checks: Record<string, boolean> = {
    predictions_valid: false,
    observations_verified: false,
    exact_bindings: false,
    required_sources_present: false,
    source_independence: false,
    source_requirements: false,
    observation_windows: false,
  };
  const errors: string[] = [];
  const predictionValidation = validatePredictedEffects(predictedEffects);
  checks.predictions_valid = predictionValidation.ok;
  if (!checks.predictions_valid) errors.push(...predictionValidation.reasons);
  if (!Array.isArray(observations) || observations.length === 0) {
    errors.push('outcome_observations_missing');
  }

  const observation_results = Array.isArray(observations)
    ? observations.map((observation) => verifyOutcomeObservation(observation, opts))
    : [];
  checks.observations_verified = observation_results.length > 0
    && observation_results.every((result) => result.valid);
  observation_results.forEach((result, index) => {
    if (!result.valid) errors.push(...result.errors.map((reason) => `observation[${index}]: ${reason}`));
  });

  const first = observations?.[0];
  checks.exact_bindings = checks.observations_verified
    && observations.every((observation) => (
      observation.receipt_id === first.receipt_id
      && normalizeDigest(observation.receipt_digest) === normalizeDigest(first.receipt_digest)
      && normalizeDigest(observation.action_hash) === normalizeDigest(first.action_hash)
      && observation.action_caid === first.action_caid
      && observation.consumption_nonce === first.consumption_nonce
      && observation.operation_id === first.operation_id
      && (opts.expectedReceiptId === undefined || observation.receipt_id === opts.expectedReceiptId)
      && (opts.expectedReceiptDigest === undefined
        || normalizeDigest(observation.receipt_digest) === normalizeDigest(opts.expectedReceiptDigest))
      && (opts.expectedActionHash === undefined
        || normalizeDigest(observation.action_hash) === normalizeDigest(opts.expectedActionHash))
      && (opts.expectedConsumptionNonce === undefined
        || observation.consumption_nonce === opts.expectedConsumptionNonce)
      && (opts.expectedActionCaid === undefined || observation.action_caid === opts.expectedActionCaid)
      && (opts.expectedOperationId === undefined || observation.operation_id === opts.expectedOperationId)
      && (opts.expectedFacilityId === undefined || observation.source.facility_id === opts.expectedFacilityId)
    ));
  if (!checks.exact_bindings) errors.push('outcome_observations_not_exactly_bound');

  const grouped = new Map<string, { selector: { role: string; source_class: string | null }; predictions: Obj[] }>();
  if (checks.predictions_valid) {
    for (const prediction of predictedEffects) {
      const selector = sourceSelector(prediction);
      const key = selectorKey(selector);
      const group = grouped.get(key) || { selector, predictions: [] };
      group.predictions.push(prediction);
      grouped.set(key, group);
    }
  }
  const missing_sources: Obj[] = [];
  const evaluations: Obj[] = [];
  if (checks.observations_verified && checks.exact_bindings) {
    for (const { selector, predictions } of grouped.values()) {
      const matches = observations.filter((observation) => (
        observation.source.role === selector.role
        && (selector.source_class === null || observation.source.source_class === selector.source_class)
      ));
      if (matches.length === 0) {
        missing_sources.push(selector);
        continue;
      }
      for (const observation of matches) {
        evaluations.push({
          source: observation.source,
          ...evaluatePredictedEffects(predictions, observation.observed_effects),
        });
      }
    }
  }
  checks.required_sources_present = checks.predictions_valid
    && grouped.size > 0 && missing_sources.length === 0;
  missing_sources.forEach((selector) => errors.push(
    `required_outcome_source_missing:${selector.role}:${selector.source_class || '*'}`,
  ));

  const verifiedObservations = checks.observations_verified ? observations : [];
  const sourcePins = opts.sourceKeys && typeof opts.sourceKeys === 'object' ? opts.sourceKeys : {};
  let sourceIndependence = true;
  const independent = verifiedObservations.filter((item) => item.source.role === 'independent_observer');
  const nonIndependent = verifiedObservations.filter((item) => item.source.role !== 'independent_observer');
  for (const observer of independent) {
    const observerPin = sourcePins[observer.source.source_id];
    const observerKey = canonicalOutcomeSourceKey(observerPin?.public_key);
    const observerDomain = observerPin?.control_domain_id;
    if (typeof observerDomain !== 'string' || !observerDomain) {
      sourceIndependence = false;
      errors.push(`independent_source_control_domain_missing:${observer.source.source_id}`);
      continue;
    }
    for (const other of nonIndependent) {
      const otherPin = sourcePins[other.source.source_id];
      const otherKey = canonicalOutcomeSourceKey(otherPin?.public_key);
      const otherDomain = otherPin?.control_domain_id;
      if (observerKey && otherKey && observerKey.key_id === otherKey.key_id) {
        sourceIndependence = false;
        errors.push(`independent_source_key_reused:${observer.source.source_id}:${other.source.source_id}`);
      }
      if (typeof otherDomain !== 'string' || !otherDomain) {
        sourceIndependence = false;
        errors.push(`source_control_domain_missing:${other.source.source_id}`);
      } else if (observerDomain === otherDomain) {
        sourceIndependence = false;
        errors.push(`independent_control_domain_reused:${observer.source.source_id}:${other.source.source_id}`);
      }
    }
  }
  checks.source_independence = checks.observations_verified && sourceIndependence;

  const requirements = opts.sourceRequirements === undefined ? [] : opts.sourceRequirements;
  let requirementsValid = Array.isArray(requirements);
  if (!requirementsValid) errors.push('outcome_source_requirements_malformed');
  if (requirementsValid) {
    for (const requirement of requirements) {
      const role = requirement?.role;
      const sourceClass = requirement?.source_class;
      const minimum = requirement?.min_distinct_sources ?? 1;
      const distinctBy = requirement?.distinct_by ?? ['key'];
      const allowedSourceIds = requirement?.source_ids;
      const shapeValid = requirement && typeof requirement === 'object' && !Array.isArray(requirement)
        && Object.keys(requirement).every((key) => [
          'role', 'source_class', 'min_distinct_sources', 'distinct_by', 'source_ids',
        ].includes(key))
        && OUTCOME_SOURCE_ROLES.includes(role)
        && (sourceClass === undefined || (typeof sourceClass === 'string' && sourceClass.length > 0))
        && Number.isInteger(minimum) && minimum >= 1 && minimum <= 16
        && Array.isArray(distinctBy) && distinctBy.length > 0
        && distinctBy.every((value) => value === 'key' || value === 'control_domain')
        && new Set(distinctBy).size === distinctBy.length
        && (allowedSourceIds === undefined || (Array.isArray(allowedSourceIds)
          && allowedSourceIds.length > 0
          && allowedSourceIds.every((value) => typeof value === 'string' && value.length > 0)
          && new Set(allowedSourceIds).size === allowedSourceIds.length));
      if (!shapeValid) {
        requirementsValid = false;
        errors.push('outcome_source_requirement_malformed');
        continue;
      }
      const matches = verifiedObservations.filter((observation) => (
        observation.source.role === role
        && (sourceClass === undefined || observation.source.source_class === sourceClass)
        && (allowedSourceIds === undefined || allowedSourceIds.includes(observation.source.source_id))
      ));
      const sourceIds = new Set(matches.map((item) => item.source.source_id));
      const dimensionsValid = distinctBy.every((dimension) => {
        const values = matches.map((item) => {
          const pin = sourcePins[item.source.source_id];
          return dimension === 'key'
            ? canonicalOutcomeSourceKey(pin?.public_key)?.key_id
            : pin?.control_domain_id;
        });
        return values.every((value) => typeof value === 'string' && value.length > 0)
          && new Set(values).size === values.length;
      });
      if (sourceIds.size < minimum || !dimensionsValid) {
        requirementsValid = false;
        errors.push(`outcome_source_quorum_not_met:${role}:${sourceClass || '*'}:${minimum}`);
      }
    }
  }
  checks.source_requirements = checks.observations_verified && requirementsValid;

  const windows = opts.observationWindows === undefined ? [] : opts.observationWindows;
  let windowsValid = Array.isArray(windows);
  if (!windowsValid) errors.push('outcome_observation_windows_malformed');
  if (windowsValid) {
    for (const window of windows) {
      const notBeforeMs = strictInstantMs(window?.not_before);
      const notAfterMs = strictInstantMs(window?.not_after);
      const maximumDelay = window?.max_attestation_delay_ms;
      const sourceClass = window?.source_class;
      const shapeValid = window && typeof window === 'object' && !Array.isArray(window)
        && Object.keys(window).every((key) => [
          'role', 'source_class', 'relation', 'not_before', 'not_after', 'max_attestation_delay_ms',
        ].includes(key))
        && OUTCOME_SOURCE_ROLES.includes(window.role)
        && (sourceClass === undefined || (typeof sourceClass === 'string' && sourceClass.length > 0))
        && ['exact', 'within', 'covers'].includes(window.relation)
        && [notBeforeMs, notAfterMs].every(Number.isFinite) && notBeforeMs <= notAfterMs
        && (maximumDelay === undefined
          || (Number.isInteger(maximumDelay) && maximumDelay >= 0 && maximumDelay <= 86_400_000));
      if (!shapeValid) {
        windowsValid = false;
        errors.push('outcome_observation_window_requirement_malformed');
        continue;
      }
      const matches = verifiedObservations.filter((observation) => (
        observation.source.role === window.role
        && (sourceClass === undefined || observation.source.source_class === sourceClass)
      ));
      if (matches.length === 0) {
        windowsValid = false;
        errors.push(`outcome_observation_window_source_missing:${window.role}:${sourceClass || '*'}`);
        continue;
      }
      for (const observation of matches) {
        const fromMs = strictInstantMs(observation.observed_from);
        const untilMs = strictInstantMs(observation.observed_until);
        const attestedMs = strictInstantMs(observation.attested_at);
        const relationValid = window.relation === 'exact'
          ? fromMs === notBeforeMs && untilMs === notAfterMs
          : window.relation === 'within'
            ? fromMs >= notBeforeMs && untilMs <= notAfterMs
            : fromMs <= notBeforeMs && untilMs >= notAfterMs;
        if (!relationValid) {
          windowsValid = false;
          errors.push(`outcome_observation_window_mismatch:${observation.source.source_id}`);
        }
        if (maximumDelay !== undefined && attestedMs - untilMs > maximumDelay) {
          windowsValid = false;
          errors.push(`outcome_observation_attestation_stale:${observation.source.source_id}`);
        }
      }
    }
  }
  checks.observation_windows = checks.observations_verified && windowsValid;

  const lifecycle_state = Object.values(checks).every(Boolean) ? 'reconciled' : 'indeterminate';
  const outcome = lifecycle_state === 'reconciled'
    ? evaluations.some((item) => item.outcome === 'divergent') ? 'divergent'
      : evaluations.some((item) => item.outcome === 'incomparable') ? 'incomparable'
        : 'in_bounds'
    : null;
  const result: Obj = {
    '@version': OUTCOME_BINDING_SET_RESULT_VERSION,
    valid: lifecycle_state === 'reconciled' && outcome === 'in_bounds',
    lifecycle_state,
    outcome,
    checks,
    errors,
    prediction_commitment: safeDigest(predictedEffects),
    observation_commitments: Array.isArray(observations) ? observations.map(safeDigest) : [],
    exact_binding: first ? {
      receipt_id: first.receipt_id,
      receipt_digest: normalizeDigest(first.receipt_digest),
      action_hash: normalizeDigest(first.action_hash),
      action_caid: first.action_caid || null,
      consumption_nonce: first.consumption_nonce,
      operation_id: first.operation_id,
    } : null,
    missing_sources,
    observation_results,
    evaluations,
  };
  return { ...result, result_digest: outcomeBindingSetResultDigest(result) };
}

/** Verify a Trust Receipt and then reconcile all required signed outcome sources. */
export function verifyOutcomeBindingSetCore(
  receipt: Obj,
  observations: Obj[],
  opts: OutcomeSetOptions = {},
  verifyReceipt: any,
): Obj {
  let receipt_result: any = null;
  try {
    receipt_result = typeof verifyReceipt === 'function'
      ? verifyReceipt(receipt, opts.receiptOptions || {})
      : null;
  } catch {
    receipt_result = null;
  }
  const signedPredictions = receipt?.action?.predicted_effects;
  const predictionDigestBound = Array.isArray(signedPredictions)
    && normalizeDigest(receipt?.action?.predicted_effects_digest)
      === normalizeDigest(predictedEffectsDigest(signedPredictions));
  const base = verifyOutcomeObservationSet(
    Array.isArray(signedPredictions) ? signedPredictions : [],
    observations,
    opts,
  );
  const receiptDigest = safeDigest(receipt);
  const receiptBound = Array.isArray(observations) && observations.length > 0
    && observations.every((observation) => (
      observation.receipt_id === receipt?.receipt_id
      && normalizeDigest(observation.receipt_digest) === normalizeDigest(receiptDigest)
      && normalizeDigest(observation.action_hash) === normalizeDigest(receipt?.action_hash)
      && observation.consumption_nonce === receipt?.consumption?.nonce
    ));
  const checks = {
    receipt_verified: receipt_result?.valid === true,
    signed_predictions_bound: predictionDigestBound,
    observations_bound_to_receipt: receiptBound,
    observation_set_reconciled: base.lifecycle_state === 'reconciled',
  };
  const errors = [
    ...base.errors,
    ...(checks.receipt_verified ? [] : ['receipt_verification_failed']),
    ...(checks.signed_predictions_bound ? [] : ['signed_predictions_missing_or_mismatched']),
    ...(checks.observations_bound_to_receipt ? [] : ['observations_not_bound_to_verified_receipt']),
  ];
  const lifecycle_state = Object.values(checks).every(Boolean) ? 'reconciled' : 'indeterminate';
  const result: Obj = {
    '@version': OUTCOME_BINDING_SET_VERSION,
    valid: lifecycle_state === 'reconciled' && base.outcome === 'in_bounds',
    lifecycle_state,
    outcome: lifecycle_state === 'reconciled' ? base.outcome : null,
    checks,
    errors,
    receipt_result,
    observation_set: base,
  };
  return { ...result, result_digest: outcomeBindingSetResultDigest(result) };
}

function combineEvaluations(signed: Obj, policy: Obj | null): Obj {
  const evaluations: Obj[] = [
    { source: 'signed_receipt', ...signed },
    ...(policy ? [{ source: 'relying_party_policy', ...policy }] : []),
  ];
  const outcome = evaluations.some((item) => item.outcome === 'divergent') ? 'divergent'
    : evaluations.some((item) => item.outcome === 'incomparable') ? 'incomparable'
      : 'in_bounds';
  return {
    '@version': OUTCOME_BINDING_VERSION,
    outcome,
    evaluations,
    reasons: evaluations.flatMap((item) => (item.reasons as string[]).map((reason: string) => `${item.source}: ${reason}`)),
  };
}

/**
 * Core composition. `verifyReceipt` must perform the full Trust Receipt
 * cryptographic verification; the main package export injects
 * verifyTrustReceipt. This shape keeps the module independently testable.
 */
export function verifyOutcomeBindingCore(
  receipt: Obj,
  attestation: Obj,
  opts: OutcomeOptions = {},
  verifyReceipt: any,
) {
  opts = opts && typeof opts === 'object' ? opts : {};
  let receiptCanonical = true;
  let attestationCanonical = true;
  try { canonicalize(receipt); } catch { receiptCanonical = false; receipt = {}; }
  try { canonicalize(attestation); } catch { attestationCanonical = false; attestation = {}; }
  const checks: Record<string, boolean> = {
    receipt_verified: false,
    signed_predictions: false,
    receipt_bound: false,
    receipt_digest_bound: false,
    action_bound: false,
    consumption_bound: false,
    attestation_verified: false,
  };
  const errors: string[] = [];
  let receiptResult: any = null;
  let attestationResult: any = null;
  const exactCommitments = () => ({
    receipt_id: typeof receipt?.receipt_id === 'string' ? receipt.receipt_id : null,
    attested_receipt_id: typeof attestation?.receipt_id === 'string'
      ? attestation.receipt_id : null,
    receipt_digest: safeDigest(receipt),
    attested_receipt_digest: normalizeDigest(attestation?.receipt_digest),
    action_hash: normalizeDigest(receipt?.action_hash),
    attested_action_hash: normalizeDigest(attestation?.action_hash),
    consumption_nonce: typeof receipt?.consumption?.nonce === 'string'
      ? receipt.consumption.nonce : null,
    attested_consumption_nonce: typeof attestation?.consumption_nonce === 'string'
      ? attestation.consumption_nonce : null,
    execution_id: typeof attestation?.execution_id === 'string' ? attestation.execution_id : null,
    executor_id: typeof attestation?.executor_id === 'string' ? attestation.executor_id : null,
    executor_key_id: typeof attestation?.proof?.key_id === 'string'
      ? attestation.proof.key_id : null,
    observed_effects_digest: normalizeDigest(attestation?.observed_effects_digest),
  });
  const inputCommitments = () => ({
    receipt_digest: safeDigest(receipt),
    attestation_digest: safeDigest(attestation),
    signed_predictions_digest: safeDigest(receipt?.action?.predicted_effects),
    signed_predictions_commitment: normalizeDigest(receipt?.action?.predicted_effects_digest),
    policy_predictions_present: Object.hasOwn(opts, 'policyPredictedEffects'),
    policy_predictions_digest: Object.hasOwn(opts, 'policyPredictedEffects')
      ? safeDigest(opts.policyPredictedEffects)
      : null,
  });
  const refuse = (reason: string) => {
    errors.push(reason);
    const outcome_binding = {
      '@version': OUTCOME_BINDING_VERSION,
      outcome: 'incomparable',
      evaluations: [],
      reasons: [...errors],
    };
    const result = {
      valid: false,
      checks,
      errors,
      input_commitments: inputCommitments(),
      receipt,
      attestation,
      commitments: exactCommitments(),
      receipt_result: receiptResult,
      attestation_result: attestationResult,
      outcome_binding,
    };
    return {
      ...result,
      result_digest: outcomeBindingResultDigest(result),
    };
  };
  if (!receiptCanonical) return refuse('receipt_not_canonical_json');
  if (!attestationCanonical) return refuse('attestation_not_canonical_json');
  if (typeof verifyReceipt !== 'function') return refuse('receipt_verifier_required');
  try {
    receiptResult = verifyReceipt(receipt, opts.receiptOptions || {});
  } catch {
    return refuse('receipt_verifier_failed');
  }
  checks.receipt_verified = receiptResult?.valid === true;
  if (!checks.receipt_verified) return refuse('receipt_verification_failed');

  const signedPredictions = receipt?.action?.predicted_effects;
  const boundPredictionDigest = receipt?.action?.predicted_effects_digest;
  const predictionValidation = validatePredictedEffects(signedPredictions);
  checks.signed_predictions = predictionValidation.ok
    && normalizeDigest(boundPredictionDigest) === normalizeDigest(predictedEffectsDigest(signedPredictions));
  if (!checks.signed_predictions) return refuse('signed_predictions_missing_or_mismatched');
  if (Object.hasOwn(opts, 'policyPredictedEffects')
      && !Array.isArray(opts.policyPredictedEffects)) {
    return refuse('policy_predictions_present_but_not_array');
  }
  if (Array.isArray(opts.policyPredictedEffects)) {
    const policyValidation = validatePredictedEffects(opts.policyPredictedEffects);
    if (!policyValidation.ok) {
      errors.push(...policyValidation.reasons.map((reason) => `relying_party_policy: ${reason}`));
      return refuse('policy_predictions_malformed');
    }
  }

  attestationResult = verifyOutcomeAttestation(attestation, {
    executorKeys: opts.executorKeys || {},
    now: opts.now,
  });
  checks.attestation_verified = attestationResult.valid;
  if (!checks.attestation_verified) {
    errors.push(...attestationResult.errors);
    return refuse('outcome_attestation_verification_failed');
  }

  checks.receipt_bound = attestation.receipt_id === receipt.receipt_id;
  checks.receipt_digest_bound = normalizeDigest(attestation.receipt_digest)
    === normalizeDigest(trustReceiptDigest(receipt));
  checks.action_bound = normalizeDigest(attestation.action_hash) === normalizeDigest(receipt.action_hash);
  checks.consumption_bound = typeof receipt?.consumption?.nonce === 'string'
    && attestation.consumption_nonce === receipt.consumption.nonce;
  if (!checks.receipt_bound) errors.push('receipt_id_mismatch');
  if (!checks.receipt_digest_bound) errors.push('receipt_digest_mismatch');
  if (!checks.action_bound) errors.push('action_hash_mismatch');
  if (!checks.consumption_bound) errors.push('consumption_nonce_mismatch');
  if (!checks.receipt_bound || !checks.receipt_digest_bound
      || !checks.action_bound || !checks.consumption_bound) {
    return refuse('attestation_not_bound_to_verified_receipt');
  }

  const signedEvaluation = evaluatePredictedEffects(
    signedPredictions,
    attestation.observed_effects,
  );
  const policyEvaluation = Array.isArray(opts.policyPredictedEffects)
    ? evaluatePredictedEffects(opts.policyPredictedEffects, attestation.observed_effects)
    : null;
  const outcome_binding = combineEvaluations(signedEvaluation, policyEvaluation);
  const valid = Object.values(checks).every(Boolean)
    && outcome_binding.outcome === 'in_bounds';
  const result = {
    valid,
    checks,
    errors: [...errors, ...outcome_binding.reasons],
    input_commitments: inputCommitments(),
    receipt,
    attestation,
    commitments: exactCommitments(),
    receipt_result: receiptResult,
    attestation_result: attestationResult,
    outcome_binding,
  };
  return {
    ...result,
    result_digest: outcomeBindingResultDigest(result),
  };
}

// ===========================================================================
// EP-OUTCOME-ATTESTATION-v2 / EP-OUTCOME-OBSERVATION-v2 -- hybrid
// (Ed25519 + ML-DSA-65)
// ===========================================================================
/**
 * Reference hybrid migration for both signed artifacts in this file. Copies
 * the five moves from EP-REVOCATION-v2 (packages/verify/src/revocation.ts):
 *
 * 1. VERSION BUMP. `@version` moves -v1 to -v2 for each artifact.
 *    verifyOutcomeAttestation/verifyOutcomeObservation above are UNCHANGED
 *    and refuse a v2 artifact on the `@version` marker (via `exactKeys`
 *    against the unchanged v1 key sets, since `required_algorithms` is not a
 *    v1 field) before any signature is inspected.
 * 2. SET SHAPE. `proof.signatures` carries exactly the two AgileSignature
 *    entries ({alg, sig, key_id}) for Ed25519 and ML-DSA-65, reusing
 *    EP-SIG-AGILITY-v1's shape verbatim.
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` is a TOP-LEVEL field of the
 *    artifact (inside the signed bytes via the existing `unsigned()` helper,
 *    which strips only `proof`), independently recomputed from the
 *    registered set.
 * 4. V1 COMPATIBILITY. v1 artifacts keep verifying, unchanged, through the
 *    sync functions above. v2 verification is a separate ASYNC entry point.
 * 5. NAMED REFUSALS. Nothing throws on caller input; a missing ML-DSA backend
 *    is 'pq_backend_unavailable' from the agility module, never a pass on the
 *    Ed25519 leg alone.
 *
 * SCOPE BOUNDARY: only the two SIGNED leaves (executor attestation, source
 * observation) are hybridized here. verifyOutcomeObservationSet /
 * verifyOutcomeBindingCore / verifyOutcomeBindingSetCore are COMPOSITIONS
 * that reconcile predictions against already-verified observations; they
 * take a caller-injected verifyReceipt and operate on whichever version's
 * verify* function opts route to. Rewiring those compositions to accept a
 * mixed v1/v2 observation bag is a separate, larger change left to the
 * receipt-issuance hybridization workstream (packages/issue,
 * packages/verify/src/index.ts) that owns EP-RECEIPT-v1/v2 itself; this file
 * adds the leaves purely additively so lib/evidence/evidence-graph.ts's
 * existing EP-OUTCOME-BINDING-v1 consumption is unaffected.
 */

export const OUTCOME_ATTESTATION_V2_VERSION = 'EP-OUTCOME-ATTESTATION-v2';
export const OUTCOME_ATTESTATION_V2_DOMAIN = 'EP-OUTCOME-ATTESTATION-v2\0';
export const OUTCOME_OBSERVATION_V2_VERSION = 'EP-OUTCOME-OBSERVATION-v2';
export const OUTCOME_OBSERVATION_V2_DOMAIN = 'EP-OUTCOME-OBSERVATION-v2\0';
/** The registered required algorithm set, in canonical order. */
export const OUTCOME_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

const PQ_KEY_ID_RE = /^ep:executor-key:ml-dsa-65:sha256:[0-9a-f]{64}$/;
const PQ_SOURCE_KEY_ID_RE = /^ep:outcome-source-key:ml-dsa-65:sha256:[0-9a-f]{64}$/;
const TOP_V2_KEYS = new Set([...TOP_KEYS, 'required_algorithms']);
const OBSERVATION_V2_KEYS = new Set([...OBSERVATION_KEYS, 'required_algorithms']);
const PROOF_V2_KEYS = new Set(['key_id', 'pq_key_id', 'public_key', 'pq_public_key', 'signatures']);

function algorithmSetMatchesRegisteredOutcome(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === OUTCOME_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === OUTCOME_V2_REQUIRED_ALGORITHMS[i]);
}

function pqExecutorKeyId(publicKeyRawB64u: unknown): string {
  try {
    if (typeof publicKeyRawB64u !== 'string' || publicKeyRawB64u.length === 0) return '';
    const raw = Buffer.from(publicKeyRawB64u, 'base64url');
    if (raw.length !== ML_DSA_65_PUBLIC_KEY_BYTES || raw.toString('base64url') !== publicKeyRawB64u) return '';
    return `ep:executor-key:ml-dsa-65:sha256:${sha256hex(raw)}`;
  } catch {
    return '';
  }
}

function pqOutcomeSourceKeyId(publicKeyRawB64u: unknown): string {
  try {
    if (typeof publicKeyRawB64u !== 'string' || publicKeyRawB64u.length === 0) return '';
    const raw = Buffer.from(publicKeyRawB64u, 'base64url');
    if (raw.length !== ML_DSA_65_PUBLIC_KEY_BYTES || raw.toString('base64url') !== publicKeyRawB64u) return '';
    return `ep:outcome-source-key:ml-dsa-65:sha256:${sha256hex(raw)}`;
  } catch {
    return '';
  }
}

function signingBytesV2(attestation: Obj): Buffer {
  return Buffer.from(`${OUTCOME_ATTESTATION_V2_DOMAIN}${canonicalize(unsigned(attestation))}`, 'utf8');
}

function observationSigningBytesV2(observation: Obj): Buffer {
  return Buffer.from(`${OUTCOME_OBSERVATION_V2_DOMAIN}${canonicalize(unsigned(observation))}`, 'utf8');
}

interface OutcomeV2Signer {
  privateKey: crypto.KeyObject;
  publicKey?: string;
  key_id?: string;
  /** ML-DSA-65 secret key: raw bytes or base64url, 4032 bytes. */
  pqPrivateKey: Uint8Array | string;
  pqPublicKey?: string;
  pq_key_id?: string;
}

interface OutcomeV2Options extends AgilityOptions {
  executorKeys?: Record<string, { public_key?: string; pq_public_key?: string; key_id?: string; pq_key_id?: string }>;
  now?: string;
}

/** Build an executor-signed hybrid observed-effects attestation. */
export async function buildOutcomeAttestationV2({
  receipt_id,
  receipt_digest,
  action_hash,
  consumption_nonce,
  execution_id,
  executor_id,
  executed_at,
  observed_effects,
  signer,
}: Obj = {}): Promise<Obj> {
  const observedValidation = validateObservedEffects(observed_effects);
  if (!observedValidation.ok) throw new Error(observedValidation.errors.join('; '));
  if (typeof receipt_id !== 'string' || !receipt_id) throw new Error('receipt_id is required');
  if (!normalizeDigest(receipt_digest)) throw new Error('receipt_digest must be sha256:<64-hex>');
  if (!normalizeDigest(action_hash)) throw new Error('action_hash must be sha256:<64-hex>');
  if (typeof consumption_nonce !== 'string' || !consumption_nonce) throw new Error('consumption_nonce is required');
  if (typeof execution_id !== 'string' || !execution_id) throw new Error('execution_id is required');
  if (typeof executor_id !== 'string' || !executor_id) throw new Error('executor_id is required');
  if (!Number.isFinite(strictInstantMs(executed_at))) throw new Error('executed_at must be a strict RFC 3339 instant');
  const s = signer as OutcomeV2Signer;
  if (!s?.privateKey) throw new Error('signer.privateKey is required');
  if (!s?.pqPrivateKey) throw new Error('signer.pqPrivateKey is required');
  const publicKey = s.publicKey || publicKeyB64u(s.privateKey);
  const keyId = executorKeyId(publicKey);
  if (s.key_id !== undefined && s.key_id !== keyId) throw new Error('signer.key_id does not match signer public key');
  const pqPublicKey = s.pqPublicKey;
  if (typeof pqPublicKey !== 'string' || !pqPublicKey) throw new Error('signer.pqPublicKey is required');
  const pqKeyId = pqExecutorKeyId(pqPublicKey);
  if (!pqKeyId) throw new Error('signer.pqPublicKey must be a canonical 1952-byte ML-DSA-65 key');
  if (s.pq_key_id !== undefined && s.pq_key_id !== pqKeyId) throw new Error('signer.pq_key_id does not match signer pq public key');
  const body = {
    '@version': OUTCOME_ATTESTATION_V2_VERSION,
    receipt_id,
    receipt_digest: normalizeDigest(receipt_digest),
    action_hash: normalizeDigest(action_hash),
    consumption_nonce,
    execution_id,
    executor_id,
    executed_at,
    observed_effects,
    observed_effects_digest: observedEffectsDigest(observed_effects),
    required_algorithms: [...OUTCOME_V2_REQUIRED_ALGORITHMS],
  };
  const bytes = signingBytesV2(body);
  const signatures = await signAgileSet(new Uint8Array(bytes), [
    { alg: 'Ed25519', private_key: s.privateKey, key_id: keyId },
    { alg: 'ML-DSA-65', private_key: s.pqPrivateKey, key_id: pqKeyId },
  ]);
  return {
    ...body,
    proof: { key_id: keyId, pq_key_id: pqKeyId, public_key: publicKey, pq_public_key: pqPublicKey, signatures },
  };
}

/** Verify a hybrid executor attestation. Async; never verifies on one leg alone. */
export async function verifyOutcomeAttestationV2(attestation: Obj, opts: OutcomeV2Options = {}) {
  opts = opts && typeof opts === 'object' ? opts : {};
  const executorKeys = opts.executorKeys && typeof opts.executorKeys === 'object' ? opts.executorKeys : {};
  const { now } = opts;
  const checks: Record<string, boolean> = {
    structure: false,
    observation_digest: false,
    algorithm_set: false,
    executor_key_pinned: false,
    signature: false,
    execution_time: false,
  };
  const errors: string[] = [];
  const out = () => ({ valid: Object.values(checks).every(Boolean), checks, errors });
  try {
    canonicalize(attestation);
  } catch {
    errors.push('malformed_outcome_attestation: outside canonical JSON domain');
    return out();
  }
  if (!exactKeys(attestation, TOP_V2_KEYS)
      || attestation?.['@version'] !== OUTCOME_ATTESTATION_V2_VERSION
      || typeof attestation.receipt_id !== 'string' || !attestation.receipt_id
      || !normalizeDigest(attestation.receipt_digest)
      || !normalizeDigest(attestation.action_hash)
      || typeof attestation.consumption_nonce !== 'string' || !attestation.consumption_nonce
      || typeof attestation.execution_id !== 'string' || !attestation.execution_id
      || typeof attestation.executor_id !== 'string' || !attestation.executor_id
      || !DIGEST_RE.test(attestation.observed_effects_digest || '')
      || !exactKeys(attestation.proof, PROOF_V2_KEYS)
      || !KEY_ID_RE.test(attestation.proof.key_id || '')
      || !PQ_KEY_ID_RE.test(attestation.proof.pq_key_id || '')
      || typeof attestation.proof.public_key !== 'string'
      || typeof attestation.proof.pq_public_key !== 'string'
      || !Array.isArray(attestation.proof.signatures) || attestation.proof.signatures.length !== 2) {
    errors.push('malformed_outcome_attestation');
    return out();
  }
  const observedValidation = validateObservedEffects(attestation.observed_effects);
  if (!observedValidation.ok) {
    errors.push(...observedValidation.errors);
    return out();
  }
  checks.structure = true;

  checks.observation_digest = observedEffectsDigest(attestation.observed_effects)
    === attestation.observed_effects_digest;
  if (!checks.observation_digest) errors.push('observed_effects_digest_mismatch');

  checks.algorithm_set = algorithmSetMatchesRegisteredOutcome(attestation.required_algorithms);
  if (!checks.algorithm_set) errors.push('required_algorithms_not_registered_set');

  const seenAlgs = new Set<string>();
  let sigsMalformed = false;
  for (const s of attestation.proof.signatures as Partial<AgileSignature>[]) {
    if (!s || typeof s !== 'object' || typeof s.alg !== 'string' || typeof s.sig !== 'string' || seenAlgs.has(s.alg)) {
      sigsMalformed = true;
      break;
    }
    seenAlgs.add(s.alg);
  }
  const legsPresent = !sigsMalformed && OUTCOME_V2_REQUIRED_ALGORITHMS.every((alg) => seenAlgs.has(alg));

  const derivedKeyId = executorKeyId(attestation.proof.public_key);
  const derivedPqKeyId = pqExecutorKeyId(attestation.proof.pq_public_key);
  const pin = executorKeys[attestation.executor_id];
  checks.executor_key_pinned = legsPresent
    && derivedKeyId === attestation.proof.key_id
    && derivedPqKeyId === attestation.proof.pq_key_id
    && pin?.public_key === attestation.proof.public_key
    && pin?.pq_public_key === attestation.proof.pq_public_key
    && (pin?.key_id === undefined || pin.key_id === derivedKeyId)
    && (pin?.pq_key_id === undefined || pin.pq_key_id === derivedPqKeyId);
  if (!checks.executor_key_pinned) errors.push('executor_key_not_pinned');

  if (checks.executor_key_pinned) {
    const bytes = signingBytesV2(attestation);
    let setResult;
    try {
      setResult = await verifyAgileSignatureSet(
        new Uint8Array(bytes),
        attestation.proof.signatures,
        [
          { alg: 'Ed25519', public_key: pin.public_key, key_id: derivedKeyId },
          { alg: 'ML-DSA-65', public_key: pin.pq_public_key, key_id: derivedPqKeyId },
        ],
        { ...opts, policy: 'hybrid_all', requiredAlgorithms: [...OUTCOME_V2_REQUIRED_ALGORITHMS] },
      );
    } catch {
      setResult = null;
    }
    checks.signature = setResult?.verified === true;
  }
  if (!checks.signature) errors.push('executor_signature_invalid');

  const executedAt = strictInstantMs(attestation.executed_at);
  const nowMs = now === undefined ? Date.now() : strictInstantMs(now);
  checks.execution_time = Number.isFinite(executedAt)
    && Number.isFinite(nowMs)
    && executedAt <= nowMs;
  if (!checks.execution_time) errors.push('execution_time_invalid_or_future');
  return out();
}

interface OutcomeSourceV2Signer {
  privateKey: crypto.KeyObject;
  publicKey?: string;
  key_id?: string;
  /** ML-DSA-65 secret key: raw bytes or base64url, 4032 bytes. */
  pqPrivateKey: Uint8Array | string;
  pqPublicKey?: string;
  pq_key_id?: string;
}

/** Build a hybrid-signed observation from an executor, system of record, or independent observer. */
export async function buildOutcomeObservationV2({
  receipt_id,
  receipt_digest,
  action_hash,
  action_caid,
  consumption_nonce,
  operation_id,
  source,
  observed_from,
  observed_until,
  attested_at,
  observed_effects,
  signer,
}: Obj = {}): Promise<Obj> {
  const observedValidation = validateObservedEffects(observed_effects);
  if (!observedValidation.ok) throw new Error(observedValidation.errors.join('; '));
  if (typeof receipt_id !== 'string' || !receipt_id) throw new Error('receipt_id is required');
  if (!normalizeDigest(receipt_digest)) throw new Error('receipt_digest must be sha256:<64-hex>');
  if (!normalizeDigest(action_hash)) throw new Error('action_hash must be sha256:<64-hex>');
  if (action_caid !== undefined && (typeof action_caid !== 'string' || !action_caid)) {
    throw new Error('action_caid must be a non-empty string when present');
  }
  if (typeof consumption_nonce !== 'string' || !consumption_nonce) throw new Error('consumption_nonce is required');
  if (typeof operation_id !== 'string' || !operation_id) throw new Error('operation_id is required');
  if (!exactKeys(source, SOURCE_KEYS)
      || !OUTCOME_SOURCE_ROLES.includes(source.role)
      || typeof source.source_id !== 'string' || !source.source_id
      || typeof source.source_class !== 'string' || !source.source_class
      || (source.facility_id !== undefined
        && (typeof source.facility_id !== 'string' || !source.facility_id))) {
    throw new Error('source must carry a closed role, source_id, source_class, and optional facility_id');
  }
  const fromMs = strictInstantMs(observed_from);
  const untilMs = strictInstantMs(observed_until);
  const attestedMs = strictInstantMs(attested_at);
  if (![fromMs, untilMs, attestedMs].every(Number.isFinite)
      || fromMs > untilMs || untilMs > attestedMs) {
    throw new Error('observation timestamps must be strict RFC 3339 instants ordered observed_from <= observed_until <= attested_at');
  }
  const s = signer as OutcomeSourceV2Signer;
  if (!s?.privateKey) throw new Error('signer.privateKey is required');
  if (!s?.pqPrivateKey) throw new Error('signer.pqPrivateKey is required');
  const publicKey = s.publicKey || publicKeyB64u(s.privateKey);
  const keyId = outcomeSourceKeyId(publicKey);
  if (s.key_id !== undefined && s.key_id !== keyId) throw new Error('signer.key_id does not match signer public key');
  const pqPublicKey = s.pqPublicKey;
  if (typeof pqPublicKey !== 'string' || !pqPublicKey) throw new Error('signer.pqPublicKey is required');
  const pqKeyId = pqOutcomeSourceKeyId(pqPublicKey);
  if (!pqKeyId) throw new Error('signer.pqPublicKey must be a canonical 1952-byte ML-DSA-65 key');
  if (s.pq_key_id !== undefined && s.pq_key_id !== pqKeyId) throw new Error('signer.pq_key_id does not match signer pq public key');
  const body: Obj = {
    '@version': OUTCOME_OBSERVATION_V2_VERSION,
    receipt_id,
    receipt_digest: normalizeDigest(receipt_digest),
    action_hash: normalizeDigest(action_hash),
    ...(action_caid === undefined ? {} : { action_caid }),
    consumption_nonce,
    operation_id,
    source,
    observed_from,
    observed_until,
    attested_at,
    observed_effects,
    observed_effects_digest: observedEffectsDigest(observed_effects),
    required_algorithms: [...OUTCOME_V2_REQUIRED_ALGORITHMS],
  };
  const bytes = observationSigningBytesV2(body);
  const signatures = await signAgileSet(new Uint8Array(bytes), [
    { alg: 'Ed25519', private_key: s.privateKey, key_id: keyId },
    { alg: 'ML-DSA-65', private_key: s.pqPrivateKey, key_id: pqKeyId },
  ]);
  return {
    ...body,
    proof: { key_id: keyId, pq_key_id: pqKeyId, public_key: publicKey, pq_public_key: pqPublicKey, signatures },
  };
}

/** Verify one hybrid-signed outcome observation. Async; never verifies on one leg alone. */
export async function verifyOutcomeObservationV2(observation: Obj, opts: OutcomeSetOptions & AgilityOptions = {}) {
  const sourceKeys = (opts.sourceKeys && typeof opts.sourceKeys === 'object' ? opts.sourceKeys : {}) as Record<string, Obj>;
  const checks: Record<string, boolean> = {
    structure: false,
    observation_digest: false,
    algorithm_set: false,
    source_key_pinned: false,
    source_metadata_pinned: false,
    source_key_current: false,
    signature: false,
    observation_time: false,
  };
  const errors: string[] = [];
  const out = () => ({ valid: Object.values(checks).every(Boolean), checks, errors });
  try {
    canonicalize(observation);
  } catch {
    errors.push('malformed_outcome_observation: outside canonical JSON domain');
    return out();
  }
  if (!exactKeys(observation, OBSERVATION_V2_KEYS)
      || observation?.['@version'] !== OUTCOME_OBSERVATION_V2_VERSION
      || typeof observation.receipt_id !== 'string' || !observation.receipt_id
      || !normalizeDigest(observation.receipt_digest)
      || !normalizeDigest(observation.action_hash)
      || (observation.action_caid !== undefined
        && (typeof observation.action_caid !== 'string' || !observation.action_caid))
      || typeof observation.consumption_nonce !== 'string' || !observation.consumption_nonce
      || typeof observation.operation_id !== 'string' || !observation.operation_id
      || !exactKeys(observation.source, SOURCE_KEYS)
      || !OUTCOME_SOURCE_ROLES.includes(observation.source?.role)
      || typeof observation.source?.source_id !== 'string' || !observation.source.source_id
      || typeof observation.source?.source_class !== 'string' || !observation.source.source_class
      || (observation.source?.facility_id !== undefined
        && (typeof observation.source.facility_id !== 'string' || !observation.source.facility_id))
      || !DIGEST_RE.test(observation.observed_effects_digest || '')
      || !exactKeys(observation.proof, PROOF_V2_KEYS)
      || !SOURCE_KEY_ID_RE.test(observation.proof.key_id || '')
      || !PQ_SOURCE_KEY_ID_RE.test(observation.proof.pq_key_id || '')
      || typeof observation.proof.public_key !== 'string'
      || typeof observation.proof.pq_public_key !== 'string'
      || !Array.isArray(observation.proof.signatures) || observation.proof.signatures.length !== 2) {
    errors.push('malformed_outcome_observation');
    return out();
  }
  const observedValidation = validateObservedEffects(observation.observed_effects);
  if (!observedValidation.ok) {
    errors.push(...observedValidation.errors);
    return out();
  }
  checks.structure = true;
  checks.observation_digest = observedEffectsDigest(observation.observed_effects)
    === observation.observed_effects_digest;
  if (!checks.observation_digest) errors.push('observed_effects_digest_mismatch');

  checks.algorithm_set = algorithmSetMatchesRegisteredOutcome(observation.required_algorithms);
  if (!checks.algorithm_set) errors.push('required_algorithms_not_registered_set');

  const seenAlgs = new Set<string>();
  let sigsMalformed = false;
  for (const s of observation.proof.signatures as Partial<AgileSignature>[]) {
    if (!s || typeof s !== 'object' || typeof s.alg !== 'string' || typeof s.sig !== 'string' || seenAlgs.has(s.alg)) {
      sigsMalformed = true;
      break;
    }
    seenAlgs.add(s.alg);
  }
  const legsPresent = !sigsMalformed && OUTCOME_V2_REQUIRED_ALGORITHMS.every((alg) => seenAlgs.has(alg));

  const observationKey = canonicalOutcomeSourceKey(observation.proof.public_key);
  const derivedPqKeyId = pqOutcomeSourceKeyId(observation.proof.pq_public_key);
  const pin = sourceKeys[observation.source.source_id];
  const pinnedKey = canonicalOutcomeSourceKey(pin?.public_key);
  checks.source_key_pinned = legsPresent
    && observationKey !== null
    && pinnedKey !== null
    && observationKey.key_id === observation.proof.key_id
    && pinnedKey.key_id === observationKey.key_id
    && derivedPqKeyId === observation.proof.pq_key_id
    && pin?.pq_public_key === observation.proof.pq_public_key
    && (pin.key_id === undefined || pin.key_id === observationKey.key_id)
    && (pin.pq_key_id === undefined || pin.pq_key_id === derivedPqKeyId);
  if (!checks.source_key_pinned) errors.push('outcome_source_key_not_pinned');
  checks.source_metadata_pinned = pin?.role === observation.source.role
    && pin?.source_class === observation.source.source_class
    && (pin.facility_id === undefined || pin.facility_id === observation.source.facility_id);
  if (!checks.source_metadata_pinned) errors.push('outcome_source_metadata_not_pinned');

  if (checks.source_key_pinned && checks.source_metadata_pinned) {
    const bytes = observationSigningBytesV2(observation);
    let setResult;
    try {
      setResult = await verifyAgileSignatureSet(
        new Uint8Array(bytes),
        observation.proof.signatures,
        [
          { alg: 'Ed25519', public_key: pinnedKey!.public_key, key_id: observationKey!.key_id },
          { alg: 'ML-DSA-65', public_key: pin.pq_public_key, key_id: derivedPqKeyId },
        ],
        { ...opts, policy: 'hybrid_all', requiredAlgorithms: [...OUTCOME_V2_REQUIRED_ALGORITHMS] },
      );
    } catch {
      setResult = null;
    }
    checks.signature = setResult?.verified === true;
  }
  if (!checks.signature) errors.push('outcome_source_signature_invalid');

  const fromMs = strictInstantMs(observation.observed_from);
  const untilMs = strictInstantMs(observation.observed_until);
  const attestedMs = strictInstantMs(observation.attested_at);
  const nowMs = opts.now === undefined ? Date.now() : strictInstantMs(opts.now);
  checks.observation_time = [fromMs, untilMs, attestedMs, nowMs].every(Number.isFinite)
    && fromMs <= untilMs && untilMs <= attestedMs && attestedMs <= nowMs;
  if (!checks.observation_time) errors.push('observation_time_invalid_or_future');

  const validFromMs = strictInstantMs(pin?.valid_from);
  const validToMs = strictInstantMs(pin?.valid_to);
  const status = pin?.status;
  const compromisedAtMs = pin?.compromised_at === undefined
    ? NaN : strictInstantMs(pin.compromised_at);
  const statusShapeValid = status === 'active' || status === 'retired' || status === 'compromised';
  const compromiseShapeValid = status === 'compromised'
    ? Number.isFinite(compromisedAtMs)
    : pin?.compromised_at === undefined;
  checks.source_key_current = statusShapeValid
    && compromiseShapeValid
    && [validFromMs, validToMs, attestedMs].every(Number.isFinite)
    && validFromMs <= attestedMs
    && attestedMs <= validToMs
    && (status !== 'compromised' || attestedMs < compromisedAtMs);
  if (!checks.source_key_current) errors.push('outcome_source_key_not_current');
  return out();
}

export const OUTCOME_BINDING_OUTCOMES = DIVERGENCE_OUTCOMES;
