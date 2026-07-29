// SPDX-License-Identifier: Apache-2.0

/**
 * EMILIA Trusted Context Pack.
 *
 * A provider verifies its native memory artifact and emits a signed projection
 * commitment. EMILIA then binds that commitment to one exact proposed action,
 * evaluates relying-party policy, and carries the digests into independently
 * verified execution and outcome evidence. None of these steps authorizes an
 * action by itself.
 */
import crypto from 'node:crypto';

// The compatibility entry point resolves to dist from both native TypeScript
// tests and compiled package consumers.
// @ts-ignore declarations live behind the compatibility entry point.
import { canonicalize } from '../execution-binding.js';

type RecordLike = Record<string, any>;

export const CONTEXT_PROJECTION_COMPONENT = 'ep-memory-projection';
export const TRUSTED_CONTEXT_BINDING_VERSION = 'EP-TRUSTED-CONTEXT-BINDING-v1';

const BINDING_DOMAIN = Buffer.from('EP-TRUSTED-CONTEXT-BINDING-v1\0', 'utf8');
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const EVIDENCE_KEYS = new Set([
  'provider_id',
  'provider_profile',
  'projection_record',
  'context_binding',
]);
const ACTION_CONTEXT_KEYS = new Set([
  'provider_id',
  'provider_profile',
  'projection_record_digest',
  'projection_digest',
  'context_binding_digest',
]);
const BINDING_KEYS = new Set([
  '@version',
  'provider_id',
  'provider_profile',
  'projection_record_digest',
  'projection_digest',
  'action_subject_digest',
  'policy_digest',
  'nonce',
  'issued_at',
  'expires_at',
  'binder',
  'proof',
]);
const BINDER_KEYS = new Set(['id', 'key_id']);
const PROOF_KEYS = new Set(['alg', 'key_id', 'signature_b64u']);

export type ContextVerificationState = 'VERIFIED' | 'NOT_VERIFIED' | 'INDETERMINATE';

export interface ContextProviderClaims {
  projection_id: string;
  projection_record_digest: string;
  projection_digest: string;
  created_at: string;
  trust_evaluated_at: string;
  adapter_status_checked_at: string;
  adapter_id: string;
  adapter_key_id: string;
  delivered_trust: readonly string[];
  excluded_by_reason: Readonly<Record<string, number>>;
}

export interface ContextProviderVerification {
  state: ContextVerificationState;
  reason: string | null;
  claims?: ContextProviderClaims;
}

export interface ContextEvidenceProvider {
  readonly providerId: string;
  readonly profileId: string;
  verifyProjection(
    record: unknown,
    context: { verificationTime: string; maxSignerStatusAgeSec: number },
  ): ContextProviderVerification;
}

export interface TrustedContextPolicy extends RecordLike {
  policy_id: string;
  provider_id: string;
  provider_profile: string;
  max_projection_age_sec: number;
  max_keyring_age_sec: number;
  max_signer_status_age_sec: number;
  allowed_trust: string[];
  allowed_exclusion_reasons: string[];
  max_excluded_objects: number;
  require_current_signer_status: boolean;
}

export interface TrustedContextEvaluatorOptions {
  providers: ContextEvidenceProvider[];
  policy: TrustedContextPolicy;
  bindingKeys: Record<string, unknown>;
  bindingStatusCheckedAt: string | (() => string);
  expectedBindingNonce: string | (() => string);
  verificationTime: string | (() => string);
}

function isRecord(value: unknown): value is RecordLike {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isDataRecord(value: unknown): value is RecordLike {
  if (!isRecord(value)) return false;
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}

function exactKeys(value: unknown, keys: Set<string>): value is RecordLike {
  return isDataRecord(value)
    && Object.keys(value).length === keys.size
    && Object.keys(value).every((key) => keys.has(key));
}

function canonicalCopy<T>(value: T): T {
  return JSON.parse(canonicalize(value));
}

function sha256(value: Uint8Array | string): string {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

function canonicalDigest(value: unknown): string {
  return sha256(Buffer.from(canonicalize(value), 'utf8'));
}

function canonicalInstant(value: unknown): string | null {
  if (typeof value !== 'string' || !RFC3339.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
}

function ageSeconds(then: unknown, now: string): number | null {
  const normalized = canonicalInstant(then);
  if (!normalized) return null;
  const age = (Date.parse(now) - Date.parse(normalized)) / 1000;
  return Number.isFinite(age) && age >= 0 ? age : null;
}

function boundedString(value: unknown, maximum = 512): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function safeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function normalizeStringSet(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) return null;
  const entries: string[] = [];
  for (const entry of value) {
    if (!boundedString(entry, 128)) return null;
    entries.push(entry);
  }
  if (new Set(entries).size !== entries.length) return null;
  return entries.sort();
}

function resolveInstant(value: string | (() => string)): string | null {
  try {
    return canonicalInstant(typeof value === 'function' ? value() : value);
  } catch {
    return null;
  }
}

function resolveBoundedString(value: string | (() => string), maximum: number): string | null {
  try {
    const resolved = typeof value === 'function' ? value() : value;
    return boundedString(resolved, maximum) ? resolved : null;
  } catch {
    return null;
  }
}

function publicKey(value: unknown): crypto.KeyObject | null {
  try {
    if (value instanceof crypto.KeyObject) {
      return value.type === 'public' ? value : crypto.createPublicKey(value as any);
    }
    if (typeof value !== 'string' || !BASE64URL.test(value)) return null;
    const bytes = Buffer.from(value, 'base64url');
    if (bytes.toString('base64url') !== value) return null;
    return crypto.createPublicKey({ key: bytes, format: 'der', type: 'spki' });
  } catch {
    return null;
  }
}

function keyDirectoryEntry(value: unknown): (RecordLike & { key: crypto.KeyObject }) | null {
  if (!isDataRecord(value)
      || !['active', 'revoked', 'superseded'].includes(value.status)
      || !canonicalInstant(value.valid_from)
      || !canonicalInstant(value.valid_to)
      || Date.parse(value.valid_to) <= Date.parse(value.valid_from)
      || (value.revoked_at !== null && !canonicalInstant(value.revoked_at))) return null;
  const key = publicKey(value.public_key_spki_b64u);
  return key ? { ...(value as RecordLike), key } : null;
}

function refusal(state: Exclude<ContextVerificationState, 'VERIFIED'>, reason: string) {
  return Object.freeze({ state, reason, authorizes: false as const });
}

function signingInput(binding: RecordLike): Buffer {
  const { proof: _proof, ...unsigned } = binding;
  return Buffer.concat([BINDING_DOMAIN, Buffer.from(canonicalize(unsigned), 'utf8')]);
}

function actionSubject(action: unknown): RecordLike | null {
  if (!isDataRecord(action)) return null;
  const subject: RecordLike = {};
  for (const [key, value] of Object.entries(action)) {
    if (key !== 'trusted_context') subject[key] = value;
  }
  return Object.keys(subject).length > 0 ? subject : null;
}

export function trustedContextActionSubjectDigest(action: unknown): string | null {
  const subject = actionSubject(action);
  if (!subject) return null;
  try {
    return canonicalDigest(subject);
  } catch {
    return null;
  }
}

export function canonicalContextRecordDigest(record: unknown): string {
  return canonicalDigest(record);
}

export function canonicalContextBindingDigest(binding: unknown): string {
  return canonicalDigest(binding);
}

export function trustedContextPolicyDigest(policy: unknown): string {
  const normalized = validatePolicy(policy);
  if (!normalized) throw new TypeError('trusted context policy invalid');
  return canonicalDigest(normalized);
}

export interface SignTrustedContextBindingInput {
  providerId: string;
  providerProfile: string;
  projectionRecord: RecordLike;
  action: RecordLike;
  policyDigest: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  binderId: string;
  keyId: string;
  privateKey: crypto.KeyLike;
}

/** Sign a context-to-action join without creating an authorization claim. */
export function signTrustedContextBinding(input: SignTrustedContextBindingInput) {
  const subjectDigest = trustedContextActionSubjectDigest(input.action);
  if (!subjectDigest || !DIGEST.test(input.policyDigest)
      || !boundedString(input.providerId, 128)
      || !boundedString(input.providerProfile, 256)
      || !boundedString(input.nonce, 256)
      || !boundedString(input.binderId, 256)
      || !boundedString(input.keyId, 256)
      || !canonicalInstant(input.issuedAt)
      || !canonicalInstant(input.expiresAt)
      || Date.parse(input.expiresAt) <= Date.parse(input.issuedAt)
      || !isDataRecord(input.projectionRecord)
      || !isDataRecord(input.projectionRecord.projection)
      || !DIGEST.test(input.projectionRecord.projection.digest)) {
    throw new TypeError('trusted context binding input invalid');
  }
  const unsigned = {
    '@version': TRUSTED_CONTEXT_BINDING_VERSION,
    provider_id: input.providerId,
    provider_profile: input.providerProfile,
    projection_record_digest: canonicalContextRecordDigest(input.projectionRecord),
    projection_digest: input.projectionRecord.projection.digest,
    action_subject_digest: subjectDigest,
    policy_digest: input.policyDigest,
    nonce: input.nonce,
    issued_at: canonicalInstant(input.issuedAt),
    expires_at: canonicalInstant(input.expiresAt),
    binder: { id: input.binderId, key_id: input.keyId },
  };
  const signature = crypto.sign(
    null,
    Buffer.concat([BINDING_DOMAIN, Buffer.from(canonicalize(unsigned), 'utf8')]),
    input.privateKey,
  );
  return Object.freeze({
    ...unsigned,
    proof: {
      alg: 'Ed25519',
      key_id: input.keyId,
      signature_b64u: signature.toString('base64url'),
    },
  });
}

function validatePolicy(value: unknown): TrustedContextPolicy | null {
  if (!isDataRecord(value)
      || !boundedString(value.policy_id, 256)
      || !boundedString(value.provider_id, 128)
      || !boundedString(value.provider_profile, 256)
      || !safeInteger(value.max_projection_age_sec)
      || !safeInteger(value.max_keyring_age_sec)
      || !safeInteger(value.max_signer_status_age_sec)
      || !safeInteger(value.max_excluded_objects)
      || typeof value.require_current_signer_status !== 'boolean') return null;
  const allowedTrust = normalizeStringSet(value.allowed_trust);
  const allowedExclusions = normalizeStringSet(value.allowed_exclusion_reasons);
  if (!allowedTrust || !allowedExclusions) return null;
  try {
    return canonicalCopy({
      ...(value as TrustedContextPolicy),
      allowed_trust: allowedTrust,
      allowed_exclusion_reasons: allowedExclusions,
    }) as TrustedContextPolicy;
  } catch {
    return null;
  }
}

function verifyContextBinding({
  binding,
  action,
  projectionRecordDigest,
  projectionDigest,
  policy,
  bindingKeys,
  bindingStatusCheckedAt,
  expectedBindingNonce,
  verificationTime,
}: RecordLike) {
  if (!exactKeys(binding, BINDING_KEYS)
      || binding['@version'] !== TRUSTED_CONTEXT_BINDING_VERSION
      || !boundedString(binding.provider_id, 128)
      || !boundedString(binding.provider_profile, 256)
      || !DIGEST.test(binding.projection_record_digest)
      || !DIGEST.test(binding.projection_digest)
      || !DIGEST.test(binding.action_subject_digest)
      || !DIGEST.test(binding.policy_digest)
      || !boundedString(binding.nonce, 256)
      || !canonicalInstant(binding.issued_at)
      || !canonicalInstant(binding.expires_at)
      || !exactKeys(binding.binder, BINDER_KEYS)
      || !boundedString(binding.binder.id, 256)
      || !boundedString(binding.binder.key_id, 256)
      || !exactKeys(binding.proof, PROOF_KEYS)
      || binding.proof.alg !== 'Ed25519'
      || binding.proof.key_id !== binding.binder.key_id
      || typeof binding.proof.signature_b64u !== 'string'
      || !BASE64URL.test(binding.proof.signature_b64u)) {
    return refusal('NOT_VERIFIED', 'context_binding_invalid');
  }
  if (binding.provider_id !== policy.provider_id
      || binding.provider_profile !== policy.provider_profile
      || binding.projection_record_digest !== projectionRecordDigest
      || binding.projection_digest !== projectionDigest
      || binding.policy_digest !== trustedContextPolicyDigest(policy)) {
    return refusal('NOT_VERIFIED', 'context_binding_mismatch');
  }
  if (binding.nonce !== expectedBindingNonce) {
    return refusal('NOT_VERIFIED', 'context_binding_nonce_mismatch');
  }
  const subjectDigest = trustedContextActionSubjectDigest(action);
  if (!subjectDigest || binding.action_subject_digest !== subjectDigest) {
    return refusal('NOT_VERIFIED', 'action_context_binding_mismatch');
  }
  const issued = Date.parse(binding.issued_at);
  const expires = Date.parse(binding.expires_at);
  const now = Date.parse(verificationTime);
  if (issued > now || now > expires) return refusal('NOT_VERIFIED', 'context_binding_expired');

  const statusAge = ageSeconds(bindingStatusCheckedAt, verificationTime);
  if (policy.require_current_signer_status
      && (statusAge === null || statusAge > policy.max_signer_status_age_sec)) {
    return refusal('INDETERMINATE', 'binding_signer_status_stale');
  }
  const entry = bindingKeys.get(binding.binder.key_id);
  if (!entry) return refusal('NOT_VERIFIED', 'binding_signer_not_pinned');
  if (entry.status === 'revoked'
      && entry.revoked_at !== null
      && Date.parse(verificationTime) >= Date.parse(entry.revoked_at)) {
    return refusal('NOT_VERIFIED', 'binding_signer_revoked');
  }
  if (entry.status !== 'active'
      || Date.parse(verificationTime) < Date.parse(entry.valid_from)
      || Date.parse(verificationTime) > Date.parse(entry.valid_to)) {
    return refusal('NOT_VERIFIED', 'binding_signer_inactive');
  }
  let signature: Buffer;
  try {
    signature = Buffer.from(binding.proof.signature_b64u, 'base64url');
    if (signature.length !== 64 || signature.toString('base64url') !== binding.proof.signature_b64u) {
      return refusal('NOT_VERIFIED', 'context_binding_invalid');
    }
  } catch {
    return refusal('NOT_VERIFIED', 'context_binding_invalid');
  }
  if (!crypto.verify(null, signingInput(binding), entry.key, signature)) {
    return refusal('NOT_VERIFIED', 'context_binding_signature_invalid');
  }
  return Object.freeze({ state: 'VERIFIED' as const, reason: null, authorizes: false as const });
}

/**
 * Create a relying-party-owned context evaluator. Provider implementations,
 * policy, signer keys, and status snapshots are all constructor-pinned.
 */
export function createTrustedContextEvaluator(options: TrustedContextEvaluatorOptions) {
  const pinnedPolicy = validatePolicy(options.policy);
  if (!pinnedPolicy || !Array.isArray(options.providers) || options.providers.length === 0
      || !isDataRecord(options.bindingKeys)) {
    throw new TypeError('trusted context evaluator configuration invalid');
  }
  const providers = new Map<string, ContextEvidenceProvider>();
  for (const provider of options.providers) {
    if (!provider || !boundedString(provider.providerId, 128)
        || !boundedString(provider.profileId, 256)
        || typeof provider.verifyProjection !== 'function') {
      throw new TypeError('trusted context provider invalid');
    }
    const key = `${provider.providerId}\u0000${provider.profileId}`;
    if (providers.has(key)) throw new TypeError('duplicate trusted context provider');
    providers.set(key, Object.freeze({
      providerId: provider.providerId,
      profileId: provider.profileId,
      verifyProjection: provider.verifyProjection.bind(provider),
    }));
  }
  const bindingKeys = new Map<string, RecordLike & { key: crypto.KeyObject }>();
  for (const [keyId, value] of Object.entries(options.bindingKeys)) {
    if (!boundedString(keyId, 256)) {
      throw new TypeError('trusted context binding key id invalid');
    }
    const entry = keyDirectoryEntry(value);
    if (!entry) throw new TypeError('trusted context binding key invalid');
    bindingKeys.set(keyId, Object.freeze({ ...entry }));
  }
  if (bindingKeys.size === 0) throw new TypeError('trusted context binding key required');
  const verificationTimeSource = options.verificationTime;
  const bindingStatusSource = options.bindingStatusCheckedAt;
  const expectedNonceSource = options.expectedBindingNonce;

  const evaluatePinnedContext = function evaluatePinnedContext(input: RecordLike) {
    if (!isDataRecord(input) || !exactKeys(input.evidence, EVIDENCE_KEYS)
        || !isDataRecord(input.action)) {
      return refusal('NOT_VERIFIED', 'context_evidence_schema_invalid');
    }
    const evidence = input.evidence;
    if (evidence.provider_id !== pinnedPolicy.provider_id
        || evidence.provider_profile !== pinnedPolicy.provider_profile) {
      return refusal('NOT_VERIFIED', 'provider_policy_mismatch');
    }
    const selected = providers.get(`${evidence.provider_id}\u0000${evidence.provider_profile}`);
    if (!selected) return refusal('NOT_VERIFIED', 'provider_not_pinned');
    const verificationTime = resolveInstant(verificationTimeSource);
    const bindingStatusCheckedAt = resolveInstant(bindingStatusSource);
    const expectedBindingNonce = resolveBoundedString(expectedNonceSource, 256);
    if (!verificationTime || !bindingStatusCheckedAt) {
      return refusal('INDETERMINATE', 'verification_time_unavailable');
    }
    if (!expectedBindingNonce) {
      return refusal('INDETERMINATE', 'binding_nonce_unavailable');
    }
    let providerResult: ContextProviderVerification;
    try {
      providerResult = selected.verifyProjection(evidence.projection_record, {
        verificationTime,
        maxSignerStatusAgeSec: pinnedPolicy.max_signer_status_age_sec,
      });
    } catch {
      return refusal('INDETERMINATE', 'provider_verification_unavailable');
    }
    if (!providerResult || providerResult.state !== 'VERIFIED' || !providerResult.claims) {
      const state = providerResult?.state === 'NOT_VERIFIED' ? 'NOT_VERIFIED' : 'INDETERMINATE';
      return refusal(state, providerResult?.reason || 'provider_verification_failed');
    }
    const claims = providerResult.claims;
    if (!DIGEST.test(claims.projection_record_digest)
        || !DIGEST.test(claims.projection_digest)
        || !boundedString(claims.projection_id, 512)
        || !Array.isArray(claims.delivered_trust)
        || !isDataRecord(claims.excluded_by_reason)) {
      return refusal('NOT_VERIFIED', 'provider_claims_invalid');
    }
    const projectionAge = ageSeconds(claims.created_at, verificationTime);
    if (projectionAge === null || projectionAge > pinnedPolicy.max_projection_age_sec) {
      return refusal('INDETERMINATE', 'projection_stale');
    }
    const keyringAge = ageSeconds(claims.trust_evaluated_at, verificationTime);
    if (keyringAge === null || keyringAge > pinnedPolicy.max_keyring_age_sec) {
      return refusal('INDETERMINATE', 'keyring_status_stale');
    }
    const allowedTrust = new Set(pinnedPolicy.allowed_trust);
    if (claims.delivered_trust.some((entry) => !allowedTrust.has(entry))) {
      return refusal('NOT_VERIFIED', 'projection_trust_policy_mismatch');
    }
    const allowedExclusions = new Set(pinnedPolicy.allowed_exclusion_reasons);
    let excluded = 0;
    for (const [reason, count] of Object.entries(claims.excluded_by_reason)) {
      if (!safeInteger(count)) return refusal('NOT_VERIFIED', 'projection_exclusion_claim_invalid');
      if (count > 0 && !allowedExclusions.has(reason)) {
        return refusal('NOT_VERIFIED', 'projection_exclusion_policy_mismatch');
      }
      excluded += count;
    }
    if (excluded > pinnedPolicy.max_excluded_objects) {
      return refusal('NOT_VERIFIED', 'projection_exclusion_limit_exceeded');
    }

    const bindingResult = verifyContextBinding({
      binding: evidence.context_binding,
      action: input.action,
      projectionRecordDigest: claims.projection_record_digest,
      projectionDigest: claims.projection_digest,
      policy: pinnedPolicy,
      bindingKeys,
      bindingStatusCheckedAt,
      expectedBindingNonce,
      verificationTime,
    });
    if (bindingResult.state !== 'VERIFIED') return bindingResult;

    const actionContext = input.action.trusted_context;
    if (!exactKeys(actionContext, ACTION_CONTEXT_KEYS)
        || actionContext.provider_id !== pinnedPolicy.provider_id
        || actionContext.provider_profile !== pinnedPolicy.provider_profile
        || actionContext.projection_record_digest !== claims.projection_record_digest
        || actionContext.projection_digest !== claims.projection_digest
        || actionContext.context_binding_digest !== canonicalContextBindingDigest(evidence.context_binding)) {
      return refusal('NOT_VERIFIED', 'action_context_binding_mismatch');
    }
    let actionDigest: string;
    try {
      actionDigest = canonicalDigest(input.action);
    } catch {
      return refusal('NOT_VERIFIED', 'action_not_canonical');
    }
    return Object.freeze({
      state: 'VERIFIED' as const,
      reason: null,
      authorizes: false as const,
      provider_id: pinnedPolicy.provider_id,
      provider_profile: pinnedPolicy.provider_profile,
      projection_id: claims.projection_id,
      projection_record_digest: claims.projection_record_digest,
      projection_digest: claims.projection_digest,
      context_binding_digest: canonicalContextBindingDigest(evidence.context_binding),
      action_digest: actionDigest,
      policy_digest: trustedContextPolicyDigest(pinnedPolicy),
    });
  };

  return function evaluateTrustedContext(input: RecordLike) {
    try {
      return evaluatePinnedContext(input);
    } catch {
      return refusal('INDETERMINATE', 'context_evaluation_unavailable');
    }
  };
}

export function createTrustedContextAecVerifier({ evaluator }: {
  evaluator: ReturnType<typeof createTrustedContextEvaluator>;
}) {
  if (typeof evaluator !== 'function') throw new TypeError('trusted context evaluator required');
  return function trustedContextAecVerifier(evidence: unknown, context: RecordLike) {
    const result = evaluator({ evidence, action: context?.action });
    return Object.freeze({
      valid: result.state === 'VERIFIED',
      action_digest: result.state === 'VERIFIED' ? result.action_digest : null,
      detail: result,
    });
  };
}

/**
 * Compare already-verified execution and outcome evidence to a verified context
 * decision. This is a digest-continuity check, not a signature verifier and not
 * an authorization decision.
 */
export function verifyTrustedContextContinuity({
  verifiedContext,
  execution,
  outcome,
}: RecordLike) {
  if (!isDataRecord(verifiedContext) || verifiedContext.state !== 'VERIFIED'
      || !DIGEST.test(verifiedContext.action_digest)
      || !DIGEST.test(verifiedContext.projection_record_digest)) {
    return Object.freeze({ status: 'INDETERMINATE', reason: 'context_not_verified', authorizes: false });
  }
  if (!isDataRecord(execution) || execution.verified !== true
      || !DIGEST.test(execution.action_digest)
      || !DIGEST.test(execution.projection_record_digest)
      || !DIGEST.test(execution.execution_digest)) {
    return Object.freeze({ status: 'INDETERMINATE', reason: 'execution_not_verified', authorizes: false });
  }
  if (execution.action_digest !== verifiedContext.action_digest
      || execution.projection_record_digest !== verifiedContext.projection_record_digest) {
    return Object.freeze({ status: 'BROKEN', reason: 'context_execution_binding_mismatch', authorizes: false });
  }
  if (!isDataRecord(outcome) || outcome.verified !== true
      || !DIGEST.test(outcome.action_digest)
      || !DIGEST.test(outcome.projection_record_digest)
      || !DIGEST.test(outcome.execution_digest)
      || !DIGEST.test(outcome.outcome_digest)) {
    return Object.freeze({ status: 'INDETERMINATE', reason: 'outcome_not_verified', authorizes: false });
  }
  if (outcome.action_digest !== execution.action_digest
      || outcome.projection_record_digest !== execution.projection_record_digest
      || outcome.execution_digest !== execution.execution_digest) {
    return Object.freeze({ status: 'BROKEN', reason: 'execution_outcome_binding_mismatch', authorizes: false });
  }
  return Object.freeze({
    status: 'CONTINUOUS',
    reason: null,
    authorizes: false,
    projection_record_digest: verifiedContext.projection_record_digest,
    action_digest: verifiedContext.action_digest,
    execution_digest: execution.execution_digest,
    outcome_digest: outcome.outcome_digest,
  });
}

export default Object.freeze({
  CONTEXT_PROJECTION_COMPONENT,
  TRUSTED_CONTEXT_BINDING_VERSION,
  canonicalContextRecordDigest,
  canonicalContextBindingDigest,
  trustedContextActionSubjectDigest,
  trustedContextPolicyDigest,
  signTrustedContextBinding,
  createTrustedContextEvaluator,
  createTrustedContextAecVerifier,
  verifyTrustedContextContinuity,
});
