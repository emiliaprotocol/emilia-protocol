// SPDX-License-Identifier: Apache-2.0
/**
 * Provider outcome bridge for one Gate admission.
 *
 * The bridge does not trust a digest, a presenter-supplied key, or an outcome
 * label on its own. It verifies a complete EP-OUTCOME-OBSERVATION-v2 with the
 * relying party's out-of-band source pins, then requires the signed observation
 * to commit the digest of one closed provider-context object.
 */
import {
  verifyOutcomeObservationV2,
} from '@emilia-protocol/verify/outcome-binding';
import type { AgilityOptions } from '@emilia-protocol/verify/pq-signature-agility';
import {
  RISK_CAID,
  RISK_DIGEST,
  riskClone,
  riskDigest,
  riskExact,
  riskFreeze,
  riskIdentifier,
  riskInstant,
  riskRecord,
  type RiskRecord,
} from './reliance-risk-crypto.js';

export const PROVIDER_OUTCOME_CONTEXT_VERSION = 'EP-PROVIDER-OUTCOME-CONTEXT-v1';
export const PROVIDER_OUTCOME_BINDING_VERSION = 'EP-PROVIDER-OUTCOME-BINDING-v1';
export const PROVIDER_OUTCOME_EFFECT_TYPE = 'emilia.provider_outcome.v1';
export const PROVIDER_OUTCOME_BINDING_CLAIM_BOUNDARY =
  'verified_source_observation_bound_to_one_exact_provider_context_not_provider_truth_not_external_effect_not_coverage_not_claim_adjudication';

export const PROVIDER_OUTCOMES = Object.freeze([
  'COMMITTED',
  'PROVEN_NOT_COMMITTED',
  'INDETERMINATE',
] as const);

export type ProviderOutcome = typeof PROVIDER_OUTCOMES[number];

export interface ProviderOutcomeContext {
  readonly '@version': typeof PROVIDER_OUTCOME_CONTEXT_VERSION;
  readonly tenant_id: string;
  readonly admission_id: string;
  readonly operation_id: string;
  readonly snapshot_digest: string;
  readonly caid: string;
  readonly action_digest: string;
  readonly effect_request_digest: string;
  readonly provider: string;
  readonly account: string;
  readonly environment: string;
  readonly adapter_id: string;
  readonly idempotency_key: string;
  readonly outcome: ProviderOutcome;
  readonly observed_at: string;
}

export interface ProviderOutcomeSourceIdentity {
  readonly role: 'executor' | 'system_of_record' | 'independent_observer';
  readonly source_id: string;
  readonly source_class: string;
  readonly facility_id?: string;
}

export interface ProviderOutcomeBinding {
  readonly '@version': typeof PROVIDER_OUTCOME_BINDING_VERSION;
  readonly provider_context: Readonly<ProviderOutcomeContext>;
  readonly provider_context_digest: string;
  readonly outcome_observation_digest: string;
  readonly claim_boundary: typeof PROVIDER_OUTCOME_BINDING_CLAIM_BOUNDARY;
}

export interface VerifyProviderOutcomeBindingOptions {
  /** Relying-party pins. These are never read from the presented bridge. */
  readonly source_keys: Record<string, RiskRecord>;
  /** The one source identity this provider observation must use. */
  readonly expected_source: Readonly<ProviderOutcomeSourceIdentity>;
  /** Expected action and provider context from the relying party. */
  readonly expected_context: Readonly<ProviderOutcomeContext>;
  readonly now: string;
  readonly maximum_observation_age_ms: number;
  readonly agility?: AgilityOptions;
}

export type ProviderOutcomeBindingCheck =
  | 'binding_structure'
  | 'provider_context_structure'
  | 'provider_context_digest'
  | 'expected_context_external'
  | 'expected_context_exact'
  | 'observation_present'
  | 'observation_digest'
  | 'source_identity_exact'
  | 'outcome_observation_v2'
  | 'action_exact'
  | 'operation_exact'
  | 'provider_context_signed'
  | 'observation_fresh';

export interface ProviderOutcomeBindingVerification {
  readonly valid: boolean;
  readonly status: 'VERIFIED' | 'INCOMPLETE' | 'CONFLICTED';
  readonly reason: string | null;
  readonly checks: Readonly<Record<ProviderOutcomeBindingCheck, boolean>>;
  readonly provider_context_digest: string | null;
  readonly outcome_observation_digest: string | null;
  readonly source_errors: readonly string[];
  readonly context: Readonly<ProviderOutcomeContext> | null;
  /** Signed interval from the verified Outcome Observation v2. */
  readonly observation_interval: Readonly<{
    observed_from: string;
    observed_until: string;
    attested_at: string;
  }> | null;
}

const CONTEXT_KEYS = [
  '@version',
  'tenant_id',
  'admission_id',
  'operation_id',
  'snapshot_digest',
  'caid',
  'action_digest',
  'effect_request_digest',
  'provider',
  'account',
  'environment',
  'adapter_id',
  'idempotency_key',
  'outcome',
  'observed_at',
] as const;

const BINDING_KEYS = [
  '@version',
  'provider_context',
  'provider_context_digest',
  'outcome_observation_digest',
  'claim_boundary',
] as const;

const SOURCE_KEYS = ['role', 'source_id', 'source_class'] as const;
const SOURCE_KEYS_WITH_FACILITY = [...SOURCE_KEYS, 'facility_id'] as const;

function canonicalUtcInstant(value: unknown): value is string {
  if (typeof value !== 'string' || !Number.isFinite(riskInstant(value))) return false;
  try {
    return new Date(Date.parse(value)).toISOString() === value;
  } catch {
    return false;
  }
}

function validContext(value: unknown): value is ProviderOutcomeContext {
  return riskExact(value, CONTEXT_KEYS)
    && value['@version'] === PROVIDER_OUTCOME_CONTEXT_VERSION
    && riskIdentifier(value.tenant_id)
    && riskIdentifier(value.admission_id)
    && riskIdentifier(value.operation_id)
    && typeof value.snapshot_digest === 'string'
    && RISK_DIGEST.test(value.snapshot_digest)
    && typeof value.caid === 'string'
    && RISK_CAID.test(value.caid)
    && typeof value.action_digest === 'string'
    && RISK_DIGEST.test(value.action_digest)
    && typeof value.effect_request_digest === 'string'
    && RISK_DIGEST.test(value.effect_request_digest)
    && riskIdentifier(value.provider)
    && riskIdentifier(value.account)
    && riskIdentifier(value.environment)
    && riskIdentifier(value.adapter_id)
    && riskIdentifier(value.idempotency_key)
    && PROVIDER_OUTCOMES.includes(value.outcome as ProviderOutcome)
    && canonicalUtcInstant(value.observed_at);
}

function validSourceIdentity(value: unknown): value is ProviderOutcomeSourceIdentity {
  if (!riskRecord(value)) return false;
  const keys = Object.hasOwn(value, 'facility_id')
    ? SOURCE_KEYS_WITH_FACILITY : SOURCE_KEYS;
  return riskExact(value, keys)
    && ['executor', 'system_of_record', 'independent_observer'].includes(value.role)
    && riskIdentifier(value.source_id)
    && riskIdentifier(value.source_class)
    && (!Object.hasOwn(value, 'facility_id') || riskIdentifier(value.facility_id));
}

function sameSourceIdentity(left: unknown, right: ProviderOutcomeSourceIdentity): boolean {
  return validSourceIdentity(left)
    && left.role === right.role
    && left.source_id === right.source_id
    && left.source_class === right.source_class
    && left.facility_id === right.facility_id;
}

function sameContext(left: ProviderOutcomeContext, right: ProviderOutcomeContext): boolean {
  return CONTEXT_KEYS.every((key) => left[key] === right[key]);
}

function fullV2Observation(value: unknown): value is RiskRecord {
  return riskRecord(value)
    && value['@version'] === 'EP-OUTCOME-OBSERVATION-v2'
    && riskRecord(value.proof)
    && Array.isArray(value.proof.signatures)
    && value.proof.signatures.length > 0;
}

/** Canonical, domain-separated digest committed by the signed observation. */
export function providerOutcomeContextDigest(context: unknown): string {
  if (!validContext(context)) throw new TypeError('provider outcome context is invalid');
  return riskDigest({
    profile: PROVIDER_OUTCOME_CONTEXT_VERSION,
    context,
  });
}

/**
 * The only observed-effect shape accepted by this bridge. Callers pass this
 * array to buildOutcomeObservationV2, so the source signatures cover the exact
 * provider-context digest.
 */
export function providerOutcomeObservationEffects(
  context: Readonly<ProviderOutcomeContext>,
): readonly Readonly<{ effect_type: string; target: string; value: string }>[] {
  const digest = providerOutcomeContextDigest(context);
  return riskFreeze([{
    effect_type: PROVIDER_OUTCOME_EFFECT_TYPE,
    target: context.provider,
    value: digest,
  }]);
}

/** Build a content-addressed bridge. Cryptographic acceptance happens only in verify. */
export function buildProviderOutcomeBinding(input: {
  provider_context: Readonly<ProviderOutcomeContext>;
  outcome_observation: unknown;
}): Readonly<ProviderOutcomeBinding> {
  if (!validContext(input?.provider_context)) {
    throw new TypeError('provider outcome context is invalid');
  }
  if (!fullV2Observation(input?.outcome_observation)) {
    throw new TypeError('a complete EP-OUTCOME-OBSERVATION-v2 is required');
  }
  const providerContext = riskClone(input.provider_context);
  return riskFreeze({
    '@version': PROVIDER_OUTCOME_BINDING_VERSION,
    provider_context: providerContext,
    provider_context_digest: providerOutcomeContextDigest(providerContext),
    outcome_observation_digest: riskDigest(input.outcome_observation),
    claim_boundary: PROVIDER_OUTCOME_BINDING_CLAIM_BOUNDARY,
  });
}

function emptyChecks(): Record<ProviderOutcomeBindingCheck, boolean> {
  return {
    binding_structure: false,
    provider_context_structure: false,
    provider_context_digest: false,
    expected_context_external: false,
    expected_context_exact: false,
    observation_present: false,
    observation_digest: false,
    source_identity_exact: false,
    outcome_observation_v2: false,
    action_exact: false,
    operation_exact: false,
    provider_context_signed: false,
    observation_fresh: false,
  };
}

function result(
  checks: Record<ProviderOutcomeBindingCheck, boolean>,
  status: ProviderOutcomeBindingVerification['status'],
  reason: string | null,
  binding: unknown,
  observation: unknown,
  sourceErrors: readonly string[] = [],
): Readonly<ProviderOutcomeBindingVerification> {
  const context = riskRecord(binding) && validContext(binding.provider_context)
    ? riskFreeze(riskClone(binding.provider_context)) : null;
  const observationInterval = fullV2Observation(observation)
      && canonicalUtcInstant(observation.observed_from)
      && canonicalUtcInstant(observation.observed_until)
      && canonicalUtcInstant(observation.attested_at)
    ? riskFreeze({
      observed_from: observation.observed_from,
      observed_until: observation.observed_until,
      attested_at: observation.attested_at,
    }) : null;
  return riskFreeze({
    valid: status === 'VERIFIED' && Object.values(checks).every(Boolean),
    status,
    reason,
    checks,
    provider_context_digest: context === null ? null : providerOutcomeContextDigest(context),
    outcome_observation_digest: fullV2Observation(observation)
      ? riskDigest(observation) : null,
    source_errors: [...sourceErrors],
    context,
    observation_interval: observationInterval,
  });
}

/**
 * Verify the signed outcome under external pins and exact relying-party input.
 * Caller input is always a refusal, never an exception.
 */
export async function verifyProviderOutcomeBinding(
  binding: unknown,
  outcomeObservation: unknown,
  options: Readonly<VerifyProviderOutcomeBindingOptions>,
): Promise<Readonly<ProviderOutcomeBindingVerification>> {
  const checks = emptyChecks();
  try {
    if (!riskExact(binding, BINDING_KEYS)
        || binding['@version'] !== PROVIDER_OUTCOME_BINDING_VERSION
        || binding.claim_boundary !== PROVIDER_OUTCOME_BINDING_CLAIM_BOUNDARY
        || typeof binding.provider_context_digest !== 'string'
        || !RISK_DIGEST.test(binding.provider_context_digest)
        || typeof binding.outcome_observation_digest !== 'string'
        || !RISK_DIGEST.test(binding.outcome_observation_digest)) {
      return result(checks, 'CONFLICTED', 'binding_structure_invalid', binding, outcomeObservation);
    }
    checks.binding_structure = true;

    if (!validContext(binding.provider_context)) {
      return result(checks, 'CONFLICTED', 'provider_context_invalid', binding, outcomeObservation);
    }
    checks.provider_context_structure = true;
    const contextDigest = providerOutcomeContextDigest(binding.provider_context);
    checks.provider_context_digest = contextDigest === binding.provider_context_digest;
    if (!checks.provider_context_digest) {
      return result(checks, 'CONFLICTED', 'provider_context_digest_mismatch', binding, outcomeObservation);
    }

    checks.expected_context_external = validContext(options?.expected_context);
    if (!checks.expected_context_external) {
      return result(checks, 'INCOMPLETE', 'expected_context_missing_or_invalid', binding, outcomeObservation);
    }
    checks.expected_context_exact = sameContext(binding.provider_context, options.expected_context);
    if (!checks.expected_context_exact) {
      return result(checks, 'CONFLICTED', 'expected_context_mismatch', binding, outcomeObservation);
    }

    if (!fullV2Observation(outcomeObservation)) {
      return result(checks, 'INCOMPLETE', 'complete_signed_observation_required', binding, outcomeObservation);
    }
    checks.observation_present = true;
    const observation = outcomeObservation;
    checks.observation_digest = riskDigest(observation)
      === binding.outcome_observation_digest;
    if (!checks.observation_digest) {
      return result(checks, 'CONFLICTED', 'outcome_observation_digest_mismatch', binding, outcomeObservation);
    }

    if (!validSourceIdentity(options?.expected_source)) {
      return result(checks, 'INCOMPLETE', 'expected_source_missing_or_invalid', binding, outcomeObservation);
    }
    checks.source_identity_exact = sameSourceIdentity(
      observation.source,
      options.expected_source,
    );
    if (!checks.source_identity_exact) {
      return result(checks, 'CONFLICTED', 'outcome_source_substitution', binding, outcomeObservation);
    }
    if (!riskRecord(options?.source_keys)
        || !riskRecord(options.source_keys[options.expected_source.source_id])) {
      return result(checks, 'INCOMPLETE', 'pinned_outcome_source_key_required', binding, outcomeObservation);
    }
    if (!canonicalUtcInstant(options?.now)
        || !Number.isSafeInteger(options?.maximum_observation_age_ms)
        || options.maximum_observation_age_ms < 0
        || options.maximum_observation_age_ms > 31_536_000_000) {
      return result(checks, 'INCOMPLETE', 'currentness_inputs_missing_or_invalid', binding, outcomeObservation);
    }

    const sourceVerification = await verifyOutcomeObservationV2(
      observation,
      {
        ...(options.agility ?? {}),
        sourceKeys: options.source_keys,
        now: options.now,
      },
    );
    checks.outcome_observation_v2 = sourceVerification.valid === true;
    if (!checks.outcome_observation_v2) {
      const stale = sourceVerification.errors.includes('outcome_source_key_not_current')
        || sourceVerification.errors.includes('observation_time_invalid_or_future');
      return result(
        checks,
        stale ? 'INCOMPLETE' : 'CONFLICTED',
        stale ? 'outcome_source_not_current' : 'outcome_observation_not_verified',
        binding,
        outcomeObservation,
        sourceVerification.errors,
      );
    }

    checks.action_exact = observation.action_hash === binding.provider_context.action_digest
      && observation.action_caid === binding.provider_context.caid;
    checks.operation_exact = observation.operation_id
      === binding.provider_context.operation_id;
    if (!checks.action_exact || !checks.operation_exact) {
      return result(checks, 'CONFLICTED', 'signed_observation_binding_mismatch', binding, outcomeObservation);
    }

    const expectedEffects = providerOutcomeObservationEffects(binding.provider_context);
    checks.provider_context_signed = riskDigest(observation.observed_effects)
      === riskDigest(expectedEffects)
      && Array.isArray(observation.observed_effects)
      && observation.observed_effects.length === 1;
    if (!checks.provider_context_signed) {
      return result(checks, 'CONFLICTED', 'provider_context_not_signed', binding, outcomeObservation);
    }

    // Each source has its own signed observation interval. provider_context.observed_at
    // is the shared provider-event time committed inside observed_effects, while
    // freshness is measured from this source's signed interval end.
    const age = Date.parse(options.now) - Date.parse(observation.observed_until);
    checks.observation_fresh = age >= 0 && age <= options.maximum_observation_age_ms;
    if (!checks.observation_fresh) {
      return result(checks, 'INCOMPLETE', 'outcome_observation_stale', binding, outcomeObservation);
    }

    return result(checks, 'VERIFIED', null, binding, outcomeObservation);
  } catch {
    return result(checks, 'CONFLICTED', 'provider_outcome_binding_invalid', binding, outcomeObservation);
  }
}
