// SPDX-License-Identifier: Apache-2.0
/**
 * Server-pinned EP-STATUS-v1 verification for Proposal-to-Effect AEB legs.
 *
 * Signed non-revocation status and relying-party consumption state answer
 * different questions. This helper authenticates the former with
 * verifyStatusArtifact and requires an authenticated local answer for the
 * latter. The later atomic AEB reserve remains the race-closing operation.
 */

import type { AebDigest, AebStatusInput } from '@emilia-protocol/verify/aeb-adapter-contract';
import {
  verifyStatusArtifact,
  type RevokerAuthorityPin,
  type StatusTarget,
} from '@emilia-protocol/verify/status';

import type {
  ProposalToEffectCurrentStatusVerification,
  ProposalToEffectOptions,
} from './proposal-to-effect.js';

type MaybePromise<T> = T | Promise<T>;
type ProposalToEffectStatusVerifier = ProposalToEffectOptions['aeb']['statusVerifier'];

export type ProposalToEffectStatusVerifierInput =
  Parameters<ProposalToEffectStatusVerifier>[0];
export type ProposalToEffectStatusExpected =
  Readonly<ProposalToEffectStatusVerifierInput['expected']>;

export interface ProposalToEffectStatusResolverContext {
  expected: ProposalToEffectStatusExpected;
  target: Readonly<StatusTarget>;
}

export interface ProposalToEffectPreviousHeadResolution {
  /** Confirms this result came from the relying party's authenticated store. */
  authenticated: boolean;
  /** Null means the store authoritatively has no accepted head for the target. */
  status: unknown | null;
}

export interface ProposalToEffectConsumptionState {
  /** Must be true; presenter assertions and unauthenticated cache data fail. */
  authenticated: boolean;
  consumed: boolean;
}

export interface ProposalToEffectConsumptionResolverContext
  extends ProposalToEffectStatusResolverContext {
  status_digest: AebDigest;
  sequence: number;
}

export interface ProposalToEffectStatusVerifierOptions {
  /** Copied at factory construction; callers cannot swap the authority pin later. */
  authorityPin: RevokerAuthorityPin;
  /** Trusted code mapping the closed PTE expected binding to one exact status target. */
  targetMapper(input: {
    expected: ProposalToEffectStatusExpected;
  }): MaybePromise<StatusTarget>;
  /** Server-side certificate lookup. The presenter never supplies this certificate. */
  certificateResolver(
    input: ProposalToEffectStatusResolverContext,
  ): MaybePromise<unknown>;
  /** Server-side lookup of the relying party's previously accepted status head. */
  previousHeadResolver(
    input: ProposalToEffectStatusResolverContext,
  ): MaybePromise<ProposalToEffectPreviousHeadResolution>;
  /** Authenticated local consumption lookup; this is not inferred from EP-STATUS-v1. */
  consumptionStateResolver(
    input: ProposalToEffectConsumptionResolverContext,
  ): MaybePromise<ProposalToEffectConsumptionState>;
}

const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const CAID_PATTERN = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
const EXPECTED_KEYS = [
  'tenant_id',
  'executor_id',
  'operation_id',
  'caid',
  'artifact_ref',
  'evidence_digest',
  'replay_unit',
] as const;
const TARGET_KEYS = ['type', 'id', 'digest', 'usage'] as const;
const AUTHORITY_PIN_KEYS = [
  'authority_domain',
  'authority_id',
  'key_id',
  'public_key',
] as const;

function dataRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return Boolean(descriptor?.enumerable && Object.hasOwn(descriptor, 'value'));
  });
}

function exactDataRecord(
  value: unknown,
  keys: readonly string[],
): value is Record<string, unknown> {
  if (!dataRecord(value)) return false;
  const actual = Reflect.ownKeys(value);
  return actual.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function boundedString(value: unknown, maximum = 512): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum;
}

function digest(value: unknown): value is AebDigest {
  return typeof value === 'string' && DIGEST_PATTERN.test(value);
}

function snapshotAuthorityPin(value: unknown): Readonly<RevokerAuthorityPin> | null {
  if (!exactDataRecord(value, AUTHORITY_PIN_KEYS)
      || !boundedString(value.authority_domain, 253)
      || !boundedString(value.authority_id)
      || !boundedString(value.key_id)
      || !boundedString(value.public_key, 4096)) return null;
  return Object.freeze({
    authority_domain: value.authority_domain,
    authority_id: value.authority_id,
    key_id: value.key_id,
    public_key: value.public_key,
  });
}

function snapshotExpected(value: unknown): ProposalToEffectStatusExpected | null {
  if (!exactDataRecord(value, EXPECTED_KEYS)
      || !boundedString(value.tenant_id)
      || !boundedString(value.executor_id)
      || !boundedString(value.operation_id)
      || typeof value.caid !== 'string'
      || !CAID_PATTERN.test(value.caid)
      || !boundedString(value.artifact_ref)
      || !digest(value.evidence_digest)
      || !digest(value.replay_unit)) return null;
  return Object.freeze({
    tenant_id: value.tenant_id,
    executor_id: value.executor_id,
    operation_id: value.operation_id,
    caid: value.caid,
    artifact_ref: value.artifact_ref,
    evidence_digest: value.evidence_digest,
    replay_unit: value.replay_unit,
  });
}

function snapshotTarget(value: unknown): Readonly<StatusTarget> | null {
  if (!exactDataRecord(value, TARGET_KEYS)
      || !['receipt', 'commit', 'delegation'].includes(value.type as string)
      || !boundedString(value.id)
      || !digest(value.digest)
      || !['authorization', 'execution', 'delegation'].includes(value.usage as string)) {
    return null;
  }
  return Object.freeze({
    type: value.type as StatusTarget['type'],
    id: value.id,
    digest: value.digest,
    usage: value.usage as StatusTarget['usage'],
  });
}

function denseDataArray(value: unknown): value is unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return false;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || !keys.includes('length')) return false;
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return false;
  }
  return true;
}

function snapshotJson(value: unknown, seen = new WeakSet<object>()): unknown {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (Number.isFinite(value)) return value;
    throw new TypeError('non-finite JSON number');
  }
  if (typeof value !== 'object' || seen.has(value)) {
    throw new TypeError('value is outside the JSON data model');
  }
  seen.add(value);
  if (denseDataArray(value)) {
    return value.map((member) => snapshotJson(member, seen));
  }
  if (!dataRecord(value)) throw new TypeError('value is not a plain data object');
  const snapshot: Record<string, unknown> = {};
  for (const key of Object.keys(value)) {
    snapshot[key] = snapshotJson(value[key], seen);
  }
  return snapshot;
}

function normalizedInstant(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) return null;
  return new Date(milliseconds).toISOString();
}

function refusal(
  outcome: 'revoked' | 'indeterminate',
  reason: string,
): ProposalToEffectCurrentStatusVerification {
  return {
    valid: false,
    outcome,
    status: null,
    reason,
  };
}

function verifierConfiguration(
  options: ProposalToEffectStatusVerifierOptions,
): Readonly<RevokerAuthorityPin> {
  const authorityPin = snapshotAuthorityPin(options?.authorityPin);
  if (!authorityPin
      || typeof options.targetMapper !== 'function'
      || typeof options.certificateResolver !== 'function'
      || typeof options.previousHeadResolver !== 'function'
      || typeof options.consumptionStateResolver !== 'function') {
    throw new TypeError('proposal_to_effect_status_configuration_invalid');
  }
  return authorityPin;
}

/**
 * Build the server-side verifier expected by
 * `ProposalToEffectOptions.aeb.statusVerifier`.
 */
export function createProposalToEffectStatusVerifier(
  options: ProposalToEffectStatusVerifierOptions,
): ProposalToEffectStatusVerifier {
  const authorityPin = verifierConfiguration(options);
  const targetMapper = options.targetMapper;
  const certificateResolver = options.certificateResolver;
  const previousHeadResolver = options.previousHeadResolver;
  const consumptionStateResolver = options.consumptionStateResolver;

  return async (input): Promise<ProposalToEffectCurrentStatusVerification> => {
    const expected = snapshotExpected(input?.expected);
    const checkedAt = normalizedInstant(input?.now);
    if (!expected || !checkedAt) {
      return refusal('indeterminate', 'status_expected_binding_invalid');
    }

    let statusArtifact: unknown;
    let target: Readonly<StatusTarget>;
    try {
      statusArtifact = snapshotJson(input.status_artifact);
      const mapped = await targetMapper({ expected });
      const snapshot = snapshotTarget(mapped);
      if (!snapshot) return refusal('indeterminate', 'status_target_resolution_failed');
      target = snapshot;
    } catch {
      return refusal('indeterminate', 'status_target_resolution_failed');
    }

    const context = Object.freeze({ expected, target });
    let certificate: unknown;
    let previousStatus: unknown;
    try {
      const resolvedCertificate = await certificateResolver(context);
      if (resolvedCertificate === undefined || resolvedCertificate === null) {
        return refusal('indeterminate', 'status_certificate_unavailable');
      }
      certificate = snapshotJson(resolvedCertificate);
    } catch {
      return refusal('indeterminate', 'status_certificate_unavailable');
    }
    try {
      const resolution = await previousHeadResolver(context);
      if (!dataRecord(resolution)
          || resolution.authenticated !== true
          || !Object.hasOwn(resolution, 'status')
          || resolution.status === undefined) {
        return refusal('indeterminate', 'status_previous_head_unavailable');
      }
      previousStatus = resolution.status === null
        ? undefined : snapshotJson(resolution.status);
    } catch {
      return refusal('indeterminate', 'status_previous_head_unavailable');
    }

    const verification = verifyStatusArtifact(target, statusArtifact, {
      authorityPin,
      certificate,
      previousStatus,
      now: input.now,
    });
    if (!verification.valid || verification.outcome === 'indeterminate') {
      return refusal(
        'indeterminate',
        verification.reasons[0] ?? 'status_verification_failed',
      );
    }
    if (verification.outcome === 'revoked') {
      return refusal('revoked', 'status_revoked');
    }
    if (!digest(verification.status_digest)
        || !Number.isSafeInteger(verification.sequence)
        || verification.sequence === null) {
      return refusal('indeterminate', 'status_verification_incomplete');
    }

    let consumption: ProposalToEffectConsumptionState;
    try {
      consumption = await consumptionStateResolver(Object.freeze({
        ...context,
        status_digest: verification.status_digest,
        sequence: verification.sequence,
      }));
    } catch {
      return refusal('indeterminate', 'status_consumption_state_unavailable');
    }
    if (!dataRecord(consumption)
        || consumption.authenticated !== true
        || typeof consumption.consumed !== 'boolean') {
      return refusal('indeterminate', 'status_consumption_state_unknown');
    }
    if (consumption.consumed) {
      return refusal('indeterminate', 'status_consumed');
    }

    const expiresAt = normalizedInstant(verification.next_update);
    if (!expiresAt || Date.parse(checkedAt) >= Date.parse(expiresAt)) {
      return refusal('indeterminate', 'status_expiry_invalid');
    }

    // This local answer is an authenticated pre-reservation observation. It
    // does not claim race freedom; Proposal-to-Effect's atomic AEB reserve does.
    const status: AebStatusInput = {
      checked_at: checkedAt,
      expires_at: expiresAt,
      revocation_checked: true,
      revoked: false,
      consumed: false,
    };
    return {
      valid: true,
      outcome: 'current_not_revoked',
      status,
    };
  };
}
