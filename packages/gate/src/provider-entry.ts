// SPDX-License-Identifier: Apache-2.0

/**
 * Final, relying-party-owned checks immediately before an external provider is
 * entered. Receipt verification answers whether an action was authorized; this
 * boundary answers whether it is still safe to release the actuator now.
 */

export const PROVIDER_ENTRY_GUARD_VERSION = 'EP-GATE-PROVIDER-ENTRY-GUARD-v1';

export type ProviderEntryContext = Readonly<{
  authorization: Readonly<Record<string, any>>;
  selector: Readonly<Record<string, any>>;
  observed_action: Readonly<Record<string, any>> | null;
  capability: Readonly<Record<string, any>> | null;
  checked_at: string;
}>;

export type ProviderEntryGuardResult = Readonly<{
  ok: boolean;
  reason?: string;
  status?: number;
  evidence?: Record<string, any> | null;
  reservation?: 'release' | 'burn' | 'hold';
}>;

export type ProviderEntryGuard = ((
  context: ProviderEntryContext,
) => ProviderEntryGuardResult | Promise<ProviderEntryGuardResult>) & Readonly<{
  /**
   * An authenticated observation is advisory. When set, provider entry must
   * also serialize against this exact state domain in the owning store.
   */
  required_control_domain_id?: string;
}>;

function attachRequiredControlDomain(
  guard: ProviderEntryGuard,
  controlDomainId: string | null,
): ProviderEntryGuard {
  if (controlDomainId === null) return guard;
  Object.defineProperty(guard, 'required_control_domain_id', {
    value: controlDomainId,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  return guard;
}

/** Return the state domain that must serialize the final provider-entry step. */
export function requiredProviderEntryControlDomain(
  guard: ProviderEntryGuard | null | undefined,
): string | null {
  const value = guard?.required_control_domain_id;
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function cloneFreeze<T>(value: T): T {
  if (value === null || value === undefined) return value;
  const clone = structuredClone(value);
  const freeze = (candidate: any): any => {
    if (!candidate || typeof candidate !== 'object' || Object.isFrozen(candidate)) return candidate;
    for (const child of Object.values(candidate)) freeze(child);
    return Object.freeze(candidate);
  };
  return freeze(clone);
}

function boundedReason(value: unknown, fallback: string): string {
  return typeof value === 'string' && value.length > 0 && value.length <= 128
    ? value
    : fallback;
}

/** Build an immutable context so a buggy policy hook cannot rewrite the effect. */
export function providerEntryContext({
  authorization,
  selector = {},
  observedAction = null,
  capability = null,
  now = Date.now,
}: {
  authorization?: Record<string, any> | null;
  selector?: Record<string, any>;
  observedAction?: Record<string, any> | null;
  capability?: Record<string, any> | null;
  now?: number | (() => number);
} = {}): ProviderEntryContext {
  const at = typeof now === 'function' ? now() : now;
  if (!Number.isFinite(at)) throw new TypeError('provider-entry clock must be finite');
  return Object.freeze({
    authorization: cloneFreeze(authorization ?? {}),
    selector: cloneFreeze(selector),
    observed_action: cloneFreeze(observedAction),
    capability: cloneFreeze(capability),
    checked_at: new Date(Number(at)).toISOString(),
  });
}

/**
 * Execute one guard under a closed result contract. A throw, malformed result,
 * or non-boolean `ok` is an availability failure and therefore a refusal.
 */
export async function evaluateProviderEntryGuard(
  guard: ProviderEntryGuard | null | undefined,
  context: ProviderEntryContext,
): Promise<ProviderEntryGuardResult> {
  if (guard == null) return Object.freeze({ ok: true, evidence: null });
  if (typeof guard !== 'function') {
    return Object.freeze({
      ok: false,
      reason: 'provider_entry_guard_invalid',
      status: 503,
      reservation: 'hold',
    });
  }
  try {
    const result = await guard(context);
    if (!result || typeof result !== 'object' || typeof result.ok !== 'boolean') {
      return Object.freeze({
        ok: false,
        reason: 'provider_entry_guard_malformed',
        status: 503,
        reservation: 'hold',
      });
    }
    if (result.ok !== true) {
      const dispositionValid = result.reservation === undefined
        || result.reservation === 'release'
        || result.reservation === 'burn'
        || result.reservation === 'hold';
      return Object.freeze({
        ok: false,
        reason: dispositionValid
          ? boundedReason(result.reason, 'provider_entry_refused')
          : 'provider_entry_guard_disposition_invalid',
        status: Number.isSafeInteger(result.status) && Number(result.status) >= 400
          ? Number(result.status)
          : 409,
        evidence: cloneFreeze(result.evidence ?? null),
        reservation: dispositionValid && result.reservation !== undefined
          ? result.reservation
          : 'hold',
      });
    }
    return Object.freeze({ ok: true, evidence: cloneFreeze(result.evidence ?? null) });
  } catch {
    return Object.freeze({
      ok: false,
      reason: 'provider_entry_guard_unavailable',
      status: 503,
      reservation: 'hold',
    });
  }
}

/** Compose independent guards without collapsing their evidence or semantics. */
export function composeProviderEntryGuards(
  ...guards: Array<ProviderEntryGuard | null | undefined>
): ProviderEntryGuard {
  const active = guards.filter((guard): guard is ProviderEntryGuard => typeof guard === 'function');
  const controlDomains = [...new Set(active
    .map((guard) => requiredProviderEntryControlDomain(guard))
    .filter((value): value is string => value !== null))];
  if (controlDomains.length > 1) {
    throw new TypeError('provider-entry guards require different serialized control domains');
  }
  const composed: ProviderEntryGuard = async (context) => {
    const evidence: Record<string, any>[] = [];
    for (const guard of active) {
      const result = await evaluateProviderEntryGuard(guard, context);
      if (!result.ok) return result;
      if (result.evidence) evidence.push(result.evidence);
    }
    return { ok: true, evidence: { guards: evidence } };
  };
  return attachRequiredControlDomain(composed, controlDomains[0] ?? null);
}

export type OrganizationStatusObservation = Readonly<{
  organization_id: string;
  status: 'active' | 'suspended' | 'revoked' | 'archived';
  epoch: number;
  observed_at: string;
  authenticated: boolean;
  source_digest?: string | null;
}>;

/**
 * Organization-wide panic check. The deployment pins its organization and its
 * authenticated status resolver; presenter-supplied status is never accepted.
 */
export function createOrganizationStatusProviderEntryGuard({
  organizationId,
  resolveStatus,
  maxAgeMs = 5_000,
  now = Date.now,
  controlDomainId = organizationId,
}: {
  organizationId: string;
  resolveStatus: (input: Readonly<{ organization_id: string; context: ProviderEntryContext }>) =>
    OrganizationStatusObservation | Promise<OrganizationStatusObservation>;
  maxAgeMs?: number;
  now?: number | (() => number);
  /** Owning state domain that must serialize freeze and provider entry. */
  controlDomainId?: string;
}): ProviderEntryGuard {
  if (typeof organizationId !== 'string' || organizationId.length === 0 || organizationId.length > 512) {
    throw new TypeError('organizationId must be a bounded non-empty string');
  }
  if (typeof resolveStatus !== 'function') throw new TypeError('resolveStatus must be a function');
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 0 || maxAgeMs > 60_000) {
    throw new TypeError('maxAgeMs must be a safe integer from 0 through 60000');
  }
  if (typeof controlDomainId !== 'string' || controlDomainId.length === 0
      || controlDomainId.length > 512) {
    throw new TypeError('controlDomainId must be a bounded non-empty string');
  }
  const guard: ProviderEntryGuard = async (context) => {
    let status: OrganizationStatusObservation;
    try {
      status = await resolveStatus(Object.freeze({ organization_id: organizationId, context }));
    } catch {
      return { ok: false, reason: 'organization_status_unavailable', status: 503, reservation: 'hold' };
    }
    if (!status || status.authenticated !== true) {
      return { ok: false, reason: 'organization_status_unauthenticated', status: 503, reservation: 'hold' };
    }
    if (status.organization_id !== organizationId) {
      return { ok: false, reason: 'organization_status_mismatch', status: 409, reservation: 'hold' };
    }
    if (!Number.isSafeInteger(status.epoch) || status.epoch < 0) {
      return { ok: false, reason: 'organization_status_epoch_invalid', status: 503, reservation: 'hold' };
    }
    const observedAt = Date.parse(status.observed_at);
    const at = typeof now === 'function' ? now() : now;
    if (!Number.isFinite(observedAt) || !Number.isFinite(at)
        || observedAt > Number(at) + 1_000 || Number(at) - observedAt > maxAgeMs) {
      return { ok: false, reason: 'organization_status_stale', status: 503, reservation: 'hold' };
    }
    if (status.status !== 'active') {
      return {
        ok: false,
        reason: status.status === 'suspended'
          ? 'organization_suspended'
          : status.status === 'revoked'
            ? 'organization_revoked'
            : 'organization_archived',
        status: 423,
        reservation: 'burn',
        evidence: { organization_id: organizationId, status: status.status, epoch: status.epoch },
      };
    }
    return {
      ok: true,
      evidence: {
        version: PROVIDER_ENTRY_GUARD_VERSION,
        kind: 'organization_status',
        organization_id: organizationId,
        status: 'active',
        epoch: status.epoch,
        observed_at: status.observed_at,
        source_digest: status.source_digest ?? null,
      },
    };
  };
  return attachRequiredControlDomain(guard, controlDomainId);
}

export default {
  PROVIDER_ENTRY_GUARD_VERSION,
  providerEntryContext,
  evaluateProviderEntryGuard,
  composeProviderEntryGuards,
  createOrganizationStatusProviderEntryGuard,
  requiredProviderEntryControlDomain,
};
