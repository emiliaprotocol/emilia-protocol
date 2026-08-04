// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Final, relying-party-owned checks immediately before an external provider is
 * entered. Receipt verification answers whether an action was authorized; this
 * boundary answers whether it is still safe to release the actuator now.
 */
export const PROVIDER_ENTRY_GUARD_VERSION = 'EP-GATE-PROVIDER-ENTRY-GUARD-v1';
function cloneFreeze(value) {
    if (value === null || value === undefined)
        return value;
    const clone = structuredClone(value);
    const freeze = (candidate) => {
        if (!candidate || typeof candidate !== 'object' || Object.isFrozen(candidate))
            return candidate;
        for (const child of Object.values(candidate))
            freeze(child);
        return Object.freeze(candidate);
    };
    return freeze(clone);
}
function boundedReason(value, fallback) {
    return typeof value === 'string' && value.length > 0 && value.length <= 128
        ? value
        : fallback;
}
/** Build an immutable context so a buggy policy hook cannot rewrite the effect. */
export function providerEntryContext({ authorization, selector = {}, observedAction = null, capability = null, now = Date.now, } = {}) {
    const at = typeof now === 'function' ? now() : now;
    if (!Number.isFinite(at))
        throw new TypeError('provider-entry clock must be finite');
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
export async function evaluateProviderEntryGuard(guard, context) {
    if (guard == null)
        return Object.freeze({ ok: true, evidence: null });
    if (typeof guard !== 'function') {
        return Object.freeze({ ok: false, reason: 'provider_entry_guard_invalid', status: 503 });
    }
    try {
        const result = await guard(context);
        if (!result || typeof result !== 'object' || typeof result.ok !== 'boolean') {
            return Object.freeze({ ok: false, reason: 'provider_entry_guard_malformed', status: 503 });
        }
        if (result.ok !== true) {
            return Object.freeze({
                ok: false,
                reason: boundedReason(result.reason, 'provider_entry_refused'),
                status: Number.isSafeInteger(result.status) && Number(result.status) >= 400
                    ? Number(result.status)
                    : 409,
                evidence: cloneFreeze(result.evidence ?? null),
                reservation: result.reservation === 'release'
                    || result.reservation === 'burn'
                    || result.reservation === 'hold'
                    ? result.reservation
                    : 'hold',
            });
        }
        return Object.freeze({ ok: true, evidence: cloneFreeze(result.evidence ?? null) });
    }
    catch {
        return Object.freeze({
            ok: false,
            reason: 'provider_entry_guard_unavailable',
            status: 503,
            reservation: 'hold',
        });
    }
}
/** Compose independent guards without collapsing their evidence or semantics. */
export function composeProviderEntryGuards(...guards) {
    const active = guards.filter((guard) => typeof guard === 'function');
    return async (context) => {
        const evidence = [];
        for (const guard of active) {
            const result = await evaluateProviderEntryGuard(guard, context);
            if (!result.ok)
                return result;
            if (result.evidence)
                evidence.push(result.evidence);
        }
        return { ok: true, evidence: { guards: evidence } };
    };
}
/**
 * Organization-wide panic check. The deployment pins its organization and its
 * authenticated status resolver; presenter-supplied status is never accepted.
 */
export function createOrganizationStatusProviderEntryGuard({ organizationId, resolveStatus, maxAgeMs = 5_000, now = Date.now, }) {
    if (typeof organizationId !== 'string' || organizationId.length === 0 || organizationId.length > 512) {
        throw new TypeError('organizationId must be a bounded non-empty string');
    }
    if (typeof resolveStatus !== 'function')
        throw new TypeError('resolveStatus must be a function');
    if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 0 || maxAgeMs > 60_000) {
        throw new TypeError('maxAgeMs must be a safe integer from 0 through 60000');
    }
    return async (context) => {
        let status;
        try {
            status = await resolveStatus(Object.freeze({ organization_id: organizationId, context }));
        }
        catch {
            return { ok: false, reason: 'organization_status_unavailable', status: 503 };
        }
        if (!status || status.authenticated !== true) {
            return { ok: false, reason: 'organization_status_unauthenticated', status: 503 };
        }
        if (status.organization_id !== organizationId) {
            return { ok: false, reason: 'organization_status_mismatch', status: 409 };
        }
        if (!Number.isSafeInteger(status.epoch) || status.epoch < 0) {
            return { ok: false, reason: 'organization_status_epoch_invalid', status: 503 };
        }
        const observedAt = Date.parse(status.observed_at);
        const at = typeof now === 'function' ? now() : now;
        if (!Number.isFinite(observedAt) || !Number.isFinite(at)
            || observedAt > Number(at) + 1_000 || Number(at) - observedAt > maxAgeMs) {
            return { ok: false, reason: 'organization_status_stale', status: 503 };
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
}
export default {
    PROVIDER_ENTRY_GUARD_VERSION,
    providerEntryContext,
    evaluateProviderEntryGuard,
    composeProviderEntryGuards,
    createOrganizationStatusProviderEntryGuard,
};
//# sourceMappingURL=provider-entry.js.map