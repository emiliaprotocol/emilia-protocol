/**
 * Final, relying-party-owned checks immediately before an external provider is
 * entered. Receipt verification answers whether an action was authorized; this
 * boundary answers whether it is still safe to release the actuator now.
 */
export declare const PROVIDER_ENTRY_GUARD_VERSION = "EP-GATE-PROVIDER-ENTRY-GUARD-v1";
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
export type ProviderEntryGuard = (context: ProviderEntryContext) => ProviderEntryGuardResult | Promise<ProviderEntryGuardResult>;
/** Build an immutable context so a buggy policy hook cannot rewrite the effect. */
export declare function providerEntryContext({ authorization, selector, observedAction, capability, now, }?: {
    authorization?: Record<string, any> | null;
    selector?: Record<string, any>;
    observedAction?: Record<string, any> | null;
    capability?: Record<string, any> | null;
    now?: number | (() => number);
}): ProviderEntryContext;
/**
 * Execute one guard under a closed result contract. A throw, malformed result,
 * or non-boolean `ok` is an availability failure and therefore a refusal.
 */
export declare function evaluateProviderEntryGuard(guard: ProviderEntryGuard | null | undefined, context: ProviderEntryContext): Promise<ProviderEntryGuardResult>;
/** Compose independent guards without collapsing their evidence or semantics. */
export declare function composeProviderEntryGuards(...guards: Array<ProviderEntryGuard | null | undefined>): ProviderEntryGuard;
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
export declare function createOrganizationStatusProviderEntryGuard({ organizationId, resolveStatus, maxAgeMs, now, }: {
    organizationId: string;
    resolveStatus: (input: Readonly<{
        organization_id: string;
        context: ProviderEntryContext;
    }>) => OrganizationStatusObservation | Promise<OrganizationStatusObservation>;
    maxAgeMs?: number;
    now?: number | (() => number);
}): ProviderEntryGuard;
declare const _default: {
    PROVIDER_ENTRY_GUARD_VERSION: string;
    providerEntryContext: typeof providerEntryContext;
    evaluateProviderEntryGuard: typeof evaluateProviderEntryGuard;
    composeProviderEntryGuards: typeof composeProviderEntryGuards;
    createOrganizationStatusProviderEntryGuard: typeof createOrganizationStatusProviderEntryGuard;
};
export default _default;
//# sourceMappingURL=provider-entry.d.ts.map