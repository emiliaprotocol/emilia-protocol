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
    /** HTTP refusal status. Values outside 400 through 599 are normalized. */
    status?: number;
    /**
     * Plain finite-JSON object only. Before provider entry Gate canonicalizes,
     * snapshots, and bounds it to depth 32, 10,000 nodes, and 256 KiB of string
     * data. Dates, Maps, accessors, symbols, cycles, and non-finite numbers are
     * refused; finite decimal measurements remain valid.
     */
    evidence?: Record<string, any> | null;
    reservation?: 'release' | 'burn' | 'hold';
}>;
export type ProviderEntryGuard = ((context: ProviderEntryContext) => ProviderEntryGuardResult | Promise<ProviderEntryGuardResult>) & Readonly<{
    /**
     * An authenticated observation is advisory. When set, provider entry must
     * also serialize against this exact state domain in the owning store.
     */
    required_control_domain_id?: string;
}>;
/** Return the state domain that must serialize the final provider-entry step. */
export declare function requiredProviderEntryControlDomain(guard: ProviderEntryGuard | null | undefined): string | null;
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
export declare function createOrganizationStatusProviderEntryGuard({ organizationId, resolveStatus, maxAgeMs, now, controlDomainId, }: {
    organizationId: string;
    resolveStatus: (input: Readonly<{
        organization_id: string;
        context: ProviderEntryContext;
    }>) => OrganizationStatusObservation | Promise<OrganizationStatusObservation>;
    maxAgeMs?: number;
    now?: number | (() => number);
    /** Owning state domain that must serialize freeze and provider entry. */
    controlDomainId?: string;
}): ProviderEntryGuard;
declare const _default: {
    PROVIDER_ENTRY_GUARD_VERSION: string;
    providerEntryContext: typeof providerEntryContext;
    evaluateProviderEntryGuard: typeof evaluateProviderEntryGuard;
    composeProviderEntryGuards: typeof composeProviderEntryGuards;
    createOrganizationStatusProviderEntryGuard: typeof createOrganizationStatusProviderEntryGuard;
    requiredProviderEntryControlDomain: typeof requiredProviderEntryControlDomain;
};
export default _default;
//# sourceMappingURL=provider-entry.d.ts.map