import type { AgilityOptions } from '@emilia-protocol/verify/pq-signature-agility';
import { type RiskRecord } from './reliance-risk-crypto.js';
export declare const PROVIDER_OUTCOME_CONTEXT_VERSION = "EP-PROVIDER-OUTCOME-CONTEXT-v1";
export declare const PROVIDER_OUTCOME_BINDING_VERSION = "EP-PROVIDER-OUTCOME-BINDING-v1";
export declare const PROVIDER_OUTCOME_EFFECT_TYPE = "emilia.provider_outcome.v1";
export declare const PROVIDER_OUTCOME_BINDING_CLAIM_BOUNDARY = "verified_source_observation_bound_to_one_exact_provider_context_not_provider_truth_not_external_effect_not_coverage_not_claim_adjudication";
export declare const PROVIDER_OUTCOMES: readonly ["COMMITTED", "PROVEN_NOT_COMMITTED", "INDETERMINATE"];
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
export type ProviderOutcomeBindingCheck = 'binding_structure' | 'provider_context_structure' | 'provider_context_digest' | 'expected_context_external' | 'expected_context_exact' | 'observation_present' | 'observation_digest' | 'source_identity_exact' | 'outcome_observation_v2' | 'action_exact' | 'operation_exact' | 'provider_context_signed' | 'observation_fresh';
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
/** Canonical, domain-separated digest committed by the signed observation. */
export declare function providerOutcomeContextDigest(context: unknown): string;
/**
 * The only observed-effect shape accepted by this bridge. Callers pass this
 * array to buildOutcomeObservationV2, so the source signatures cover the exact
 * provider-context digest.
 */
export declare function providerOutcomeObservationEffects(context: Readonly<ProviderOutcomeContext>): readonly Readonly<{
    effect_type: string;
    target: string;
    value: string;
}>[];
/** Build a content-addressed bridge. Cryptographic acceptance happens only in verify. */
export declare function buildProviderOutcomeBinding(input: {
    provider_context: Readonly<ProviderOutcomeContext>;
    outcome_observation: unknown;
}): Readonly<ProviderOutcomeBinding>;
/**
 * Verify the signed outcome under external pins and exact relying-party input.
 * Caller input is always a refusal, never an exception.
 */
export declare function verifyProviderOutcomeBinding(binding: unknown, outcomeObservation: unknown, options: Readonly<VerifyProviderOutcomeBindingOptions>): Promise<Readonly<ProviderOutcomeBindingVerification>>;
//# sourceMappingURL=provider-outcome-binding.d.ts.map