import type { AdmissionSnapshot, AdmissionStore } from './admission-store.js';
import type { QualificationDecision } from '@emilia-protocol/verify/gate-qualification';
export declare const GATE_QUALIFICATION_V2_VERSION = "EP-GATE-QUALIFICATION-v2";
type AdmissionDigestV2 = AdmissionSnapshot['snapshot_digest'];
export type QualificationModeV2 = 'enforce' | 'shadow';
export type ProviderOutcomeV2 = 'COMMITTED' | 'PROVEN_NOT_COMMITTED' | 'INDETERMINATE';
export interface BoundRequirementDecisionV2 {
    readonly decision: 'allow' | 'deny';
    readonly requirementId: string;
    readonly caid: string;
    readonly actionDigest: AdmissionDigestV2;
    readonly evidenceDigest: AdmissionDigestV2;
    readonly reason?: string;
}
export interface BoundLocalPolicyDecisionV2 {
    readonly decision: 'allow' | 'deny';
    readonly policyId: string;
    /** Digest of the relying-party authorization policy that made this decision. */
    readonly policyDigest?: AdmissionDigestV2;
    readonly caid: string;
    readonly actionDigest: AdmissionDigestV2;
    readonly evidenceDigest: AdmissionDigestV2;
    readonly reason?: string;
}
/** The qualification leg is the verifier's real three-way result. */
export interface GateQualificationBundleV2 {
    readonly qualification: Readonly<QualificationDecision>;
    readonly aeb: Readonly<BoundRequirementDecisionV2>;
    readonly aec: Readonly<BoundRequirementDecisionV2>;
    readonly localPolicy: Readonly<BoundLocalPolicyDecisionV2>;
}
export interface QualificationCompositionInputV2 {
    readonly snapshot: Readonly<AdmissionSnapshot>;
    readonly qualification: Readonly<GateQualificationBundleV2>;
}
export interface GateQualificationDecisionV2 {
    readonly version: typeof GATE_QUALIFICATION_V2_VERSION;
    readonly allow: boolean;
    readonly reasons: readonly string[];
    readonly tenantId: string;
    readonly admissionId: string;
    readonly operationId: string;
    readonly caid: string;
    readonly actionDigest: string;
    readonly snapshotDigest: string;
    readonly programDigest: AdmissionDigestV2;
    readonly effectKey: string;
    readonly requirements: Readonly<{
        qualificationEvidenceDigest: string;
        aebRequirementId: string;
        aebEvidenceDigest: string;
        aecRequirementId: string;
        aecEvidenceDigest: string;
        localPolicyId: string;
        localPolicyEvidenceDigest: string;
    }>;
}
/**
 * The adapter sees only the exact immutable snapshot returned by
 * AdmissionStore.beginInvocation and the store-issued invocation capability.
 */
export interface ProtectedInvocationV2 {
    readonly snapshot: Readonly<AdmissionSnapshot>;
    readonly invocationToken: string;
}
export interface ProtectedReconciliationV2 extends ProtectedInvocationV2 {
    readonly reconciliationOnly: true;
}
/** Provider credentials and mutation implementation remain inside this object. */
export interface ProtectedAdapterV2 {
    readonly custody: 'protected';
    readonly credentialsExposed: false;
    invoke(input: Readonly<ProtectedInvocationV2>): Promise<unknown>;
    reconcile(input: Readonly<ProtectedReconciliationV2>): Promise<unknown>;
}
export interface ProviderEvidenceV2 {
    readonly evidenceId: string;
    readonly evidenceDigest: AdmissionDigestV2;
    readonly tenantId: string;
    readonly admissionId: string;
    readonly operationId: string;
    readonly snapshotDigest: AdmissionDigestV2;
    readonly caid: string;
    readonly actionDigest: AdmissionDigestV2;
    readonly effectRequestDigest: AdmissionDigestV2;
    readonly provider: Readonly<AdmissionSnapshot['body']['provider']>;
    readonly executorAdapterDigest: AdmissionDigestV2;
    readonly idempotencyKey: string;
    readonly outcome: ProviderOutcomeV2;
    readonly observedAt: string;
}
export type ProviderEvidenceVerificationV2 = {
    readonly ok: true;
    readonly evidence: Readonly<ProviderEvidenceV2>;
} | {
    readonly ok: false;
    readonly reason: string;
};
export interface ProviderEvidenceVerifierV2 {
    verify(rawEvidence: unknown, expected: Readonly<AdmissionSnapshot>): Promise<ProviderEvidenceVerificationV2>;
}
export interface ObservedEffectRelationV2 {
    readonly relation: 'OBSERVED_AS_REQUESTED' | 'DIVERGED' | 'INDETERMINATE';
    readonly evidenceDigest: AdmissionDigestV2 | null;
    readonly tenantId: string;
    readonly admissionId: string;
    readonly operationId: string;
    readonly snapshotDigest: AdmissionDigestV2;
    readonly caid: string;
    readonly actionDigest: AdmissionDigestV2;
    readonly providerEvidenceDigest: AdmissionDigestV2;
    readonly observedEffectDigest: AdmissionDigestV2 | null;
    readonly observedAt: string;
}
export interface ObservedEffectRelatorV2 {
    relate(evidence: Readonly<ProviderEvidenceV2>, expected: Readonly<AdmissionSnapshot>): Promise<Readonly<ObservedEffectRelationV2>>;
}
export interface LegacyQualificationV1 {
    qualify(input: Readonly<QualificationCompositionInputV2>): Promise<{
        readonly allow: boolean;
        readonly reasons: readonly string[];
    }>;
}
export type GateQualificationV2Options = {
    readonly mode: 'shadow';
    readonly legacyQualification?: LegacyQualificationV1;
    readonly admissionStore?: never;
    readonly protectedAdapter?: never;
    readonly providerEvidenceVerifier?: never;
    readonly observedEffectRelator?: never;
    readonly invocationRemeasurer?: never;
    readonly authorityCustody?: never;
    readonly adapterTimeoutMs?: never;
    readonly testOnly?: never;
} | {
    readonly mode: 'enforce';
    readonly admissionStore: AdmissionStore;
    readonly protectedAdapter: ProtectedAdapterV2;
    readonly providerEvidenceVerifier: ProviderEvidenceVerifierV2;
    readonly observedEffectRelator: ObservedEffectRelatorV2;
    readonly invocationRemeasurer: InvocationRemeasurerV2;
    readonly authorityCustody: InvocationAuthorityCustodyV2;
    readonly adapterTimeoutMs?: number;
    readonly testOnly?: true;
    readonly legacyQualification?: never;
};
export type GateQualificationExecutionInputV2 = QualificationCompositionInputV2;
export interface ShadowComparisonV2 {
    readonly legacyAllowed: boolean | null;
    readonly v2Allowed: boolean;
    readonly match: boolean | null;
    readonly legacyReasons: readonly string[];
    readonly v2Reasons: readonly string[];
}
export type GateQualificationExecutionResultV2 = {
    readonly status: 'shadow';
    readonly decision: Readonly<GateQualificationDecisionV2>;
    readonly comparison: Readonly<ShadowComparisonV2>;
} | {
    readonly status: 'refused';
    readonly reason: string;
    readonly programDigest: AdmissionDigestV2;
    readonly decision?: Readonly<GateQualificationDecisionV2>;
} | {
    readonly status: 'reconciliation_required';
    readonly reason: string;
    readonly admissionId: string;
} | {
    readonly status: 'committed' | 'not_committed';
    readonly admissionId: string;
    readonly evidence: Readonly<ProviderEvidenceV2>;
    readonly relation: Readonly<ObservedEffectRelationV2>;
};
interface InvocationAuthorityV2 {
    ownerToken: string;
    invocationToken: string;
    snapshotDigest: AdmissionDigestV2;
}
/**
 * A protected, restart-safe custody boundary for the capabilities needed to
 * reconcile an invocation whose provider outcome is not yet final.
 */
export interface InvocationAuthorityCustodyV2 {
    readonly custody: 'protected';
    readonly durable: boolean;
    readonly testOnly?: true;
    put(input: Readonly<{
        tenantId: string;
        admissionId: string;
        authority: Readonly<InvocationAuthorityV2>;
    }>): Promise<void>;
    get(input: Readonly<{
        tenantId: string;
        admissionId: string;
    }>): Promise<Readonly<InvocationAuthorityV2> | null>;
    delete(input: Readonly<{
        tenantId: string;
        admissionId: string;
    }>): Promise<void>;
}
/**
 * Rereads every mutable qualification/authority leg from authoritative
 * sources immediately before the store atomically consumes execution rights.
 */
export interface InvocationRemeasurerV2 {
    readonly source: 'authoritative';
    remeasure(snapshot: Readonly<AdmissionSnapshot>): Promise<Readonly<GateQualificationBundleV2>>;
}
/** Explicitly test-only custody. Production callers must supply durable KMS-backed custody. */
export declare function createMemoryInvocationAuthorityCustodyV2(): InvocationAuthorityCustodyV2 & {
    readonly testOnly: true;
};
/** Pure deterministic composition; it performs no store or adapter access. */
export declare function composeQualificationDecisionV2(input: QualificationCompositionInputV2): Readonly<GateQualificationDecisionV2>;
export declare class GateQualificationV2 {
    #private;
    readonly mode: QualificationModeV2;
    constructor(options: GateQualificationV2Options);
    execute(input: GateQualificationExecutionInputV2): Promise<GateQualificationExecutionResultV2>;
    /** Evidence-only reconciliation. This method has no mutation-adapter path. */
    reconcile(input: Readonly<Pick<AdmissionSnapshot['body'], 'tenant_id' | 'admission_id'>>): Promise<GateQualificationExecutionResultV2>;
}
declare const _default: {
    GATE_QUALIFICATION_V2_VERSION: string;
    composeQualificationDecisionV2: typeof composeQualificationDecisionV2;
    GateQualificationV2: typeof GateQualificationV2;
};
export default _default;
//# sourceMappingURL=gate-qualification-v2.d.ts.map