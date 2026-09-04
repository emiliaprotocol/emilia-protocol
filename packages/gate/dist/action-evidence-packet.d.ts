/**
 * Action Evidence Packet v1.
 *
 * This is a content-addressed join of native artifacts for one exact Gate
 * action. This module orchestrates relying-party-supplied native verifier
 * adapters; it does not itself implement or certify those native verifiers.
 * The packet never decides coverage, causation, liability, a claim, or payment.
 */
import { type RiskRecord } from './reliance-risk-crypto.js';
import { type ProviderOutcomeContext, type ProviderOutcomeSourceIdentity } from './provider-outcome-binding.js';
import type { AgilityOptions } from '@emilia-protocol/verify/pq-signature-agility';
export declare const ACTION_EVIDENCE_PACKET_VERSION = "EP-ACTION-EVIDENCE-PACKET-v1";
export declare const ACTION_EVIDENCE_MANIFEST_VERSION = "EP-ACTION-EVIDENCE-MANIFEST-v1";
export declare const ACTION_EVIDENCE_PACKET_RESULT_VERSION = "EP-ACTION-EVIDENCE-PACKET-RESULT-v1";
export declare const ACTION_EVIDENCE_PACKET_CLAIM_BOUNDARY = "technical_evidence_join_for_one_exact_action_not_insurance_coverage_not_claim_adjudication_not_causation_not_liability_not_payment";
export declare const ACTION_EVIDENCE_PACKET_RESULTS: readonly ["TECHNICALLY_COMPLETE", "INCOMPLETE", "CONFLICTED", "INDETERMINATE"];
export type ActionEvidencePacketResult = typeof ACTION_EVIDENCE_PACKET_RESULTS[number];
export type ActionEvidenceScheduleEvaluation = 'ELIGIBLE' | 'NOT_ELIGIBLE' | 'INDETERMINATE';
export declare const ACTION_EVIDENCE_COMPONENT_ROLES: readonly ["aeb", "admission_snapshot", "admission_decision", "qualification_statement", "qualification_status_head", "open_exposure_ceiling", "open_exposure_record", "open_exposure_history", "observed_effect_relation", "coverage_surface", "refusal_probe", "supplied_population_report", "loss_report", "recourse", "loss_allocation"];
export type ActionEvidenceComponentRole = typeof ACTION_EVIDENCE_COMPONENT_ROLES[number];
declare const REQUIRED_COMPONENT_ROLES: readonly ["aeb", "admission_snapshot", "admission_decision", "qualification_statement", "qualification_status_head", "open_exposure_ceiling", "open_exposure_record", "open_exposure_history", "observed_effect_relation", "coverage_surface", "refusal_probe", "supplied_population_report"];
declare const OPTIONAL_COMPONENT_ROLES: readonly ["loss_report", "recourse", "loss_allocation"];
export interface ActionEvidenceArtifactReference {
    readonly artifact_digest: string;
    /** Native result normalized by the relying-party-selected verifier. */
    readonly expected_state: string;
}
export interface ActionEvidenceScheduleReference {
    readonly artifact_digest: string;
    readonly evaluation: ActionEvidenceScheduleEvaluation;
}
export interface ActionEvidenceProviderReference {
    readonly binding_artifact_digest: string;
    readonly outcome_observation_artifact_digest: string;
    readonly expected_source: Readonly<ProviderOutcomeSourceIdentity>;
}
export interface ActionEvidenceOutcomeSourceRequirement {
    readonly role: ProviderOutcomeSourceIdentity['role'];
    readonly source_class: string;
}
export interface ActionEvidenceObservationWindow {
    readonly opens_before_provider_entry_sec: number;
    readonly closes_after_provider_entry_sec: number;
    readonly max_observation_age_sec: number;
}
export interface ActionEvidenceOutcomeRequirements {
    readonly required_sources: readonly Readonly<ActionEvidenceOutcomeSourceRequirement>[];
    readonly quorum: number;
    readonly observation_window: Readonly<ActionEvidenceObservationWindow>;
    readonly require_control_domain_independence: true;
}
export type ActionEvidenceComponents = {
    readonly [K in typeof REQUIRED_COMPONENT_ROLES[number]]: Readonly<ActionEvidenceArtifactReference>;
} & {
    readonly [K in typeof OPTIONAL_COMPONENT_ROLES[number]]: Readonly<ActionEvidenceArtifactReference> | null;
};
export interface ActionEvidenceManifest {
    readonly '@version': typeof ACTION_EVIDENCE_MANIFEST_VERSION;
    readonly packet_id: string;
    readonly assembled_at: string;
    readonly subject: Readonly<ProviderOutcomeContext>;
    readonly subject_digest: string;
    readonly schedule: Readonly<ActionEvidenceScheduleReference>;
    readonly components: Readonly<ActionEvidenceComponents>;
    readonly provider_outcomes: readonly Readonly<ActionEvidenceProviderReference>[];
    readonly claim_boundary: typeof ACTION_EVIDENCE_PACKET_CLAIM_BOUNDARY;
}
export interface ActionEvidencePacket {
    readonly '@version': typeof ACTION_EVIDENCE_PACKET_VERSION;
    readonly manifest: Readonly<ActionEvidenceManifest>;
    readonly manifest_digest: string;
    readonly attachments: Readonly<Record<string, unknown>>;
}
export type NativeEvidenceStatus = 'VERIFIED' | 'NOT_VERIFIED' | 'INDETERMINATE';
export type NativeEvidenceCurrentness = 'CURRENT' | 'STALE' | 'INDETERMINATE';
export interface ActionEvidenceNativeVerification {
    readonly verification: NativeEvidenceStatus;
    readonly currentness: NativeEvidenceCurrentness;
    /** Recomputed by the native adapter, never copied from the manifest. */
    readonly artifact_digest: string;
    /** Exact action join produced by the trusted adapter. */
    readonly subject_digest: string;
    /** Normalized native state, compared with the manifest reference. */
    readonly state: string;
    readonly reason: string | null;
}
export interface ActionEvidenceScheduleVerification extends Omit<ActionEvidenceNativeVerification, 'state'> {
    readonly evaluation: ActionEvidenceScheduleEvaluation;
    /** Read from the verified schedule, not from the packet manifest. */
    readonly outcome_requirements: Readonly<ActionEvidenceOutcomeRequirements>;
}
export interface ActionEvidenceVerificationRequest {
    readonly role: ActionEvidenceComponentRole;
    readonly artifact: unknown;
    readonly artifact_digest: string;
    readonly subject: Readonly<ProviderOutcomeContext>;
    readonly subject_digest: string;
    readonly expected_state: string;
    readonly now: string;
}
export interface ActionEvidenceScheduleVerificationRequest {
    readonly artifact: unknown;
    readonly artifact_digest: string;
    readonly subject: Readonly<ProviderOutcomeContext>;
    readonly subject_digest: string;
    readonly expected_evaluation: ActionEvidenceScheduleEvaluation;
    readonly now: string;
}
export type ActionEvidenceComponentVerifier = (request: Readonly<ActionEvidenceVerificationRequest>) => ActionEvidenceNativeVerification | Promise<ActionEvidenceNativeVerification>;
export type ActionEvidenceScheduleVerifier = (request: Readonly<ActionEvidenceScheduleVerificationRequest>) => ActionEvidenceScheduleVerification | Promise<ActionEvidenceScheduleVerification>;
export interface VerifyActionEvidencePacketOptions {
    /** Relying-party expected action. Never accepted from the packet as trust. */
    readonly expected_context: Readonly<ProviderOutcomeContext>;
    readonly now: string;
    readonly verify_schedule: ActionEvidenceScheduleVerifier;
    readonly component_verifiers: Partial<Record<ActionEvidenceComponentRole, ActionEvidenceComponentVerifier>>;
    readonly provider_outcome: {
        readonly source_keys: Record<string, RiskRecord & {
            control_domain_id?: string;
        }>;
        /** Externally verified provider-entry instant used with the signed schedule window. */
        readonly provider_entry_at: string;
        /** Optional relying-party tightening. It can never widen the signed schedule age. */
        readonly maximum_observation_age_ms?: number;
        readonly agility?: AgilityOptions;
    };
}
export interface ActionEvidencePacketVerification {
    readonly '@version': typeof ACTION_EVIDENCE_PACKET_RESULT_VERSION;
    readonly result: ActionEvidencePacketResult;
    readonly reasons: readonly string[];
    readonly manifest_digest: string | null;
    readonly subject_digest: string | null;
    readonly verified_components: readonly ActionEvidenceComponentRole[];
    readonly incomplete_components: readonly string[];
    readonly conflicted_components: readonly string[];
    readonly indeterminate_components: readonly string[];
    readonly claim_boundary: typeof ACTION_EVIDENCE_PACKET_CLAIM_BOUNDARY;
}
/** Canonical digest for every JSON attachment. */
export declare function actionEvidenceArtifactDigest(artifact: unknown): string;
/** Canonical digest for the closed manifest. */
export declare function actionEvidenceManifestDigest(manifest: unknown): string;
/**
 * Build a complete content-addressed container. This function checks shape and
 * attachment addressing only. Native acceptance remains the responsibility of
 * the explicitly supplied verifier adapters.
 */
export declare function buildActionEvidencePacket(input: {
    manifest: Readonly<ActionEvidenceManifest>;
    attachments: readonly unknown[];
}): Readonly<ActionEvidencePacket>;
/**
 * Fail-closed orchestration of the packet and every native verifier adapter.
 * No packet field can introduce a trust key or currentness rule.
 */
export declare function verifyActionEvidencePacket(packet: unknown, options: Readonly<VerifyActionEvidencePacketOptions>): Promise<Readonly<ActionEvidencePacketVerification>>;
export {};
//# sourceMappingURL=action-evidence-packet.d.ts.map