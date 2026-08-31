/**
 * A neutral compiler surface for AEB-ADAPTER-v1.
 *
 * Native bytes remain native. The compiler asks the relying-party-pinned
 * adapters to verify and map those bytes, composes their results through the
 * existing AEB evaluator and AEC engine, and projects one closed report. It
 * performs no network access, credential issuance, consumption, provider
 * entry, execution, or outcome reconciliation.
 *
 * The report is evidence, not a bearer credential or an authorization result.
 * A caller-supplied policy input is preserved as input only. Gate or another
 * local runtime must evaluate authorization and reserve authority before
 * provider entry.
 */
import { AEC_VERSION } from './evidence-chain.js';
import { AEB_ADAPTER_VERSION, type Acceptance, type AebAdapter, type AebDigest, type AebEvidenceLegInput, type AebEvidenceSubject, type AebFreshness, type AebLegVerdict, type AebPinnedConfig, type AebRequirement, type AebVerdict, type MappingVerdict, type NativeVerification } from './aeb-adapter-contract.js';
export declare const AEB_NATIVE_COMPILER_VERSION = "EP-AEB-NATIVE-COMPILER-v1";
export declare const AEB_NATIVE_DESCRIPTOR_VERSION = "EP-AEB-NATIVE-DESCRIPTOR-v1";
export type AebNativeCompilerVerified = NativeVerification | 'INDETERMINATE';
export type AebNativeCompilerPolicyInputDecision = 'ALLOW' | 'DENY' | 'INDETERMINATE';
export type AebNativeCompilerInputProvenance = 'RELYING_PARTY_INPUT';
export type AebSemanticLossStatus = 'NONE' | 'NON_MATERIAL_ONLY' | 'MATERIAL' | 'UNKNOWN';
export type AebSemanticOmissionClassification = 'material' | 'non_material' | 'unknown';
export type AebSemanticOmissionDeclaration = 'omitted_material_fields' | 'omitted_nonmaterial_fields' | 'profile_semantics_unavailable' | 'native_profile_binding_unestablished';
export type AebNativeCompilerNotEvaluated = 'NOT_EVALUATED';
export type AebNativeCompilerNotEstablished = 'NOT_ESTABLISHED';
export interface AebNativeDescriptor {
    '@version': typeof AEB_NATIVE_DESCRIPTOR_VERSION;
    protocol: {
        id: string;
        revision: string;
    };
    /** A closed source descriptor. At least one of media_type or schema is required. */
    source: {
        media_type: string | null;
        schema: {
            id: string;
            revision: string;
        } | null;
    };
    /** This is a relying-party pin, not proof that running code was measured. */
    verifier: {
        implementation_id: string;
        implementation_revision: string;
        implementation_digest: AebDigest;
    };
    adapter: {
        id: string;
        revision: string;
    };
    mapping_profile: {
        id: string;
        revision: string;
        digest: AebDigest;
    };
    target_action_type: string;
    replay_scope: string;
    /** Digest of descriptor_id plus every field above. */
    descriptor_digest: AebDigest;
}
export interface AebNativeDescriptorSet {
    /** Out-of-band relying-party digest pins, keyed by descriptor ID. */
    pins: Record<string, AebDigest>;
    /** Closed descriptor bodies, independently checked against pins. */
    registry: Record<string, AebNativeDescriptor>;
}
export interface AebNativeCompilerLegInput extends AebEvidenceLegInput {
    native_descriptor_id: string;
}
export interface AebNativeCompilerExpectedAction {
    caid: string;
    /** Exact action value supplied by the relying party for comparison. */
    value: unknown;
}
export interface AebNativeCompilerRequirement {
    ref: string;
    /** Must be byte-equivalent to the requirement under the relying-party pins. */
    definition: AebRequirement;
}
export interface AebNativeCompilerLocalPolicyInput {
    policy_id: string;
    policy_version: string;
    decision: 'ALLOW' | 'DENY';
    reasons: readonly string[];
}
export interface AebNativeCompilerInput {
    /** Complete AEB-ADAPTER-v1 relying-party pins. */
    pins: AebPinnedConfig;
    /** Pure, offline adapter implementations selected by adapter ID. */
    adapters: Record<string, AebAdapter>;
    /** Compiler-local source and verifier metadata, pinned by digest. */
    native_descriptors: AebNativeDescriptorSet;
    native_legs: AebNativeCompilerLegInput[];
    expected_action: AebNativeCompilerExpectedAction;
    requirement: AebNativeCompilerRequirement;
    initiator_id: string;
    executor_id?: string;
    evaluated_at: string;
    /** Unverified policy input. The compiler preserves it but does not authorize. */
    local_policy_input: AebNativeCompilerLocalPolicyInput;
}
export interface AebNativeCompilerAxis<T extends string> {
    result: T;
    reasons: string[];
}
export interface AebSemanticLossReport {
    status: AebSemanticLossStatus;
    profile_pinned: boolean;
    omitted_material_fields: string[];
    omitted_nonmaterial_fields: string[];
    omissions: AebSemanticOmission[];
}
export interface AebSemanticOmission {
    /** Exact stable path declared by the profile; `$` means the whole unknown projection. */
    path: string;
    classification: AebSemanticOmissionClassification;
    basis: {
        profile_id: string;
        profile_digest: AebDigest;
        profile_pinned: boolean;
        declaration: AebSemanticOmissionDeclaration;
        /** Commits the omission and classification to the profile digest above. */
        binding_digest: AebDigest;
    };
}
export interface AebNativeCompilerLegReport {
    artifact_ref: string;
    native_descriptor: {
        id: string;
        digest: AebDigest;
        pinned: boolean;
        protocol: {
            id: string;
            revision: string;
        };
        source: {
            media_type: string | null;
            schema: {
                id: string;
                revision: string;
            } | null;
        };
        verifier: {
            implementation_id: string;
            implementation_revision: string;
            implementation_digest: AebDigest;
        };
        target_action_type: string;
        replay_scope: string;
    };
    native_profile: {
        adapter_id: string;
        adapter_revision: string;
        mapping_profile_id: string;
        mapping_profile_revision: string;
    };
    artifact_digest: AebDigest;
    native_result: {
        verification: NativeVerification;
        acceptance: Acceptance;
    };
    pins: {
        adapter_config_digest: AebDigest;
        profile_digest: AebDigest;
        mapper_id: string;
        resolver: {
            id: string;
            revision: string;
            implementation_digest: AebDigest;
        };
    };
    action: {
        /** Compiler-effective relation. Lossy or unknown semantics force this closed. */
        mapping: MappingVerdict;
        caid: string | null;
        normalized_action_digest: AebDigest | null;
        /** Raw output from the native mapper, retained only for diagnostics. */
        native_raw_mapping: MappingVerdict;
        native_raw_caid: string | null;
        native_raw_normalized_action_digest: AebDigest | null;
    };
    evidence: {
        role: string;
        subject: AebEvidenceSubject | null;
        freshness: AebFreshness;
    };
    replay_unit: AebDigest;
    semantic_loss: AebSemanticLossReport;
    verdict: AebLegVerdict;
    reasons: string[];
}
export interface AebNativeCompilerReport {
    '@version': typeof AEB_NATIVE_COMPILER_VERSION;
    relying_party_id: string;
    evaluated_at: string;
    engine: {
        evaluator: typeof AEB_ADAPTER_VERSION;
        composition: typeof AEC_VERSION;
        signed_evaluation: false;
    };
    requirement: {
        ref: string;
        digest: AebDigest;
        pinned: boolean;
    };
    expected_action: {
        caid: string;
        /** Detached exact value supplied by the relying party. */
        value: unknown;
        digest: AebDigest;
        provenance: AebNativeCompilerInputProvenance;
    };
    local_policy_input: {
        policy_id: string;
        policy_version: string;
        decision: AebNativeCompilerPolicyInputDecision;
        reasons: string[];
        provenance: AebNativeCompilerInputProvenance;
        /** The compiler has not authenticated or executed this decision. */
        verification: AebNativeCompilerNotEvaluated;
        input_digest: AebDigest;
    };
    legs: AebNativeCompilerLegReport[];
    /** Stable across changes to AEB artifact_ref wrapper identifiers. */
    replay_unit: AebDigest;
    semantic_loss: {
        status: AebSemanticLossStatus;
        material_present: boolean;
        unknown_present: boolean;
        profiles: Array<{
            profile_id: string;
            report: AebSemanticLossReport;
        }>;
    };
    axes: {
        verified: AebNativeCompilerAxis<AebNativeCompilerVerified>;
        accepted: AebNativeCompilerAxis<Acceptance>;
        match: AebNativeCompilerAxis<MappingVerdict>;
        satisfied: AebNativeCompilerAxis<AebVerdict>;
        policy_input: AebNativeCompilerAxis<AebNativeCompilerPolicyInputDecision>;
        local_authorization: AebNativeCompilerAxis<AebNativeCompilerNotEvaluated>;
    };
    lifecycle: {
        reservation: AebNativeCompilerAxis<AebNativeCompilerNotEvaluated>;
        consumption: AebNativeCompilerAxis<AebNativeCompilerNotEvaluated>;
        provider_entry: AebNativeCompilerAxis<AebNativeCompilerNotEstablished>;
        provider_outcome: AebNativeCompilerAxis<AebNativeCompilerNotEstablished>;
        observed_effect: AebNativeCompilerAxis<AebNativeCompilerNotEstablished>;
        retry: AebNativeCompilerAxis<AebNativeCompilerNotEvaluated>;
        reconciliation: AebNativeCompilerAxis<AebNativeCompilerNotEvaluated>;
    };
    claims: {
        local_authorization_established: false;
        provider_entry_established: false;
        execution_established: false;
        outcome_established: false;
        verifier_runtime_measurement_established: false;
    };
    /** A digest is not a credential, signature, reservation, or execution permit. */
    report_is_credential: false;
    reasons: string[];
    report_digest: AebDigest;
}
/** Digest rule for the compiler-local, relying-party-pinned native descriptor. */
export declare function aebNativeDescriptorDigest(descriptorId: string, descriptor: Omit<AebNativeDescriptor, 'descriptor_digest'> | AebNativeDescriptor): AebDigest;
/**
 * Compile native evidence into a deterministic, fail-closed AEB report.
 *
 * The function is intentionally synchronous and side-effect free. Any runtime
 * input or adapter error returns an INDETERMINATE report instead of widening
 * authority or throwing through an authorization boundary.
 */
export declare function compileAebNativeEvidence(input: AebNativeCompilerInput): AebNativeCompilerReport;
//# sourceMappingURL=aeb-native-compiler.d.ts.map