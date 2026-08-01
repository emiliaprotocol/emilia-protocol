import { type AebPinnedConfig, type AebStatusInput } from '@emilia-protocol/verify/aeb-adapter-contract';
import { type FidoAp2NativeSourceBindingInput } from '@emilia-protocol/verify/fido-ap2-bridge';
import { type AdmissionDigest, type AdmissionSnapshotInput } from './admission-store.js';
import type { GateQualificationBundleV2 } from './gate-qualification-v2.js';
export interface FidoAp2AuthenticatedStatus {
    artifact_ref: string;
    evidence_digest: AdmissionDigest;
    replay_unit: AdmissionDigest;
    authority_id: string;
    sequence: number;
    head_digest: AdmissionDigest;
    status: AebStatusInput;
}
export interface FidoAp2Provider {
    provider_id: string;
    account_id: string;
    environment: string;
}
export interface FidoAp2ProviderRequestVerifier {
    id: string;
    version: string;
    implementation_digest: AdmissionDigest;
    verify(input: Readonly<{
        effect_request_bytes: Uint8Array;
        payment_mandate_token: string;
        payment_mandate_token_digest: AdmissionDigest;
        provider: Readonly<FidoAp2Provider>;
    }>): boolean;
}
/** Server-owned dependencies. None of these values may come from the request. */
export interface FidoAp2TrustedAdmissionControls {
    now(): number | string | Date;
    pinned_config: AebPinnedConfig;
    resolve_current_statuses(input: Readonly<{
        artifact_refs: readonly [string, string];
        evidence_digests: readonly [AdmissionDigest, AdmissionDigest];
        replay_units: readonly [AdmissionDigest, AdmissionDigest];
        now: string;
    }>): readonly [FidoAp2AuthenticatedStatus, FidoAp2AuthenticatedStatus];
    tenant_id: string;
    relying_party_id: string;
    audience: string;
    operation_id: string;
    initiator_id: string;
    executor_id: string;
    provider: Readonly<FidoAp2Provider>;
    gate_trust_configuration_digest: AdmissionDigest;
    executor_adapter_digest: AdmissionDigest;
    /** Server-owned current WebAuthn signature-counter head for this credential. */
    webauthn_counter_head: number;
    ap2_source: FidoAp2NativeSourceBindingInput;
    effect_request_bytes: Uint8Array;
    provider_request_verifier: FidoAp2ProviderRequestVerifier;
}
export declare function digestFidoAp2EffectRequest(value: Uint8Array): AdmissionDigest;
/**
 * Build the complete immutable input to one Gate admission. All replay and
 * provider-operation identities are derived here; none are presenter-selected.
 */
export declare function createFidoAp2AdmissionInput(raw: unknown, controls: FidoAp2TrustedAdmissionControls): AdmissionSnapshotInput;
/**
 * Derive the AEB requirement leg and pass through only qualification, AEC, and
 * local-policy decisions that bind to the same canonical admission input.
 */
export declare function createFidoAp2QualificationBundle(raw: unknown, controls: FidoAp2TrustedAdmissionControls): GateQualificationBundleV2;
//# sourceMappingURL=fido-ap2-bridge.d.ts.map