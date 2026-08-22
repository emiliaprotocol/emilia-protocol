import { SIGNATURE_AGILITY_VERSION, type AgileSignature, type AgileSigningKey, type AgileVerificationKey, type AgilityOptions } from '@emilia-protocol/verify/pq-signature-agility';
import { type AebDigest } from '@emilia-protocol/verify/aeb-adapter-contract';
export declare const CONSEQUENCE_ENVELOPE_VERSION = "EP-CONSEQUENCE-ENVELOPE-v1";
export declare const CONSEQUENCE_ENVELOPE_DOMAIN = "EP-CONSEQUENCE-ENVELOPE-v1\0";
export declare const CONSEQUENCE_ENVELOPE_REQUIRED_ALGORITHMS: readonly ("Ed25519" | "ML-DSA-65")[];
export declare const CONSEQUENCE_ENVELOPE_REFILL_POLICY = "NEW_SIGNED_EPOCH_ONLY";
export interface ConsequenceImpactProfile {
    id: string;
    version: string;
    unit: string;
    digest: AebDigest;
    derive(action: unknown): {
        ok: true;
        impact_units: bigint;
    } | {
        ok: false;
        reason: string;
    };
}
export interface ConsequenceEnvelopeParentAllocation {
    parent_envelope_id: string;
    parent_envelope_digest: AebDigest;
    parent_state_domain_id: string;
    parent_epoch: number;
    allocation_operation_id: string;
    allocation_units: string;
}
export interface ConsequenceEnvelopeBody {
    envelope_id: string;
    state_domain_id: string;
    epoch: number;
    capacity_units: string;
    impact_profile_id: string;
    impact_profile_digest: AebDigest;
    validity: {
        not_before: string;
        not_after: string;
    };
    issuer: {
        id: string;
        key_id: string;
    };
    parent_allocation: ConsequenceEnvelopeParentAllocation | null;
    renewable: false;
    refill_policy: typeof CONSEQUENCE_ENVELOPE_REFILL_POLICY;
    signature_profile: {
        id: typeof SIGNATURE_AGILITY_VERSION;
        required_algorithms: string[];
    };
    contract_digest: AebDigest;
}
export type ConsequenceEnvelopeDraft = Omit<ConsequenceEnvelopeBody, 'signature_profile' | 'contract_digest' | 'refill_policy'>;
export interface ConsequenceEnvelope {
    '@version': typeof CONSEQUENCE_ENVELOPE_VERSION;
    body: ConsequenceEnvelopeBody;
    signatures: AgileSignature[];
}
export interface ConsequenceEnvelopeVerification {
    verified: boolean;
    reason: string | null;
    envelope_digest: AebDigest | null;
    execution_authorizing: false;
}
declare const CONSEQUENCE_ENVELOPE_OWNER: unique symbol;
export type ConsequenceEnvelopeOwner = string & {
    readonly [CONSEQUENCE_ENVELOPE_OWNER]: true;
};
export interface ConsequenceEnvelopeReservation {
    envelope_id: string;
    envelope_digest: AebDigest;
    state_domain_id: string;
    epoch: number;
    operation_id: string;
    action_digest: AebDigest;
    impact_profile_id: string;
    impact_units: string;
    owner: ConsequenceEnvelopeOwner;
}
export interface ConsequenceEnvelopeStore {
    durable: boolean;
    /** Present only on process-local conformance stores. */
    testOnly?: true;
    ownershipFenced: true;
    atomicCapacity: true;
    epochFenced: true;
    bind(input: {
        envelope_id: string;
        envelope_digest: AebDigest;
        state_domain_id: string;
        epoch: number;
        capacity_units: string;
    }): Promise<boolean>;
    reserve(input: Omit<ConsequenceEnvelopeReservation, 'owner'>): Promise<{
        reserved: true;
        owner: ConsequenceEnvelopeOwner;
    } | {
        reserved: false;
        reason: string;
    }>;
    transition(input: ConsequenceEnvelopeReservation & {
        expected_state: 'HELD' | 'ENTERED' | 'INDETERMINATE';
        next_state: 'ENTERED' | 'INDETERMINATE' | 'COMMITTED' | 'RELEASED';
    }): Promise<boolean>;
    recover(input: {
        operation_id: string;
        action_digest: AebDigest;
    }): Promise<ConsequenceEnvelopeReservation | null>;
    snapshot(): {
        capacity_units: string;
        available_units: string;
        held_units: string;
        committed_units: string;
    };
}
export type ConsequenceEnvelopeReserveResult = {
    status: 'RESERVED';
    reservation: ConsequenceEnvelopeReservation;
} | {
    status: 'REFUSED';
    reason: string;
};
export interface ConsequenceEnvelopeBoundary {
    guaranteeClass: 'durable-local-atomic' | 'test-only-process-local';
    envelope: Readonly<ConsequenceEnvelopeBody>;
    envelope_digest: AebDigest;
    profile: Readonly<ConsequenceImpactProfile>;
    reserve(input: {
        operation_id: string;
        state_domain_id: string;
        expected_epoch: number;
        action: unknown;
    }): Promise<ConsequenceEnvelopeReserveResult>;
    reserveUnits(input: {
        operation_id: string;
        state_domain_id: string;
        expected_epoch: number;
        action_digest: AebDigest;
        impact_units: string;
    }): Promise<ConsequenceEnvelopeReserveResult>;
    beginProviderEntry(reservation: ConsequenceEnvelopeReservation): Promise<{
        status: 'ENTERED';
    } | {
        status: 'REFUSED';
        reason: string;
    }>;
    releaseNotEntered(reservation: ConsequenceEnvelopeReservation): Promise<{
        status: 'RELEASED';
    } | {
        status: 'REFUSED';
        reason: string;
    }>;
    settle(reservation: ConsequenceEnvelopeReservation, outcome: 'COMMITTED' | 'PROVEN_NOT_COMMITTED' | 'INDETERMINATE'): Promise<{
        status: 'COMMITTED' | 'RELEASED' | 'INDETERMINATE';
    } | {
        status: 'REFUSED';
        reason: string;
    }>;
    reconcile(input: {
        operation_id: string;
        action_digest: AebDigest;
        outcome: 'COMMITTED' | 'PROVEN_NOT_COMMITTED';
        recovery_authorization: unknown;
    }): Promise<{
        status: 'COMMITTED' | 'RELEASED';
    } | {
        status: 'REFUSED';
        reason: string;
    }>;
    snapshot(): ReturnType<ConsequenceEnvelopeStore['snapshot']>;
    renew(): Promise<{
        status: 'REFUSED';
        reason: 'consequence_envelope_new_signed_epoch_required';
    }>;
}
export declare function consequenceEnvelopeContractDigest(input: Pick<ConsequenceEnvelopeBody, 'envelope_id' | 'state_domain_id' | 'epoch' | 'capacity_units' | 'impact_profile_id' | 'impact_profile_digest' | 'validity' | 'issuer' | 'parent_allocation' | 'renewable' | 'refill_policy'>): AebDigest;
export declare function consequenceEnvelopeSignedBytes(body: ConsequenceEnvelopeBody): Uint8Array;
export declare function consequenceEnvelopeDigest(body: ConsequenceEnvelopeBody): AebDigest;
export declare function issueConsequenceEnvelope(draft: ConsequenceEnvelopeDraft, options: AgilityOptions & {
    signing_keys: AgileSigningKey[];
}): Promise<ConsequenceEnvelope>;
export declare function verifyConsequenceEnvelope(value: unknown, options: AgilityOptions & {
    verification_keys: AgileVerificationKey[];
    now: string;
}): Promise<ConsequenceEnvelopeVerification>;
export declare const FINANCE_CUMULATIVE_EXPOSURE_PROFILE: ConsequenceImpactProfile;
export declare const GRID_ACTIVE_POWER_PROFILE: ConsequenceImpactProfile;
/**
 * Conservative GRACE curtailment allocation. One admitted event reserves the
 * absolute requested reduction in watts. Telemetry, modeled benefit, and
 * observed delivery never increase the signed envelope.
 */
export declare const GRACE_CURTAILMENT_IMPACT_PROFILE: ConsequenceImpactProfile;
export declare function createMemoryConsequenceEnvelopeStore(): ConsequenceEnvelopeStore;
export declare function createConsequenceEnvelopeBoundary(options: {
    envelope: ConsequenceEnvelope;
    verification_keys: AgileVerificationKey[];
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    profile: ConsequenceImpactProfile;
    store: ConsequenceEnvelopeStore;
    authorize_recovery?: (input: {
        operation_id: string;
        action_digest: AebDigest;
        recovery_authorization: unknown;
    }) => boolean | Promise<boolean>;
    /** Conformance-only escape hatch. Production callers must supply a durable store. */
    allow_test_store?: true;
    now?: () => string;
}): Promise<ConsequenceEnvelopeBoundary>;
export declare function allocateConsequenceEnvelopeSlice(options: {
    parent: ConsequenceEnvelopeBoundary;
    operation_id: string;
    child: {
        envelope_id: string;
        state_domain_id: string;
        epoch: number;
        capacity_units: string;
        validity: {
            not_before: string;
            not_after: string;
        };
        issuer: {
            id: string;
            key_id: string;
        };
    };
    signing_keys: AgileSigningKey[];
    mldsaBackend?: AgilityOptions['mldsaBackend'];
}): Promise<{
    status: 'ALLOCATED';
    envelope: ConsequenceEnvelope;
} | {
    status: 'REFUSED';
    reason: string;
}>;
declare const _default: Readonly<{
    CONSEQUENCE_ENVELOPE_VERSION: "EP-CONSEQUENCE-ENVELOPE-v1";
    CONSEQUENCE_ENVELOPE_REQUIRED_ALGORITHMS: readonly ("Ed25519" | "ML-DSA-65")[];
    CONSEQUENCE_ENVELOPE_REFILL_POLICY: "NEW_SIGNED_EPOCH_ONLY";
    FINANCE_CUMULATIVE_EXPOSURE_PROFILE: ConsequenceImpactProfile;
    GRID_ACTIVE_POWER_PROFILE: ConsequenceImpactProfile;
    GRACE_CURTAILMENT_IMPACT_PROFILE: ConsequenceImpactProfile;
    issueConsequenceEnvelope: typeof issueConsequenceEnvelope;
    verifyConsequenceEnvelope: typeof verifyConsequenceEnvelope;
    createMemoryConsequenceEnvelopeStore: typeof createMemoryConsequenceEnvelopeStore;
    createConsequenceEnvelopeBoundary: typeof createConsequenceEnvelopeBoundary;
    allocateConsequenceEnvelopeSlice: typeof allocateConsequenceEnvelopeSlice;
}>;
export default _default;
//# sourceMappingURL=consequence-envelope.d.ts.map