import { type AgileAlgorithm, type AgileSignature, type AgileSigningKey, type AgileVerificationKey, type AgilityOptions } from './pq-signature-agility.js';
export declare const PORTABLE_STATE_PROFILE = "EP-PORTABLE-STATE-HANDOFF-v0.1";
export declare const PORTABLE_STATE_MANIFEST_VERSION = "EP-STATE-HANDOFF-MANIFEST-v0.1";
export declare const PORTABLE_STATE_IMPORT_RECEIPT_VERSION = "EP-STATE-HANDOFF-IMPORT-RECEIPT-v0.1";
export declare const PORTABLE_STATE_AUTHORITY_PROFILE = "EP-STATE-HANDOFF-AUTHORITY-v0.1";
export declare const PORTABLE_STATE_SIGNATURE_PROFILE = "EP-SIG-AGILITY-v1";
export declare const PORTABLE_STATE_LIMITS: Readonly<{
    max_objects: 4096;
    max_reasons: 256;
    max_depth: 64;
    max_nodes: 100000;
    max_string_bytes: number;
}>;
export declare const PORTABLE_STATE_ACTIONS: Readonly<{
    readonly EXPORT: "agent.state.export.1";
    readonly IMPORT: "agent.state.import.1";
    readonly KEY_RELEASE: "agent.state.key-release.1";
    readonly RETIRE_SOURCE: "agent.state.retire-source.1";
}>;
export type StateDigest = `sha256:${string}`;
export type StateSensitivity = 'OPEN' | 'PROTECTED' | 'VAULT';
export type StateDisposition = 'ACTIVE' | 'TOMBSTONE';
export type StateImportResult = 'ACCEPTED' | 'PARTIAL' | 'REFUSED' | 'INDETERMINATE';
export type StateActionType = (typeof PORTABLE_STATE_ACTIONS)[keyof typeof PORTABLE_STATE_ACTIONS];
export interface StateSignaturePolicy {
    profile: typeof PORTABLE_STATE_SIGNATURE_PROFILE;
    required_algorithms: AgileAlgorithm[];
}
export interface StateObjectDescriptor {
    position: number;
    object_id: string;
    object_digest: StateDigest;
    media_type: string;
    schema_uri: string;
    required: boolean;
    snapshot_at: string;
    sensitivity: StateSensitivity;
    disposition: StateDisposition;
    generation: number;
    predecessor_digest: StateDigest | null;
}
export interface PortableStateManifest {
    '@version': typeof PORTABLE_STATE_MANIFEST_VERSION;
    handoff_id: string;
    transfer_mode: 'COPY';
    payload_profile: string;
    source_agent: string;
    source_boundary_id: string;
    recipient_agent: string;
    recipient_boundary_id: string;
    relying_party_id: string;
    created_at: string;
    snapshot_at: string;
    expires_at: string;
    nonce: string;
    index: {
        ordered_object_ids: string[];
        index_digest: StateDigest;
    };
    objects: StateObjectDescriptor[];
    scope_digest: StateDigest;
    authority: {
        profile: typeof PORTABLE_STATE_AUTHORITY_PROFILE;
        source_actions: StateActionType[];
        recipient_action: typeof PORTABLE_STATE_ACTIONS.IMPORT;
    };
    nonclaims: {
        source_truth: 'NOT_ESTABLISHED';
        authority_transfer: 'PROHIBITED';
        source_population_completeness: 'NOT_ESTABLISHED';
        physical_erasure: 'NOT_ESTABLISHED';
        trusted_time: 'NOT_ESTABLISHED';
    };
    signature_policy: StateSignaturePolicy;
    signatures: AgileSignature[];
}
export interface PortableStateBundle {
    manifest: PortableStateManifest;
    objects: unknown[];
    source_authority_evidence: Partial<Record<StateActionType, unknown>>;
}
export interface StateActionObject {
    action_type: StateActionType;
    handoff_id: string;
    manifest_digest: StateDigest;
    payload_profile: string;
    transfer_mode: 'COPY';
    source_agent: string;
    source_boundary_id: string;
    recipient_agent: string;
    recipient_boundary_id: string;
    relying_party_id: string;
    scope_digest: StateDigest;
    expires_at: string;
    nonce: string;
    vault_set_digest?: StateDigest;
    import_receipt_digest?: StateDigest;
    retirement_set_digest?: StateDigest;
}
export interface StateActionExpectation {
    profile: typeof PORTABLE_STATE_AUTHORITY_PROFILE;
    action_object: StateActionObject;
    caid: string;
    action_digest: StateDigest;
}
export interface StateAuthorityEvidenceRecord {
    stage: 'SOURCE_RELEASE' | 'RECIPIENT_COMMIT';
    action: StateActionType;
    caid: string;
    receipt_digest: StateDigest;
}
export interface PortableStateImportReceipt {
    '@version': typeof PORTABLE_STATE_IMPORT_RECEIPT_VERSION;
    receipt_kind: 'INITIAL' | 'RECONCILIATION';
    handoff_id: string;
    manifest_digest: StateDigest;
    payload_profile: string;
    importer_boundary_id: string;
    result: StateImportResult;
    accepted_object_ids: string[];
    unavailable_objects: Array<{
        object_id: string;
        reason: string;
    }>;
    reasons: string[];
    authority_evidence: StateAuthorityEvidenceRecord[];
    admission_record_digest: StateDigest | null;
    completed_at: string;
    issued_at: string;
    nonclaims: PortableStateManifest['nonclaims'];
    signature_policy: StateSignaturePolicy;
    signatures: AgileSignature[];
}
export interface ArtifactSigner {
    principal_id: string;
    policy: StateSignaturePolicy;
    keys: AgileSigningKey[];
    agility?: AgilityOptions;
}
export interface ArtifactSignerPin extends AgileVerificationKey {
    key_id: string;
    status: 'active' | 'revoked';
    principals: string[];
    valid_from: string;
    valid_until: string;
}
export interface StatePayloadAdapter {
    profile: string;
    validateObject(value: unknown, descriptor: Readonly<StateObjectDescriptor>): {
        status: 'VALID';
    } | {
        status: 'REFUSED' | 'INDETERMINATE';
        reasons: string[];
    };
}
export interface SourceAuthorityVerifier {
    verify(expected: Readonly<StateActionExpectation>, evidence: unknown): Promise<{
        status: 'VERIFIED';
        receipt_digest: StateDigest;
        consumption: 'CONSUMED';
    } | {
        status: 'REFUSED' | 'INDETERMINATE';
        reasons: string[];
    }>;
}
export interface StateHead {
    generation: number;
    object_digest: StateDigest;
}
export interface StateCommitWrite {
    object_id: string;
    object_digest: StateDigest;
    generation: number;
    predecessor_digest: StateDigest | null;
    object: unknown;
}
export interface StateAdmissionRecord {
    handoff_id: string;
    manifest_digest: StateDigest;
    payload_profile: string;
    recipient_boundary_id: string;
    result: 'ACCEPTED' | 'PARTIAL';
    accepted_object_ids: string[];
    unavailable_objects: Array<{
        object_id: string;
        reason: string;
    }>;
    source_authority_evidence: StateAuthorityEvidenceRecord[];
    recipient_authority_evidence: StateAuthorityEvidenceRecord;
    committed_at: string;
}
export interface RecipientCommitRequest {
    handoff_id: string;
    manifest_digest: StateDigest;
    payload_profile: string;
    recipient_boundary_id: string;
    expected_heads: Array<{
        object_id: string;
        head: StateHead | null;
    }>;
    writes: StateCommitWrite[];
    unavailable_objects: Array<{
        object_id: string;
        reason: string;
    }>;
    source_authority_evidence: StateAuthorityEvidenceRecord[];
    import_authority: {
        expected: StateActionExpectation;
        evidence: unknown;
    };
    committed_at: string;
}
export interface RecipientStateBoundary {
    readHead(objectId: string): StateHead | null;
    lookupAdmission(handoffId: string): StateAdmissionRecord | null;
    commitImport(request: RecipientCommitRequest): Promise<{
        status: 'COMMITTED';
        record: StateAdmissionRecord;
    } | {
        status: 'REFUSED' | 'INDETERMINATE';
        reasons: string[];
    }>;
}
export interface ImportPortableStateOptions {
    now: string;
    expected_recipient_agent: string;
    expected_recipient_boundary_id: string;
    expected_relying_party_id: string;
    source_signer_pins: ArtifactSignerPin[];
    payload_adapters: StatePayloadAdapter[];
    source_authority_verifier: SourceAuthorityVerifier;
    recipient_boundary: RecipientStateBoundary;
    import_authority_evidence: unknown;
    importer_signer: ArtifactSigner;
    signature_agility?: AgilityOptions;
    verify_vault_availability?: (objects: ReadonlyArray<{
        descriptor: StateObjectDescriptor;
        object: unknown;
    }>) => Promise<{
        status: 'AVAILABLE';
    } | {
        status: 'REFUSED' | 'INDETERMINATE';
        reasons: string[];
    }>;
}
export interface ReferenceRecipientBoundaryOptions {
    authorizeImport(expected: Readonly<StateActionExpectation>, evidence: unknown): {
        status: 'AUTHORIZED';
        receipt_digest: StateDigest;
    } | {
        status: 'REFUSED' | 'INDETERMINATE';
        reasons: string[];
    };
    loseAcknowledgementAfterCommit?: boolean;
}
export declare function stateHandoffDigest(value: unknown): StateDigest;
export declare const STATE_HANDOFF_CAID_DEFINITIONS: readonly ({
    action_type: "agent.state.export.1" | "agent.state.import.1";
    status: string;
    required_fields: ({
        name: string;
        type: string;
        values_ref?: undefined;
    } | {
        name: string;
        type: string;
        values_ref: string;
    })[];
    optional_fields: never[];
} | {
    action_type: "agent.state.key-release.1";
    status: string;
    required_fields: ({
        name: string;
        type: string;
        values_ref?: undefined;
    } | {
        name: string;
        type: string;
        values_ref: string;
    })[];
    optional_fields: never[];
} | {
    action_type: "agent.state.retire-source.1";
    status: string;
    required_fields: ({
        name: string;
        type: string;
        values_ref?: undefined;
    } | {
        name: string;
        type: string;
        values_ref: string;
    })[];
    optional_fields: never[];
})[];
export declare function stateActionExpectation(manifest: PortableStateManifest, actionType: StateActionType, importReceiptDigest?: StateDigest, retirementSetDigest?: StateDigest): StateActionExpectation;
/**
 * Verify, admit, and commit one portable-state handoff.
 *
 * Caller input never authorizes through a boolean. Source evidence must verify
 * as already consumed at the source boundary. Recipient authority is consumed
 * only inside RecipientStateBoundary.commitImport, in the same atomic state
 * domain that rechecks current heads and stores the objects.
 */
export declare function importPortableState(bundle: PortableStateBundle, options: ImportPortableStateOptions): Promise<PortableStateImportReceipt>;
export declare function reconcilePortableStateImport(handoffId: string, manifestDigest: StateDigest, options: ImportPortableStateOptions): Promise<PortableStateImportReceipt | null>;
export declare function verifyPortableStateImportReceipt(value: unknown, pins: ArtifactSignerPin[], agility?: AgilityOptions): Promise<{
    valid: boolean;
    reasons: string[];
}>;
/**
 * Verify an import receipt and its exact relationship to an already obtained
 * manifest. This function does not replace source-manifest signature
 * verification; it closes the cross-artifact set, boundary, CAID, and time
 * bindings after that verification has succeeded.
 */
export declare function verifyPortableStateImportReceiptForManifest(value: unknown, manifestValue: unknown, pins: ArtifactSignerPin[], agility?: AgilityOptions): Promise<{
    valid: boolean;
    reasons: string[];
}>;
/** Process-local conformance boundary. Not a durable production store. */
export declare class InMemoryRecipientStateBoundary implements RecipientStateBoundary {
    #private;
    constructor(options: ReferenceRecipientBoundaryOptions);
    readHead(objectId: string): StateHead | null;
    readObject(objectId: string): unknown;
    lookupAdmission(handoffId: string): StateAdmissionRecord | null;
    seedHead(objectId: string, head: StateHead, object?: unknown): void;
    consumptionCount(): number;
    loseNextAcknowledgement(): void;
    commitImport(request: RecipientCommitRequest): Promise<{
        status: 'COMMITTED';
        record: StateAdmissionRecord;
    } | {
        status: 'REFUSED' | 'INDETERMINATE';
        reasons: string[];
    }>;
}
export declare function signPortableStateManifest(unsigned: Omit<PortableStateManifest, 'signatures'>, signer: ArtifactSigner): Promise<PortableStateManifest>;
export declare function buildSourceRetirementExpectation(manifest: PortableStateManifest, acceptedImportReceipt: PortableStateImportReceipt): StateActionExpectation;
//# sourceMappingURL=portable-state-handoff.d.ts.map