/**
 * A2A v1.0 carrier binding for an EMILIA receipt.
 *
 * A2A supplies task, context, message, and extension semantics; it does not
 * make an unsigned Task a proof of authority. This module therefore carries a
 * separately signed companion artifact on A2A's namespaced Message extension
 * point. The artifact binds the complete receipt, exact semantic action,
 * initiating Message, server-issued Task snapshot, proof Message, selected
 * Agent Card, and target interface. Receipt verification and local execution
 * authorization remain separate relying-party decisions.
 */
import { KeyObject } from 'node:crypto';
import { type AebDigest } from './aeb-adapter-contract.js';
export declare const A2A_PROTOCOL_VERSION = "1.0";
export declare const A2A_ACTION_MEDIA_TYPE = "application/vnd.emilia.action+json";
export declare const A2A_RECEIPT_EXTENSION_URI = "https://emiliaprotocol.ai/extensions/a2a/receipt-binding/v1";
export declare const A2A_RECEIPT_EXTENSION_NAME = "ai.emiliaprotocol.a2a.receipt-binding.v1";
export declare const A2A_RECEIPT_BINDING_VERSION = "EP-A2A-RECEIPT-BINDING-v1";
export declare const A2A_RECEIPT_BINDING_DOMAIN = "EP-A2A-RECEIPT-BINDING-v1\0";
export declare const A2A_RECEIPT_PRESENTATION_VERSION = "EP-A2A-RECEIPT-PRESENTATION-v1";
export declare const RECEIPT_EXTENSIONS_VERSION = "EP-RECEIPT-EXTENSIONS-v1";
export interface A2AMessage {
    messageId: string;
    contextId?: string;
    taskId?: string;
    role: 'ROLE_USER' | 'ROLE_AGENT';
    parts: readonly unknown[];
    metadata?: Readonly<Record<string, unknown>>;
    extensions?: readonly string[];
    referenceTaskIds?: readonly string[];
}
export interface A2ATask {
    id: string;
    contextId: string;
    status: {
        state: string;
        message?: unknown;
        timestamp?: string;
    };
    artifacts?: readonly unknown[];
    history?: readonly unknown[];
    metadata?: Readonly<Record<string, unknown>>;
}
export interface A2AReceiptBindingBody {
    '@version': typeof A2A_RECEIPT_BINDING_VERSION;
    extension_name: typeof A2A_RECEIPT_EXTENSION_NAME;
    protocol_version: typeof A2A_PROTOCOL_VERSION;
    target_interface_url: string;
    agent_card_digest: AebDigest;
    task_id: string;
    context_id: string;
    task_snapshot_digest: AebDigest;
    initiating_message_id: string;
    initiating_message_digest: AebDigest;
    proof_message_id: string;
    proof_message_digest: AebDigest;
    base_receipt_digest: AebDigest;
    base_action_digest: AebDigest;
    caid: string;
    issued_at: string;
    expires_at: string;
}
export interface A2AReceiptBindingArtifact extends A2AReceiptBindingBody {
    signature: {
        algorithm: 'Ed25519';
        key_id: string;
        value: string;
    };
}
export interface A2AReceiptExtensionsCompanion {
    version: typeof RECEIPT_EXTENSIONS_VERSION;
    base_receipt_digest: AebDigest;
    base_action_digest: AebDigest;
    entries: readonly [
        {
            name: typeof A2A_RECEIPT_EXTENSION_NAME;
            operation_id: string;
            consequence_digest: null;
            artifact_digest: AebDigest;
        }
    ];
}
export interface A2AReceiptPresentationPayload {
    '@version': typeof A2A_RECEIPT_PRESENTATION_VERSION;
    action: unknown;
    receipt: unknown;
    receipt_extensions: A2AReceiptExtensionsCompanion;
    binding_artifact: A2AReceiptBindingArtifact;
}
export interface A2AReceiptPresentation {
    message: A2AMessage & {
        metadata: Record<string, unknown>;
        extensions: string[];
    };
    artifact: A2AReceiptBindingArtifact;
    companion: A2AReceiptExtensionsCompanion;
}
export interface A2AReceiptSigner {
    key_id: string;
    private_key: KeyObject;
}
export interface A2AReceiptTrustRoot {
    key_id: string;
    public_key: string;
}
export interface VerifiedReceiptBinding {
    valid: boolean;
    action_digest: string | null;
    caid: string | null;
}
export interface A2AReceiptPresentationVerification {
    valid: boolean;
    checks: {
        shape: boolean;
        protocol: boolean;
        extension: boolean;
        target: boolean;
        task: boolean;
        initiating_message: boolean;
        presentation_message: boolean;
        companion: boolean;
        signature: boolean;
        validity: boolean;
        receipt: boolean;
    };
    reasons: string[];
    decision_scope: {
        correlation_only: true;
        receipt_verified: boolean;
        a2a_server_authenticated: false;
        authorization_granted: false;
        execution_proven: false;
    };
}
export interface CreateA2AReceiptPresentationInput {
    protocol_version: string;
    target_interface_url: string;
    agent_card: unknown;
    task: unknown;
    initiating_message: unknown;
    proof_message: unknown;
    base_receipt: unknown;
    receipt_binding: {
        caid: string;
        action_digest: string;
    };
    issued_at: string;
    expires_at: string;
    signer: A2AReceiptSigner;
}
export interface VerifyA2AReceiptPresentationInput {
    protocol_version: string;
    target_interface_url: string;
    agent_card: unknown;
    task: unknown;
    initiating_message: unknown;
    presentation_message: unknown;
    negotiated_extensions: readonly string[];
    trust_roots: readonly A2AReceiptTrustRoot[];
    expected_action: unknown;
    expected_caid: string;
    now: string;
    verify_receipt?: (receipt: unknown) => VerifiedReceiptBinding;
}
/**
 * Create one A2A proof retry carrying the base receipt plus its signed,
 * receipt-extension-compatible A2A correlation artifact.
 */
export declare function createA2AReceiptPresentation(input: CreateA2AReceiptPresentationInput): A2AReceiptPresentation;
/**
 * Verify the portable A2A/receipt correlation. A caller-supplied receipt
 * verifier is mandatory and must return the action digest and CAID it verified.
 * Success remains evidence correlation; it never grants execution authority.
 */
export declare function verifyA2AReceiptPresentation(input: VerifyA2AReceiptPresentationInput): A2AReceiptPresentationVerification;
//# sourceMappingURL=a2a-receipt-binding.d.ts.map