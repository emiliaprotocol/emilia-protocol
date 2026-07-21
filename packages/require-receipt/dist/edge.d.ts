type JsonObject = Record<string, unknown>;
type HeaderValue = string | string[] | undefined;
type HeaderSource = Headers | Iterable<[string, string]> | Record<string, HeaderValue>;
export type EdgeRequestLike = {
    method?: unknown;
    url?: unknown;
    headers?: HeaderSource;
    body?: unknown;
    bodyByteLength?: unknown;
    clone?: () => {
        body?: ReadableStream<Uint8Array> | null;
    };
};
export type EdgeVerificationContext = {
    action: string;
    action_hash?: string;
    required_fields: string[];
    caid_selector?: {
        field: string;
    };
    observed_action?: JsonObject;
    request: {
        method: string;
        url: string;
        body_bytes: number;
    };
};
export type EdgeVerificationResult = {
    ok: true;
    receipt_id?: string;
    receiptId?: string;
    action?: string;
    bound_action?: string;
} | {
    ok: false;
    reason?: string;
    [key: string]: unknown;
};
export type EdgeRefusal = {
    ok: false;
    status: 428;
    headers: Record<string, string>;
    body: {
        type: string;
        title: string;
        status: 428;
        detail: string;
        instance?: string;
        required: JsonObject;
        rejected?: {
            reason: string;
        };
    };
};
export type EdgeAllow = {
    ok: true;
    status: 200;
    upstream: {
        method: string;
        url: string;
        redirect: 'manual';
        remove_headers: string[];
        set_headers: Record<string, string>;
    };
    authorization: {
        action: string;
        receipt_id: string;
        consumption: 'consumed' | 'not_configured';
    };
};
export type EdgeDecision = EdgeRefusal | EdgeAllow;
export type ReceiptRequiredEdgeOptions = {
    action: string | ((request: EdgeRequestLike) => string | Promise<string>);
    actionHash?: string | ((request: EdgeRequestLike) => string | undefined | Promise<string | undefined>);
    projectAction?: (request: EdgeRequestLike) => JsonObject | Promise<JsonObject>;
    authorization: {
        authorization_endpoint: string;
        flow: 'EP-APPROVAL-v1';
    };
    requiredFields: string[];
    caidSelector?: {
        field: string;
    };
    manifestUrl?: string;
    assuranceClass?: 'software' | 'class_a' | 'quorum';
    maxAgeSec?: number;
    proofHeader?: string;
    maxHeaderBytes?: number;
    maxReceiptBytes?: number;
    maxBodyBytes?: number;
    verifyReceipt: (carrier: string, context: EdgeVerificationContext) => EdgeVerificationResult | Promise<EdgeVerificationResult>;
    consume?: (receiptId: string, context: EdgeVerificationContext) => boolean | Promise<boolean>;
};
/**
 * Create a reference edge authorization handler.
 *
 * The injected verifier MUST authenticate the receipt under relying-party pins
 * and bind it to `context.action`. When `consume` is supplied it MUST perform a
 * durable atomic insert-if-absent and return exactly true only for the winner.
 * Omitting consumption is suitable for verification-only profiles, not for a
 * one-use irreversible consequence boundary.
 */
export declare function createReceiptRequiredEdgeHandler(options: ReceiptRequiredEdgeOptions): (request: EdgeRequestLike) => Promise<EdgeDecision>;
export {};
//# sourceMappingURL=edge.d.ts.map