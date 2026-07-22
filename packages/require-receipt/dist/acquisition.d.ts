type JsonObject = Record<string, any>;
type FetchLike = typeof fetch;
type RequesterAuthorization = string | (() => string | Promise<string>);
export declare const EP_APPROVAL_FLOW = "EP-APPROVAL-v1";
export declare const APPROVAL_REQUEST_ID_PATTERN: RegExp;
export declare const APPROVAL_POLL_TOKEN_PATTERN: RegExp;
export declare const APPROVAL_IDEMPOTENCY_KEY_PATTERN: RegExp;
export declare const APPROVAL_STATUSES: readonly ["pending", "indeterminate", "approved", "denied", "expired", "cancelled"];
export declare function approvalActionHash(action: unknown): string;
export declare function validateApprovalAuthorization(input: unknown): {
    ok: true;
    value: {
        authorization_endpoint: string;
        flow: typeof EP_APPROVAL_FLOW;
    };
} | {
    ok: false;
    reason: string;
};
export declare function validateRequiredFields(input: unknown): {
    ok: true;
    value: string[];
} | {
    ok: false;
    reason: string;
};
export declare function validateCaidSelector(input: unknown): {
    ok: true;
    value: {
        field: string;
    };
} | {
    ok: false;
    reason: string;
};
export declare function beginReceiptApproval({ authorization, trustedAuthorization, challenge, action, approver_id, idempotency_key, requesterAuthorization, fetchImpl, }: {
    authorization: unknown;
    trustedAuthorization: unknown;
    challenge: unknown;
    action: unknown;
    approver_id: string;
    idempotency_key: string;
    requesterAuthorization: RequesterAuthorization;
    fetchImpl?: FetchLike;
}): Promise<JsonObject>;
export declare function pollReceiptApproval({ authorization, trustedAuthorization, request_id, poll_token, fetchImpl, }: {
    authorization: unknown;
    trustedAuthorization: unknown;
    request_id: string;
    poll_token: string;
    fetchImpl?: FetchLike;
}): Promise<JsonObject>;
export {};
//# sourceMappingURL=acquisition.d.ts.map