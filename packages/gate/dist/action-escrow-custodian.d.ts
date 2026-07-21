export declare const ACTION_ESCROW_CUSTODIAN_OBSERVATION_VERSION = "EP-ACTION-ESCROW-CUSTODIAN-OBSERVATION-v1";
/**
 * The bridge implements the kernel's release/getRelease contract. It never
 * claims that EMILIA holds funds or that the external provider is licensed.
 */
export declare function createActionEscrowCustodianBridge({ adapter, observationSigner, now, }?: {
    adapter?: Record<string, any>;
    observationSigner?: Record<string, any>;
    now?: () => string;
}): Readonly<{
    provider: any;
    environment: any;
    release(untrustedRequest: any): Promise<{
        accepted: boolean;
    }>;
    getRelease(untrustedRequest: any): Promise<{
        authenticated: boolean;
        statement: any;
    }>;
}>;
export declare function createActionEscrowCustodianStatementVerifier({ operatorKeys, providerId, environment, }?: {
    operatorKeys?: Record<string, any>;
    providerId?: string;
    environment?: string;
}): (statement: any, expected: any) => Promise<{
    valid: boolean;
    reason: string;
    authenticated?: undefined;
    statement_type?: undefined;
    status?: undefined;
    statement_digest?: undefined;
    provider_id?: undefined;
    agreement_digest?: undefined;
    document_action_binding_digest?: undefined;
    milestone_id?: undefined;
    release_action_digest?: undefined;
    parties_digest?: undefined;
    profile_digest?: undefined;
    provider_idempotency_key?: undefined;
    provider_request_digest?: undefined;
    provider_transaction_id?: undefined;
    provider_milestone_id?: undefined;
    amount?: undefined;
    currency?: undefined;
    destination_id?: undefined;
} | {
    valid: boolean;
    authenticated: boolean;
    statement_type: any;
    status: any;
    statement_digest: string;
    provider_id: any;
    agreement_digest: any;
    document_action_binding_digest: any;
    milestone_id: any;
    release_action_digest: any;
    parties_digest: any;
    profile_digest: any;
    provider_idempotency_key: any;
    provider_request_digest: any;
    provider_transaction_id: any;
    provider_milestone_id: any;
    amount: any;
    currency: any;
    destination_id: any;
    reason?: undefined;
}>;
declare const _default: Readonly<{
    ACTION_ESCROW_CUSTODIAN_OBSERVATION_VERSION: "EP-ACTION-ESCROW-CUSTODIAN-OBSERVATION-v1";
    createActionEscrowCustodianBridge: typeof createActionEscrowCustodianBridge;
    createActionEscrowCustodianStatementVerifier: typeof createActionEscrowCustodianStatementVerifier;
}>;
export default _default;
//# sourceMappingURL=action-escrow-custodian.d.ts.map