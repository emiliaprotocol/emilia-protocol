/**
 * EP-ACTION-ESCROW-STATE-STATEMENT-v1
 *
 * A portable, operator-signed statement over one exact durable Action Escrow
 * snapshot. The signature authenticates an operator statement; it does not
 * prove the operator's database was complete or that a custodian moved money.
 */
import crypto from 'node:crypto';
export declare const ACTION_ESCROW_STATE_STATEMENT_VERSION = "EP-ACTION-ESCROW-STATE-STATEMENT-v1";
export declare const ACTION_ESCROW_STATE_STATEMENT_DOMAIN = "EP-ACTION-ESCROW-STATE-STATEMENT-v1\0";
/**
 * Sign one exact state snapshot. Issuance may throw on invalid local input;
 * verification below never throws.
 */
export declare function signActionEscrowStateStatement({ statementId, agreementId, bindingDigest, actionDigest, profileDigest, state, revision, amendmentDigests, stateRecord, previousStatementDigest, occurredAt, }?: {
    statementId?: string;
    agreementId?: string;
    bindingDigest?: string;
    actionDigest?: string;
    profileDigest?: string;
    state?: string;
    revision?: number;
    amendmentDigests?: string[];
    stateRecord?: unknown;
    previousStatementDigest?: string | null;
    occurredAt?: string;
}, { operatorId, keyId, privateKey, }?: {
    operatorId?: string;
    keyId?: string;
    privateKey?: crypto.KeyObject | Parameters<typeof crypto.createPrivateKey>[0];
}): any;
/**
 * Verify one state statement against an exact snapshot and relying-party pins.
 *
 * @param {*} statement
 */
export declare function verifyActionEscrowStateStatement(statement: any, { trustedKeys, stateRecord, expectedAgreementId, expectedBindingDigest, expectedActionDigest, expectedProfileDigest, expectedState, expectedRevision, expectedAmendmentDigests, expectedPreviousStatementDigest, now, }?: {
    trustedKeys?: unknown;
    stateRecord?: unknown;
    expectedAgreementId?: string;
    expectedBindingDigest?: string;
    expectedActionDigest?: string;
    expectedProfileDigest?: string;
    expectedState?: string;
    expectedRevision?: number;
    expectedAmendmentDigests?: string[];
    expectedPreviousStatementDigest?: string | null;
    now?: Date | number | string;
}): {
    valid: boolean;
    reason: any;
    checks: any;
    statement_digest: null;
    agreement_id: null;
    binding_digest: null;
    action_digest: null;
    profile_digest: null;
    state: null;
    revision: null;
    amendment_digests: never[];
} | {
    valid: boolean;
    reason: string;
    checks: {
        structure: boolean;
        payload: boolean;
        issuer_pin: boolean;
        signature: boolean;
        statement_digest: boolean;
        state_record: boolean;
        expected_bindings: boolean;
        time: boolean;
    };
    statement_digest: string;
    agreement_id: any;
    binding_digest: any;
    action_digest: any;
    profile_digest: any;
    state: any;
    revision: any;
    amendment_digests: any[];
};
/**
 * Build the callback expected by verifyActionEscrowEvidencePackage. The
 * package carries both the exact durable snapshot and the signed statement
 * over it; trust keys and time remain verifier configuration.
 */
export declare function createActionEscrowStatePackageVerifier({ trustedKeys, now, minimumRevision, }?: {
    trustedKeys?: unknown;
    now?: Date | number | string;
    minimumRevision?: number;
}): (packaged: any, expected?: {
    agreementId?: string;
    bindingDigest?: string;
    actionDigest?: string;
    profileDigest?: string;
    stage?: string;
    amendmentDigests?: string[];
}) => Promise<{
    valid: boolean;
    reason: any;
    checks: any;
    statement_digest: null;
    agreement_id: null;
    binding_digest: null;
    action_digest: null;
    profile_digest: null;
    state: null;
    revision: null;
    amendment_digests: never[];
} | {
    valid: boolean;
    reason: string;
    checks: {
        structure: boolean;
        payload: boolean;
        issuer_pin: boolean;
        signature: boolean;
        statement_digest: boolean;
        state_record: boolean;
        expected_bindings: boolean;
        time: boolean;
    };
    statement_digest: string;
    agreement_id: any;
    binding_digest: any;
    action_digest: any;
    profile_digest: any;
    state: any;
    revision: any;
    amendment_digests: any[];
}>;
declare const _default: {
    ACTION_ESCROW_STATE_STATEMENT_VERSION: string;
    ACTION_ESCROW_STATE_STATEMENT_DOMAIN: string;
    signActionEscrowStateStatement: typeof signActionEscrowStateStatement;
    verifyActionEscrowStateStatement: typeof verifyActionEscrowStateStatement;
    createActionEscrowStatePackageVerifier: typeof createActionEscrowStatePackageVerifier;
};
export default _default;
//# sourceMappingURL=action-escrow-state.d.ts.map