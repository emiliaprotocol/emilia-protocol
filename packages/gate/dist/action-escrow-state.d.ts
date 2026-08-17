/**
 * EP-ACTION-ESCROW-STATE-STATEMENT-v1
 *
 * A portable, operator-signed statement over one exact durable Action Escrow
 * snapshot. The signature authenticates an operator statement; it does not
 * prove the operator's database was complete or that a custodian moved money.
 */
import crypto from 'node:crypto';
import { type AgilityOptions } from '@emilia-protocol/verify/pq-signature-agility';
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
/**
 * REFERENCE-DERIVED HYBRID MIGRATION. This copies, move for move, the reference
 * hybrid migration documented in docs/protocol/pq-hybrid-program.md, section
 * "PATTERN: the reference hybrid migration" (EP-REVOCATION-v2 in
 * packages/verify/src/revocation.ts). The five moves, applied to the escrow
 * state statement:
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of
 *    `signature`, a wire-format change, so the artifact takes a new `version`
 *    marker (EP-ACTION-ESCROW-STATE-STATEMENT-v2). The v1 verifier above is
 *    untouched and refuses a v2 statement on its `structure` check (the version
 *    marker) before inspecting any signature, and never throws.
 * 2. SET SHAPE. `signature` carries `required_algorithms` plus a `signatures`
 *    array shaped exactly like EP-SIG-AGILITY-v1's AgileSignature
 *    ({ alg, sig, key_id? }), one entry per algorithm in the registered order.
 *    Ed25519 keeps its base64url SPKI DER public key; ML-DSA-65 carries raw
 *    base64url public key bytes.
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is committed INSIDE the
 *    signed bytes (stateV2SigningBytes below). Drop the ML-DSA leg and narrow
 *    `required_algorithms` and the surviving Ed25519 signature no longer
 *    verifies, because the bytes changed. This is a byte-level commitment,
 *    strictly stronger than EP-SIG-AGILITY-v1's relying-party `hybrid_all`
 *    policy alone. The verifier rebuilds the bytes from the REGISTERED set.
 * 4. V1 COMPATIBILITY. v1 statements keep verifying through the unchanged
 *    synchronous verifier; v2 verification is ASYNC (ML-DSA verification is
 *    async), so it is a SEPARATE entry point, with verifyActionEscrowStateStatementAny()
 *    routing on the version marker. The v1 verifier is never made async.
 * 5. NAMED REFUSALS. Every failure sets a named check false and pushes a
 *    readable reason; nothing throws on caller input. An absent ML-DSA backend
 *    is 'pq_backend_unavailable' surfaced through the agility result, never a
 *    skipped check and never a pass on the classical leg.
 *
 * HONEST BOUNDARIES carry over from v1: verification authenticates an operator
 * statement over one snapshot; it does not prove the operator's database was
 * complete or that a custodian moved money. The ML-DSA backend is
 * @noble/post-quantum's pure-JS FIPS 204 implementation, not independently
 * audited and not a FIPS validated module. v2 does NOT retroactively protect
 * statements already issued under v1.
 */
export declare const ACTION_ESCROW_STATE_STATEMENT_V2_VERSION = "EP-ACTION-ESCROW-STATE-STATEMENT-v2";
export declare const ACTION_ESCROW_STATE_STATEMENT_V2_DOMAIN = "EP-ACTION-ESCROW-STATE-STATEMENT-v2\0";
/** The registered required algorithm set, in canonical order. */
export declare const ACTION_ESCROW_STATE_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
/**
 * The bytes BOTH legs sign: the same domain-separated canonical body as v1
 * (version, issuer, payload) plus the committed `required_algorithms` set,
 * under the v2 domain tag. Recomputed independently by the verifier from the
 * PRESENTED fields and the REGISTERED set. See PATTERN move 3.
 */
export declare function stateV2SigningBytes(statement: {
    version?: unknown;
    issuer?: unknown;
    payload?: unknown;
}, requiredAlgorithms?: readonly string[]): Buffer;
/**
 * FAIL-CLOSED hybrid verifier for one EP-ACTION-ESCROW-STATE-STATEMENT-v2. Never
 * throws on caller input; a v2 statement NEVER verifies on one leg alone. See
 * the PATTERN reference above.
 */
export declare function verifyActionEscrowStateStatementV2(statement: any, { trustedKeys, stateRecord, expectedAgreementId, expectedBindingDigest, expectedActionDigest, expectedProfileDigest, expectedState, expectedRevision, expectedAmendmentDigests, expectedPreviousStatementDigest, now, mldsaBackend, mldsaBackendLoader, }?: {
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
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}): Promise<{
    valid: boolean;
    reason: string;
    checks: Record<string, boolean>;
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
    checks: Record<string, boolean>;
    statement_digest: string;
    agreement_id: any;
    binding_digest: any;
    action_digest: any;
    profile_digest: any;
    state: any;
    revision: any;
    amendment_digests: any[];
}>;
/**
 * Route a statement of EITHER version to its verifier. v1 statements keep the
 * exact v1 verdict (synchronous path, wrapped); v2 statements get the hybrid
 * check. A statement whose `version` is neither refuses through the v1 verifier,
 * which is the fail-closed answer.
 */
export declare function verifyActionEscrowStateStatementAny(statement: any, options?: any): Promise<{
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
} | {
    valid: boolean;
    reason: string;
    checks: Record<string, boolean>;
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
    ACTION_ESCROW_STATE_STATEMENT_V2_VERSION: string;
    ACTION_ESCROW_STATE_STATEMENT_V2_DOMAIN: string;
    ACTION_ESCROW_STATE_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
    signActionEscrowStateStatement: typeof signActionEscrowStateStatement;
    verifyActionEscrowStateStatement: typeof verifyActionEscrowStateStatement;
    verifyActionEscrowStateStatementV2: typeof verifyActionEscrowStateStatementV2;
    verifyActionEscrowStateStatementAny: typeof verifyActionEscrowStateStatementAny;
    stateV2SigningBytes: typeof stateV2SigningBytes;
    createActionEscrowStatePackageVerifier: typeof createActionEscrowStatePackageVerifier;
};
export default _default;
//# sourceMappingURL=action-escrow-state.d.ts.map