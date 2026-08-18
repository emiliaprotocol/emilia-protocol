import { type AgileSigningKey, type AgilityOptions } from '@emilia-protocol/verify/pq-signature-agility';
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
/**
 * REFERENCE-DERIVED HYBRID MIGRATION. Copies, move for move, the reference
 * hybrid migration documented in docs/protocol/pq-hybrid-program.md, section
 * "PATTERN: the reference hybrid migration" (EP-REVOCATION-v2 in
 * packages/verify/src/revocation.ts). The five moves, applied to the
 * custodian observation:
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of
 *    the proof, a wire-format change, so the observation payload takes a new
 *    `@version` (EP-ACTION-ESCROW-CUSTODIAN-OBSERVATION-v1 -> -v2).
 *    createActionEscrowCustodianStatementVerifier() above is untouched: its
 *    returned verifyStatement() requires
 *    `payload['@version'] === ACTION_ESCROW_CUSTODIAN_OBSERVATION_VERSION`
 *    (v1) as part of the `exact` boolean, so a v2 payload refuses on
 *    `custodian_observation_binding_mismatch` before any signature math, and
 *    never throws.
 * 2. SET SHAPE. The single `signature` object is replaced by `proof`,
 *    carrying `required_algorithms` plus a `signatures` array shaped exactly
 *    like EP-SIG-AGILITY-v1's AgileSignature ({ alg, sig, key_id? }).
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is committed INSIDE the
 *    signed bytes (custodianObservationV2Bytes below). Drop the ML-DSA leg
 *    and narrow `required_algorithms` and the surviving Ed25519 signature no
 *    longer verifies, because the bytes changed.
 * 4. V1 COMPATIBILITY. v1 statements (minted by the bridge factory above)
 *    keep verifying, unchanged, through createActionEscrowCustodianStatementVerifier.
 *    v2 verification is ASYNC (ML-DSA verification is async), so it is a
 *    SEPARATE, standalone function rather than a change to the bridge's
 *    internal signing closure. The v1 path is never made async.
 * 5. NAMED REFUSALS. Every failure path returns a named reason; nothing
 *    throws on caller input. An absent ML-DSA backend is
 *    'pq_backend_unavailable', never a skipped check and never a pass on the
 *    classical leg alone.
 *
 * SCOPE BOUNDARY (honest, not a hedge): this migration is a standalone pure
 * builder/signer/verifier pair over the SAME observation payload shape the
 * bridge's internal signObservation() closure builds; it deliberately does
 * not thread a hybrid signer into createActionEscrowCustodianBridge's
 * closures, so the deployed bridge factory keeps minting v1 (Ed25519-only)
 * observations exactly as before. A relying party that wants hybrid
 * custodian observations builds the same fields the bridge already computes
 * (see signObservation above for the source shape) and calls
 * signActionEscrowCustodianObservationV2 directly.
 *
 * HONEST BOUNDARIES carry over from v1: this authenticates an OPERATOR
 * statement about one external-custodian snapshot; it does not prove the
 * custodian holds funds or that EMILIA is a licensed money transmitter. The
 * ML-DSA backend is @noble/post-quantum's pure-JS FIPS 204 implementation,
 * not independently audited and not a FIPS validated module. v2 does NOT
 * retroactively protect statements already issued under v1.
 */
export declare const ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_VERSION = "EP-ACTION-ESCROW-CUSTODIAN-OBSERVATION-v2";
/** The registered required algorithm set, in canonical order. */
export declare const ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_REQUIRED_ALGORITHMS: readonly string[];
/**
 * The bytes BOTH legs sign: the SAME canonicalized payload the v1 statement
 * signs, plus the committed `required_algorithms` set, under the v2 domain
 * tag. Recomputed independently by the verifier from the PRESENTED payload
 * and the REGISTERED set.
 */
export declare function custodianObservationV2Bytes(payload: any, requiredAlgorithms?: readonly string[]): Buffer<ArrayBuffer>;
/**
 * Mint a real hybrid custodian observation over caller-supplied fields (the
 * SAME field set signObservation() above computes from the kernel request and
 * provider result). Throws on issuer misuse; there is no caller input to
 * fail-close over on the signing side.
 */
export declare function signActionEscrowCustodianObservationV2(fields: Omit<Record<string, any>, '@version'>, signers: AgileSigningKey[], options?: AgilityOptions): Promise<any>;
/**
 * FAIL-CLOSED hybrid verifier for one EP-ACTION-ESCROW-CUSTODIAN-OBSERVATION-v2
 * statement. Never throws on caller input; a v2 statement NEVER verifies on
 * one leg alone. `operatorKeys` is keyed by `proof.key_id`, and BOTH halves
 * (`public_key`, `pq_public_key`) must be pinned there for that key id.
 */
export declare function verifyActionEscrowCustodianStatementV2(statement: any, { operatorKeys, providerId, environment, expected, mldsaBackend, mldsaBackendLoader, }?: {
    operatorKeys?: Record<string, any>;
    providerId?: string;
    environment?: string;
    expected?: Record<string, any>;
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}): Promise<{
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
/**
 * Route a custodian statement of EITHER version. A v1 statement (flat
 * `signature`) is checked against the v1 verifier factory's returned
 * function; a v2 statement (`proof` with a `signatures` set) gets the hybrid
 * check.
 */
export declare function verifyActionEscrowCustodianStatementAny(statement: any, options?: {
    operatorKeys?: Record<string, any>;
    providerId?: string;
    environment?: string;
    expected?: Record<string, any>;
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}): Promise<{
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
    ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_VERSION: "EP-ACTION-ESCROW-CUSTODIAN-OBSERVATION-v2";
    ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_REQUIRED_ALGORITHMS: readonly string[];
    createActionEscrowCustodianBridge: typeof createActionEscrowCustodianBridge;
    createActionEscrowCustodianStatementVerifier: typeof createActionEscrowCustodianStatementVerifier;
    custodianObservationV2Bytes: typeof custodianObservationV2Bytes;
    signActionEscrowCustodianObservationV2: typeof signActionEscrowCustodianObservationV2;
    verifyActionEscrowCustodianStatementV2: typeof verifyActionEscrowCustodianStatementV2;
    verifyActionEscrowCustodianStatementAny: typeof verifyActionEscrowCustodianStatementAny;
}>;
export default _default;
//# sourceMappingURL=action-escrow-custodian.d.ts.map