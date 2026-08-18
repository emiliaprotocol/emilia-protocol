import { type FipsPosture } from '@emilia-protocol/verify/fips-mode';
import { type AgilityOptions } from '@emilia-protocol/verify/pq-signature-agility';
export declare const ACTION_REMEDY_RECEIPT_VERSION = "EP-ACTION-REMEDY-RECEIPT-v1";
export declare const REMEDY_PROGRAM_RECEIPT_VERSION = "EP-ACTION-REMEDY-RECEIPT-v1";
export declare const ACTION_REMEDY_RECEIPT_DOMAIN = "EP-ACTION-REMEDY-RECEIPT-v1\0";
/** See the EP-ACTION-REMEDY-RECEIPT-v2 header for why v2 accepts both. */
export declare const REMEDY_PROGRAM_PROFILE_V2_VERSION = "EP-GATE-REMEDY-PROGRAM-PROFILE-v2";
type DataRecord = Record<string, any>;
export interface RemedyReceiptExpectedBindings extends Record<string, unknown> {
    original_operation_id: string;
    original_action_digest: string;
    original_terminal_evidence_digest: string;
    case_instance_id: string;
    case_revision: number;
    case_status: string;
    remedy_operation_id: string;
    remedy_action_digest: string;
    remedy_caid: string;
    destination_binding_digest: string;
    units: number;
    unit: string;
    owner_mode: string;
    owner_digest: string;
}
/** Derive every relying-party binding that must be independently expected. */
export declare function expectedRemedyProgramReceiptBindings(state: unknown, remedyOperationId: string): Readonly<RemedyReceiptExpectedBindings>;
/** Return the exact domain-separated canonical bytes signed by Ed25519. */
export declare function remedyProgramReceiptSigningBytes(receipt: unknown): Buffer;
/**
 * Issue one receipt. Local private keys require an explicit ephemeral/test
 * opt-in; production issuance requires an external signer declaring KMS/HSM
 * custody. Every returned signature is verified against the configured public
 * key before the receipt leaves this function.
 */
export declare function issueRemedyProgramReceipt(input?: {
    state?: unknown;
    remedyOperationId?: string;
}, options?: {
    context?: unknown;
    privateKey?: unknown;
    signer?: unknown;
    allowEphemeralState?: boolean;
    fipsPosture?: FipsPosture;
}): Promise<Readonly<{
    signature: {
        algorithm: string;
        value: string;
    };
    content_digest: string;
    version: string;
    issuer: DataRecord;
    payload: DataRecord;
}>>;
export declare const signRemedyProgramReceipt: typeof issueRemedyProgramReceipt;
export declare const createRemedyProgramReceipt: typeof issueRemedyProgramReceipt;
/**
 * Verify a receipt without network access. Trust keys, all issuer fields, the
 * exact current state snapshot, and every material original/remedy binding are
 * relying-party inputs; none are accepted from the receipt itself.
 */
export declare function verifyRemedyProgramReceipt(receipt: unknown, { trustedKeys, expectedIssuer, state, expected, }?: {
    trustedKeys?: unknown;
    expectedIssuer?: unknown;
    state?: unknown;
    expected?: unknown;
}): Readonly<{
    valid: false;
    reason: string;
    checks: Readonly<{
        [x: string]: boolean;
    }>;
    content_digest: null;
    payload: null;
}> | Readonly<{
    valid: boolean;
    reason: string;
    checks: {
        structure: boolean;
        payload: boolean;
        content_digest: boolean;
        issuer_pin: boolean;
        key: boolean;
        signature: boolean;
        state_snapshot: boolean;
        expected_bindings: boolean;
    };
    content_digest: string;
    payload: DataRecord;
}>;
/**
 * Copies the five-move EP-REVOCATION-v2 template
 * (packages/verify/src/revocation.ts) onto the operator remedy receipt.
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. `signature: {algorithm, value}` becomes
 *    `signature: {profile, required_algorithms, public_key, key_id,
 *    pq_public_key, pq_key_id, signatures}`, a wire-format change, so the
 *    receipt takes a new `version` (-v1 -> -v2). verifyRemedyProgramReceipt
 *    above is UNCHANGED and refuses a v2 receipt at
 *    `receipt_structure_invalid` -- its exact-key check on the closed
 *    `{algorithm, value}` signature object fails before any signature is
 *    inspected, and it does not crash.
 * 2. SET SHAPE. `signature.signatures` is an EP-SIG-AGILITY-v1 AgileSignature
 *    array ({ alg, sig, key_id? }), one entry per registered algorithm, in the
 *    registered order, reused verbatim. Ed25519 keeps its base64url SPKI DER
 *    public key; ML-DSA-65 carries raw base64url public key bytes.
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` is INSIDE the signed bytes
 *    (remedyProgramReceiptV2SigningBytes). Drop the ML-DSA leg and narrow the
 *    set to ["Ed25519"] and the surviving Ed25519 signature no longer
 *    verifies. Leave the set intact and the missing leg is a structural
 *    refusal. The verifier rebuilds the bytes from the REGISTERED set and from
 *    the body it independently recomputed.
 * 4. V1 COMPATIBILITY. verifyRemedyProgramReceipt stays SYNCHRONOUS and
 *    untouched. verifyRemedyProgramReceiptV2 is a SEPARATE async entry point
 *    (ML-DSA verification is inherently async); verifyRemedyProgramReceiptStatement
 *    routes on the version marker for callers holding a mixed bag.
 * 5. NAMED REFUSALS. Verification never throws on caller input; every failure
 *    returns `{valid:false, reason}` with the same reason vocabulary as v1 plus
 *    the hybrid-specific ones. An absent ML-DSA backend surfaces as
 *    `pq_backend_unavailable`, never a skipped check and never a pass on the
 *    classical leg. Issuance keeps v1's throw-on-misuse contract.
 *
 * THE PROFILE MARKER, STATED PRECISELY. A v2 receipt may describe a case whose
 * state snapshot carries EITHER EP-GATE-REMEDY-PROGRAM-PROFILE-v1 or -v2. That
 * is not a loose pin: the state snapshot's own `version` string is inside
 * `canonicalDigest(state)`, which is `payload.case.state_snapshot_digest`,
 * which is inside `content_digest`, which is inside the signed bytes. Swapping
 * the profile marker on a presented state therefore breaks BOTH the recomputed
 * state-snapshot digest and both signature legs. Accepting both is what keeps
 * the v2 receipt issuable over the Remedy Program kernel as it ships today,
 * without weakening what the signature commits to. The v1 receipt is
 * unchanged and still describes v1-profile states ONLY.
 *
 * THE FIPS CONSULT. The `fipsPosture` opt-in that v1 issuance already carries
 * is threaded through the v2 path and consults checkOperationPolicy() for BOTH
 * registered algorithms before the signer is called. Under a posture that is
 * not verifiably FIPS-inactive, ML-DSA-65's policy is a REFUSAL unless the
 * deployment explicitly acknowledges the unvalidated implementation
 * (`allowUnvalidatedMldsa: true`), because EP's ML-DSA backend is pure
 * JavaScript and inside no validated module boundary. Under a plainly
 * non-FIPS posture (`fips_status: 'inactive'`, the normal case) no
 * acknowledgment is required and the consult changes nothing. Left undefined
 * (the default), the consult does not run at all, exactly as in v1.
 *
 * HONEST BOUNDARY, UNCHANGED FROM V1: the receipt preserves the original
 * effect as an immutable fact and describes a later remedy only as a
 * compensating action. It never claims the original effect was rolled back or
 * erased. The ML-DSA-65 backend is @noble/post-quantum's pure-JS FIPS 204
 * implementation, not independently audited and not a FIPS validated module,
 * and its secret key is software-held: this profile does NOT satisfy a
 * kms/hsm-only custody requirement, and issuing under it is not a
 * certification claim.
 */
export declare const ACTION_REMEDY_RECEIPT_V2_VERSION = "EP-ACTION-REMEDY-RECEIPT-v2";
export declare const REMEDY_PROGRAM_RECEIPT_V2_VERSION = "EP-ACTION-REMEDY-RECEIPT-v2";
export declare const ACTION_REMEDY_RECEIPT_V2_DOMAIN = "EP-ACTION-REMEDY-RECEIPT-v2\0";
/** The registered required algorithm set, in canonical order. */
export declare const ACTION_REMEDY_RECEIPT_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
/** A v2 issuer pin: BOTH public halves, pinned out of band by key id. */
export interface RemedyReceiptV2KeyPin {
    /** Ed25519 base64url SPKI DER. */
    public_key: string;
    /** ML-DSA-65 base64url raw public key bytes. */
    pq_public_key: string;
}
/**
 * An injected hybrid signer. Structurally the `signSet()` contract of
 * lib/key-custody.ts's HybridCustodySigner: sign the SAME bytes under every
 * required algorithm, in canonical order. Accepted structurally rather than
 * imported because @emilia-protocol/gate does not depend on the app-tier lib/
 * tree; a HybridCustodySigner satisfies this shape as-is.
 */
export interface RemedyReceiptV2SignSetSigner {
    keyId: string;
    custody?: string;
    publicKeys: RemedyReceiptV2KeyPin;
    signSet(bytes: Uint8Array | Buffer, context?: Record<string, unknown>): Promise<Array<{
        alg: string;
        sig: string;
        key_id?: string;
    }>>;
}
export interface RemedyReceiptV2SigningKeys {
    ed: {
        privateKey: unknown;
        publicKey?: string;
    };
    pq: {
        secretKey: Uint8Array | string;
        publicKey: string;
    };
}
/**
 * Derive every relying-party binding for a v2 receipt. Identical to
 * expectedRemedyProgramReceiptBindings except that it accepts a state snapshot
 * under EITHER Remedy Program profile marker, which is exactly the set a v2
 * receipt may describe.
 */
export declare function expectedRemedyProgramReceiptV2Bindings(state: unknown, remedyOperationId: string): Readonly<RemedyReceiptExpectedBindings>;
/**
 * The bytes BOTH legs sign: the same body v1 signs (version, issuer, payload,
 * content_digest) under the v2 domain tag, plus the committed
 * `required_algorithms` set. Recomputed independently by the verifier from the
 * PRESENTED body and the REGISTERED set. See move 3 above.
 */
export declare function remedyProgramReceiptV2SigningBytes(receipt: unknown, requiredAlgorithms?: readonly string[]): Buffer;
/**
 * Issue one hybrid receipt. Local private keys require an explicit
 * ephemeral/test opt-in; production issuance requires an external signSet
 * signer. Every returned signature set is verified against the configured
 * public halves before the receipt leaves this function.
 */
export declare function issueRemedyProgramReceiptV2(input?: {
    state?: unknown;
    remedyOperationId?: string;
}, options?: {
    context?: unknown;
    keys?: RemedyReceiptV2SigningKeys;
    signer?: RemedyReceiptV2SignSetSigner;
    allowEphemeralState?: boolean;
    fipsPosture?: FipsPosture;
    /**
     * ML-DSA-65 is implemented in JavaScript and is inside no validated
     * module. Under a configured `fipsPosture` its policy is a REFUSAL unless
     * the deployment acknowledges that explicitly here. The default is the
     * named refusal, never a silent pass.
     */
    allowUnvalidatedMldsa?: boolean;
}): Promise<Readonly<{
    signature: {
        profile: string;
        required_algorithms: ("Ed25519" | "ML-DSA-65")[];
        public_key: string;
        key_id: any;
        pq_public_key: string;
        pq_key_id: string;
        signatures: {
            alg: string;
            sig: string;
        }[];
    };
    content_digest: string;
    version: string;
    issuer: DataRecord;
    payload: DataRecord;
}>>;
export declare const signRemedyProgramReceiptV2: typeof issueRemedyProgramReceiptV2;
/**
 * FAIL-CLOSED hybrid remedy-receipt verifier. Never throws on caller input; a
 * v2 receipt NEVER verifies on one leg alone. Trust keys, all issuer fields,
 * the exact current state snapshot, and every material original/remedy binding
 * are relying-party inputs; none is accepted from the receipt itself.
 */
export declare function verifyRemedyProgramReceiptV2(receipt: unknown, { trustedKeys, expectedIssuer, state, expected, mldsaBackend, mldsaBackendLoader, }?: {
    trustedKeys?: unknown;
    expectedIssuer?: unknown;
    state?: unknown;
    expected?: unknown;
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}): Promise<Readonly<{
    valid: false;
    reason: string;
    checks: Readonly<{
        [x: string]: boolean;
    }>;
    content_digest: null;
    payload: null;
}> | Readonly<{
    valid: boolean;
    reason: string;
    checks: {
        structure: boolean;
        payload: boolean;
        content_digest: boolean;
        issuer_pin: boolean;
        algorithm_set: boolean;
        legs_present: boolean;
        key: boolean;
        signature: boolean;
        state_snapshot: boolean;
        expected_bindings: boolean;
    };
    content_digest: string;
    payload: DataRecord;
}>>;
/**
 * Route a receipt of EITHER version to its verifier. v1 receipts keep the exact
 * v1 verdict; v2 receipts get the hybrid check. A receipt whose `version` is
 * neither refuses through the v1 verifier, which is the fail-closed answer.
 */
export declare function verifyRemedyProgramReceiptStatement(receipt: unknown, options?: {
    trustedKeys?: unknown;
    expectedIssuer?: unknown;
    state?: unknown;
    expected?: unknown;
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}): Promise<Readonly<{
    valid: false;
    reason: string;
    checks: Readonly<{
        [x: string]: boolean;
    }>;
    content_digest: null;
    payload: null;
}> | Readonly<{
    valid: boolean;
    reason: string;
    checks: {
        structure: boolean;
        payload: boolean;
        content_digest: boolean;
        issuer_pin: boolean;
        key: boolean;
        signature: boolean;
        state_snapshot: boolean;
        expected_bindings: boolean;
    };
    content_digest: string;
    payload: DataRecord;
}>>;
declare const _default: {
    ACTION_REMEDY_RECEIPT_VERSION: string;
    REMEDY_PROGRAM_RECEIPT_VERSION: string;
    ACTION_REMEDY_RECEIPT_DOMAIN: string;
    ACTION_REMEDY_RECEIPT_V2_VERSION: string;
    REMEDY_PROGRAM_RECEIPT_V2_VERSION: string;
    ACTION_REMEDY_RECEIPT_V2_DOMAIN: string;
    ACTION_REMEDY_RECEIPT_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
    REMEDY_PROGRAM_PROFILE_V2_VERSION: string;
    expectedRemedyProgramReceiptBindings: typeof expectedRemedyProgramReceiptBindings;
    expectedRemedyProgramReceiptV2Bindings: typeof expectedRemedyProgramReceiptV2Bindings;
    remedyProgramReceiptSigningBytes: typeof remedyProgramReceiptSigningBytes;
    remedyProgramReceiptV2SigningBytes: typeof remedyProgramReceiptV2SigningBytes;
    issueRemedyProgramReceipt: typeof issueRemedyProgramReceipt;
    issueRemedyProgramReceiptV2: typeof issueRemedyProgramReceiptV2;
    signRemedyProgramReceipt: typeof issueRemedyProgramReceipt;
    signRemedyProgramReceiptV2: typeof issueRemedyProgramReceiptV2;
    createRemedyProgramReceipt: typeof issueRemedyProgramReceipt;
    verifyRemedyProgramReceipt: typeof verifyRemedyProgramReceipt;
    verifyRemedyProgramReceiptV2: typeof verifyRemedyProgramReceiptV2;
    verifyRemedyProgramReceiptStatement: typeof verifyRemedyProgramReceiptStatement;
};
export default _default;
//# sourceMappingURL=remedy-program-receipt.d.ts.map