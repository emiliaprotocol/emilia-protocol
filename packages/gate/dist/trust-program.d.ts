/**
 * EMILIA Gate Trust Program Profile v1.
 *
 * A relying-party-controlled, fail-closed authorization DAG for consequential
 * actions. This module composes evidence verifiers; it does not redefine the
 * Handshake, Quorum, AEC, capability, or Action Escrow wire formats.
 */
import crypto from 'node:crypto';
import { type AgileSignature, type AgilityOptions } from '@emilia-protocol/verify/pq-signature-agility';
export declare const TRUST_PROGRAM_VERSION = "EP-GATE-TRUST-PROGRAM-PROFILE-v1";
export declare const TRUST_STAGE_RECEIPT_VERSION = "EP-GATE-TRUST-STAGE-RECEIPT-v1";
type RecordLike = Record<string, any>;
export type TrustJson = null | boolean | number | string | TrustJson[] | {
    [key: string]: TrustJson;
};
export interface TrustProgramState extends Record<string, unknown> {
    tenant_id: string;
    instance_id: string;
    program_digest: string;
    root_caid: string;
    action_digest: string;
    status: string;
    revision: number;
    stages: Record<string, Record<string, unknown>>;
    execution: Record<string, unknown>;
}
export interface TrustProgramResult extends Record<string, unknown> {
    ok: boolean;
    reason?: string;
    state?: TrustProgramState;
}
export interface TrustProgramStore {
    readonly durable: boolean;
    create(input: {
        tenantId: string;
        state: TrustProgramState;
    }): Promise<TrustProgramResult>;
    get(input: {
        tenantId: string;
        instanceId: string;
    }): Promise<TrustProgramResult>;
    compareAndSwap(input: {
        tenantId: string;
        instanceId: string;
        expectedRevision: number;
        state: TrustProgramState;
    }): Promise<TrustProgramResult>;
    invalidate(input: {
        tenantId: string;
        instanceId: string;
        expectedRevision: number;
        reason: string;
        at: number;
    }): Promise<TrustProgramResult>;
}
export interface TrustEvidenceProjection extends Record<string, unknown> {
    valid: boolean;
    reason?: string | null;
    binding_digest?: string;
    policy_digest?: string;
    subjects?: string[];
    key_fingerprints?: string[];
    issued_at?: string;
    expires_at?: string;
    revocation_checked_at?: string | null;
}
export type TrustEvidenceVerifier = (input: {
    artifact: unknown;
    requirement: Readonly<Record<string, unknown>>;
    program: Readonly<Record<string, unknown>>;
}) => Promise<TrustEvidenceProjection> | TrustEvidenceProjection;
export interface TrustProgramKernelConfig {
    program: unknown;
    store: TrustProgramStore;
    verifiers: Readonly<Record<string, TrustEvidenceVerifier>>;
    receiptPrivateKey?: crypto.KeyLike;
    receiptVerificationKey?: string | crypto.KeyObject;
    receiptSigner?: (input: {
        signingBytes: Buffer;
        body: Readonly<Record<string, unknown>>;
        receiptDigest: string;
    }) => Promise<string> | string;
    receiptContext: Readonly<{
        issuer: string;
        tenant: string;
        environment: string;
        audience: string;
        key_id: string;
    }>;
    allowEphemeralState?: boolean;
    actionBindingVerifier?: (input: Readonly<Record<string, unknown>>) => Promise<boolean> | boolean;
    executionBindingVerifier?: (input: Readonly<Record<string, unknown>>) => Promise<boolean> | boolean;
    executionEvidenceRevalidator?: (input: Readonly<Record<string, unknown>>) => Promise<boolean> | boolean;
    executionOutcomeVerifier?: (input: Readonly<Record<string, unknown>>) => Promise<boolean> | boolean;
    reconciliationVerifier?: (input: Readonly<Record<string, unknown>>) => Promise<boolean> | boolean;
    now?: () => number;
}
export interface TrustProgramKernel {
    readonly program_digest: string;
    start(input: {
        instanceId: string;
        action?: unknown;
    }): Promise<TrustProgramResult>;
    status(instanceId: string): Promise<TrustProgramResult>;
    challenge(input: {
        instanceId: string;
        stageId: string;
        requirementId: string;
    }): Promise<TrustProgramResult>;
    admit(input: {
        instanceId: string;
        stageId: string;
        requirementId: string;
        artifact: unknown;
    }): Promise<TrustProgramResult>;
    claimExecution(input: {
        instanceId: string;
        operationId?: string;
        claimToken?: string;
    }): Promise<TrustProgramResult>;
    finalizeExecution(input: {
        instanceId: string;
        claimToken: string;
        outcome: 'executed' | 'refused' | 'indeterminate';
        evidenceDigest: string;
        evidence?: unknown;
    }): Promise<TrustProgramResult>;
    reconcileExecution(input: {
        instanceId: string;
        outcome: 'executed' | 'proved_no_effect';
        evidenceDigest: string;
        evidence?: unknown;
    }): Promise<TrustProgramResult>;
    invalidate(input: {
        instanceId: string;
        expectedRevision: number;
        reason: string;
    }): Promise<TrustProgramResult>;
}
/** Validate the closed, bounded DAG before any state is created. */
export declare function validateTrustProgram(program: unknown): {
    valid: boolean;
    reason: string;
    digest: null;
} | {
    valid: boolean;
    reason: null;
    digest: string;
};
export declare function trustProgramDigest(program: unknown): string;
/** Independently verify one stage receipt and optional relying-party bindings. */
export declare function verifyTrustStageReceipt(receipt: unknown, options?: {
    trustedKeys?: Readonly<Record<string, string | crypto.KeyObject>>;
    expected?: Readonly<Record<string, unknown>>;
    expectedIssuer?: Readonly<Record<string, unknown>>;
}): {
    valid: boolean;
    reason: string;
    checks: {
        structure: boolean;
        digest: boolean;
        key: boolean;
        signature: boolean;
        issuer: boolean;
        expected: boolean;
    };
    receipt_digest?: undefined;
    payload?: undefined;
} | {
    valid: boolean;
    reason: null;
    checks: {
        structure: boolean;
        digest: boolean;
        key: boolean;
        signature: boolean;
        issuer: boolean;
        expected: boolean;
    };
    receipt_digest: any;
    payload: any;
};
/**
 * In-process compare-and-swap store. Deliberately rejected by the kernel unless
 * allowEphemeralState is explicit; production must use a durable atomic store.
 */
export declare function createMemoryTrustProgramStore(): TrustProgramStore;
export declare function createTrustProgramKernel(options: TrustProgramKernelConfig): TrustProgramKernel;
/**
 * Copies the five-move EP-REVOCATION-v2 template
 * (packages/verify/src/revocation.ts) onto the two Trust Program artifacts.
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. The stage receipt's
 *    `signature: {algorithm, value}` becomes
 *    `signature: {profile, required_algorithms, public_key, key_id,
 *    pq_public_key, pq_key_id, signatures}`, which is a wire-format change, so
 *    the receipt takes a new `version` (-v1 -> -v2). The PROGRAM PROFILE moves
 *    with it: a v2 stage receipt is a receipt over a v2 program, and the
 *    program's `@version` is inside `program_digest`, which is inside the
 *    signed payload. verifyTrustStageReceipt and validateTrustProgram above
 *    are UNCHANGED and both refuse their v2 counterpart on the version marker
 *    (`receipt_structure_invalid` / `program_version_unsupported`) BEFORE any
 *    signature is inspected, and neither crashes on one.
 * 2. SET SHAPE. `signature.signatures` is an EP-SIG-AGILITY-v1 AgileSignature
 *    array ({ alg, sig, key_id? }), one entry per registered algorithm, reused
 *    verbatim. Ed25519 keeps its base64url SPKI DER public key; ML-DSA-65
 *    carries raw base64url public key bytes.
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` is INSIDE the signed bytes
 *    (trustStageReceiptV2SigningBytes). Drop the ML-DSA leg and narrow the set
 *    to ["Ed25519"] and the surviving Ed25519 signature no longer verifies,
 *    because the bytes changed. Leave the set intact and the missing leg is a
 *    structural refusal. The verifier rebuilds the bytes from the REGISTERED
 *    set and from the body it recomputed itself; the presented receipt never
 *    chooses what it is checked against.
 * 4. V1 COMPATIBILITY. verifyTrustStageReceipt stays SYNCHRONOUS and untouched.
 *    verifyTrustStageReceiptV2 is a SEPARATE async entry point (ML-DSA
 *    verification is inherently async); verifyTrustStageReceiptStatement routes
 *    on the version marker for callers holding a mixed bag. The v1 kernel
 *    (createTrustProgramKernel) is untouched and still mints v1 receipts.
 * 5. NAMED REFUSALS. Every failure sets a named check false and returns a
 *    readable reason; nothing throws on caller input. An absent ML-DSA backend
 *    surfaces as `pq_backend_unavailable` through the agility result, never a
 *    skipped check and never a pass on the classical leg alone.
 *
 * HONEST BOUNDARY. The ML-DSA-65 backend is @noble/post-quantum's pure-JS FIPS
 * 204 implementation, which is not independently audited and is not a FIPS
 * validated module; issuing or verifying under this profile is not a
 * certification claim. This profile is opt-in and is not on in any deployment.
 * v2 does NOT retroactively protect receipts already issued under v1.
 */
export declare const TRUST_PROGRAM_V2_VERSION = "EP-GATE-TRUST-PROGRAM-PROFILE-v2";
export declare const TRUST_STAGE_RECEIPT_V2_VERSION = "EP-GATE-TRUST-STAGE-RECEIPT-v2";
/** The registered required algorithm set, in canonical order. */
export declare const TRUST_STAGE_RECEIPT_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
/** A v2 stage-receipt issuer pin: BOTH public halves, pinned out of band. */
export interface TrustStageReceiptV2KeyPin {
    /** Ed25519 base64url SPKI DER. */
    public_key: string;
    /** ML-DSA-65 base64url raw public key bytes. */
    pq_public_key: string;
}
/**
 * An injected hybrid signer. Structurally the `signSet()` contract of
 * lib/key-custody.ts's HybridCustodySigner: sign the SAME bytes under every
 * required algorithm, in canonical order. It is accepted structurally rather
 * than imported because @emilia-protocol/gate does not depend on the app-tier
 * lib/ tree; a HybridCustodySigner satisfies this shape as-is.
 */
export interface TrustStageReceiptV2SignSetSigner {
    signSet(bytes: Uint8Array | Buffer, context?: Record<string, unknown>): Promise<Array<{
        alg: string;
        sig: string;
        key_id?: string;
    }>>;
}
export interface TrustStageReceiptV2SigningKeys {
    ed: {
        privateKey: crypto.KeyObject;
        publicKey?: string;
    };
    pq: {
        secretKey: Uint8Array | string;
        publicKey: string;
    };
}
/** Validate a v2 Trust Program profile. Same DAG body as v1, v2 marker only. */
export declare function validateTrustProgramV2(program: unknown): {
    valid: boolean;
    reason: string;
    digest: null;
} | {
    valid: boolean;
    reason: null;
    digest: string;
};
/** Digest a v2 Trust Program profile. Throws on an invalid program, like v1. */
export declare function trustProgramV2Digest(program: unknown): string;
/**
 * Route a program of EITHER profile version to its validator. A program whose
 * `@version` is neither refuses through the v1 validator, which is the
 * fail-closed answer. Synchronous: program validation has no signature.
 */
export declare function validateTrustProgramStatement(program: unknown): {
    valid: boolean;
    reason: string;
    digest: null;
} | {
    valid: boolean;
    reason: null;
    digest: string;
};
/**
 * The bytes BOTH legs sign: the same body v1 signs (version, issuer, payload)
 * under the v2 domain tag, plus the committed `required_algorithms` set.
 * Recomputed independently by the verifier from the PRESENTED body and the
 * REGISTERED set. See move 3 above.
 */
export declare function trustStageReceiptV2SigningBytes(body: {
    version?: unknown;
    issuer?: unknown;
    payload?: unknown;
}, requiredAlgorithms?: readonly string[]): Buffer;
/**
 * Mint a hybrid stage receipt. Throws on invalid input, a signer that returns
 * a malformed set, or an unavailable ML-DSA backend: a receipt missing the
 * ML-DSA leg must never be emitted, only refused.
 */
export declare function signTrustStageReceiptV2({ payload, context, keys, signer, }: {
    payload: Record<string, unknown>;
    context: Readonly<Record<string, unknown>>;
    keys?: TrustStageReceiptV2SigningKeys;
    signer?: TrustStageReceiptV2SignSetSigner;
}): Promise<{
    receipt_digest: string;
    signature: {
        profile: string;
        required_algorithms: ("Ed25519" | "ML-DSA-65")[];
        public_key: string;
        key_id: unknown;
        pq_public_key: string;
        pq_key_id: string;
        signatures: AgileSignature[];
    };
    version: string;
    issuer: {
        issuer: unknown;
        tenant: unknown;
        environment: unknown;
        audience: unknown;
        key_id: unknown;
    };
    payload: Record<string, unknown>;
}>;
/**
 * FAIL-CLOSED hybrid stage-receipt verifier. Never throws on caller input; a
 * v2 receipt NEVER verifies on one leg alone. Trust keys, the expected issuer,
 * and every expected payload binding are relying-party inputs; none is
 * accepted from the receipt itself.
 */
export declare function verifyTrustStageReceiptV2(receipt: unknown, options?: {
    trustedKeys?: Readonly<Record<string, TrustStageReceiptV2KeyPin>>;
    expected?: Readonly<Record<string, unknown>>;
    expectedIssuer?: Readonly<Record<string, unknown>>;
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}): Promise<{
    valid: boolean;
    reason: string;
    checks: {
        structure: boolean;
        digest: boolean;
        algorithm_set: boolean;
        legs_present: boolean;
        key: boolean;
        signature: boolean;
        issuer: boolean;
        expected: boolean;
    };
} | {
    valid: boolean;
    reason: null;
    checks: {
        structure: boolean;
        digest: boolean;
        algorithm_set: boolean;
        legs_present: boolean;
        key: boolean;
        signature: boolean;
        issuer: boolean;
        expected: boolean;
    };
    receipt_digest: string;
    payload: RecordLike;
}>;
/**
 * Route a stage receipt of EITHER version to its verifier. v1 receipts keep
 * the exact v1 verdict; v2 receipts get the hybrid check. A receipt whose
 * `version` is neither refuses through the v1 verifier, which is the
 * fail-closed answer.
 */
export declare function verifyTrustStageReceiptStatement(receipt: unknown, options?: {
    trustedKeys?: Readonly<Record<string, string | crypto.KeyObject | TrustStageReceiptV2KeyPin>>;
    expected?: Readonly<Record<string, unknown>>;
    expectedIssuer?: Readonly<Record<string, unknown>>;
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}): Promise<{
    valid: boolean;
    reason: string;
    checks: {
        structure: boolean;
        digest: boolean;
        key: boolean;
        signature: boolean;
        issuer: boolean;
        expected: boolean;
    };
    receipt_digest?: undefined;
    payload?: undefined;
} | {
    valid: boolean;
    reason: null;
    checks: {
        structure: boolean;
        digest: boolean;
        key: boolean;
        signature: boolean;
        issuer: boolean;
        expected: boolean;
    };
    receipt_digest: any;
    payload: any;
} | {
    valid: boolean;
    reason: string;
    checks: {
        structure: boolean;
        digest: boolean;
        algorithm_set: boolean;
        legs_present: boolean;
        key: boolean;
        signature: boolean;
        issuer: boolean;
        expected: boolean;
    };
}>;
declare const _default: {
    TRUST_PROGRAM_VERSION: string;
    TRUST_STAGE_RECEIPT_VERSION: string;
    TRUST_PROGRAM_V2_VERSION: string;
    TRUST_STAGE_RECEIPT_V2_VERSION: string;
    TRUST_STAGE_RECEIPT_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
    validateTrustProgram: typeof validateTrustProgram;
    validateTrustProgramV2: typeof validateTrustProgramV2;
    validateTrustProgramStatement: typeof validateTrustProgramStatement;
    trustProgramDigest: typeof trustProgramDigest;
    trustProgramV2Digest: typeof trustProgramV2Digest;
    verifyTrustStageReceipt: typeof verifyTrustStageReceipt;
    trustStageReceiptV2SigningBytes: typeof trustStageReceiptV2SigningBytes;
    signTrustStageReceiptV2: typeof signTrustStageReceiptV2;
    verifyTrustStageReceiptV2: typeof verifyTrustStageReceiptV2;
    verifyTrustStageReceiptStatement: typeof verifyTrustStageReceiptStatement;
    createMemoryTrustProgramStore: typeof createMemoryTrustProgramStore;
    createTrustProgramKernel: typeof createTrustProgramKernel;
};
export default _default;
//# sourceMappingURL=trust-program.d.ts.map