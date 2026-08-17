/**
 * Exact-action technical refusal evidence. It is not a legal determination,
 * an adverse-benefit denial, an authorization grant, or proof of delivery.
 */
import crypto from 'node:crypto';
import { type RiskRecord, type TrustedRiskKeys } from './reliance-risk-crypto.js';
import { type AgilityOptions } from '@emilia-protocol/verify/pq-signature-agility';
export declare const ACTION_REFUSAL_STATEMENT_VERSION = "EP-ACTION-REFUSAL-STATEMENT-v1";
export declare const ACTION_REFUSAL_CLAIM_BOUNDARY = "technical_refusal_not_legal_or_benefit_determination";
export declare const ACTION_REFUSAL_CLASSES: readonly string[];
export type ActionRefusalExpectedBindings = {
    caid?: string;
    action_digest?: string;
    relying_party_id?: string;
    program_id?: string;
    program_version?: number;
    source_digest?: string;
    program_digest?: string;
    nonce?: string;
};
export type ActionRefusalReplayStore = {
    durable: boolean;
    consume(relyingPartyId: string, nonce: string, refusalDigest: string): Promise<{
        accepted: boolean;
        reason: string | null;
    }>;
};
export type ActionRefusalExternalEvidenceStatus = 'VERIFIED' | 'NOT_VERIFIED' | 'INDETERMINATE';
export type ActionRefusalExternalEvidenceVerifier = (input: {
    statement: unknown;
    reference: Readonly<RiskRecord>;
    expected_evidence_digest: string;
}) => Promise<{
    status: ActionRefusalExternalEvidenceStatus;
    evidence_digest: string;
    reason: string | null;
}>;
export type ActionRefusalExternalEvidenceOptions = {
    trusted_keys?: TrustedRiskKeys;
    required?: Array<'delivery' | 'custody' | 'transparency_anchor'>;
    verifiers?: Partial<Record<'delivery' | 'custody' | 'transparency_anchor', ActionRefusalExternalEvidenceVerifier>>;
};
export declare function signActionRefusalStatement(input: RiskRecord, signer: {
    issuer_id: string;
    key_id: string;
    private_key: any;
}): RiskRecord;
export declare function actionRefusalStatementDigest(statement: unknown): string;
export declare function verifyActionRefusalStatement(statement: unknown, options?: {
    trusted_keys?: TrustedRiskKeys;
    now?: string | number;
    max_future_skew_sec?: number;
    expected?: ActionRefusalExpectedBindings;
}): {
    accepted: false;
    verified: false;
    reason: string;
    refusal_digest: string | null;
    semantics: null;
    delivery_evidence: "NOT_EVIDENCED";
    custody_evidence: "NOT_EVIDENCED";
    transparency_anchor: "NOT_REFERENCED";
    claim_boundary: string;
} | {
    accepted: true;
    verified: true;
    reason: null;
    refusal_digest: string | null;
    relying_party_id: any;
    nonce: any;
    semantics: any;
    delivery_evidence: string;
    custody_evidence: string;
    transparency_anchor: string;
    claim_boundary: string;
};
export declare function createMemoryActionRefusalReplayStore(): ActionRefusalReplayStore;
/**
 * Verify referenced delivery, custody, and transparency evidence with
 * relying-party-pinned adapters. A digest reference alone remains explicitly
 * unverified. This function never upgrades REFERENCED into VERIFIED by itself.
 */
export declare function verifyActionRefusalExternalEvidence(statement: unknown, options?: ActionRefusalExternalEvidenceOptions): Promise<{
    accepted: false;
    reason: string;
    legs: null;
} | {
    accepted: false;
    reason: string;
    legs: RiskRecord;
} | {
    accepted: true;
    reason: null;
    legs: RiskRecord;
}>;
export declare function acceptActionRefusalStatement(statement: unknown, options?: {
    trusted_keys?: TrustedRiskKeys;
    now?: string | number;
    max_future_skew_sec?: number;
    expected?: ActionRefusalExpectedBindings;
    replayStore?: ActionRefusalReplayStore;
    allowEphemeralReplayStore?: boolean;
    external_evidence?: ActionRefusalExternalEvidenceOptions;
}): Promise<{
    accepted: false;
    reason: string;
    replay_checked: boolean;
    replay_store_durable: boolean;
    verified: false;
    refusal_digest: string | null;
    semantics: null;
    delivery_evidence: "NOT_EVIDENCED";
    custody_evidence: "NOT_EVIDENCED";
    transparency_anchor: "NOT_REFERENCED";
    claim_boundary: string;
} | {
    accepted: false;
    reason: string;
    replay_checked: boolean;
    replay_store_durable: boolean;
    verified: true;
    refusal_digest: string | null;
    relying_party_id: any;
    nonce: any;
    semantics: any;
    delivery_evidence: string;
    custody_evidence: string;
    transparency_anchor: string;
    claim_boundary: string;
} | {
    external_evidence: {
        accepted: false;
        reason: string;
        legs: null;
    } | {
        accepted: false;
        reason: string;
        legs: RiskRecord;
    };
    accepted: false;
    reason: string;
    replay_checked: boolean;
    replay_store_durable: boolean;
    verified: false;
    refusal_digest: string | null;
    semantics: null;
    delivery_evidence: "NOT_EVIDENCED";
    custody_evidence: "NOT_EVIDENCED";
    transparency_anchor: "NOT_REFERENCED";
    claim_boundary: string;
} | {
    external_evidence: {
        accepted: false;
        reason: string;
        legs: null;
    } | {
        accepted: false;
        reason: string;
        legs: RiskRecord;
    };
    accepted: false;
    reason: string;
    replay_checked: boolean;
    replay_store_durable: boolean;
    verified: true;
    refusal_digest: string | null;
    relying_party_id: any;
    nonce: any;
    semantics: any;
    delivery_evidence: string;
    custody_evidence: string;
    transparency_anchor: string;
    claim_boundary: string;
} | {
    accepted: true;
    replay_checked: boolean;
    replay_store_durable: boolean;
    external_evidence: {
        accepted: true;
        reason: null;
        legs: RiskRecord;
    } | null;
    verified: true;
    reason: null;
    refusal_digest: string | null;
    relying_party_id: any;
    nonce: any;
    semantics: any;
    delivery_evidence: string;
    custody_evidence: string;
    transparency_anchor: string;
    claim_boundary: string;
}>;
/**
 * REFERENCE-DERIVED HYBRID MIGRATION. Copies, move for move, the reference
 * hybrid migration in docs/protocol/pq-hybrid-program.md, section "PATTERN: the
 * reference hybrid migration" (EP-REVOCATION-v2, packages/verify/src/revocation.ts):
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of the
 *    proof, a wire-format change, so the artifact takes a new @version
 *    (EP-ACTION-REFUSAL-STATEMENT-v2). The v1 verifier is untouched and refuses a
 *    v2 statement on its version marker (verifyRiskBody's @version check) before
 *    inspecting any signature, and never throws.
 * 2. SET SHAPE. `proof` carries `required_algorithms` plus a `signatures` array
 *    shaped exactly like EP-SIG-AGILITY-v1's AgileSignature ({ alg, sig, key_id? }),
 *    one entry per algorithm in the registered order. Ed25519 keeps its base64url
 *    SPKI DER public key; ML-DSA-65 carries raw base64url public key bytes.
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is committed INSIDE the
 *    signed bytes (actionRefusalV2SignedPayload below), under the same
 *    domain-separated `version\0canonicalize(body)` form the v1 risk-crypto
 *    signer uses. Drop the ML-DSA leg and narrow `required_algorithms` and the
 *    surviving Ed25519 signature no longer verifies. The verifier rebuilds the
 *    bytes from the REGISTERED set; the presented statement never chooses what it
 *    is checked against.
 * 4. V1 COMPATIBILITY. v1 statements keep verifying through the unchanged
 *    synchronous verifyActionRefusalStatement; v2 verification is ASYNC (ML-DSA
 *    verification is async), so it is a SEPARATE entry point, with
 *    verifyActionRefusalStatementAny() routing on @version. The v1 verifier is
 *    never made async.
 * 5. NAMED REFUSALS. Every failure sets a named check false and pushes a readable
 *    reason; nothing throws on caller input. An absent ML-DSA backend is
 *    'pq_backend_unavailable' surfaced through the agility result, never a skipped
 *    check and never a pass on the classical leg.
 *
 * HONEST BOUNDARIES carry over from v1: this is exact-action technical refusal
 * evidence, not a legal or benefit determination, not an authorization grant, not
 * proof of delivery. The ML-DSA backend is @noble/post-quantum's pure-JS FIPS 204
 * implementation, not independently audited and not a FIPS validated module. v2
 * does NOT retroactively protect statements already issued under v1.
 */
export declare const ACTION_REFUSAL_STATEMENT_V2_VERSION = "EP-ACTION-REFUSAL-STATEMENT-v2";
export declare const ACTION_REFUSAL_STATEMENT_V2_DOMAIN = "EP-ACTION-REFUSAL-STATEMENT-v2\0";
/** The registered required algorithm set, in canonical order. */
export declare const ACTION_REFUSAL_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export interface ActionRefusalV2TrustedKeys {
    [key_id: string]: {
        issuer_id: string;
        public_key: string;
        pq_public_key: string;
    };
}
/**
 * The bytes BOTH legs sign: the same domain-separated `version\0canonicalize(body)`
 * form as the v1 risk-crypto signer, plus the committed `required_algorithms` set,
 * under the v2 domain tag. `body` is the full v2 body (with @version and issuer)
 * and WITHOUT the proof. Recomputed independently by the verifier from the
 * PRESENTED body and the REGISTERED set. See PATTERN move 3.
 */
export declare function actionRefusalV2SignedPayload(body: RiskRecord, requiredAlgorithms?: readonly string[]): Buffer;
/**
 * Mint a real hybrid v2 refusal statement. Issuance may throw on invalid local
 * input (matching signActionRefusalStatement); verification below never throws.
 * The domain body is validated by the exact same v1 validators, so a v2 statement
 * carries an identical, fully-checked refusal body.
 */
export declare function signActionRefusalStatementV2(input: RiskRecord, signer: {
    issuer_id: string;
    key_id: string;
    private_key: crypto.KeyObject | Parameters<typeof crypto.createPrivateKey>[0];
    pq_public_key: string;
    pq_private_key: string | Uint8Array;
}, options?: AgilityOptions): Promise<RiskRecord>;
/**
 * FAIL-CLOSED hybrid verifier for one EP-ACTION-REFUSAL-STATEMENT-v2. Never throws
 * on caller input; a v2 statement NEVER verifies on one leg alone.
 */
export declare function verifyActionRefusalStatementV2(statement: unknown, options?: {
    trusted_keys?: ActionRefusalV2TrustedKeys;
    now?: string | number;
    max_future_skew_sec?: number;
    expected?: ActionRefusalExpectedBindings;
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}): Promise<{
    accepted: false;
    verified: false;
    reason: string;
    refusal_digest: string | null;
    checks: Record<string, boolean>;
    semantics: null;
    claim_boundary: string;
} | {
    accepted: true;
    verified: true;
    reason: null;
    refusal_digest: string;
    relying_party_id: any;
    nonce: any;
    semantics: any;
    checks: Record<string, boolean>;
    claim_boundary: string;
}>;
/**
 * Route a statement of EITHER version to its verifier. v1 statements keep the
 * exact v1 verdict; v2 statements get the hybrid check. A statement whose
 * @version is neither refuses through the v1 verifier, which is fail-closed.
 */
export declare function verifyActionRefusalStatementAny(statement: unknown, options?: any): Promise<{
    accepted: false;
    verified: false;
    reason: string;
    refusal_digest: string | null;
    semantics: null;
    delivery_evidence: "NOT_EVIDENCED";
    custody_evidence: "NOT_EVIDENCED";
    transparency_anchor: "NOT_REFERENCED";
    claim_boundary: string;
} | {
    accepted: true;
    verified: true;
    reason: null;
    refusal_digest: string | null;
    relying_party_id: any;
    nonce: any;
    semantics: any;
    delivery_evidence: string;
    custody_evidence: string;
    transparency_anchor: string;
    claim_boundary: string;
} | {
    accepted: false;
    verified: false;
    reason: string;
    refusal_digest: string | null;
    checks: Record<string, boolean>;
    semantics: null;
    claim_boundary: string;
} | {
    accepted: true;
    verified: true;
    reason: null;
    refusal_digest: string;
    relying_party_id: any;
    nonce: any;
    semantics: any;
    checks: Record<string, boolean>;
    claim_boundary: string;
}>;
//# sourceMappingURL=action-refusal-statement.d.ts.map