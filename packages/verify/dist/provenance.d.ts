import { type AgilityOptions } from './pq-signature-agility.js';
type Obj = Record<string, any>;
interface ProvenanceOptions {
    humanKeyClasses?: string[];
    allowUnsignedDelegations?: boolean;
    now?: number;
    requireActionApprovalAlways?: boolean;
    rootVerification?: Obj;
    root_verification?: Obj;
    actionVerification?: Obj;
    action_verification?: Obj;
    delegationKeys?: Record<string, Obj>;
    reversibilityAsserted?: (execution: Obj) => boolean;
}
export declare const PROVENANCE_VERSION = "EP-PROVENANCE-CHAIN-v1";
/**
 * Verify an EP-PROVENANCE-CHAIN-v1 document fully offline. FAIL CLOSED.
 * See lib/provenance/chain.js for the full contract; opts mirror it
 * (humanKeyClasses, delegationKeys, reversibilityAsserted, allowUnsignedDelegations,
 * now, requireActionApprovalAlways).
 */
export declare function verifyProvenanceOffline(doc: Obj, opts?: ProvenanceOptions): {
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
    links: Obj[];
    agent_identity: {
        agent_id: any;
        claimed_by: any;
        claim_only: boolean;
        attestation_signature_valid: boolean | null;
    } | null;
    liability: {
        owner: any;
        owner_name: any;
        evidence_only: boolean;
        attestation_signature_valid: boolean | null;
    } | null;
};
/**
 * Reference hybrid migration for this surface. The chain document's OWN
 * cryptographic surface -- the part packages/verify/src/provenance.ts owns
 * directly -- is the delegation-link proof (delegationProofBytes /
 * verifyDetachedSignature above). The embedded root/action receipts remain
 * whatever EP-RECEIPT-v1/v2 the receipt-issuance hybridization workstream
 * (packages/issue, packages/verify/src/index.ts) ships; this file composes
 * verifyTrustReceipt UNCHANGED in both v1 and v2, exactly as the v1 header
 * describes ("adds NO new trust"). Copies the five moves from
 * EP-REVOCATION-v2 (packages/verify/src/revocation.ts):
 *
 * 1. VERSION BUMP. The document's `@version` moves EP-PROVENANCE-CHAIN-v1 to
 *    -v2. verifyProvenanceOffline above is UNCHANGED and refuses a v2
 *    document on the version marker before inspecting any delegation proof.
 * 2. SET SHAPE. Each delegation link's `proof_set` (replacing v1's `proof`)
 *    carries `required_algorithms` plus a `signatures` array shaped exactly
 *    like EP-SIG-AGILITY-v1's AgileSignature ({alg, sig, key_id?}), one entry
 *    per algorithm, reusing that shape verbatim.
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` is INSIDE the signed bytes
 *    (delegationProofV2Bytes), independently recomputed by the verifier from
 *    the registered set -- never read off the presented link.
 * 4. V1 COMPATIBILITY. v1 documents keep verifying, unchanged, through the
 *    sync verifyProvenanceOffline above. v2 verification is a separate ASYNC
 *    entry point (ML-DSA verification is async) because a delegation chain
 *    may be arbitrarily long and every hop's proof must be awaited.
 * 5. NAMED REFUSALS. Nothing throws on caller input; a missing ML-DSA backend
 *    is a refusal via the agility module's `pq_backend_unavailable`, never a
 *    skipped check and never a pass on the Ed25519 leg alone.
 *
 * HARDENING BEYOND V1. verifyDelegationProofSetV2 verifies ONLY against the
 * relying-party-PINNED key pair for the delegator -- it never reads a public
 * key off the presented proof at all, so there is no "presented key equals
 * pinned key" indirection to get wrong (v1's proof_key_bound check exists
 * only because v1 carries the signer's public key inline; v2 doesn't).
 */
export declare const PROVENANCE_V2_VERSION = "EP-PROVENANCE-CHAIN-v2";
export declare const PROVENANCE_DELEGATION_PROOF_V2_VERSION = "EP-PROVENANCE-DELEGATION-PROOF-v2";
/** The registered required algorithm set, in canonical order. */
export declare const PROVENANCE_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export interface ProvenanceDelegationV2Pin {
    /** Ed25519: base64url SPKI DER. */
    public_key?: string;
    /** ML-DSA-65: base64url of the raw 1952-byte public key. */
    pq_public_key?: string;
}
export interface ProvenanceV2Options extends AgilityOptions {
    humanKeyClasses?: string[];
    allowUnsignedDelegations?: boolean;
    now?: number;
    requireActionApprovalAlways?: boolean;
    rootVerification?: Obj;
    root_verification?: Obj;
    actionVerification?: Obj;
    action_verification?: Obj;
    delegationKeys?: Record<string, ProvenanceDelegationV2Pin>;
    reversibilityAsserted?: (execution: Obj) => boolean;
}
/**
 * Bytes BOTH legs sign for one delegation link's hybrid proof. Same signed
 * field subset as v1's delegationProofBytes (DELEGATION_PROOF_FIELDS),
 * domain-separated and committing the REGISTERED algorithm set. Recomputed
 * independently by the verifier; never trusts a presented algorithm list.
 */
export declare function delegationProofV2Bytes(link: Obj, requiredAlgorithms?: readonly string[]): Buffer;
/**
 * Verify one v2 (hybrid) delegation-link `proof_set`. FAIL-CLOSED, never
 * throws. A missing pin, a stripped leg, or a narrowed `required_algorithms`
 * all refuse; neither algorithm alone ever suffices.
 */
export declare function verifyDelegationProofSetV2(link: Obj, pin: ProvenanceDelegationV2Pin | undefined, opts?: AgilityOptions): Promise<boolean>;
/**
 * Verify an EP-PROVENANCE-CHAIN-v2 document fully offline. FAIL CLOSED.
 * Identical control flow to verifyProvenanceOffline (root/action receipt
 * verification via the unchanged verifyTrustReceipt, scope containment,
 * monotonic constraints, leaf-permits-action) except each delegation link's
 * proof is verified via verifyDelegationProofSetV2 (hybrid, async) against
 * `link.proof_set` instead of verifyDetachedSignature against `link.proof`.
 */
export declare function verifyProvenanceOfflineV2(doc: Obj, opts?: ProvenanceV2Options): Promise<{
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
    links: Obj[];
    agent_identity: {
        agent_id: any;
        claimed_by: any;
        claim_only: boolean;
        attestation_signature_valid: boolean | null;
    } | null;
    liability: {
        owner: any;
        owner_name: any;
        evidence_only: boolean;
        attestation_signature_valid: boolean | null;
    } | null;
}>;
/**
 * Route a document of EITHER version to its verifier. A `@version` naming
 * neither refuses through the v1 (sync) verifier's version check, which is
 * the fail-closed answer.
 */
export declare function verifyProvenanceOfflineStatement(doc: Obj, opts?: ProvenanceV2Options): Promise<{
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
    links: Obj[];
    agent_identity: {
        agent_id: any;
        claimed_by: any;
        claim_only: boolean;
        attestation_signature_valid: boolean | null;
    } | null;
    liability: {
        owner: any;
        owner_name: any;
        evidence_only: boolean;
        attestation_signature_valid: boolean | null;
    } | null;
}>;
export {};
//# sourceMappingURL=provenance.d.ts.map