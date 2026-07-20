/**
 * @emilia-protocol/verify — THIRD-PARTY-verifiable one-time CONSUMPTION proofs
 * (sparse-Merkle-over-nonce consumption profile). EXPERIMENTAL / additive.
 *
 * THE PROBLEM THIS CLOSES. A trust receipt's `consumption` block today is an
 * OPERATOR ASSERTION: the operator says "I committed this nonce once." Nothing
 * in the receipt makes double-spend of a nonce detectable OFFLINE. A malicious
 * operator can commit the SAME nonce twice and hand each relying party a receipt
 * that verifies in isolation; catching it needs an ONLINE audit that walks the
 * whole log. This profile replaces the assertion with a proof: the operator must
 * maintain a sparse Merkle tree keyed by nonce, and produce, at commit time, a
 * proof that the nonce transitioned ABSENT -> PRESENT exactly once between two
 * WITNESSED log heads. A second commit of the same nonce cannot also exhibit a
 * valid absent-at-h1 proof under the same append-only log, so double-consumption
 * becomes offline-detectable by any third party holding these two heads.
 *
 * WHAT A CONSUMPTION BUNDLE PROVES (all three, conjunctively, fail-closed):
 *   (a) NON-INCLUSION at head h1: the nonce's leaf held the DEFAULT (empty)
 *       value at h1  -> the nonce was not yet consumed as of h1.
 *   (b) INCLUSION at head h2: the same nonce's leaf holds the PRESENT marker at
 *       h2  -> the nonce is consumed as of h2.
 *   (c) APPEND-ONLY h1 -> h2: h2 is a consistency-proven extension of h1 (reuses
 *       verifyCheckpointConsistency from consistency.js — the SAME EP-MERKLE-v2
 *       branch construction; this module does NOT invent a second Merkle scheme).
 * Together: the nonce went absent -> present exactly once between two heads that
 * are provably the same append-only log. There is no valid bundle in which the
 * nonce is BOTH absent-at-h1 under this log AND was already consumed earlier.
 *
 * HONESTY / SCOPE (this is a house rule, stated in code on purpose):
 *   - This module ships BOTH sides at reference level: the VERIFIER
 *     (`verifyConsumptionProof`) and the reference issuer-side EMITTER
 *     (`ReferenceConsumptionTree`, exported). The emitter maintains a sparse
 *     consumption tree, inserts a nonce leaf, and PRODUCES the non-inclusion /
 *     inclusion sub-proofs in the exact wire format the verifier accepts, so a
 *     third party can reproduce a bundle, not only check one. It is a
 *     spec-faithful REFERENCE that pins the wire format; a production issuer
 *     emits byte-equivalent proofs from its own ledger. The reference emitter is
 *     NOT itself a production consumption ledger (in-memory present set, roots
 *     recomputed by DFS). Running an independent issuer/log is deployment.
 *   - Offline verification of a bundle establishes append-only consistency
 *     between two OBSERVED heads. It does NOT establish CURRENCY (that h2 is the
 *     log's latest head) and does NOT by itself defeat split-view equivocation
 *     (a log showing different histories to different verifiers). Currency and
 *     non-equivocation need a fresh signed head plus independent witnesses /
 *     gossip. See docs/security/TRANSPARENCY-LAYER-DESIGN.md.
 *   - The sparse-tree construction here binds VALUES to leaves. It does NOT by
 *     itself verify the two checkpoints' log SIGNATURES; that is the caller's
 *     job (verifyTrustReceipt checks checkpoint_signature). This function proves
 *     the tree-shaped facts; pass it roots you have independently authenticated.
 *
 * DOMAIN SEPARATION (reuses EP-MERKLE-v2 branch bytes; adds distinct LEAF bytes):
 *   - Branch  = SHA-256(0x01 || leftHex || rightHex) -> hex   [SAME as EP-MERKLE-v2]
 *   - PRESENT leaf = SHA-256(0x02 || keyHex || valueHex) -> hex   [EP-SMT-CONSUME-v1]
 *   - DEFAULT leaf = SHA-256(0x03) -> hex (the empty-subtree/absent marker)
 *   Distinct 0x02 (present) and 0x03 (default) leaf domains mean a DEFAULT leaf
 *   can never be reinterpreted as a PRESENT leaf at the same key, and neither can
 *   collide with a dense-log leaf (0x00) or a branch (0x01). The empty-subtree
 *   marker at every level is derived by folding DEFAULT leaves up with the SAME
 *   0x01 branch rule, so a non-inclusion proof and an inclusion proof share one
 *   hash construction end to end.
 *
 * SPARSE-MERKLE SHAPE. Fixed depth D (default SMT_DEPTH). The key path is the
 * top D bits of SHA-256(nonce), MSB first (bit i selects left=0/right=1 at level
 * i from the root). Each proof is D sibling hashes, root-to-leaf order. A leaf is
 * PRESENT (value = SHA-256 of the nonce commitment content) or DEFAULT (absent).
 *
 * @license Apache-2.0
 */
interface SubProof {
    root?: unknown;
    siblings?: unknown;
    present?: unknown;
    value?: unknown;
}
interface ConsumptionChecks {
    non_inclusion: boolean;
    inclusion: boolean;
    consistency: boolean;
}
interface ConsumptionResult {
    valid: boolean;
    checks: ConsumptionChecks;
    reason: string | null;
}
export declare const CONSUMPTION_PROFILE = "EP-SMT-CONSUME-v1";
/** Leaf domain tag for the sparse consumption tree (documented in reason strings). */
export declare const CONSUMPTION_LEAF_DOMAIN = "EP-SMT-CONSUME-v1";
/** Fixed sparse-tree depth (bits of SHA-256(nonce) consumed as the key path). */
export declare const SMT_DEPTH = 32;
/**
 * Verify a third-party CONSUMPTION proof bundle: prove a nonce transitioned
 * ABSENT -> PRESENT exactly once between two witnessed, append-only-linked heads.
 *
 * bundle shape:
 *   {
 *     nonce: string,                       // the one-time nonce being consumed
 *     non_inclusion_proof: {               // @ head h1: nonce ABSENT
 *       root, siblings[SMT_DEPTH], present:false
 *     },
 *     inclusion_proof: {                   // @ head h2: nonce PRESENT
 *       root, siblings[SMT_DEPTH], present:true, value
 *     },
 *     consistency_proof: string[],         // RFC 6962 h1 -> h2 (EP-MERKLE-v2)
 *     checkpoints: {
 *       h1: { tree_size, root_hash },      // dense-log head witnessing h1's SMT root
 *       h2: { tree_size, root_hash }       // dense-log head witnessing h2's SMT root
 *     }
 *   }
 *
 * The `checkpoints.h*.root_hash` are the DENSE append-only log roots the
 * consistency proof links (currency of the SMT roots is carried by the log; the
 * caller must have authenticated the checkpoint signatures separately — this
 * function proves only the tree-shaped facts). `non_inclusion_proof.root` and
 * `inclusion_proof.root` are the SMT roots as of h1 and h2 respectively.
 *
 * FAIL-CLOSED: any missing/malformed/invalid sub-proof, a non-append-only
 * h1->h2, a present-at-h1, or an absent-at-h2 refuses with a DISTINCT reason.
 * The default for `present` is refusal (never inferred). Nothing silently passes.
 *
 * @param {object} bundle
 * @returns {{valid:boolean, checks:{non_inclusion:boolean, inclusion:boolean, consistency:boolean}, reason:(string|null)}}
 */
export declare function verifyConsumptionProof(bundle: unknown): ConsumptionResult;
/**
 * Reference issuer-side consumption emitter. Keys are hex SHA-256(nonce); only
 * PRESENT leaves are stored, everything else is the default. `insert(nonce)`
 * consumes a nonce and `prove(nonce)` emits the non-inclusion / inclusion
 * sub-proof in the wire format `verifyConsumptionProof()` accepts. Pairing two
 * roots (before and after the insert) with a dense-log consistency proof yields
 * a full bundle. This is the REFERENCE emitter that pins the wire format so a
 * third party can reproduce a proof; a production issuer emits byte-equivalent
 * proofs from its own ledger. EXPERIMENTAL / additive; not a production ledger.
 */
export declare class ReferenceConsumptionTree {
    depth: number;
    empty: string[];
    present: Map<string, string>;
    constructor(depth?: number);
    /** Insert (consume) a nonce with a value; value defaults to the key itself. */
    insert(nonce: string, value?: unknown): {
        keyHex: string;
        valueHex: string;
    };
    _leafAt(keyHex: string): string;
    root(): string;
    _rootRec(level: number, prefixBits: string): string;
    _bitsOf(keyHex: string, n: number): string;
    /**
     * Produce a proof for `nonce`: the sibling path root-to-leaf, plus whether the
     * leaf is present and its value. Works for both present (inclusion) and absent
     * (non-inclusion) keys.
     */
    prove(nonce: string): SubProof;
}
export {};
//# sourceMappingURL=consumption-proof.d.ts.map