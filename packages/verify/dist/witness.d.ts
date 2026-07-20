/**
 * @emilia-protocol/verify — WITNESS COSIGNATURE verification (EP-WITNESS-v1)
 *
 * Step 3 of the transparency layer (see docs/security/TRANSPARENCY-LAYER-DESIGN.md
 * and consistency.js). A transparency-log operator signs its own checkpoint
 * {tree_size, root_hash, log_key_id, ...}. A single operator signature does NOT
 * make a split view (equivocation) detectable: the operator can sign two
 * internally-consistent but divergent heads and show each to a different
 * verifier. An INDEPENDENT WITNESS re-signs the SAME committed checkpoint bytes.
 * When several independent witnesses each cosign whatever head they observed,
 * two verifiers who later gossip their witness cosignatures can detect that the
 * log presented divergent heads at the same tree_size.
 *
 * WHAT A WITNESS COSIGNATURE PROVES
 *   "I, witness <witness_id>, observed a checkpoint claiming this tree_size and
 *    this root_hash under this log_key_id, and I attest to having seen exactly
 *    these committed bytes."
 *
 * WHAT IT DOES *NOT* PROVE (honesty)
 *   - It does NOT vouch for the log's honesty or that the log is append-only. A
 *     witness signs the bytes it was shown; it does not re-derive the tree.
 *   - It does NOT establish CURRENT validity. A cosignature attests to a head as
 *     OBSERVED at cosign time only; currency needs a fresh signed head / online
 *     check, exactly as for the log's own signature.
 *   - A SINGLE witness detects nothing. Equivocation is only detectable when
 *     multiple INDEPENDENT witnesses cosign and their views are later compared
 *     (gossip). requireWitnessQuorum() enforces the "multiple distinct pinned
 *     witnesses agree on ONE head" half of that; cross-view gossip is the
 *     deployment's job.
 *
 * DOMAIN SEPARATION (critical)
 *   The log signs   Ed25519( null, SHA-256( canonicalize(signedCheckpoint) ) ).
 *   A witness signs  Ed25519( null, SHA-256( WITNESS_DOMAIN_TAG || canonicalize(signedCheckpoint) ) ).
 *   `signedCheckpoint` is the checkpoint with its own `log_signature` removed —
 *   i.e. the identical committed bytes the log signed. Prepending the domain tag
 *   to the pre-image means a witness cosignature and a log signature are
 *   computed over DIFFERENT bytes and can never be confused or replayed for one
 *   another, even if (by misconfiguration) the same key were pinned in both
 *   roles. Byte-identical convention used by witness/server.mjs.
 *
 * KEY / HASH ENCODING (matches index.js exactly)
 *   - Public keys: base64url-encoded SPKI DER, verified with crypto.verify(null,…).
 *   - Signatures:  base64url.
 *   - Hashes in the checkpoint: "sha256:<hex>" or bare hex; compared prefix-stripped.
 *
 * FAIL-CLOSED
 *   Every check refuses on missing / malformed / unrecognized input and never
 *   silently passes. An unknown or unpinned witness key refuses. A signature over
 *   different bytes refuses. A cosignature presented for a different checkpoint
 *   (different tree_size / root_hash / log_key_id than the one being verified)
 *   refuses. The k-of-n helper refuses on fewer than k DISTINCT pinned witnesses.
 *
 * This module imports canonicalize() from index.js so the witness and every other
 * signed-material computation in the package share one canonicalization source of
 * truth. It adds NO new canonicalization.
 *
 * @license Apache-2.0
 */
export declare const WITNESS_VERSION = "EP-WITNESS-v1";
/**
 * Domain-separation tag prepended to the SHA-256 pre-image a witness signs.
 * A UTF-8 label with a trailing 0x00 so it can never be a prefix of the
 * canonical JSON that follows (canonical JSON begins with '{' 0x7b, never 0x00).
 * The log's own signature has NO such prefix, so the two pre-images are disjoint.
 */
export declare const WITNESS_DOMAIN_TAG = "EP-WITNESS-COSIGN-v1\0";
export interface WitnessCheckpoint {
    tree_size?: unknown;
    root_hash?: unknown;
    log_key_id?: unknown;
    [key: string]: unknown;
}
export interface WitnessCosignature {
    witness_id?: unknown;
    signature?: unknown;
    alg?: unknown;
    tree_size?: unknown;
    root_hash?: unknown;
    log_key_id?: unknown;
    [key: string]: unknown;
}
export interface PinnedWitnessKey {
    witness_id?: unknown;
    public_key?: unknown;
    [key: string]: unknown;
}
export declare function witnessSigningDigest(checkpoint: unknown): Buffer | null;
/**
 * Verify a single witness cosignature over a checkpoint.
 *
 * @param {object} checkpoint  the log checkpoint {tree_size, root_hash, log_key_id, ...}.
 *   May or may not still carry `log_signature` — it is stripped before hashing,
 *   so a witness cosignature is over the same committed bytes the log signed.
 * @param {object} cosignature  {
 *     witness_id: string,        // stable id of the cosigning witness
 *     signature: string,         // base64url Ed25519 over witnessSigningDigest(checkpoint)
 *     tree_size?: number,        // OPTIONAL echo of the head the witness cosigned
 *     root_hash?: string,        //   ... used to refuse a cosignature reused for a
 *     log_key_id?: string,       //   different checkpoint (fail-closed when echoed)
 *     alg?: string,              // OPTIONAL, must equal 'EP-WITNESS-v1' when present
 *   }
 * @param {{witness_id: string, public_key: string}} pinnedWitnessKey  the ONE
 *   witness the caller trusts for this cosignature: a stable witness_id plus its
 *   base64url SPKI-DER Ed25519 public key. An unknown / unpinned witness refuses.
 * @returns {{verified: boolean, witness_id: string|null, reason?: string}}
 */
export declare function verifyWitnessCosignature(checkpoint: WitnessCheckpoint | null | undefined, cosignature: WitnessCosignature | null | undefined, pinnedWitnessKey: PinnedWitnessKey | null | undefined): {
    verified: boolean;
    witness_id: string | null;
    reason?: string;
};
/**
 * Require >= k DISTINCT pinned witnesses to have validly cosigned the SAME head.
 *
 * Detects the "not enough independent observers agree on one head" condition:
 * accepts iff at least `k` cosignatures verify, each from a DIFFERENT pinned
 * witness_id, all over the ONE checkpoint passed in. Duplicate witness_ids count
 * ONCE (a single witness cannot satisfy a k-of-n threshold by cosigning twice).
 * Cosignatures that fail verification, name an unpinned witness, or reference a
 * different head are ignored (they do not count toward k) and recorded in
 * `reasons` for diagnostics.
 *
 * HONESTY: this proves k distinct trusted witnesses attest to ONE head. It does
 * NOT by itself detect that the log showed a DIFFERENT head to someone else —
 * that cross-view comparison (gossip) is the deployment's responsibility. This
 * helper is the local, single-view half of the check.
 *
 * @param {object} checkpoint  the ONE checkpoint head all witnesses must have cosigned.
 * @param {object[]} cosignatures  candidate witness cosignatures (see verifyWitnessCosignature).
 * @param {Array<{witness_id:string, public_key:string}>} pinnedWitnessKeys  the set of
 *   trusted witnesses. Entries with a duplicate or missing witness_id are dropped.
 * @param {number} k  threshold; must be an integer >= 1.
 * @returns {{ ok: boolean, met: number, required: number,
 *   witness_ids: string[], reasons: string[] }}
 *   `met` is the number of DISTINCT pinned witnesses that validly cosigned this
 *   head; `witness_ids` lists them. Fail-closed: bad inputs return ok:false.
 */
export declare function requireWitnessQuorum(checkpoint: WitnessCheckpoint | null | undefined, cosignatures: unknown, pinnedWitnessKeys: unknown, k: number): {
    required: number;
    ok: boolean;
    met: number;
    witness_ids: string[];
    reasons: string[];
};
//# sourceMappingURL=witness.d.ts.map